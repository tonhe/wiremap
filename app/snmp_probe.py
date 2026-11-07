"""SNMP fallback probe.

Runs whenever a login fails (auth, refused, timeout, SSH negotiation) and SNMP
credentials were supplied. A device that will not accept a login is not
necessarily unreachable -- sysDescr alone tells us the platform,
the software version and the real hostname, which is enough to stop the device
being an anonymous failure in the report.

This sits outside BaseCollector deliberately. That interface is CLI-shaped
(get_commands returning command strings, parse receiving raw text) and does not
describe OID retrieval.
"""
import asyncio
import logging
import re

logger = logging.getLogger(__name__)

SYS_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}

# ENTITY-MIB table columns, not scalars -- read with GETNEXT to take the first
# entry, which is the chassis on essentially all implementations. sysDescr says
# nothing useful on PAN-OS and several other platforms, so this is where model
# and serial actually come from.
ENTITY_COLUMNS = {
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
}

# Vendor branches for platforms that populate neither sysDescr nor ENTITY-MIB.
# Keyed by the device type parse_sysdescr resolves.
VENDOR_OIDS = {
    "paloalto_panos": {
        # PAN-COMMON-MIB::panSys
        "software_version": "1.3.6.1.4.1.25461.2.1.2.1.1.0",
        "model": "1.3.6.1.4.1.25461.2.1.2.1.2.0",
        "serial": "1.3.6.1.4.1.25461.2.1.2.1.3.0",
    },
}
# Alias so callers can look the branch up by vendor name too.
VENDOR_OIDS["paloalto"] = VENDOR_OIDS["paloalto_panos"]

_VALID_VERSIONS = ("v2c", "v3")

# Per-device outcome of the fallback, recorded on the failure record so the
# report says whether a device that refused a login answered SNMP at all.
# A v2c agent silently drops a wrong community, so for v2c a bad community
# is indistinguishable from no agent: both read as TIMEOUT. Only v3 rejects
# out loud (unknown user, wrong digest, decryption error).
OUTCOME_OK = {"v2c": "v2c ok", "v3": "v3 ok"}
OUTCOME_TIMEOUT = "timeout"
OUTCOME_REJECTED = "auth/community rejected"
OUTCOME_NO_CREDENTIALS = "no credentials"
OUTCOME_ERROR_PREFIX = "error: "

_REJECTED_INDICATIONS = {
    "UnknownUserName", "WrongDigest", "DecryptionError",
    "AuthenticationFailure", "AuthenticationError", "UnknownSecurityName",
    "UnsupportedSecurityLevel", "NoAuthentication",
}
_REJECTED_STATUSES = {"authorizationerror", "noaccess"}


class SnmpQueryError(Exception):
    """A query the agent answered with an error, or never answered."""
    def __init__(self, outcome, detail=""):
        super().__init__(detail or outcome)
        self.outcome = outcome


def classify_snmp_error(error_indication=None, error_status=None):
    """Map a pysnmp error indication or PDU error status to an outcome."""
    if error_indication:
        name = type(error_indication).__name__
        text = str(error_indication)
        if name == "RequestTimedOut" or "timeout" in text.lower():
            return OUTCOME_TIMEOUT
        if name in _REJECTED_INDICATIONS:
            return OUTCOME_REJECTED
        return OUTCOME_ERROR_PREFIX + (text or name)
    status = str(error_status or "")
    if status.lower() in _REJECTED_STATUSES:
        return OUTCOME_REJECTED
    return OUTCOME_ERROR_PREFIX + (status or "unknown")

# sysDescr is the only universally implemented identity string, so platform
# detection keys off it. Ordered -- NX-OS also says "Cisco".
_PLATFORM_PATTERNS = [
    (re.compile(r"NX-OS", re.I), "cisco_nxos"),
    (re.compile(r"Adaptive Security Appliance|\bASAv?\b", re.I), "cisco_asa"),
    (re.compile(r"IOS[- ]XE", re.I), "cisco_xe"),
    (re.compile(r"IOS[- ]XR", re.I), "cisco_xr"),
    (re.compile(r"Cisco Controller|AireOS", re.I), "cisco_wlc"),
    (re.compile(r"Cisco IOS|Cisco Internetwork", re.I), "cisco_ios"),
    (re.compile(r"Arista", re.I), "arista_eos"),
    (re.compile(r"VyOS|Vyatta", re.I), "vyos"),
    (re.compile(r"JUNOS|Juniper", re.I), "juniper_junos"),
    (re.compile(r"WatchGuard|Fireware", re.I), "watchguard_fireware"),
    (re.compile(r"PAN-OS|Palo Alto", re.I), "paloalto_panos"),
    (re.compile(r"FortiGate|FortiOS", re.I), "fortinet"),
    (re.compile(r"ProCurve", re.I), "hp_procurve"),
    (re.compile(r"Comware", re.I), "hp_comware"),
    (re.compile(r"ExtremeXOS", re.I), "extreme"),
    (re.compile(r"MikroTik|RouterOS", re.I), "mikrotik_routeros"),
]

_VERSION_PATTERNS = [
    re.compile(r"Version\s+([0-9][^\s,]*)", re.I),
    re.compile(r"\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9]+)?)\b"),
]


class SnmpCredentials:
    def __init__(self, version=None, community="", username="",
                 auth_key="", priv_key="", auth_protocol="sha",
                 priv_protocol="aes"):
        if version is None:
            self.version = None
        elif version not in _VALID_VERSIONS:
            raise ValueError(
                f"unsupported SNMP version {version!r}; expected one of {_VALID_VERSIONS}")
        else:
            self.version = version

        self.community = community or ""
        self.username = username or ""
        self.auth_key = auth_key or ""
        self.priv_key = priv_key or ""
        self.auth_protocol = (auth_protocol or "sha").lower()
        self.priv_protocol = (priv_protocol or "aes").lower()

        if self.version == "v2c" and not self.community:
            raise ValueError("SNMP v2c requires a community string")
        if self.version == "v3" and not self.username:
            raise ValueError("SNMP v3 requires a username")

    def is_configured(self) -> bool:
        return self.version in _VALID_VERSIONS


def parse_sysdescr(descr) -> dict:
    """Derive device type and software version from sysDescr."""
    facts = {"device_type": None, "software_version": None}
    if not descr:
        return facts

    text = str(descr)
    for pattern, device_type in _PLATFORM_PATTERNS:
        if pattern.search(text):
            facts["device_type"] = device_type
            break

    for pattern in _VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            facts["software_version"] = match.group(1)
            break

    return facts


def _auth_protocol(name):
    from pysnmp.hlapi.v3arch.asyncio import (
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol)
    return {"md5": usmHMACMD5AuthProtocol}.get(name, usmHMACSHAAuthProtocol)


def _priv_protocol(name):
    from pysnmp.hlapi.v3arch.asyncio import (
        usmAesCfb128Protocol, usmDESPrivProtocol)
    return {"des": usmDESPrivProtocol}.get(name, usmAesCfb128Protocol)


def _auth_data(creds):
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, UsmUserData

    if creds.version == "v2c":
        return CommunityData(creds.community, mpModel=1)
    return UsmUserData(
        creds.username,
        authKey=creds.auth_key or None,
        privKey=creds.priv_key or None,
        authProtocol=_auth_protocol(creds.auth_protocol) if creds.auth_key else None,
        privProtocol=_priv_protocol(creds.priv_protocol) if creds.priv_key else None,
    )


async def _get_async(host, creds, oids, timeout, port):
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData, ObjectIdentity, ObjectType, SnmpEngine,
        UdpTransportTarget, get_cmd)

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
    error_indication, error_status, _, var_binds = await get_cmd(
        engine,
        _auth_data(creds),
        target,
        ContextData(),
        *[ObjectType(ObjectIdentity(oid)) for oid in oids],
    )

    if error_indication or error_status:
        logger.debug(f"SNMP probe {host}: {error_indication or error_status}")
        raise SnmpQueryError(
            classify_snmp_error(error_indication, error_status),
            str(error_indication or error_status))

    results = {}
    for var_bind in var_binds:
        oid, value = var_bind
        text = str(value).strip()
        if text and "No Such" not in text:
            results[str(oid)] = text
    return results


async def _next_async(host, creds, oid, timeout, port):
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData, ObjectIdentity, ObjectType, SnmpEngine,
        UdpTransportTarget, next_cmd)

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
    error_indication, error_status, _, var_binds = await next_cmd(
        engine,
        _auth_data(creds),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    )

    if error_indication or error_status or not var_binds:
        return None
    _, value = var_binds[0]
    text = str(value).strip()
    if not text or "No Such" in text:
        return None
    return text


def _snmp_get(host, creds, oids, timeout, port):
    """Seam for tests -- performs the actual network call."""
    return asyncio.run(_get_async(host, creds, oids, timeout, port))


def _snmp_walk_first(host, creds, oid, timeout, port):
    """First value under a table column, or None. Seam for tests."""
    return asyncio.run(_next_async(host, creds, oid, timeout, port))


async def _walk_async(host, creds, oid, timeout, port, max_rows):
    from pysnmp.hlapi.v3arch.asyncio import (
        ContextData, ObjectIdentity, ObjectType, SnmpEngine,
        UdpTransportTarget, bulk_cmd, next_cmd)

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)
    prefix = oid.rstrip(".") + "."
    results = {}
    current = ObjectType(ObjectIdentity(oid))

    while len(results) < max_rows:
        if creds.version == "v2c":
            error_indication, error_status, _, var_bind_table = await bulk_cmd(
                engine, _auth_data(creds), target, ContextData(),
                0, 25, current, lexicographicMode=False)
        else:
            error_indication, error_status, _, var_bind_table = await next_cmd(
                engine, _auth_data(creds), target, ContextData(),
                current, lexicographicMode=False)

        if error_indication or error_status or not var_bind_table:
            break

        advanced = False
        for var_bind in var_bind_table:
            name, value = var_bind
            name = str(name)
            if not name.startswith(prefix):
                return results
            text = str(value).strip()
            if text and "No Such" not in text:
                results[name] = text
            current = ObjectType(ObjectIdentity(name))
            advanced = True

        if not advanced:
            break

    return results


def _snmp_walk(host, creds, oid, timeout, port, max_rows=5000):
    """Every value under an OID subtree. Seam for tests."""
    return asyncio.run(_walk_async(host, creds, oid, timeout, port, max_rows))


def make_walker(host, creds, timeout: int = 5, port: int = 161):
    """Return a walk(oid) callable bound to one device.

    snmp_tables takes this rather than a host, so table collection is testable
    without a network and independent of the transport.
    """
    def walk(oid):
        return _snmp_walk(host, creds, oid, timeout, port)
    return walk


def probe(host, creds: SnmpCredentials, timeout: int = 3, port: int = 161):
    """Return a partial device record, or None if the device did not answer.

    Never raises: a failed SNMP probe is a fallback that did not help, not an
    error worth aborting discovery over.
    """
    record, _ = probe_with_outcome(host, creds, timeout=timeout, port=port)
    return record


def probe_with_outcome(host, creds: SnmpCredentials, timeout: int = 3,
                       port: int = 161):
    """(record or None, outcome) -- outcome is one of the OUTCOME_* values,
    or OUTCOME_ERROR_PREFIX followed by what went wrong. Never raises."""
    if not creds or not creds.is_configured():
        return None, OUTCOME_NO_CREDENTIALS

    try:
        values = _snmp_get(host, creds, list(SYS_OIDS.values()), timeout, port)
    except SnmpQueryError as e:
        logger.debug(f"SNMP probe failed for {host}: {e.outcome}")
        return None, e.outcome
    except Exception as e:
        logger.debug(f"SNMP probe failed for {host}: {type(e).__name__}: {e}")
        return None, f"{OUTCOME_ERROR_PREFIX}{type(e).__name__}: {e}"

    if not values:
        # Answered with nothing usable, or a seam reporting silence.
        return None, OUTCOME_TIMEOUT

    sys_name = values.get(SYS_OIDS["sysName"], "")
    sys_descr = values.get(SYS_OIDS["sysDescr"], "")
    facts = parse_sysdescr(sys_descr)

    hostname = sys_name.split(".")[0].strip() if sys_name else host
    model = ""
    serial = ""
    version = facts["software_version"] or ""

    # Enrichment is best effort: a device that answered the system group has
    # already been identified, and losing that to a table timeout would be
    # worse than returning a thinner record.
    try:
        model = _snmp_walk_first(
            host, creds, ENTITY_COLUMNS["entPhysicalModelName"], timeout, port) or ""
        serial = _snmp_walk_first(
            host, creds, ENTITY_COLUMNS["entPhysicalSerialNum"], timeout, port) or ""
    except Exception as e:
        logger.debug(f"SNMP entity walk failed for {host}: {type(e).__name__}: {e}")

    vendor = VENDOR_OIDS.get(facts["device_type"] or "")
    if vendor and not (model and serial and version):
        try:
            vendor_values = _snmp_get(
                host, creds, list(vendor.values()), timeout, port)
            for field, oid in vendor.items():
                got = vendor_values.get(oid)
                if not got:
                    continue
                if field == "model" and not model:
                    model = got
                elif field == "serial" and not serial:
                    serial = got
                elif field == "software_version" and not version:
                    version = got
        except Exception as e:
            logger.debug(f"SNMP vendor probe failed for {host}: {type(e).__name__}: {e}")

    record = {
        "hostname": hostname,
        "mgmt_ip": host,
        "device_type": facts["device_type"],
        "software_version": version or None,
        "model": model or None,
        "serial": serial or None,
        "sys_descr": sys_descr,
        "sys_object_id": values.get(SYS_OIDS["sysObjectID"]),
        "sys_location": values.get(SYS_OIDS["sysLocation"]),
        "discovery_source": "snmp",
        "login_succeeded": False,
    }
    return record, OUTCOME_OK[creds.version]
