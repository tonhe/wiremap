"""SNMP fallback probe.

Runs only when SSH and telnet have both failed. A device that will not accept
a login is not necessarily unreachable -- sysDescr alone tells us the platform,
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

_VALID_VERSIONS = ("v2c", "v3")

# sysDescr is the only universally implemented identity string, so platform
# detection keys off it. Ordered -- NX-OS also says "Cisco".
_PLATFORM_PATTERNS = [
    (re.compile(r"NX-OS", re.I), "cisco_nxos"),
    (re.compile(r"Adaptive Security Appliance|ASA", re.I), "cisco_ios"),
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
        return {}

    results = {}
    for var_bind in var_binds:
        oid, value = var_bind
        text = str(value).strip()
        if text and "No Such" not in text:
            results[str(oid)] = text
    return results


def _snmp_get(host, creds, oids, timeout, port):
    """Seam for tests -- performs the actual network call."""
    return asyncio.run(_get_async(host, creds, oids, timeout, port))


def probe(host, creds: SnmpCredentials, timeout: int = 3, port: int = 161):
    """Return a partial device record, or None if the device did not answer.

    Never raises: a failed SNMP probe is a fallback that did not help, not an
    error worth aborting discovery over.
    """
    if not creds or not creds.is_configured():
        return None

    try:
        values = _snmp_get(host, creds, list(SYS_OIDS.values()), timeout, port)
    except Exception as e:
        logger.debug(f"SNMP probe failed for {host}: {type(e).__name__}: {e}")
        return None

    if not values:
        return None

    sys_name = values.get(SYS_OIDS["sysName"], "")
    sys_descr = values.get(SYS_OIDS["sysDescr"], "")
    facts = parse_sysdescr(sys_descr)

    hostname = sys_name.split(".")[0].strip() if sys_name else host

    return {
        "hostname": hostname,
        "mgmt_ip": host,
        "device_type": facts["device_type"],
        "software_version": facts["software_version"],
        "sys_descr": sys_descr,
        "sys_object_id": values.get(SYS_OIDS["sysObjectID"]),
        "sys_location": values.get(SYS_OIDS["sysLocation"]),
        "discovery_source": "snmp",
        "login_succeeded": False,
    }
