"""
Cisco AireOS wireless LAN controller collector.

Runs the controller command list once, then the per-item commands built
from it: each interface, WLAN, RF profile, ACL, FlexConnect group and port,
then APs that failed to join, then three commands per AP. Per-AP commands
are the slow part (seconds each on a large controller), so they run last
and a timeout late in the run leaves everything before it intact.

Output another collector already gathered in this session is reused rather
than sent again. Secrets are redacted and client identifiers (MACs, IPs,
user names) are removed before anything is stored; only counts survive.
Local guest account names are replaced with a stable pseudonym.
"""
import logging
import re

from .base import BaseCollector
from . import wlc_text as t

try:
    from app.collectors.errors import send_failure_output, error_reason
    from app.redact import REDACTED, mask_names, pseudonym, redact_config
    from app.settings import redact_secrets_enabled
    from app.wlc_session import WLC_TYPE, SYSINFO
except ImportError:
    from collectors.errors import send_failure_output, error_reason
    from redact import REDACTED, mask_names, pseudonym, redact_config
    from settings import redact_secrets_enabled
    from wlc_session import WLC_TYPE, SYSINFO

logger = logging.getLogger(__name__)

RUN_CONFIG = "show run-config commands"
PAGING = "config paging disable"

BLOCK_SESSION = [PAGING, SYSINFO, "show time"]
BLOCK_PLATFORM = [
    "show inventory", "show boot", "show license all", "show license summary",
    "show license capacity", "show switchconfig", "show memory statistics", "show cpu",
    "show stats switch summary", "show stats port summary", "show coredump summary",
    "show traplog", "show msglog", "show logging", "show serial", "show loginsession",
    "show sessions",
]
BLOCK_HA = [
    "show redundancy summary", "show redundancy detail", "show redundancy interfaces",
    "show redundancy peer-route summary", "show redundancy statistics",
    "show redundancy timers",
]
BLOCK_CONFIG = [RUN_CONFIG]
BLOCK_NETWORK = [
    "show interface summary", "show interface group summary", "show port summary",
    "show lag summary", "show network summary", "show network multicast mgid summary",
    "show route summary", "show arp switch", "show cdp", "show cdp neighbors detail",
    "show ipv6 summary", "show dhcp summary", "show dhcp proxy", "show dhcp timeout",
]
BLOCK_WLAN = [
    "show wlan summary", "show wlan apgroups", "show guest-lan summary",
    "show remote-lan summary", "show mobility anchor", "show custom-web all",
    "show band-select", "show load-balancing", "show advanced eap", "show advanced timers",
    "show advanced probe",
]
BLOCK_RF = [
    "show 802.11a", "show 802.11b", "show 802.11h",
    "show advanced 802.11a summary", "show advanced 802.11b summary",
    "show advanced 802.11a channel", "show advanced 802.11b channel",
    "show advanced 802.11a txpower", "show advanced 802.11b txpower",
    "show advanced 802.11a coverage", "show advanced 802.11b coverage",
    "show advanced 802.11a group", "show advanced 802.11b group",
    "show advanced 802.11a monitor", "show advanced 802.11b monitor",
    "show advanced 802.11a profile global", "show advanced 802.11b profile global",
    "show advanced fra", "show 802.11a cleanair config", "show 802.11b cleanair config",
    "show 802.11a cleanair air-quality summary", "show 802.11b cleanair air-quality summary",
    "show rf-profile summary",
]
BLOCK_AP = [
    "show ap summary", "show ap inventory all", "show ap cdp neighbors all",
    "show ap image all", "show ap uptime", "show ap join stats summary all",
    "show ap config global", "show ap link-encryption all", "show ap module summary all",
    "show ap stats ethernet summary", "show ap tcp-mss-adjust all", "show ap retransmit all",
    "show ap crash-file", "show ap max-count summary", "show flexconnect group summary",
    "show mesh ap summary",
]
BLOCK_CLIENT = ["show client summary", "show exclusionlist"]
BLOCK_AAA = [
    "show radius summary", "show radius auth statistics", "show radius acct statistics",
    "show radius rfc3576 statistics", "show tacacs summary", "show tacacs auth statistics",
    "show aaa auth", "show local-auth config", "show local-auth statistics",
    "show netuser summary", "show mgmtuser", "show acl summary", "show acl cpu",
    "show flexconnect acl summary", "show wps summary", "show wps mfp summary",
    "show wps signature summary", "show wps ap-authentication summary",
    "show rogue ap summary", "show rogue client summary", "show rogue adhoc summary",
    "show rogue rule summary", "show rogue auto-contain",
]
BLOCK_SERVICES = [
    "show mobility summary", "show mobility statistics", "show mobility ap-list",
    "show mdns summary", "show mdns service summary", "show mdns profile summary",
    "show nmsp status", "show nmsp subscription summary", "show location summary",
    "show flow exporter summary", "show flow monitor summary", "show avc profile summary",
]
BLOCK_QOS = ["show qos platinum", "show qos gold", "show qos silver", "show qos bronze",
             "show qos qosmap", "show qos-map"]
BLOCK_MGMT = [
    "show snmpversion", "show snmpcommunity", "show snmpv3user", "show snmptrap",
    "show trapflags", "show certificate summary", "show certificate lsc summary",
    "show local-auth certificates", "show network summary",
]


def _ordered(*blocks):
    seen, out = set(), []
    for block in blocks:
        for cmd in block:
            if cmd not in seen:
                seen.add(cmd)
                out.append(cmd)
    return out


CONTROLLER_COMMANDS = _ordered(BLOCK_SESSION, BLOCK_PLATFORM, BLOCK_HA, BLOCK_CONFIG,
                               BLOCK_NETWORK, BLOCK_WLAN, BLOCK_RF, BLOCK_AP, BLOCK_CLIENT,
                               BLOCK_AAA, BLOCK_SERVICES, BLOCK_QOS, BLOCK_MGMT)

# Outputs that carry configuration and so may carry secrets.
_SECRET_BEARING = re.compile(
    r"config|wlan|local-auth|flexconnect|radius|tacacs|mgmtuser|netuser|snmp|mobility|"
    r"certificate")
# Outputs that list clients; every MAC in them is a client's.
_CLIENT_LISTS = ("show client summary", "show exclusionlist")
# Logs that mention clients among AP and controller events.
_LOGS = ("show traplog", "show msglog")
CLIENT_MAC = "xx:xx:xx:xx:xx:xx"
CLIENT_IP = "x.x.x.x"
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_USER_FIELD = re.compile(r"(User\s*Name\s*[:=]?\s*)(\S+)", re.I)
DEFAULT_COMMUNITIES = ("public", "private")


# ---------------------------------------------------------------------------
# Per-item command lists, read from the controller-level output
# ---------------------------------------------------------------------------

def _column(text, *names):
    """First word of the named column, from the first table that has it."""
    for rows in t.tables(text):
        if rows and t.lookup(rows[0], *names) is not None:
            return [t.lookup(r, *names).split()[0] for r in rows if t.lookup(r, *names)]
    return []


def interface_names(text):
    return _column(text, "Interface Name")


def wlan_ids(text):
    return [i for i in _column(text, "WLAN ID", "WLAN Id") if i.isdigit()]


def ap_names(text):
    return _column(text, "AP Name")


def join_failure_macs(text):
    out = []
    for row in t.table(text):
        status = (t.lookup(row, "Status") or "").lower()
        mac = t.norm_mac(t.lookup(row, "Base Mac", "Base MAC", "Radio MAC"))
        if mac and status and status != "joined":
            out.append(mac)
    if out or t.table(text):
        return out
    # Some code prints the table without a dash rule: base MAC first, status last.
    for line in (text or "").splitlines():
        macs = t.macs_in(line)
        if macs and re.search(r"\bnot\s+joined\b", line, re.I):
            out.append(t.norm_mac(macs[0]))
    return out


def rf_profile_names(text):
    return _column(text, "RF Profile Name", "Profile Name")


def acl_names(text):
    return _column(text, "ACL Name", "IPv4 ACL Name")


def flex_group_names(text):
    names = _column(text, "Group Name", "FlexConnect Group Name")
    if names:
        return names
    # Older code prints the summary without a dash rule.
    out, started = [], False
    for line in (text or "").splitlines():
        if re.match(r"^\s*(FlexConnect )?Group Name\b", line, re.I):
            started = True
            continue
        if started and line.strip():
            out.append(line.split()[0])
    return out


def port_numbers(text):
    return [p for p in _column(text, "Pr", "Port") if p.isdigit()]


def item_commands(outputs):
    """[(kind, command)] for Part C, per-AP commands last."""
    out = []
    out += [("interface", f"show interface detailed {n}")
            for n in interface_names(outputs.get("show interface summary"))]
    out += [("wlan", f"show wlan {i}") for i in wlan_ids(outputs.get("show wlan summary"))]
    out += [("rf_profile", f"show rf-profile details {n}")
            for n in rf_profile_names(outputs.get("show rf-profile summary"))]
    out += [("acl", f"show acl detailed {n}") for n in acl_names(outputs.get("show acl summary"))]
    out += [("flex_acl", f"show flexconnect acl detailed {n}")
            for n in acl_names(outputs.get("show flexconnect acl summary"))]
    out += [("flex_group", f"show flexconnect group detail {n}")
            for n in flex_group_names(outputs.get("show flexconnect group summary"))]
    out += [("port", f"show stats port detailed {n}")
            for n in port_numbers(outputs.get("show port summary"))]
    out += [("join", f"show ap join stats detailed {m}")
            for m in join_failure_macs(outputs.get("show ap join stats summary all"))]
    for name in ap_names(outputs.get("show ap summary")):
        out += [("ap", f"show ap config general {name}"),
                ("ap", f"show ap config 802.11a {name}"),
                ("ap", f"show ap config 802.11b {name}")]
    return out


# ---------------------------------------------------------------------------
# Privacy: client identifiers out, guest names pseudonymised, communities masked
# ---------------------------------------------------------------------------

def ap_macs(outputs):
    macs = set()
    for cmd in ("show ap summary", "show ap join stats summary all", "show ap inventory all"):
        macs.update(t.norm_mac(m) for m in t.macs_in(outputs.get(cmd)))
    return {m for m in macs if m}


def scrub_client_list(text):
    text = re.sub(t._MAC_RE, CLIENT_MAC, text or "")
    text = _USER_FIELD.sub(lambda m: m.group(1) + REDACTED, text)
    return text


def scrub_log(text, known_macs):
    """Mask MACs that are not an AP's, and client IPs and user names on
    lines about clients."""
    out = []
    for line in (text or "").splitlines(keepends=True):
        line = re.sub(t._MAC_RE, lambda m: m.group(0) if t.norm_mac(m.group(0)) in known_macs
                      else CLIENT_MAC, line)
        if re.search(r"client|station|user", line, re.I):
            line = _IPV4.sub(CLIENT_IP, line)
            line = _USER_FIELD.sub(lambda m: m.group(1) + REDACTED, line)
        out.append(line)
    return "".join(out)


def netuser_names(outputs):
    names = set(_column(outputs.get("show netuser summary"), "User Name", "Username"))
    for m in re.finditer(r"^\s*config\s+netuser\s+add\s+(\S+)", outputs.get(RUN_CONFIG) or "",
                         re.I | re.M):
        names.add(m.group(1))
    return {n for n in names if n != REDACTED}


def pseudonymise(text, names):
    for name in sorted(names, key=len, reverse=True):
        text = re.sub(r"(?<!\S)" + re.escape(name) + r"(?!\S)", pseudonym(name), text)
    return text


def snmp_communities(text):
    return _column(text, "SNMP Community Name", "Community Name")


def protect(outputs, redact=True):
    """Return (outputs safe to store, facts recorded before masking)."""
    communities = snmp_communities(outputs.get("show snmpcommunity"))
    facts = {"snmp_communities": len(communities),
             "snmp_default_communities": sorted(
                 {c.lower() for c in communities if c.lower() in DEFAULT_COMMUNITIES})}
    known = ap_macs(outputs)
    users = netuser_names(outputs)
    safe = {}
    for cmd, text in outputs.items():
        if not text or error_reason(text):
            safe[cmd] = text
            continue
        if cmd in _CLIENT_LISTS:
            text = scrub_client_list(text)
        elif cmd in _LOGS:
            text = scrub_log(text, known)
        if users and ("netuser" in cmd or cmd == RUN_CONFIG):
            text = pseudonymise(text, users)
        if redact:
            if cmd == "show snmpcommunity" and communities:
                text = mask_names(text, communities)[0]
            elif _SECRET_BEARING.search(cmd):
                text = redact_config(text)
        safe[cmd] = text
    return safe, facts


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

def _reusable(context):
    """{command: output} other collectors already stored this session."""
    out = {}
    for data in ((context or {}).get("collector_data") or {}).values():
        for cmd, text in ((data or {}).get("raw") or {}).items():
            if text and not error_reason(text) and cmd not in out:
                out[cmd] = text
    return out


class WlcCollector(BaseCollector):
    name = "wlc"
    label = "Cisco WLC"
    description = ("Controller platform, HA, interfaces, WLANs, RF, access points, AAA, "
                   "mobility and management plane from AireOS controllers")
    enabled_by_default = True
    optional = True
    needs_custom_collect = True
    needs_device_context = True

    def applies_to(self, device_type):
        return device_type == WLC_TYPE

    def get_commands(self, device_type):
        return list(CONTROLLER_COMMANDS) if device_type == WLC_TYPE else []

    def collect(self, connection, device_type, context=None):
        if device_type != WLC_TYPE:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"wlc does not apply to {device_type}"}}
        reuse = _reusable(context)
        raw = {}

        def run(cmd):
            if cmd in raw:
                return
            if cmd in reuse:
                raw[cmd] = reuse[cmd]
                return
            try:
                raw[cmd] = connection.send_command(cmd)
            except Exception as e:
                logger.warning(f"wlc: '{cmd}' failed: {e}")
                raw[cmd] = send_failure_output(e)

        for cmd in CONTROLLER_COMMANDS:
            run(cmd)
        items = item_commands({c: ("" if error_reason(v or "") else v) for c, v in raw.items()})
        planned = {}
        for kind, _ in items:
            planned[kind] = planned.get(kind, 0) + 1
        aps = planned.get("ap", 0) // 3
        if aps:
            logger.info(f"wlc: {aps} APs, {len(items)} per-item commands")
        done = {}
        for n, (kind, cmd) in enumerate(items, 1):
            run(cmd)
            done[kind] = done.get(kind, 0) + 1
            if kind == "ap" and done[kind] % 150 == 0:
                logger.info(f"wlc: per-AP commands {done[kind] // 3}/{aps} APs")

        raw, facts = protect(raw, redact=redact_secrets_enabled())
        parsed = self.parse_collected(raw, device_type)
        parsed.update(facts)
        parsed["per_item"] = {k: {"planned": v, "run": done.get(k, 0)}
                              for k, v in planned.items()}
        return {"raw": raw, "parsed": parsed}

    def parse(self, raw_outputs, device_type):
        info = t.dotted(raw_outputs.get(SYSINFO))
        return {
            "system_name": t.lookup(info, "System Name") or "",
            "product_version": t.lookup(info, "Product Version") or "",
            "counts": {
                "aps": len(ap_names(raw_outputs.get("show ap summary"))),
                "wlans": len(wlan_ids(raw_outputs.get("show wlan summary"))),
                "interfaces": len(interface_names(raw_outputs.get("show interface summary"))),
            },
        }
