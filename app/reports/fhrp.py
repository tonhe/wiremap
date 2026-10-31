"""
FHRP (HSRP / GLBP / VRRP) rows shared by the routing summary and internet
edge reports.

State comes from the hsrp collector. The running config, when collected,
also says which protocol and groups each interface is configured for, so an
interface whose show command was rejected, failed or never ran still gets a
row ("state not collected") instead of vanishing from the sheet.
"""
import re

try:
    from app.ifname import canonical_ifname
except ImportError:
    from ifname import canonical_ifname

FHRP_HEADERS = ["Device", "Site/Location", "Interface", "Protocol", "Group",
                "Priority", "State", "Virtual IP"]

# States a healthy group sits in. Anything else (Init, Speak, Disabled, ...)
# is worth a finding.
FHRP_OK_STATES = frozenset({"active", "standby", "listen", "master", "backup", ""})

NOT_COLLECTED = "state not collected"

_INTF = re.compile(r"^interface\s+(\S+)", re.IGNORECASE)
_IP = r"(\d+\.\d+\.\d+\.\d+)"
# (protocol, regex). Group in group 1; a virtual IP, when on the line, in 2.
_CONFIG_RULES = [
    # IOS: " standby [N] ip [A.B.C.D]" -- the group number defaults to 0.
    ("HSRP", re.compile(r"^\s+standby\s+(?:(\d+)\s+)?ip(?:\s+" + _IP + r")?(?:\s|$)",
                        re.IGNORECASE)),
    ("HSRP", re.compile(r"^\s+standby\s+(?:(\d+)\s+)?ipv6\b()", re.IGNORECASE)),
    # NX-OS: " hsrp N"
    ("HSRP", re.compile(r"^\s+hsrp\s+(\d+)()(?:\s|$)", re.IGNORECASE)),
    ("GLBP", re.compile(r"^\s+glbp\s+(\d+)\s+ip(?:v6)?(?:\s+" + _IP + r")?(?:\s|$)",
                        re.IGNORECASE)),
    # IOS VRRPv2 " vrrp N ip A.B.C.D", VRRPv3 " vrrp N address-family ipv4",
    # NX-OS " vrrp N" / " vrrpv3 N address-family ipv4".
    ("VRRP", re.compile(r"^\s+vrrp\s+(\d+)\s+ip(?:\s+" + _IP + r")?(?:\s|$)",
                        re.IGNORECASE)),
    ("VRRP", re.compile(r"^\s+vrrp(?:v3)?\s+(\d+)()(?:\s+address-family\b.*)?\s*$",
                        re.IGNORECASE)),
]


def configured_fhrp(config_text):
    """FHRP groups configured under interfaces in a running config.

    Returns [{"interface", "protocol", "group", "virtual_ip"}], one per
    (interface, protocol, group), in config order.
    """
    groups = []
    seen = {}
    intf = None
    for line in (config_text or "").splitlines():
        m = _INTF.match(line)
        if m:
            intf = m.group(1)
            continue
        if not line[:1].isspace():
            intf = None
            continue
        if intf is None:
            continue
        for proto, rule in _CONFIG_RULES:
            m = rule.match(line)
            if not m:
                continue
            group = m.group(1) or "0"
            key = (intf, proto, group)
            vip = m.group(2) or ""
            if key in seen:
                if vip and not seen[key]["virtual_ip"]:
                    seen[key]["virtual_ip"] = vip
            else:
                seen[key] = {"interface": intf, "protocol": proto,
                             "group": group, "virtual_ip": vip}
                groups.append(seen[key])
            break
    return groups


def _parsed(device, name):
    return (device.get("collector_data", {}).get(name, {}) or {}).get("parsed") or {}


def device_fhrp_entries(device):
    """Collected FHRP entries plus config-only groups marked not collected."""
    entries = [dict(e, protocol=e.get("protocol") or "HSRP")
               for e in _parsed(device, "hsrp").get("entries") or []]
    have = {(canonical_ifname(e.get("interface", "")), e["protocol"],
             str(e.get("group", ""))) for e in entries}
    config = _parsed(device, "config").get("config", "")
    for g in configured_fhrp(config):
        key = (canonical_ifname(g["interface"]), g["protocol"], g["group"])
        if key in have:
            continue
        entries.append({
            "protocol": g["protocol"],
            "interface": g["interface"],
            "group": g["group"],
            "priority": "",
            "virtual_ip": g["virtual_ip"],
            "state": NOT_COLLECTED,
            "config_only": True,
        })
    return entries


def has_fhrp_data(inventory_data):
    for device in inventory_data.get("devices", {}).values():
        if _parsed(device, "hsrp").get("entries"):
            return True
        if configured_fhrp(_parsed(device, "config").get("config", "")):
            return True
    return False


def fhrp_rows(inventory_data, derive_site):
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        entries = device_fhrp_entries(device)
        if not entries:
            continue
        site = derive_site(hostname)
        for e in entries:
            rows.append([
                hostname, site,
                e.get("interface", ""),
                e.get("protocol", ""),
                e.get("group", ""),
                e.get("priority", ""),
                e.get("state", ""),
                e.get("virtual_ip", ""),
            ])
    return rows


def fhrp_state_findings(hostname, device, make_finding, severity):
    """Findings for collected groups sitting in an unexpected state."""
    findings = []
    for e in _parsed(device, "hsrp").get("entries") or []:
        state = e.get("state", "")
        if state.lower() in FHRP_OK_STATES:
            continue
        proto = e.get("protocol") or "HSRP"
        findings.append(make_finding(
            hostname, severity, "FHRP group in unexpected state",
            (f"Interface {e.get('interface', '?')} {proto} group "
             f"{e.get('group', '?')} VIP {e.get('virtual_ip', '?')} state: {state}"),
        ))
    return findings
