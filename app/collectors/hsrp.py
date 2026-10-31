"""
HSRP / GLBP / VRRP first-hop redundancy collector.
Gathers FHRP state, virtual IPs, priorities, and active/standby roles.
Uses ntc-templates for parsing where available.

Every entry carries a "protocol" (HSRP, GLBP or VRRP). A platform that does
not run one of them rejects the command, and the base class files that as
not-applicable, so asking for all three costs nothing on a box without them.
"""
import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

_COMMANDS = {
    "cisco_ios": [
        "show standby brief",
        "show glbp brief",
        "show vrrp brief",
    ],
    "cisco_xe": [
        "show standby brief",
        "show glbp brief",
        "show vrrp brief",
    ],
    "cisco_nxos": [
        "show hsrp brief",
        # Nexus 7000 only; other Nexus platforms reject it as not-applicable.
        "show glbp brief",
    ],
    "arista_eos": [
        # Arista uses VRRP, not HSRP
    ],
    "juniper_junos": [
        # Junos uses VRRP
    ],
    # VyOS runs VRRP via keepalived.
    "vyos": [
        "show vrrp",
    ],
    # PAN-OS pairs via HA, not an FHRP. active/passive is the only way to
    # tell which of a pair is carrying traffic.
    "paloalto_panos": [
        "show high-availability all",
    ],
}
_DEFAULT_COMMANDS = [
    "show standby brief",
]


_NTC_PLATFORM_MAP = {"cisco_xe": "cisco_ios", "cisco_xr": "cisco_ios"}

HSRP, GLBP, VRRP = "HSRP", "GLBP", "VRRP"


def command_protocol(command):
    cmd = command.lower()
    if "glbp" in cmd:
        return GLBP
    if "vrrp" in cmd:
        return VRRP
    return HSRP


def _short_vlan(interface):
    return re.sub(r"^Vl(\d)", r"Vlan\1", interface)


_IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_GLBP_STATES = {"active", "standby", "listen", "speak", "init", "disabled"}


def _parse_glbp_brief_raw(raw):
    """Parse IOS / IOS-XE / NX-OS 'show glbp brief'.

        Interface   Grp  Fwd Pri State    Address         Active router   Standby router
        Vl10        10   -   110 Active   192.0.2.1       local           192.0.2.3
        Vl10        10   1   -   Active   0007.b400.0a01  local           -
        Vl10        10   2   -   Listen   0007.b400.0a02  192.0.2.3       -

    The Fwd "-" row is the gateway (AVG) and carries the virtual IP, the
    priority and the AVG roles; numbered rows are the forwarders (AVF),
    which are attached to their group's entry.
    """
    entries = []
    by_key = {}
    in_table = False
    pending_intf = ""
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "Interface" and "Grp" in parts and "Fwd" in parts:
            in_table = True
            continue
        if not in_table:
            continue
        if len(parts) == 1:
            # Long interface names wrap onto a line of their own.
            pending_intf = parts[0]
            continue
        if pending_intf and parts[0].isdigit():
            parts = [pending_intf] + parts
        pending_intf = ""
        if len(parts) < 8 or not parts[1].isdigit():
            continue
        intf, grp, fwd, pri, state, addr, active, standby = parts[:8]
        if state.lower() not in _GLBP_STATES:
            continue
        intf = _short_vlan(intf)
        key = (intf, grp)
        if fwd == "-":
            entry = {
                "protocol": GLBP,
                "interface": intf,
                "group": grp,
                "priority": "" if pri == "-" else pri,
                "virtual_ip": addr if _IPV4.match(addr) else "",
                "state": state,
                "active": "" if active == "-" else active,
                "standby": "" if standby == "-" else standby,
                "forwarders": [],
            }
            if key in by_key:
                # Forwarder rows arrived first; keep them.
                entry["forwarders"] = by_key[key]["forwarders"]
                entries[entries.index(by_key[key])] = entry
            else:
                entries.append(entry)
            by_key[key] = entry
        else:
            entry = by_key.get(key)
            if entry is None:
                entry = {"protocol": GLBP, "interface": intf, "group": grp,
                         "priority": "", "virtual_ip": "", "state": "",
                         "active": "", "standby": "", "forwarders": []}
                entries.append(entry)
                by_key[key] = entry
            entry["forwarders"].append({
                "forwarder": fwd,
                "state": state,
                "mac": addr,
                "owner": "" if active == "-" else active,
            })
    return entries


_VRRP_STATES = {"master", "backup", "init"}


def _parse_vrrp_brief_raw(raw):
    """Parse IOS / IOS-XE 'show vrrp brief', VRRPv2 and VRRPv3 layouts.

        Interface          Grp Pri Time  Own Pre State   Master addr     Group addr
        Vl30               30  110 3570       Y  Master  198.51.100.2    198.51.100.1

          Interface          Grp  A-F Pri  Time Own Pre State   Master addr/Group addr
          Vl40                40 IPv4 110     0  N   Y  MASTER  192.0.2.130(local) 192.0.2.129
    """
    entries = []
    in_table = False
    pending_intf = ""
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "Interface" and "Grp" in parts:
            in_table = True
            continue
        if not in_table:
            continue
        if len(parts) == 1:
            pending_intf = parts[0]
            continue
        if pending_intf and parts[0].isdigit():
            parts = [pending_intf] + parts
        pending_intf = ""
        state_i = next((i for i, p in enumerate(parts)
                        if p.lower() in _VRRP_STATES), None)
        if state_i is None or len(parts) < state_i + 3 or not parts[1].isdigit():
            continue
        intf, grp = parts[0], parts[1]
        rest = parts[2:state_i]
        pri = next((p for p in rest if p.isdigit()), "")
        state = parts[state_i].capitalize()
        master = parts[state_i + 1]
        local = master.endswith("(local)")
        master = master.replace("(local)", "")
        entries.append({
            "protocol": VRRP,
            "interface": _short_vlan(intf),
            "group": grp,
            "priority": pri,
            "virtual_ip": parts[state_i + 2],
            "state": state,
            "active": "local" if local or state == "Master" else master,
            "standby": "",
        })
    return entries


def _ntc_parse(raw: str, device_type: str, command: str) -> list[dict]:
    if not raw:
        return []
    try:
        from ntc_templates.parse import parse_output
        platform = _NTC_PLATFORM_MAP.get(device_type, device_type)
        return parse_output(platform=platform, command=command, data=raw)
    except Exception:
        logger.debug(f"ntc-templates parse failed for {command} on {device_type}")
        return []


def _parse_hsrp_brief_raw(raw: str) -> list[dict]:
    """Parse 'show hsrp brief' or 'show standby brief' from raw output.

    NX-OS format:
        *:IPv6 group   #:differing timers
                                                P   Active
        Interface   Grp  Prio VIP              State      Standby
        Vlan1       0    110  10.1.1.1         Active     10.1.1.253
        Vlan2       0    110  10.44.1.1        Standby    10.44.1.254

    IOS format:
                             P indicates configured to preempt.
                             |
        Interface   Grp  Pri P State    Active          Standby         Virtual IP
        Vl1         0    110 P Active   local           10.1.1.253      10.1.1.1
    """
    results = []
    in_table = False
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip header lines
        if "Interface" in stripped and ("Grp" in stripped or "Group" in stripped):
            in_table = True
            continue
        if stripped.startswith("---") or stripped.startswith("*:"):
            continue
        if not in_table:
            continue

        # Try to parse the data line
        parts = stripped.split()
        if len(parts) < 5:
            continue

        interface = parts[0]
        # Normalize short IOS names like Vl1 -> Vlan1
        interface = re.sub(r"^Vl(\d)", r"Vlan\1", interface)

        try:
            group = parts[1]
            priority = parts[2]
        except (IndexError, ValueError):
            continue

        # Find the IP address (x.x.x.x pattern)
        vip = ""
        state = ""
        active_peer = ""
        standby_peer = ""

        # NX-OS: Interface Grp Prio VIP State Standby
        # IOS:   Interface Grp Pri P State Active Standby VIP
        ips = [p for p in parts if re.match(r"\d+\.\d+\.\d+\.\d+", p)]

        if len(ips) >= 1:
            # Detect format by checking where the IP is
            for i, p in enumerate(parts):
                if p in ("Active", "Standby", "Listen", "Init", "Speak"):
                    state = p
                    break
                if p == "P" and i == 3:
                    # IOS format with preempt flag
                    continue

            if not state:
                # Try matching state from parts
                for p in parts:
                    if p.lower() in ("active", "standby", "listen", "init", "speak"):
                        state = p.capitalize()
                        break

            # Last IP is usually the VIP
            vip = ips[-1] if ips else ""
            if len(ips) >= 2:
                # Multiple IPs: active peer, standby peer, VIP
                # IOS: active standby vip
                # NX-OS: vip is before state
                pass

        # IOS order is "... State Active Standby VIP"; "local" stands in
        # for this device in either peer column.
        if state in parts:
            at = parts.index(state)
            before = [p for p in parts[:at] if _IPV4.match(p)]
            after = [p for p in parts[at + 1:]
                     if p in ("local", "unknown") or _IPV4.match(p)]
            if before:
                # Older NX-OS layout "Grp Prio VIP State Standby": the VIP
                # sits before the state and only the standby peer follows.
                vip = before[0]
                standby_peer = after[0] if after else ""
            elif len(after) >= 3:
                active_peer, standby_peer = after[0], after[1]
        if active_peer == "unknown":
            active_peer = ""
        if standby_peer == "unknown":
            standby_peer = ""

        results.append({
            "protocol": HSRP,
            "interface": interface,
            "group": group,
            "priority": priority,
            "virtual_ip": vip,
            "state": state,
            "active": active_peer,
            "standby": standby_peer,
        })

    return results


def _normalize_entries(entries: list[dict], device_type: str,
                       protocol: str = HSRP) -> list[dict]:
    """Normalize ntc-templates output to common format.

    IOS (show standby brief) fields: interface, group, priority, preempt,
    state, active, standby, virtual_ip_address
    IOS (show vrrp brief) fields: interface, group, priority, state,
    master_ip_address, virtual_ip_address
    NX-OS (show hsrp all) fields: INTERFACE, GROUP_NUMBER, PRIORITY, HSRP_ROUTER_STATE, PRIMARY_IPV4_ADDRESS
    """
    normalized = []
    for entry in entries:
        interface = (entry.get("interface", "") or entry.get("INTERFACE", ""))
        # Normalize Vl1 -> Vlan1
        interface = re.sub(r"^Vl(\d)", r"Vlan\1", interface)

        n = {
            "interface": interface,
            "group": str(
                entry.get("group", "") or entry.get("grp", "")
                or entry.get("GROUP_NUMBER", "")
            ),
            "priority": str(
                entry.get("priority", "") or entry.get("pri", "")
                or entry.get("PRIORITY", "") or entry.get("CONFIGURED_PRIORITY", "")
            ),
            "virtual_ip": (
                entry.get("virtual_ip", "") or entry.get("virtualip", "")
                or entry.get("virtual_ip_address", "")
                or entry.get("PRIMARY_IPV4_ADDRESS", "")
            ),
            "state": (
                entry.get("state", "") or entry.get("HSRP_ROUTER_STATE", "")
            ),
        }
        n["protocol"] = protocol
        if protocol == VRRP:
            n["state"] = n["state"].capitalize()
            master = entry.get("master_ip_address", "")
            n["active"] = "local" if n["state"] == "Master" else master
            n["standby"] = ""
        else:
            active = entry.get("active", "")
            standby = entry.get("standby", "")
            n["active"] = "" if active == "unknown" else active
            n["standby"] = "" if standby == "unknown" else standby
        if n["interface"] and n["virtual_ip"]:
            normalized.append(n)
    return normalized


class HsrpCollector(BaseCollector):
    name = "hsrp"
    label = "HSRP/GLBP/VRRP"
    description = "Collect HSRP/GLBP/VRRP first-hop redundancy state, virtual IPs, and priorities"
    enabled_by_default = True
    # A WLC has no FHRP; a Firebox clusters via FireCluster, not VRRP.
    unsupported_platforms = frozenset({"cisco_wlc", "watchguard_fireware"})

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

        entries = []
        for cmd in commands:
            raw = raw_outputs.get(cmd, "")
            if not raw:
                continue
            protocol = command_protocol(cmd)
            if protocol == GLBP:
                # No ntc-templates template exists for show glbp brief.
                entries.extend(_parse_glbp_brief_raw(raw))
                continue
            parsed = _ntc_parse(raw, device_type, cmd)
            found = _normalize_entries(parsed, device_type, protocol) if parsed else []
            if not found:
                if protocol == VRRP:
                    found = _parse_vrrp_brief_raw(raw)
                else:
                    found = _parse_hsrp_brief_raw(raw)
            entries.extend(found)

        return {
            "entries": entries,
        }
