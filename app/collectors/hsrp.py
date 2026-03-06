"""
HSRP / VRRP first-hop redundancy collector.
Gathers HSRP state, virtual IPs, priorities, and active/standby roles.
Uses ntc-templates for parsing where available.
"""
import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

_COMMANDS = {
    "cisco_ios": [
        "show standby brief",
    ],
    "cisco_xe": [
        "show standby brief",
    ],
    "cisco_nxos": [
        "show hsrp brief",
    ],
    "arista_eos": [
        # Arista uses VRRP, not HSRP
    ],
    "juniper_junos": [
        # Junos uses VRRP
    ],
}
_DEFAULT_COMMANDS = [
    "show standby brief",
]


_NTC_PLATFORM_MAP = {"cisco_xe": "cisco_ios", "cisco_xr": "cisco_ios"}


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

        results.append({
            "interface": interface,
            "group": group,
            "priority": priority,
            "virtual_ip": vip,
            "state": state,
        })

    return results


def _normalize_entries(entries: list[dict], device_type: str) -> list[dict]:
    """Normalize ntc-templates output to common format.

    IOS (show standby brief) fields: interface, grp, pri, p, state, active, standby, virtualip
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
                or entry.get("PRIMARY_IPV4_ADDRESS", "")
            ),
            "state": (
                entry.get("state", "") or entry.get("HSRP_ROUTER_STATE", "")
            ),
        }
        if n["interface"] and n["virtual_ip"]:
            normalized.append(n)
    return normalized


class HsrpCollector(BaseCollector):
    name = "hsrp"
    label = "HSRP/VRRP"
    description = "Collect HSRP/VRRP first-hop redundancy state, virtual IPs, and priorities"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

        entries = []
        for cmd in commands:
            raw = raw_outputs.get(cmd, "")
            if not raw:
                continue
            parsed = _ntc_parse(raw, device_type, cmd)
            if parsed:
                entries = _normalize_entries(parsed, device_type)
            else:
                entries = _parse_hsrp_brief_raw(raw)

        return {
            "entries": entries,
        }
