"""
STP and VLAN collector.
Gathers spanning-tree state, root bridge info, blocked ports, VLAN list, and VTP status.
Uses ntc-templates for parsing where available, with normalization across platforms.
"""
import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

_COMMANDS = {
    "cisco_ios": [
        "show spanning-tree",
        "show spanning-tree root",
        "show spanning-tree blockedports",
        "show vlan brief",
        "show vtp status",
    ],
    "cisco_xe": [
        "show spanning-tree",
        "show spanning-tree root",
        "show spanning-tree blockedports",
        "show vlan brief",
        "show vtp status",
    ],
    "cisco_nxos": [
        "show spanning-tree",
        "show spanning-tree root",
        "show spanning-tree blockedports",
        "show vlan brief",
        "show vtp status",
    ],
    "arista_eos": [
        "show spanning-tree",
        "show vlan brief",
    ],
    "juniper_junos": [
        "show spanning-tree bridge",
        "show vlans",
    ],
}
_DEFAULT_COMMANDS = [
    "show spanning-tree",
    "show spanning-tree root",
    "show spanning-tree blockedports",
    "show vlan brief",
    "show vtp status",
]


def _ntc_parse(raw: str, device_type: str, command: str) -> list[dict]:
    if not raw:
        return []
    try:
        from ntc_templates.parse import parse_output
        return parse_output(platform=device_type, command=command, data=raw)
    except Exception:
        logger.debug(f"ntc-templates parse failed for {command} on {device_type}")
        return []


def _find_cmd(commands: list[str], *keywords: str) -> str | None:
    for cmd in commands:
        if all(kw in cmd for kw in keywords):
            return cmd
    return None


def _strip_vlan_prefix(vlan_id: str) -> str:
    """Normalize 'VLAN0001' -> '1', 'VLAN0020' -> '20', '10' -> '10'."""
    m = re.match(r"^[Vv][Ll][Aa][Nn]0*(\d+)$", vlan_id)
    if m:
        return m.group(1)
    return vlan_id


def _normalize_root_entries(entries: list[dict]) -> list[dict]:
    """Normalize spanning-tree root entries across IOS/NX-OS field names.

    IOS fields:  vlan_id, root_address, root_priority, root_cost, root_port
    NX-OS fields: vlan_id (VLAN0001), root_id, priority, root_cost, root_port
    """
    normalized = []
    for entry in entries:
        n = {
            "vlan_id": _strip_vlan_prefix(str(entry.get("vlan_id", ""))),
            "root_address": entry.get("root_address", "") or entry.get("root_id", ""),
            "root_priority": str(entry.get("root_priority", "") or entry.get("priority", "")),
            "root_cost": str(entry.get("root_cost", "")),
            "root_port": entry.get("root_port", ""),
            "hello_time": entry.get("hello_time", ""),
            "max_age": entry.get("max_age", ""),
            "fwd_delay": entry.get("fwd_delay", "") or entry.get("fwd_dly", ""),
        }
        normalized.append(n)
    return normalized


def _normalize_vlan_entries(entries: list[dict]) -> list[dict]:
    """Normalize VLAN list across IOS/NX-OS field names.

    IOS fields:  vlan_id, name
    NX-OS fields: vlan_id, vlan_name
    """
    normalized = []
    for entry in entries:
        n = {
            "vlan_id": _strip_vlan_prefix(str(entry.get("vlan_id", ""))),
            "name": entry.get("name", "") or entry.get("vlan_name", ""),
        }
        normalized.append(n)
    return normalized


def _parse_stp_port_states(raw: str) -> dict:
    """Parse per-port STP role/status from 'show spanning-tree' full output.

    Returns: {(vlan_id, interface): {role, status, stp_type}}

    Matches lines like:
        Po50             Desg BKN*1         128.4145 (vPC) Network P2p *BA_Inc
        Gi0/2            Altn BLK  4         128.2    P2p
    """
    port_states = {}
    current_vlan = None
    for line in raw.splitlines():
        stripped = line.strip()
        # Detect VLAN section header (VLAN0510, VLAN10, etc.)
        vm = re.match(r"^VLAN0*(\d+)$", stripped)
        if vm:
            current_vlan = vm.group(1)
            continue
        if current_vlan is None:
            continue
        # Match interface line: Intf  Role  Sts  Cost  Prio.Nbr  Type
        m = re.match(
            r"^(\S+)\s+(Root|Desg|Altn|Back|Mstr)\s+(\S+)\s+\S+\s+\S+\s+(.*)",
            stripped,
        )
        if m:
            iface = m.group(1)
            role = m.group(2)
            status_raw = m.group(3)
            stp_type = m.group(4).strip()
            port_states[(current_vlan, iface)] = {
                "role": role,
                "status": status_raw,
                "stp_type": stp_type,
            }
    return port_states


def _parse_blocked_ports_raw(raw_blocked: str, raw_stp: str = "") -> list[dict]:
    """Parse 'show spanning-tree blockedports' from raw output.

    Enriches with role/status/reason from 'show spanning-tree' if available.
    Handles both IOS and NX-OS formats since NX-OS has no ntc-template.
    """
    # Build port state lookup from full STP output
    port_states = _parse_stp_port_states(raw_stp) if raw_stp else {}

    results = []
    in_table = False
    for line in raw_blocked.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "Blocked Interfaces" in stripped or "blocked ports" in stripped.lower():
            in_table = True
            continue
        if stripped.startswith("---"):
            continue
        if stripped.startswith("Number of blocked"):
            continue
        if in_table:
            m = re.match(r"^(\S+)\s+(\S+.*)$", stripped)
            if m:
                vlan_part = m.group(1)
                interfaces = m.group(2).strip()
                vid = _strip_vlan_prefix(vlan_part)
                for iface in re.split(r"[,\s]+", interfaces):
                    iface = iface.strip()
                    if not iface:
                        continue
                    # Look up detailed state
                    ps = port_states.get((vid, iface), {})
                    status = ps.get("status", "BLK")
                    role = ps.get("role", "")
                    stp_type = ps.get("stp_type", "")
                    # Extract reason from stp_type (e.g., "*BA_Inc", "Peer(STP)")
                    reason = ""
                    reason_match = re.search(r"\*(\S+)", stp_type)
                    if reason_match:
                        reason = reason_match.group(1)
                    results.append({
                        "vlan_id": vid,
                        "interface": iface,
                        "name": "",
                        "status": status,
                        "role": role,
                        "reason": reason,
                    })
    return results


class StpVlanCollector(BaseCollector):
    name = "stp_vlan"
    label = "STP/VLAN"
    description = "Collect spanning-tree state, root bridges, blocked ports, VLANs, and VTP status"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

        # Spanning tree
        stp_cmds = [c for c in commands if "spanning-tree" in c]
        base_stp_cmd = next(
            (c for c in stp_cmds if "root" not in c and "blocked" not in c and "bridge" not in c),
            stp_cmds[0] if stp_cmds else None,
        )
        spanning_tree = _ntc_parse(
            raw_outputs.get(base_stp_cmd, ""), device_type, base_stp_cmd
        ) if base_stp_cmd else []

        # STP root -- normalize field names
        root_cmd = _find_cmd(commands, "spanning-tree", "root")
        raw_root = _ntc_parse(
            raw_outputs.get(root_cmd, ""), device_type, root_cmd
        ) if root_cmd else []
        spanning_tree_root = _normalize_root_entries(raw_root)

        # Blocked ports -- try ntc-templates first, fall back to raw parsing
        blocked_cmd = _find_cmd(commands, "blocked")
        blocked_ports = _ntc_parse(
            raw_outputs.get(blocked_cmd, ""), device_type, blocked_cmd
        ) if blocked_cmd else []
        if not blocked_ports and blocked_cmd:
            blocked_ports = _parse_blocked_ports_raw(
                raw_outputs.get(blocked_cmd, ""),
                raw_outputs.get(base_stp_cmd, ""),
            )

        # VLANs -- normalize field names
        vlan_cmd = _find_cmd(commands, "vlan")
        raw_vlans = _ntc_parse(
            raw_outputs.get(vlan_cmd, ""), device_type, vlan_cmd
        ) if vlan_cmd else []
        vlans = _normalize_vlan_entries(raw_vlans)

        # VTP status
        vtp_cmd = _find_cmd(commands, "vtp")
        vtp_status = _ntc_parse(
            raw_outputs.get(vtp_cmd, ""), device_type, vtp_cmd
        ) if vtp_cmd else []

        return {
            "spanning_tree": spanning_tree,
            "spanning_tree_root": spanning_tree_root,
            "blocked_ports": blocked_ports,
            "vlans": vlans,
            "vtp_status": vtp_status,
        }
