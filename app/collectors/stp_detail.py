"""
STP detail collector.
Gathers spanning-tree detail, inconsistent ports, and root summary.
"""
import re

from .base import BaseCollector

_CMD_DETAIL = "show spanning-tree detail"
_CMD_INCONSISTENT = "show spanning-tree inconsistentports"
_CMD_ROOT = "show spanning-tree root"

# Platforms that omit the inconsistentports command
_NO_INCONSISTENT = {"cisco_nxos", "arista_eos"}


class StpDetailCollector(BaseCollector):
    name = "stp_detail"
    label = "STP Detail"
    description = "Collect spanning-tree detail, inconsistent ports, and root summary"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        cmds = [_CMD_DETAIL]
        if device_type not in _NO_INCONSISTENT:
            cmds.append(_CMD_INCONSISTENT)
        cmds.append(_CMD_ROOT)
        return cmds

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        return {
            "stp_detail": _parse_stp_detail(raw_outputs.get(_CMD_DETAIL, "")),
            "inconsistent_ports": _parse_inconsistent_ports(
                raw_outputs.get(_CMD_INCONSISTENT, "")
            ),
            "stp_root_summary": _parse_stp_root(raw_outputs.get(_CMD_ROOT, "")),
        }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

# Matches VLAN header lines like " VLAN0001 is executing the rstp compatible..."
_RE_VLAN_HEADER = re.compile(r"^\s*VLAN(\d+)\s+is\s+executing")

# Matches topology change count in the per-VLAN header block:
#   Number of topology changes 369 last change occurred ...
_RE_VLAN_TOPO_CHANGES = re.compile(
    r"Number of topology changes\s+(\d+)"
)

# Matches per-port lines like:
#   Port 4096 (port-channel1, vPC Peer-link) of VLAN0001 is designated forwarding
# Interface name may contain commas/spaces inside parens.
_RE_PORT_LINE = re.compile(
    r"Port\s+\d+\s+\((.+?)\)\s+of\s+VLAN\d+\s+is\s+(\S+)\s+(\S+)"
)

# Matches path cost line:
#   Port path cost 4, ...
_RE_PATH_COST = re.compile(r"Port path cost\s+(\d+)")

# Matches transition count:
#   Number of transitions to forwarding state: 5
_RE_TRANSITIONS = re.compile(
    r"Number of transitions to forwarding state:\s+(\d+)"
)


def _parse_stp_detail(output: str) -> list[dict]:
    if not output or not output.strip():
        return []

    results = []
    current_vlan = None
    current_vlan_topo_changes = 0

    for line in output.splitlines():
        # Check for VLAN header
        vlan_match = _RE_VLAN_HEADER.match(line)
        if vlan_match:
            current_vlan = int(vlan_match.group(1))
            current_vlan_topo_changes = 0
            continue

        # Check for per-VLAN topology change count (before port entries)
        if current_vlan is not None:
            topo_match = _RE_VLAN_TOPO_CHANGES.search(line)
            if topo_match:
                current_vlan_topo_changes = int(topo_match.group(1))
                continue

        # Check for port line
        port_match = _RE_PORT_LINE.search(line)
        if port_match and current_vlan is not None:
            # Extract first token as canonical interface name
            iface_raw = port_match.group(1)
            iface = iface_raw.split(",")[0].strip()
            entry = {
                "vlan": current_vlan,
                "interface": iface,
                "role": port_match.group(2),
                "state": port_match.group(3),
                "cost": 0,
                "topology_changes": current_vlan_topo_changes,
            }
            results.append(entry)
            continue

        # Fill in cost for the most recent entry
        if results:
            cost_match = _RE_PATH_COST.search(line)
            if cost_match:
                results[-1]["cost"] = int(cost_match.group(1))
                continue

    return results


# Inconsistent ports table:
# Name                 Interface              Inconsistency
# -------------------- ---------------------- ------------------
# VLAN0010             GigabitEthernet0/1     Port Type Inconsistent
_RE_INCONSISTENT = re.compile(
    r"(VLAN\d+)\s+(\S+)\s+(.+)"
)


def _parse_inconsistent_ports(output: str) -> list[dict]:
    if not output or not output.strip():
        return []

    results = []
    past_header = False
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip header lines (dashes separator signals start of data)
        if stripped.startswith("---"):
            past_header = True
            continue
        if not past_header:
            continue
        m = _RE_INCONSISTENT.match(stripped)
        if m:
            vlan_str = m.group(1)
            # Extract VLAN number from e.g. VLAN0010
            vlan_num = re.search(r"\d+", vlan_str)
            results.append({
                "interface": m.group(2),
                "vlan": int(vlan_num.group()) if vlan_num else vlan_str,
                "type": m.group(3).strip(),
            })
    return results


# Root summary table:
#                                        Root    Hello Max Fwd
# Vlan                   Root ID    Cost    Time  Age Dly  Root Port
# --------------- -------------------- --------- ----- --- --- ------------
# VLAN0001        32769 0050.56aa.bb01         0    2  20  15
# VLAN0010        32778 0050.56aa.bb02         4    2  20  15 Gi0/1
_RE_ROOT_LINE = re.compile(
    r"VLAN(\d+)\s+(\d+)\s+([0-9a-fA-F.]+)\s+(\d+)\s+.*?(?:(\S+)\s*)?$"
)


def _parse_stp_root(output: str) -> list[dict]:
    if not output or not output.strip():
        return []

    results = []
    for line in output.splitlines():
        m = _RE_ROOT_LINE.search(line)
        if m:
            results.append({
                "vlan": int(m.group(1)),
                "priority": int(m.group(2)),
                "root_address": m.group(3),
                "cost": int(m.group(4)),
                "port": m.group(5) if m.group(5) else "",
            })
    return results
