"""
VRF configuration collector.
Gathers VRF definitions, interface assignments, per-VRF routing tables,
and per-VRF ARP tables.
"""
import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

_COMMANDS = {
    "cisco_ios": ["show ip vrf", "show ip vrf interfaces"],
    "cisco_xe": ["show ip vrf", "show ip vrf interfaces"],
    "cisco_nxos": ["show vrf", "show vrf all interface"],
}
_DEFAULT_COMMANDS = ["show ip vrf", "show ip vrf interfaces"]

# IOS/XE: "show ip vrf"
# Name                             Default RD            Protocols   Interfaces
# MGMT                             65000:100             ipv4        Gi0/1
#                                                                    Gi0/2
_IOS_VRF_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<rd>\S+)\s+\S+\s+(?P<intf>\S+)\s*$"
)
_IOS_VRF_CONT_RE = re.compile(
    r"^\s{30,}(?P<intf>\S+)\s*$"
)

# NX-OS: "show vrf"
# VRF-Name                           VRF-ID State   Reason
# MGMT                                    3 Up      --
_NXOS_VRF_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<id>\d+)\s+(?P<state>\S+)\s+(?P<reason>\S+)"
)

# IOS/XE: "show ip vrf interfaces"
# Interface              IP-Address      VRF                              Protocol
# Gi0/1                  10.1.1.1        MGMT                             up
_IOS_VRF_INTF_RE = re.compile(
    r"^(?P<intf>\S+)\s+(?P<ip>\S+)\s+(?P<vrf>\S+)\s+\S+"
)

# NX-OS: "show vrf all interface"
# Interface                 VRF-Name                        VRF-ID  Site-of-Origin
# Ethernet1/1               MGMT                                 3  --
_NXOS_VRF_INTF_RE = re.compile(
    r"^(?P<intf>\S+)\s+(?P<vrf>\S+)\s+(?P<id>\d+)\s+"
)


def _parse_ios_vrfs(output):
    """Parse 'show ip vrf' output for IOS/XE."""
    vrfs = {}
    current_vrf = None
    for line in output.splitlines():
        m = _IOS_VRF_RE.match(line)
        if m:
            name = m.group("name")
            current_vrf = name
            if name not in vrfs:
                vrfs[name] = {
                    "name": name,
                    "rd": m.group("rd"),
                    "description": "",
                    "interfaces": [],
                }
            vrfs[name]["interfaces"].append(m.group("intf"))
            continue
        # Continuation line (additional interfaces for the same VRF)
        if current_vrf:
            mc = _IOS_VRF_CONT_RE.match(line)
            if mc:
                vrfs[current_vrf]["interfaces"].append(mc.group("intf"))
            else:
                current_vrf = None
    return list(vrfs.values())


def _parse_nxos_vrfs(output):
    """Parse 'show vrf' output for NX-OS."""
    vrfs = []
    for line in output.splitlines():
        m = _NXOS_VRF_RE.match(line)
        if m:
            vrfs.append({
                "name": m.group("name"),
                "rd": "",
                "description": "",
                "interfaces": [],
            })
    return vrfs


def _parse_ios_vrf_interfaces(output):
    """Parse 'show ip vrf interfaces' output for IOS/XE."""
    entries = []
    for line in output.splitlines():
        m = _IOS_VRF_INTF_RE.match(line)
        if m:
            ip = m.group("ip")
            if ip.count(".") != 3:
                continue
            entries.append({
                "vrf": m.group("vrf"),
                "interface": m.group("intf"),
                "ip_address": ip,
            })
    return entries


def _parse_nxos_vrf_interfaces(output):
    """Parse 'show vrf all interface' output for NX-OS."""
    entries = []
    for line in output.splitlines():
        m = _NXOS_VRF_INTF_RE.match(line)
        if m:
            entries.append({
                "vrf": m.group("vrf"),
                "interface": m.group("intf"),
                "ip_address": "",
            })
    return entries


def _parse_vrf_routes(output: str) -> list[dict]:
    """Parse 'show ip route vrf <name>' output into route entries."""
    routes = []
    if not output or not output.strip():
        return routes
    for line in output.splitlines():
        # Match route lines like:
        # "C    10.1.1.0/24 is directly connected, GigabitEthernet0/1"
        # "S    0.0.0.0/0 [1/0] via 10.1.1.1"
        # "O    10.2.0.0/16 [110/20] via 10.1.1.1, 00:05:00, Gi0/1"
        m = re.match(
            r"^\s*([A-Z*]+(?:\s+\S+)?)\s+"  # protocol code(s)
            r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)"  # network/mask
            r"\s+(.+)",  # rest of line
            line,
        )
        if m:
            code = m.group(1).strip()
            network = m.group(2)
            detail = m.group(3).strip()
            # Extract next-hop if present
            via_match = re.search(r"via\s+(\S+)", detail)
            next_hop = via_match.group(1).rstrip(",") if via_match else ""
            routes.append({
                "protocol": code,
                "network": network,
                "next_hop": next_hop,
            })
    return routes


def _parse_vrf_arp(output: str) -> list[dict]:
    """Parse 'show ip arp vrf <name>' output into ARP entries."""
    entries = []
    if not output or not output.strip():
        return entries
    for line in output.splitlines():
        # "Internet  10.1.1.1   0   0050.56aa.bb01  ARPA   GigabitEthernet0/1"
        m = re.match(
            r"^\s*Internet\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+"  # IP address
            r"(\S+)\s+"  # age
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"  # MAC
            r"\S+\s+"  # type (ARPA)
            r"(\S+)",  # interface
            line,
        )
        if m:
            entries.append({
                "ip_address": m.group(1),
                "age": m.group(2),
                "mac_address": m.group(3),
                "interface": m.group(4),
            })
    return entries


class VrfCollector(BaseCollector):
    name = "vrf"
    label = "VRF Configuration"
    description = "Collect VRF definitions, interface assignments, per-VRF routes and ARP"
    enabled_by_default = True
    needs_custom_collect = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, _DEFAULT_COMMANDS))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)
        vrf_cmd = commands[0]
        intf_cmd = commands[1]

        vrf_output = raw_outputs.get(vrf_cmd, "")
        intf_output = raw_outputs.get(intf_cmd, "")

        if device_type == "cisco_nxos":
            vrfs = _parse_nxos_vrfs(vrf_output) if vrf_output else []
            vrf_interfaces = _parse_nxos_vrf_interfaces(intf_output) if intf_output else []
        else:
            vrfs = _parse_ios_vrfs(vrf_output) if vrf_output else []
            vrf_interfaces = _parse_ios_vrf_interfaces(intf_output) if intf_output else []

        # Parse per-VRF routes and ARP from raw_outputs
        vrf_routes = {}
        vrf_arp = {}
        for key, val in raw_outputs.items():
            route_m = re.match(r"show ip route vrf (\S+)", key)
            if route_m:
                vrf_name = route_m.group(1)
                vrf_routes[vrf_name] = _parse_vrf_routes(val)
                continue
            arp_m = re.match(r"show ip arp vrf (\S+)", key)
            if arp_m:
                vrf_name = arp_m.group(1)
                vrf_arp[vrf_name] = _parse_vrf_arp(val)

        return {
            "vrfs": vrfs,
            "vrf_interfaces": vrf_interfaces,
            "vrf_routes": vrf_routes,
            "vrf_arp": vrf_arp,
        }

    def collect(self, connection, device_type: str) -> dict:
        """Two-phase collection: get VRF list, then per-VRF routes/ARP."""
        # Phase 1: run base commands
        cmds = self.get_commands(device_type)
        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd)
            except Exception:
                raw_outputs[cmd] = ""

        # Parse VRF names from phase 1
        vrf_cmd = cmds[0]
        vrf_output = raw_outputs.get(vrf_cmd, "")
        if device_type == "cisco_nxos":
            vrfs = _parse_nxos_vrfs(vrf_output) if vrf_output else []
        else:
            vrfs = _parse_ios_vrfs(vrf_output) if vrf_output else []

        # Phase 2: per-VRF route and ARP commands
        vrf_names = [v["name"] for v in vrfs]
        # Skip default/management VRFs that are typically uninteresting
        skip_vrfs = {"default", "management", "Mgmt-vrf"}
        for vrf_name in vrf_names:
            if vrf_name in skip_vrfs:
                continue
            route_cmd = f"show ip route vrf {vrf_name}"
            arp_cmd = f"show ip arp vrf {vrf_name}"
            for cmd in (route_cmd, arp_cmd):
                try:
                    raw_outputs[cmd] = connection.send_command(cmd)
                except Exception:
                    logger.debug(f"VRF command failed: {cmd}")
                    raw_outputs[cmd] = ""

        parsed = self.parse(raw_outputs, device_type)
        return {"raw": raw_outputs, "parsed": parsed}
