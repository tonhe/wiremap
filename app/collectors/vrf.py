"""
VRF configuration collector.
Gathers VRF definitions and interface assignments.
"""
import re

from .base import BaseCollector

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


class VrfCollector(BaseCollector):
    name = "vrf"
    label = "VRF Configuration"
    description = "Collect VRF definitions and interface assignments"
    enabled_by_default = True

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

        return {"vrfs": vrfs, "vrf_interfaces": vrf_interfaces}
