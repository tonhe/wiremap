"""
Switchport configuration collector.
Gathers switchport settings, port-security, errdisable, and storm-control data.
"""
from .base import BaseCollector

try:
    from ntc_templates.parse import parse_output
    HAS_NTC = True
except ImportError:
    HAS_NTC = False

import re

# Commands per device type
_COMMANDS = {
    "cisco_ios": [
        "show interfaces switchport",
        "show port-security",
        "show port-security address",
        "show errdisable recovery",
        "show storm-control",
    ],
    "cisco_xe": [
        "show interfaces switchport",
        "show port-security",
        "show port-security address",
        "show errdisable recovery",
        "show storm-control",
    ],
    "cisco_nxos": [
        "show interface switchport",
        "show port-security",
        "show port-security address",
        "show errdisable recovery",
        "show storm-control",
    ],
}
_DEFAULT_COMMANDS = _COMMANDS["cisco_ios"]


def _parse_switchport_regex(output):
    """Regex fallback parser for 'show interfaces switchport' output."""
    entries = []
    if not output or not output.strip():
        return entries

    # Split on interface blocks
    blocks = re.split(r'^Name:\s*', output, flags=re.MULTILINE)
    for block in blocks:
        if not block.strip():
            continue
        entry = {}

        # Interface name is the first line
        lines = block.strip().splitlines()
        entry["interface"] = lines[0].strip()

        for line in lines[1:]:
            line_stripped = line.strip()
            if line_stripped.startswith("Administrative Mode:"):
                entry["mode"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Operational Mode:"):
                entry["operational_mode"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Administrative Trunking Encapsulation:"):
                entry["trunking_encapsulation"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Access Mode VLAN:"):
                val = line_stripped.split(":", 1)[1].strip()
                # Extract just the VLAN number
                match = re.match(r'(\d+)', val)
                entry["native_vlan"] = match.group(1) if match else val
            elif line_stripped.startswith("Trunking Native Mode VLAN:"):
                val = line_stripped.split(":", 1)[1].strip()
                match = re.match(r'(\d+)', val)
                entry["native_vlan"] = match.group(1) if match else val
            elif line_stripped.startswith("Trunking VLANs Enabled:") or line_stripped.startswith("Trunking VLANs Allowed:"):
                entry["allowed_vlans"] = line_stripped.split(":", 1)[1].strip()
            elif line_stripped.startswith("Voice VLAN:"):
                val = line_stripped.split(":", 1)[1].strip()
                entry["voice_vlan"] = val if val.lower() != "none" else ""

        # Ensure required fields
        entry.setdefault("mode", "")
        entry.setdefault("native_vlan", "")
        entry.setdefault("allowed_vlans", "")
        entry.setdefault("voice_vlan", "")

        entries.append(entry)

    return entries


def _normalize_switchport(entry):
    """Normalize ntc-templates field names for switchport entries."""
    normalized = dict(entry)
    # admin_mode -> mode (NTC provides both; prefer mode if present)
    if "admin_mode" in normalized and "mode" not in normalized:
        normalized["mode"] = normalized.pop("admin_mode")
    # trunking_vlans -> allowed_vlans (NTC returns a list)
    if "trunking_vlans" in normalized and "allowed_vlans" not in normalized:
        vlans = normalized.pop("trunking_vlans")
        if isinstance(vlans, list):
            normalized["allowed_vlans"] = ",".join(vlans)
        else:
            normalized["allowed_vlans"] = str(vlans) if vlans else ""
    # Normalize voice_vlan "none" to empty string
    if normalized.get("voice_vlan", "").lower() == "none":
        normalized["voice_vlan"] = ""
    # Ensure required fields exist
    normalized.setdefault("interface", "")
    normalized.setdefault("mode", "")
    normalized.setdefault("native_vlan", "")
    normalized.setdefault("allowed_vlans", "")
    normalized.setdefault("voice_vlan", "")
    return normalized


def _try_ntc_parse(command, output, device_type):
    """Try parsing with ntc-templates, return None on failure."""
    if not HAS_NTC or not output or not output.strip():
        return None
    # Map our device_type to ntc-templates platform
    platform_map = {
        "cisco_ios": "cisco_ios",
        "cisco_xe": "cisco_ios",
        "cisco_xr": "cisco_ios",
        "cisco_nxos": "cisco_nxos",
    }
    platform = platform_map.get(device_type)
    if not platform:
        return None
    try:
        return parse_output(platform=platform, command=command, data=output)
    except Exception:
        return None


class SwitchportCollector(BaseCollector):
    name = "switchport"
    label = "Switchport Configuration"
    description = "Collect switchport, port-security, errdisable, and storm-control data"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, _DEFAULT_COMMANDS))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)
        switchport_cmd = commands[0]
        port_sec_cmd = commands[1]
        port_sec_addr_cmd = commands[2]
        errdisable_cmd = commands[3]
        storm_cmd = commands[4]

        result = {
            "switchports": [],
            "port_security": [],
            "port_security_addresses": [],
            "errdisable_recovery": [],
            "storm_control": [],
        }

        # Parse switchport output
        sw_output = raw_outputs.get(switchport_cmd, "")
        if sw_output and sw_output.strip():
            parsed = _try_ntc_parse(switchport_cmd, sw_output, device_type)
            if parsed is not None:
                result["switchports"] = [_normalize_switchport(e) for e in parsed]
            else:
                result["switchports"] = _parse_switchport_regex(sw_output)

        # Parse port-security
        ps_output = raw_outputs.get(port_sec_cmd, "")
        if ps_output and ps_output.strip():
            parsed = _try_ntc_parse(port_sec_cmd, ps_output, device_type)
            if parsed is not None:
                result["port_security"] = parsed
            # No regex fallback for port-security; keep empty list

        # Parse port-security addresses
        psa_output = raw_outputs.get(port_sec_addr_cmd, "")
        if psa_output and psa_output.strip():
            parsed = _try_ntc_parse(port_sec_addr_cmd, psa_output, device_type)
            if parsed is not None:
                result["port_security_addresses"] = parsed

        # Parse errdisable recovery
        err_output = raw_outputs.get(errdisable_cmd, "")
        if err_output and err_output.strip():
            parsed = _try_ntc_parse(errdisable_cmd, err_output, device_type)
            if parsed is not None:
                result["errdisable_recovery"] = parsed

        # Parse storm-control
        sc_output = raw_outputs.get(storm_cmd, "")
        if sc_output and sc_output.strip():
            parsed = _try_ntc_parse(storm_cmd, sc_output, device_type)
            if parsed is not None:
                result["storm_control"] = parsed

        return result
