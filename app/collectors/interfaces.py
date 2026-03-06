"""
Interface status, description, and etherchannel collector.
Uses ntc-templates for parsing where available.
"""
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

_COMMANDS = {
    "cisco_ios": [
        "show interfaces status",
        "show interfaces description",
        "show ip interface brief",
        "show ip interface",
        "show etherchannel summary",
    ],
    "cisco_xe": [
        "show interfaces status",
        "show interfaces description",
        "show ip interface brief",
        "show ip interface",
        "show etherchannel summary",
    ],
    "cisco_nxos": [
        "show interface status",
        "show interface description",
        "show ip interface brief",
        "show ip interface",
        "show port-channel summary",
    ],
    "arista_eos": [
        "show interfaces status",
        "show interfaces description",
        "show ip interface brief",
        "show ip interface",
    ],
    "juniper_junos": [
        "show interfaces terse",
        "show interfaces descriptions",
    ],
}
_DEFAULT_COMMANDS = [
    "show interfaces status",
    "show interfaces description",
    "show ip interface brief",
    "show ip interface",
    "show etherchannel summary",
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


class InterfacesCollector(BaseCollector):
    name = "interfaces"
    label = "Interface Status"
    description = "Collect interface status, descriptions, IP assignments, and etherchannel info"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

        # Interface status
        status_cmd = next((c for c in commands if "status" in c), None)
        interfaces_status = _ntc_parse(
            raw_outputs.get(status_cmd, ""), device_type, status_cmd
        ) if status_cmd else []

        # Interface descriptions
        desc_cmd = next((c for c in commands if "description" in c), None)
        interfaces_desc = _ntc_parse(
            raw_outputs.get(desc_cmd, ""), device_type, desc_cmd
        ) if desc_cmd else []

        # IP interface brief
        ip_cmd = next((c for c in commands if "ip interface" in c or "terse" in c), None)
        ip_interfaces = _ntc_parse(
            raw_outputs.get(ip_cmd, ""), device_type, ip_cmd
        ) if ip_cmd else []

        # Full IP interface (includes secondary IPs and prefix lengths)
        ip_full_cmd = next(
            (c for c in commands if c.strip() == "show ip interface"), None
        )
        ip_interfaces_full = _ntc_parse(
            raw_outputs.get(ip_full_cmd, ""), device_type, ip_full_cmd
        ) if ip_full_cmd else []

        # Etherchannel / port-channel
        ec_cmd = next((c for c in commands if "channel" in c), None)
        etherchannel = _ntc_parse(
            raw_outputs.get(ec_cmd, ""), device_type, ec_cmd
        ) if ec_cmd else []

        return {
            "interfaces_status": interfaces_status,
            "interfaces_description": interfaces_desc,
            "ip_interfaces": ip_interfaces,
            "ip_interfaces_full": ip_interfaces_full,
            "etherchannel": etherchannel,
        }
