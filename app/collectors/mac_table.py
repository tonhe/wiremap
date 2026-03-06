"""
MAC address table collector.
Uses ntc-templates for parsing.
"""
import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

_COMMANDS = {
    "cisco_ios": "show mac address-table",
    "cisco_xe": "show mac address-table",
    "cisco_nxos": "show mac address-table",
    "arista_eos": "show mac address-table",
    "juniper_junos": "show ethernet-switching table",
    "extreme": "show fdb",
}
_DEFAULT_COMMAND = "show mac address-table"


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


class MacTableCollector(BaseCollector):
    name = "mac_table"
    label = "MAC Address Table"
    description = "Collect MAC address table entries from devices"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return [_COMMANDS.get(device_type, _DEFAULT_COMMAND)]

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        cmd = _COMMANDS.get(device_type, _DEFAULT_COMMAND)
        entries = _ntc_parse(raw_outputs.get(cmd, ""), device_type, cmd)
        return {"entries": entries}
