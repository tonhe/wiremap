"""
Device inventory collector (show version, show inventory, etc.).
Uses ntc-templates for parsing.
"""
import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

# ntc-templates doesn't have cisco_xe templates; use cisco_ios instead
_NTC_PLATFORM_MAP = {
    "cisco_xe": "cisco_ios",
    "cisco_xr": "cisco_ios",
}

_COMMANDS = {
    "cisco_ios": ["show version", "show inventory", "show switch detail", "show module"],
    "cisco_xe": ["show version", "show inventory", "show switch detail", "show module"],
    "cisco_nxos": ["show version", "show inventory", "show module"],
    "arista_eos": ["show version", "show inventory", "show module"],
    "juniper_junos": ["show version", "show chassis hardware", "show virtual-chassis"],
    "extreme": ["show version", "show switch"],
}
_DEFAULT_COMMANDS = ["show version", "show inventory"]


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


def _parse_show_switch_detail(raw: str) -> list[dict]:
    """Fallback parser for 'show switch detail' if ntc-templates lacks it."""
    if not raw:
        return []
    members = []
    pattern = re.compile(
        r'[* ]*(\d+)\s+'            # switch number (may have * prefix)
        r'(\w+)\s+'                  # role
        r'([0-9a-f.]+)\s+'          # mac address
        r'(\d+)\s+'                  # priority
        r'(\S+)\s+'                  # hw version
        r'(\S+)',                    # state
        re.IGNORECASE,
    )
    for m in pattern.finditer(raw):
        members.append({
            "switch": m.group(1),
            "role": m.group(2),
            "mac_address": m.group(3),
            "priority": m.group(4),
            "hw_ver": m.group(5),
            "state": m.group(6),
        })
    return members


class DeviceInventoryCollector(BaseCollector):
    name = "device_inventory"
    label = "Device Inventory"
    description = "Collect hardware version, serial numbers, and module information"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        commands = _COMMANDS.get(device_type, _DEFAULT_COMMANDS)

        # show version
        version_cmd = next((c for c in commands if "version" in c), None)
        version = _ntc_parse(
            raw_outputs.get(version_cmd, ""), device_type, version_cmd
        ) if version_cmd else []

        # show inventory / show chassis hardware
        inv_cmd = next(
            (c for c in commands if "inventory" in c or "chassis" in c),
            None,
        )
        inventory = _ntc_parse(
            raw_outputs.get(inv_cmd, ""), device_type, inv_cmd
        ) if inv_cmd else []

        # show module
        mod_cmd = next((c for c in commands if "module" in c), None)
        modules = _ntc_parse(
            raw_outputs.get(mod_cmd, ""), device_type, mod_cmd
        ) if mod_cmd else []

        # Stack members: show switch detail (Cisco), show virtual-chassis (Juniper),
        # show switch (Extreme)
        stack_cmd = next(
            (c for c in commands if "switch detail" in c or "virtual-chassis" in c),
            None,
        )
        stack_members = []
        if stack_cmd:
            stack_raw = raw_outputs.get(stack_cmd, "")
            stack_members = _ntc_parse(stack_raw, device_type, stack_cmd)
            if not stack_members and stack_raw:
                stack_members = _parse_show_switch_detail(stack_raw)

        # For Extreme, stack data comes from "show switch" which is also the inv_cmd
        if not stack_members and device_type == "extreme":
            stack_members = _ntc_parse(
                raw_outputs.get("show switch", ""), device_type, "show switch"
            )

        return {
            "version": version,
            "inventory": inventory,
            "modules": modules,
            "stack_members": stack_members,
        }
