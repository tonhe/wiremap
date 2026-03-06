"""
ARP table collector.
Wraps existing parse_arp_table() from parsers.py.
"""
from .base import BaseCollector

try:
    from app.parsers import parse_arp_table
except ImportError:
    from parsers import parse_arp_table

# ARP commands per vendor (from discovery.py ARP_COMMANDS)
_COMMANDS = {
    "cisco_ios": "show ip arp",
    "cisco_xe": "show ip arp",
    "cisco_nxos": "show ip arp",
    "arista_eos": "show ip arp",
    "extreme": "show iparp",
    "extreme_vsp": "show ip arp",
    "juniper_junos": "show arp",
}
_DEFAULT_COMMAND = "show ip arp"


class ArpCollector(BaseCollector):
    name = "arp"
    label = "ARP Table"
    description = "Collect ARP table entries from devices"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return [_COMMANDS.get(device_type, _DEFAULT_COMMAND)]

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        cmd = _COMMANDS.get(device_type, _DEFAULT_COMMAND)
        output = raw_outputs.get(cmd, "")
        entries = parse_arp_table(output) if output else []
        return {"entries": entries}
