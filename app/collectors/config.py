"""
Running configuration collector.
Stores raw config output -- no complex parsing needed.
"""
from .base import BaseCollector

_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration",
    "extreme": "show configuration",
}
_DEFAULT_COMMAND = "show running-config"


class ConfigCollector(BaseCollector):
    name = "config"
    label = "Running Config"
    description = "Collect running configuration from devices"
    enabled_by_default = False  # opt-in, configs can be large/sensitive

    def get_commands(self, device_type: str) -> list[str]:
        return [_COMMANDS.get(device_type, _DEFAULT_COMMAND)]

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        cmd = _COMMANDS.get(device_type, _DEFAULT_COMMAND)
        return {"config": raw_outputs.get(cmd, "")}
