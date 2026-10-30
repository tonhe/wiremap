"""
Running configuration collector.
Stores raw config output -- no complex parsing needed.

SECURITY: secrets (SNMP communities, enable/user secrets, AAA and routing
keys, VPN pre-shared keys) are replaced with <REDACTED> in both raw and
parsed output before anything is stored, unless the redact_secrets
setting is turned off.
"""
from .base import BaseCollector

try:
    from app.redact import redact_config
    from app.settings import redact_secrets_enabled
except ImportError:
    from redact import redact_config
    from settings import redact_secrets_enabled

_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration",
    "extreme": "show configuration",
    "vyos": "show configuration commands",
    # Plain "show run-config" is paged and interactive on AireOS.
    "cisco_wlc": "show run-config startup-commands",
    "watchguard_fireware": "show configuration",
    "paloalto_panos": "show config running",
}
_DEFAULT_COMMAND = "show running-config"


class ConfigCollector(BaseCollector):
    name = "config"
    label = "Running Config"
    description = "Collect running configuration from devices"
    enabled_by_default = False  # opt-in, configs can be large/sensitive
    # Custom collect so the raw output is redacted too; the batch path
    # stores raw output exactly as the device returned it.
    needs_custom_collect = True

    def get_commands(self, device_type: str) -> list[str]:
        return [_COMMANDS.get(device_type, _DEFAULT_COMMAND)]

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        cmd = _COMMANDS.get(device_type, _DEFAULT_COMMAND)
        config = raw_outputs.get(cmd, "")
        redacted = redact_secrets_enabled()
        if redacted:
            config = redact_config(config)
        return {"config": config, "redacted": redacted}

    def collect(self, connection, device_type: str) -> dict:
        result = super().collect(connection, device_type)
        if redact_secrets_enabled():
            result["raw"] = {cmd: redact_config(out)
                             for cmd, out in result["raw"].items()}
        return result
