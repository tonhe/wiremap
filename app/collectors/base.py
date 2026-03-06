"""
Base class for all collectors.
Each collector gathers data from network devices by declaring commands
and parsing their output.
"""
from abc import ABC, abstractmethod


class BaseCollector(ABC):
    """Abstract base for collectors. Subclass and set class attributes."""

    name: str = ""
    label: str = ""
    description: str = ""
    enabled_by_default: bool = True

    @abstractmethod
    def get_commands(self, device_type: str) -> list[str]:
        """Return list of commands to run for the given device type."""

    @abstractmethod
    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        """Parse raw command outputs into structured data.

        Args:
            raw_outputs: dict mapping command string -> raw text output
            device_type: Netmiko device type string

        Returns:
            Parsed structured data dict.
        """

    # Override this in collectors that need dynamic commands (e.g. per-VRF)
    # or post-collection processing (e.g. SNMP redaction).
    needs_custom_collect = False

    def collect(self, connection, device_type: str) -> dict:
        """Run commands and return raw + parsed data.

        Override in subclasses that need dynamic commands or raw output
        manipulation. The discovery engine calls this instead of the
        batch path when needs_custom_collect is True.
        """
        cmds = self.get_commands(device_type)
        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd)
            except Exception:
                raw_outputs[cmd] = ""
        parsed = self.parse(raw_outputs, device_type)
        return {"raw": raw_outputs, "parsed": parsed}
