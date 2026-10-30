"""
Base class for all collectors.
Each collector gathers data from network devices by declaring commands
and parsing their output.
"""
from abc import ABC, abstractmethod

try:
    from app.collectors.errors import error_reason
except ImportError:
    from collectors.errors import error_reason


def split_command_errors(raw_outputs):
    """Separate CLI error responses from real output.

    Returns (for_parse, command_errors): for_parse is raw_outputs with every
    rejected command blanked, command_errors maps each rejected command to
    the device's error line.
    """
    command_errors = {}
    for cmd, out in raw_outputs.items():
        reason = error_reason(out)
        if reason:
            command_errors[cmd] = reason
    for_parse = dict(raw_outputs)
    for cmd in command_errors:
        for_parse[cmd] = ""
    return for_parse, command_errors


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

    # Platforms this collector cannot serve at all -- a VyOS box has no
    # switchports, a WLC has no Cisco-style routing table. Running the default
    # Cisco commands at them produces nothing but rejected-command noise.
    unsupported_platforms = frozenset()

    # Layer-2 switching collectors. An ASR or ISR is cisco_xe exactly like a
    # Catalyst, so platform gating cannot keep switchport/VLAN/STP commands
    # off routers; the engine skips these once it knows the box is a router.
    switching_only = False

    # Individual switch-only commands inside an otherwise general collector
    # (e.g. "show interfaces status" in the interfaces collector). Dropped
    # on routers while the rest of the collector still runs.
    switching_commands = frozenset()

    def parse_collected(self, raw_outputs, device_type):
        """Parse raw outputs, treating CLI error responses as failures.

        Shared by collect() and the engine's batch path so a rejected
        command is never parsed as data, whichever way it was run.
        """
        # A device that rejected the command returns error text, not data.
        # Parsing it produces rows like Area="Invalid", Interface="%".
        for_parse, command_errors = split_command_errors(raw_outputs)
        failed = [c for c in raw_outputs if c in command_errors]

        if failed and len(failed) == len(raw_outputs):
            return {
                "collector_failed": True,
                "collector_error": command_errors[failed[0]],
                "failed_commands": failed,
                "command_errors": command_errors,
            }

        # Rejected commands are blanked so a partially successful collector
        # still parses whatever did work. The caller keeps the raw error text
        # so the failure stays diagnosable.
        parsed = self.parse(for_parse, device_type)
        if failed:
            parsed["failed_commands"] = failed
            parsed["command_errors"] = command_errors
        return parsed

    def collect(self, connection, device_type: str) -> dict:
        """Run commands and return raw + parsed data.

        Override in subclasses that need dynamic commands or raw output
        manipulation. The discovery engine calls this instead of the
        batch path when needs_custom_collect is True.
        """
        if device_type in self.unsupported_platforms:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"{self.name} does not apply to {device_type}"}}

        cmds = self.get_commands(device_type)
        if not cmds:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"no commands defined for {device_type}"}}

        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd)
            except Exception:
                raw_outputs[cmd] = ""

        return {"raw": raw_outputs,
                "parsed": self.parse_collected(raw_outputs, device_type)}
