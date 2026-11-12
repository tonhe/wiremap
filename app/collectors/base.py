"""
Base class for all collectors.
Each collector gathers data from network devices by declaring commands
and parsing their output.
"""
from abc import ABC, abstractmethod

try:
    from app.collectors.errors import (
        error_reason, error_kind, send_failure_output, NOT_APPLICABLE, FAILED)
except ImportError:
    from collectors.errors import (
        error_reason, error_kind, send_failure_output, NOT_APPLICABLE, FAILED)


ASA_TYPE = "cisco_asa"
DEDICATED_PLATFORMS = frozenset({ASA_TYPE})


def command_error_kinds(parsed):
    """Map each rejected command to not_applicable, unauthorized or failed.

    Scans saved before the kinds were recorded are classified again from the
    stored error line, which is the device's own text.
    """
    parsed = parsed or {}
    kinds = parsed.get("command_error_kinds")
    if isinstance(kinds, dict):
        return dict(kinds)
    return {cmd: error_kind(reason) or FAILED
            for cmd, reason in (parsed.get("command_errors") or {}).items()}


def collector_has_failures(parsed):
    """True when a collector lost data it should have had.

    A command the platform does not support is not a failure; a timeout, an
    AAA refusal or a collector that failed without saying why is.
    """
    parsed = parsed or {}
    kinds = command_error_kinds(parsed)
    if any(kind != NOT_APPLICABLE for kind in kinds.values()):
        return True
    if not parsed.get("collector_failed") or kinds:
        return False
    # Older scans kept only the first error line of a wholly rejected
    # collector; a syntax rejection there was never a real failure.
    return error_kind(parsed.get("collector_error") or "") != NOT_APPLICABLE


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

    # Custom collectors that need what the batch collectors already found
    # (neighbours, switchports, the model) receive it as collect(context=...).
    needs_device_context = False

    # Platforms this collector cannot serve at all -- a VyOS box has no
    # switchports, a WLC has no Cisco-style routing table. Running the default
    # Cisco commands at them produces nothing but rejected-command noise.
    unsupported_platforms = frozenset()

    # ASA and ASAv speak a command set of their own, so only collectors
    # written for them run there; every other collector would send IOS
    # commands and fill Collection Errors with rejections.
    serves_asa = False

    def applies_to(self, device_type):
        if device_type in self.unsupported_platforms:
            return False
        if device_type in DEDICATED_PLATFORMS and not self.serves_asa:
            return False
        return True

    # Layer-2 switching collectors. An ASR or ISR is cisco_xe exactly like a
    # Catalyst, so platform gating cannot keep switchport/VLAN/STP commands
    # off routers; the engine skips these once it knows the box is a router.
    switching_only = False

    # Individual switch-only commands inside an otherwise general collector
    # (e.g. "show interfaces status" in the interfaces collector). Dropped
    # on routers while the rest of the collector still runs.
    switching_commands = frozenset()

    # Routing collectors. Skipped on analog voice gateways, which run IOS
    # and answer the commands but have no routing worth collecting.
    routing_only = False

    def parse_collected(self, raw_outputs, device_type):
        """Parse raw outputs, never parsing a CLI error response as data.

        Shared by collect() and the engine's batch path so a rejected
        command is never parsed as data, whichever way it was run.
        """
        # A device that rejected the command returns error text, not data.
        # Parsing it produces rows like Area="Invalid", Interface="%".
        for_parse, command_errors = split_command_errors(raw_outputs)
        failed = [c for c in raw_outputs if c in command_errors]
        kinds = {c: error_kind(raw_outputs[c]) for c in failed}
        detail = {
            "failed_commands": failed,
            "command_errors": command_errors,
            "command_error_kinds": kinds,
        }

        if failed and len(failed) == len(raw_outputs):
            real = [c for c in failed if kinds[c] != NOT_APPLICABLE]
            if not real:
                # Every command was rejected as syntax: the platform simply
                # does not have this feature, e.g. show ip vrf on LAN Base.
                return {
                    "not_applicable": True,
                    "reason": f"{self.name}: {command_errors[failed[0]]}",
                    **detail,
                }
            return {
                "collector_failed": True,
                "collector_error": command_errors[real[0]],
                **detail,
            }

        # Rejected commands are blanked so a partially successful collector
        # still parses whatever did work. The caller keeps the raw error text
        # so the failure stays diagnosable.
        parsed = self.parse(for_parse, device_type)
        if failed:
            parsed.update(detail)
        return parsed

    def collect(self, connection, device_type: str) -> dict:
        """Run commands and return raw + parsed data.

        Override in subclasses that need dynamic commands or raw output
        manipulation. The discovery engine calls this instead of the
        batch path when needs_custom_collect is True.
        """
        if not self.applies_to(device_type):
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
            except Exception as e:
                raw_outputs[cmd] = send_failure_output(e)

        return {"raw": raw_outputs,
                "parsed": self.parse_collected(raw_outputs, device_type)}
