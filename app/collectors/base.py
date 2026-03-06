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
