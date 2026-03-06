"""
Base class for all reports.
Each report generates output from discovery inventory data.
"""
from abc import ABC, abstractmethod


class BaseReport(ABC):
    """Abstract base for reports. Subclass and set class attributes."""

    name: str = ""
    label: str = ""
    description: str = ""
    required_collectors: list[str] = []
    category: str = "General"
    supported_formats: list[str] = ["xlsx"]

    @abstractmethod
    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        """Generate report from inventory data.

        Args:
            inventory_data: Full discovery inventory dict.
            fmt: Output format (must be in supported_formats).

        Returns:
            Report content as bytes.
        """

    def can_generate(self, inventory_data: dict) -> bool:
        """Check if inventory has the required collector data."""
        devices = inventory_data.get("devices", {})
        if not devices:
            return False
        for device in devices.values():
            collector_data = device.get("collector_data", {})
            if all(c in collector_data for c in self.required_collectors):
                return True
        return False

    def get_ui_options(self) -> list[dict]:
        """Return optional per-report config for the UI.

        Override in subclasses to expose report-specific toggles.
        Returns list of dicts: [{"name": "...", "label": "...", "type": "bool", "default": True}]
        """
        return []
