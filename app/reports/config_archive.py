"""
Config Archive report -- ZIP of running configs (one .txt per device).
"""
import io
import zipfile

from .base import BaseReport


class ConfigArchiveReport(BaseReport):
    name = "config_archive"
    label = "Config Archive"
    description = "Running configuration backup for all devices"
    category = "Compliance & Config"
    required_collectors = ["config"]
    supported_formats = ["zip"]

    def generate(self, inventory_data: dict, fmt: str = "zip") -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for hostname, device in sorted(inventory_data.get("devices", {}).items()):
                config_data = device.get("collector_data", {}).get("config", {})
                config_text = config_data.get("parsed", {}).get("config", "")
                if config_text:
                    zf.writestr(f"{hostname}.txt", config_text)
        return buf.getvalue()
