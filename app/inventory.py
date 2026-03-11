"""
Discovery Inventory -- persistence layer for collected network data.
Stores raw command output + parsed data from all collectors.
"""
import json
import os
import tempfile
import threading
from datetime import datetime, timezone


class DiscoveryInventory:
    """Represents a complete discovery run's data."""

    def __init__(self, data: dict):
        self._data = data
        self._lock = threading.Lock()

    @classmethod
    def create(cls, seed_ip: str, params: dict = None):
        """Create a new empty inventory."""
        now = datetime.now(timezone.utc)
        discovery_id = f"{now.strftime('%Y-%m-%d_%H-%M-%S')}_{seed_ip}"
        data = {
            "discovery_id": discovery_id,
            "seed_ip": seed_ip,
            "timestamp": now.isoformat(),
            "params": params or {},
            "devices": {},
        }
        return cls(data)

    @classmethod
    def load(cls, filepath: str):
        """Load inventory from a JSON file."""
        with open(filepath, "r") as f:
            return cls(json.load(f))

    @classmethod
    def list_inventories(cls, directory: str) -> list[dict]:
        """List all inventory files in a directory with summary info."""
        inventories = []
        for filename in sorted(os.listdir(directory), reverse=True):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                inventories.append({
                    "filename": filename,
                    "filepath": filepath,
                    "discovery_id": data.get("discovery_id", ""),
                    "seed_ip": data.get("seed_ip", ""),
                    "timestamp": data.get("timestamp", ""),
                    "device_count": len(data.get("devices", {})),
                })
            except (json.JSONDecodeError, KeyError):
                continue
        return inventories

    @property
    def discovery_id(self):
        return self._data["discovery_id"]

    @property
    def seed_ip(self):
        return self._data["seed_ip"]

    @property
    def params(self):
        return self._data["params"]

    @property
    def devices(self):
        return self._data["devices"]

    def set_scan_summary(self, elapsed: float, failed: dict):
        """Persist scan summary metadata into the inventory data."""
        self._data["scan_summary"] = {
            "elapsed": elapsed,
            "failed_count": len(failed),
            "failed": failed,
        }

    def get_summary(self) -> dict:
        """Return summary stats for the Reports tab. Safe for old inventories."""
        stored = self._data.get("scan_summary", {})
        return {
            "device_count": len(self._data.get("devices", {})),
            "seed_ip": self._data.get("seed_ip", ""),
            "timestamp": self._data.get("timestamp", ""),
            "elapsed": stored.get("elapsed"),
            "failed_count": stored.get("failed_count"),
        }

    def add_device(self, hostname: str, mgmt_ip: str = None,
                   device_type: str = None, device_category: str = None,
                   platform: str = None):
        """Add or update a device entry. Thread-safe."""
        with self._lock:
            if hostname not in self._data["devices"]:
                self._data["devices"][hostname] = {
                    "hostname": hostname,
                    "mgmt_ip": mgmt_ip,
                    "device_type": device_type,
                    "device_category": device_category,
                    "platform": platform,
                    "collector_data": {},
                }
            else:
                dev = self._data["devices"][hostname]
                if mgmt_ip and not dev.get("mgmt_ip"):
                    dev["mgmt_ip"] = mgmt_ip
                if device_type and not dev.get("device_type"):
                    dev["device_type"] = device_type
                if device_category and not dev.get("device_category"):
                    dev["device_category"] = device_category
                if platform and not dev.get("platform"):
                    dev["platform"] = platform

    def set_collector_data(self, hostname: str, collector_name: str,
                           raw: dict, parsed: dict):
        """Store raw + parsed data for a collector on a device. Thread-safe."""
        with self._lock:
            if hostname not in self._data["devices"]:
                self._data["devices"][hostname] = {
                    "hostname": hostname,
                    "mgmt_ip": None,
                    "device_type": None,
                    "device_category": None,
                    "platform": None,
                    "collector_data": {},
                }
            self._data["devices"][hostname]["collector_data"][collector_name] = {
                "raw": raw,
                "parsed": parsed,
            }

    def to_dict(self) -> dict:
        """Return the full inventory as a plain dict."""
        return self._data

    def save(self, directory: str) -> str:
        """Save inventory to a JSON file atomically. Returns the filepath."""
        os.makedirs(directory, exist_ok=True)
        filename = f"{self._data['discovery_id']}.json"
        filepath = os.path.join(directory, filename)
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._data, f, indent=2, default=str)
            os.replace(tmp_path, filepath)
        except BaseException:
            os.unlink(tmp_path)
            raise
        return filepath
