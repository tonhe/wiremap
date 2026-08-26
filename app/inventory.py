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

    @staticmethod
    def _new_record(hostname, mgmt_ip=None, device_type=None,
                    device_category=None, platform=None,
                    discovery_source=None):
        """Build a device record.

        Both add_device and set_collector_data create records, so the shape
        lives here -- otherwise a device first seen by one path is missing
        fields the other path guarantees.
        """
        return {
            "hostname": hostname,
            "mgmt_ip": mgmt_ip,
            "device_type": device_type,
            "device_category": device_category,
            "platform": platform,
            "discovery_source": discovery_source,
            "login_succeeded": False,
            "login_error": None,
            "serial": None,
            "model": None,
            "software_version": None,
            "evidence": [],
            "collector_data": {},
        }

    def add_device(self, hostname: str, mgmt_ip: str = None,
                   device_type: str = None, device_category: str = None,
                   platform: str = None, discovery_source: str = None):
        """Add or update a device entry. Thread-safe."""
        with self._lock:
            if hostname not in self._data["devices"]:
                self._data["devices"][hostname] = self._new_record(
                    hostname, mgmt_ip, device_type, device_category,
                    platform, discovery_source)
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
                if discovery_source and not dev.get("discovery_source"):
                    dev["discovery_source"] = discovery_source

    def set_collector_data(self, hostname: str, collector_name: str,
                           raw: dict, parsed: dict):
        """Store raw + parsed data for a collector on a device. Thread-safe."""
        with self._lock:
            if hostname not in self._data["devices"]:
                self._data["devices"][hostname] = self._new_record(hostname)
            self._data["devices"][hostname]["collector_data"][collector_name] = {
                "raw": raw,
                "parsed": parsed,
            }

    def mark_login_succeeded(self, hostname, serial=None, model=None,
                             software_version=None, platform=None):
        """Promote a record to logged-in, keeping how it was first sighted.

        Collected data always beats neighbour-reported data, so supplied
        values overwrite rather than filling only empty fields.
        """
        with self._lock:
            dev = self._data["devices"].get(hostname)
            if dev is None:
                return
            dev["login_succeeded"] = True
            dev["login_error"] = None
            if not dev.get("discovery_source"):
                dev["discovery_source"] = "login"
            for field, value in (("serial", serial), ("model", model),
                                 ("software_version", software_version),
                                 ("platform", platform)):
                if value:
                    dev[field] = value

    def mark_login_failed(self, hostname, error):
        with self._lock:
            dev = self._data["devices"].get(hostname)
            if dev is None:
                return
            dev["login_succeeded"] = False
            dev["login_error"] = error

    def mark_login_failed_by_ip(self, ip, error):
        """Record a login failure against whichever record holds this IP."""
        with self._lock:
            for dev in self._data["devices"].values():
                if dev.get("mgmt_ip") == ip:
                    dev["login_succeeded"] = False
                    dev["login_error"] = error
                    return

    def add_evidence(self, hostname, source, seen_from, remote_port=None):
        """Record that seen_from saw this device via source."""
        with self._lock:
            dev = self._data["devices"].get(hostname)
            if dev is None:
                return
            dev.setdefault("evidence", []).append({
                "source": source,
                "seen_from": seen_from,
                "remote_port": remote_port,
            })

    def set_chassis_id(self, hostname, chassis_id):
        with self._lock:
            dev = self._data["devices"].get(hostname)
            if dev is not None:
                dev["remote_chassis_id"] = chassis_id

    def add_unresolved_neighbour(self, seen_from, neighbor):
        """Record a neighbour sighting too thin to be a device.

        An address with no name is not a chassis -- vPC peer-keepalive
        addresses repeat across every pair in a fabric, and creating a device
        per address invents phantom hardware.
        """
        with self._lock:
            dev = self._data["devices"].get(seen_from)
            if dev is None:
                return
            dev.setdefault("unresolved_neighbours", []).append({
                "remote_ip": neighbor.get("remote_ip"),
                "remote_port": neighbor.get("remote_port"),
                "source": neighbor.get("source", "cdp"),
            })

    def merge_duplicates(self) -> int:
        """Fold records that resolve to the same chassis. Returns count merged.

        The same device arrives as SW1 from its own prompt and SW1(FOC1234)
        from a neighbour's CDP table. Devices with different serials never
        merge even when their normalized hostnames collide, because the serial
        key takes precedence over the hostname key.
        """
        from app.identity import normalize_hostname

        with self._lock:
            devices = self._data["devices"]
            merged = 0

            def fold(names):
                """Merge names into the best record. Returns count removed."""
                # Prefer the logged-in record, then the one with most data.
                names.sort(key=lambda n: (
                    not devices[n].get("login_succeeded"),
                    -len(devices[n].get("collector_data", {})),
                ))
                target = devices[names[0]]
                removed = 0
                for loser in names[1:]:
                    source = devices.pop(loser)
                    for field, value in source.items():
                        if field in ("hostname", "collector_data", "evidence"):
                            continue
                        if not target.get(field) and value:
                            target[field] = value
                    target.setdefault("evidence", []).extend(
                        source.get("evidence", []))
                    for cname, cdata in source.get("collector_data", {}).items():
                        target.setdefault("collector_data", {}).setdefault(
                            cname, cdata)
                    removed += 1
                return removed

            # Pass 1: same normalized hostname. A neighbour-derived record has
            # no serial, so grouping by serial first would never pair it with
            # its logged-in twin. Conflicting serials mean genuinely different
            # chassis that happen to share a name -- leave those alone.
            by_host = {}
            for hostname in list(devices):
                by_host.setdefault(
                    normalize_hostname(hostname), []).append(hostname)

            for names in by_host.values():
                if len(names) < 2:
                    continue
                distinct = {(devices[n].get("serial") or "").strip()
                            for n in names}
                distinct.discard("")
                if len(distinct) > 1:
                    continue
                merged += fold(names)

            # Pass 2: same serial under different names -- one chassis that
            # reported itself differently to different sources.
            by_serial = {}
            for hostname in list(devices):
                serial = (devices[hostname].get("serial") or "").strip()
                if serial:
                    by_serial.setdefault(serial, []).append(hostname)

            for names in by_serial.values():
                if len(names) > 1:
                    merged += fold(names)

            return merged

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
