"""
Manages background scan execution, event queues, and SSE streaming.
"""
import json
import logging
import threading
import time
import uuid
from queue import Queue, Empty

logger = logging.getLogger(__name__)

_SENTINEL = object()


class ScanManager:
    """In-memory singleton that tracks the active scan."""

    def __init__(self):
        self._scans = {}
        self._lock = threading.Lock()

    def start_scan(self, scan_type, target_fn):
        """Launch a scan in a background thread.

        Args:
            scan_type: "discovery" or "targeted"
            target_fn: callable(progress_cb, cancelled) that runs the scan.
                       Must call progress_cb with event dicts.
                       Must check cancelled threading.Event periodically.
                       Returns inventory or None.

        Returns:
            scan_id string, or None if a scan is already running.
        """
        with self._lock:
            if self.is_running():
                return None
            scan_id = uuid.uuid4().hex[:12]
            cancelled = threading.Event()
            events = Queue()
            scan = {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "status": "running",
                "cancelled": cancelled,
                "events": events,
                "start_time": time.time(),
                "inventory": None,
                "thread": None,
            }
            self._scans[scan_id] = scan

        def _run():
            def progress_cb(event_dict):
                events.put(event_dict)
            try:
                result = target_fn(progress_cb, cancelled)
                scan["inventory"] = result
                if scan["status"] == "running":
                    scan["status"] = "complete"
            except Exception as e:
                logger.exception("Scan %s failed", scan_id)
                events.put({"event": "scan_error", "error": str(e)})
                scan["status"] = "error"
            finally:
                events.put(_SENTINEL)

        t = threading.Thread(target=_run, daemon=True)
        scan["thread"] = t
        t.start()
        return scan_id

    def get_scan(self, scan_id):
        return self._scans.get(scan_id)

    def cancel_scan(self, scan_id):
        scan = self._scans.get(scan_id)
        if scan:
            scan["cancelled"].set()
            scan["status"] = "cancelled"

    def is_running(self):
        return any(s["status"] == "running" for s in self._scans.values())

    def event_stream(self, scan_id):
        """Yield SSE-formatted strings from the scan's event queue."""
        scan = self._scans.get(scan_id)
        if not scan:
            return
        events = scan["events"]
        while True:
            try:
                item = events.get(timeout=30)
            except Empty:
                yield ": keepalive\n\n"
                continue
            if item is _SENTINEL:
                break
            event_type = item.get("event", "message")
            data = json.dumps(item)
            yield f"event: {event_type}\ndata: {data}\n\n"
