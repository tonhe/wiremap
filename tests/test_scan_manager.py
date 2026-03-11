import threading
import time
import json
from app.scan_manager import ScanManager


def test_start_scan_returns_scan_id():
    mgr = ScanManager()
    scan_id = mgr.start_scan("discovery", _dummy_target)
    assert scan_id is not None
    assert mgr.is_running()
    mgr.cancel_scan(scan_id)
    time.sleep(0.2)


def test_reject_second_scan():
    mgr = ScanManager()
    scan_id = mgr.start_scan("discovery", _dummy_target)
    assert mgr.start_scan("discovery", _dummy_target) is None
    mgr.cancel_scan(scan_id)
    time.sleep(0.2)


def test_event_stream():
    mgr = ScanManager()
    scan_id = mgr.start_scan("discovery", _dummy_quick_target)
    time.sleep(0.5)
    events = []
    for raw in mgr.event_stream(scan_id):
        events.append(raw)
        parsed = json.loads(raw.split("data: ")[1])
        if parsed.get("event") in ("scan_complete", "scan_error"):
            break
    assert len(events) >= 1


def test_cancel_scan():
    mgr = ScanManager()
    scan_id = mgr.start_scan("discovery", _slow_target)
    time.sleep(0.1)
    mgr.cancel_scan(scan_id)
    scan = mgr.get_scan(scan_id)
    assert scan["cancelled"].is_set()
    time.sleep(0.5)


def test_get_scan_returns_none_for_unknown():
    mgr = ScanManager()
    assert mgr.get_scan("nonexistent") is None


# -- helpers --

def _dummy_target(progress_cb, cancelled):
    """Runs until cancelled -- used when we need the scan to stay 'running'."""
    progress_cb({"event": "scan_started", "scan_type": "discovery"})
    for _ in range(50):
        if cancelled.is_set():
            progress_cb({"event": "scan_cancelled", "total_devices": 0, "failed_count": 0, "elapsed": 0.1})
            return None
        time.sleep(0.1)
    progress_cb({"event": "scan_complete", "total_devices": 0, "failed_count": 0, "elapsed": 5.0})
    return None


def _dummy_quick_target(progress_cb, cancelled):
    progress_cb({"event": "scan_started", "scan_type": "discovery"})
    time.sleep(0.1)
    progress_cb({"event": "scan_complete", "total_devices": 0, "failed_count": 0, "elapsed": 0.1})
    return None


def _slow_target(progress_cb, cancelled):
    progress_cb({"event": "scan_started", "scan_type": "discovery"})
    for i in range(50):
        if cancelled.is_set():
            progress_cb({"event": "scan_cancelled", "total_devices": 0, "failed_count": 0, "elapsed": 0.1})
            return None
        time.sleep(0.1)
    progress_cb({"event": "scan_complete", "total_devices": 0, "failed_count": 0, "elapsed": 5.0})
    return None
