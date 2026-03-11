import threading
from unittest.mock import patch
from app.discovery_engine import DiscoveryEngine


def test_progress_callback_receives_events():
    """Engine with progress_callback should emit events."""
    events = []
    def cb(event):
        events.append(event)

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_ios",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="ssh",
        inventory_dir=None,
        max_workers=1,
        progress_callback=cb,
    )

    with patch.object(engine, '_discover_device', return_value=[]):
        engine.discover()

    event_types = [e["event"] for e in events]
    assert "scan_started" in event_types
    assert "device_connecting" in event_types
    assert "scan_complete" in event_types


def test_cancelled_stops_new_devices():
    """Engine should stop processing when cancelled is set."""
    events = []
    cancelled = threading.Event()

    def cb(event):
        events.append(event)
        if event.get("event") == "device_connecting":
            cancelled.set()

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_ios",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="ssh",
        inventory_dir=None,
        max_workers=1,
        progress_callback=cb,
        cancelled=cancelled,
        target_hosts=[("192.168.1.1", "cisco_ios"), ("192.168.1.2", "cisco_ios"), ("192.168.1.3", "cisco_ios")],
    )

    with patch.object(engine, '_discover_device', return_value=[]):
        engine.discover()

    event_types = [e["event"] for e in events]
    assert "scan_cancelled" in event_types


def test_no_callback_still_works():
    """Engine without progress_callback should work as before."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_ios",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="ssh",
        inventory_dir=None,
        max_workers=1,
    )

    with patch.object(engine, '_discover_device', return_value=[]):
        inventory = engine.discover()

    assert inventory is not None


def test_verbose_events_emitted():
    """New verbose events should fire during device discovery."""
    events = []
    def cb(event):
        events.append(event)

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_ios",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="ssh",
        inventory_dir=None,
        max_workers=1,
        progress_callback=cb,
    )

    from app.connection_manager import ConnectionResult
    from unittest.mock import MagicMock

    mock_conn = MagicMock()
    mock_conn.find_prompt.return_value = "CORE-SW-01#"
    mock_conn.send_command.return_value = ""

    mock_result = ConnectionResult(connection=mock_conn, protocol_used="ssh", fallback_occurred=False)

    with patch('app.connection_manager.ConnectionManager.connect', return_value=mock_result):
        engine.discover()

    event_types = [e["event"] for e in events]
    assert "device_authenticated" in event_types
    assert "collecting_data" in event_types
    assert "neighbors_found" in event_types
    assert "device_complete" in event_types
    assert "scan_complete" in event_types

    auth = [e for e in events if e["event"] == "device_authenticated"][0]
    assert auth["protocol"] == "ssh"

    complete = [e for e in events if e["event"] == "device_complete"][0]
    assert complete["hostname"] == "CORE-SW-01"

    scan_done = [e for e in events if e["event"] == "scan_complete"][0]
    assert "inventory_key" in scan_done


def test_duplicate_hostname_skipped():
    """Device reachable via multiple IPs should only be collected once."""
    events = []
    def cb(event):
        events.append(event)

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_ios",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="ssh",
        inventory_dir=None,
        max_workers=1,
        progress_callback=cb,
        target_hosts=[
            ("192.168.1.1", "cisco_ios"),
            ("10.0.0.1", "cisco_ios"),
        ],
    )

    from app.connection_manager import ConnectionResult
    from unittest.mock import MagicMock

    mock_conn = MagicMock()
    mock_conn.find_prompt.return_value = "CORE-SW-01#"
    mock_conn.send_command.return_value = ""

    mock_result = ConnectionResult(connection=mock_conn, protocol_used="ssh", fallback_occurred=False)

    with patch('app.connection_manager.ConnectionManager.connect', return_value=mock_result):
        engine.discover()

    complete_events = [e for e in events if e["event"] == "device_complete"]
    assert len(complete_events) == 2

    # First should be a real discovery, second should be skipped
    assert complete_events[0].get("skipped") is None or complete_events[0].get("skipped") is False
    assert complete_events[1]["skipped"] is True
    assert complete_events[1]["reason"] == "duplicate hostname"
    assert complete_events[1]["hostname"] == "CORE-SW-01"


def test_connection_fallback_event():
    """connection_fallback should fire before device_authenticated when fallback occurs."""
    events = []
    def cb(event):
        events.append(event)

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_ios",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="auto",
        inventory_dir=None,
        max_workers=1,
        progress_callback=cb,
    )

    from app.connection_manager import ConnectionResult
    from unittest.mock import MagicMock

    mock_conn = MagicMock()
    mock_conn.find_prompt.return_value = "SW-01#"
    mock_conn.send_command.return_value = ""

    mock_result = ConnectionResult(connection=mock_conn, protocol_used="telnet", fallback_occurred=True)

    with patch('app.connection_manager.ConnectionManager.connect', return_value=mock_result):
        engine.discover()

    event_types = [e["event"] for e in events]
    assert "connection_fallback" in event_types
    assert "device_authenticated" in event_types

    fb_idx = event_types.index("connection_fallback")
    auth_idx = event_types.index("device_authenticated")
    assert fb_idx < auth_idx
