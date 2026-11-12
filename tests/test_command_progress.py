"""Each command sent during collection is reported as it runs."""
import logging
from unittest.mock import MagicMock, patch

import pytest

from app.command_progress import SLOW_AFTER, ProgressConnection
from app.connection_manager import ConnectionManager, ConnectionResult
from app.discovery_engine import DiscoveryEngine


class Clock:
    def __init__(self, step):
        self.now = 0.0
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


def _wrapped(send, step=1.0):
    events = []
    raw = MagicMock()
    raw.send_command.side_effect = send
    conn = ProgressConnection(raw, events.append, "192.0.2.10", "lab-sw-01", clock=Clock(step))
    return conn, raw, events


def test_every_command_is_reported_with_a_running_count():
    conn, raw, events = _wrapped(lambda cmd, **kw: cmd.upper())
    assert conn.send_command("show version", read_timeout=30) == "SHOW VERSION"
    conn.send_command("show inventory")
    assert [(e["event"], e["command"], e["count"]) for e in events] == [
        ("command_running", "show version", 1), ("command_running", "show inventory", 2)]
    assert events[0]["hostname"] == "lab-sw-01" and events[0]["ip"] == "192.0.2.10"
    raw.send_command.assert_any_call("show version", read_timeout=30)


def test_slow_commands_are_reported_and_logged(caplog):
    conn, _, events = _wrapped(lambda cmd, **kw: "", step=SLOW_AFTER)
    with caplog.at_level(logging.INFO, logger="app.command_progress"):
        conn.send_command("show run-config commands")
    assert [e["event"] for e in events] == ["command_running", "command_slow"]
    assert events[1]["seconds"] == SLOW_AFTER
    assert f"lab-sw-01: 'show run-config commands' took {float(SLOW_AFTER)}s" in caplog.text


def test_quick_commands_are_not_slow():
    conn, _, events = _wrapped(lambda cmd, **kw: "", step=1.0)
    conn.send_command("show clock")
    assert [e["event"] for e in events] == ["command_running"]


def test_failures_are_reported_and_still_raised(caplog):
    def send(cmd, **kw):
        raise TimeoutError("no prompt after 120s; last line: 'Press Enter'")
    conn, _, events = _wrapped(send, step=60.0)
    with caplog.at_level(logging.WARNING, logger="app.command_progress"):
        with pytest.raises(TimeoutError):
            conn.send_command("show msglog")
    failed = events[-1]
    assert failed["event"] == "command_failed" and failed["seconds"] == 60.0
    assert "Press Enter" in failed["error"]
    assert "lab-sw-01: 'show msglog' failed after 60.0s" in caplog.text


def test_other_attributes_pass_through():
    conn, raw, _ = _wrapped(lambda cmd, **kw: "")
    raw.find_prompt.return_value = "lab-sw-01#"
    assert conn.find_prompt() == "lab-sw-01#"
    conn.disconnect()
    raw.disconnect.assert_called_once()


@pytest.fixture
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def test_scan_reports_collection_commands(_no_snmp_network):
    events = []
    conn = MagicMock()
    conn.find_prompt.return_value = "lab-sw-01#"
    conn.send_command.return_value = ""

    def connect(self):
        self.effective_device_type = self.device_type
        self.credential = self.credentials[0]
        return ConnectionResult(connection=conn, protocol_used="ssh", fallback_occurred=False)

    engine = DiscoveryEngine(
        seed_ip="192.0.2.10", seed_device_type="cisco_ios", username="admin",
        password="admin", max_depth=0, protocol="ssh", inventory_dir=None, max_workers=1,
        progress_callback=events.append)
    with patch.object(ConnectionManager, "connect", autospec=True, side_effect=connect):
        engine.discover()
    running = [e for e in events if e["event"] == "command_running"]
    assert running and all(e["hostname"] == "lab-sw-01" for e in running)
    assert [e["count"] for e in running] == list(range(1, len(running) + 1))
    names = [e["event"] for e in events]
    assert names.index("collecting_data") < names.index("command_running")
