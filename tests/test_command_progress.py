"""Each command sent during collection is reported as it runs, and anything
that went wrong with it is recorded."""
import logging
from unittest.mock import MagicMock, patch

import pytest

from app.asa_identity import ASA_PROBE
from app.command_issues import SLOW_AFTER, IssueLog
from app.command_progress import ProgressConnection
from app.connection_manager import ConnectionManager, ConnectionResult
from app.discovery_engine import DiscoveryEngine
from app.wlc_session import WlcReadTimeout


class Clock:
    def __init__(self, step):
        self.now = 0.0
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


def _wrapped(send, step=1.0, raw=None):
    events = []
    raw = raw or MagicMock()
    raw.send_command.side_effect = send
    issues = IssueLog()
    conn = ProgressConnection(raw, events.append, "192.0.2.10", "lab-sw-01", issues=issues,
                              clock=Clock(step))
    return conn, raw, events, issues


def _issues(events):
    return [(e["kind"], e["command"]) for e in events if e["event"] == "command_issue"]


def test_every_command_is_reported_with_a_running_count():
    conn, raw, events, issues = _wrapped(lambda cmd, **kw: cmd.upper())
    assert conn.send_command("show version", read_timeout=30) == "SHOW VERSION"
    conn.send_command("show inventory")
    assert [(e["event"], e["command"], e["count"]) for e in events] == [
        ("command_running", "show version", 1), ("command_running", "show inventory", 2)]
    assert events[0]["hostname"] == "lab-sw-01" and events[0]["ip"] == "192.0.2.10"
    raw.send_command.assert_any_call("show version", read_timeout=30)
    assert issues.entries() == []


def test_slow_commands_are_recorded(caplog):
    conn, _, events, issues = _wrapped(lambda cmd, **kw: "", step=SLOW_AFTER)
    with caplog.at_level(logging.INFO, logger="app.command_issues"):
        conn.send_command("show run-config commands")
    assert _issues(events) == [("slow", "show run-config commands")]
    assert issues.entries()[0]["seconds"] == SLOW_AFTER
    assert "collection issue [slow] lab-sw-01 (192.0.2.10) 'show run-config commands'" \
        in caplog.text


def test_quick_commands_are_not_slow():
    conn, _, events, _ = _wrapped(lambda cmd, **kw: "", step=1.0)
    conn.send_command("show clock")
    assert _issues(events) == []


def test_a_timeout_at_a_pager_is_recorded_and_still_raised(caplog):
    def send(cmd, **kw):
        raise WlcReadTimeout("no prompt after 120s waiting for output of show msglog; "
                             "last line: '--More-- or (q)uit'")
    conn, _, events, issues = _wrapped(send, step=60.0)
    with caplog.at_level(logging.WARNING, logger="app.command_issues"):
        with pytest.raises(WlcReadTimeout):
            conn.send_command("show msglog")
    entry = issues.entries()[0]
    assert entry["kind"] == "pager_stuck" and entry["severity"] == "error"
    assert entry["seconds"] == 60.0 and "(q)uit" in entry["detail"]
    assert "collection issue [pager_stuck] lab-sw-01 (192.0.2.10) 'show msglog' after 60.0s" \
        in caplog.text


def test_pager_text_left_in_output_is_recorded():
    conn, _, events, _ = _wrapped(lambda cmd, **kw: "line 1\n --More-- \nline 2")
    assert conn.send_command("show logging") == "line 1\n --More-- \nline 2"
    assert _issues(events) == [("pager_in_output", "show logging")]


def test_aireos_questions_answered_no_are_recorded():
    class Session:
        def __init__(self):
            self.notes = []

        def send_command(self, cmd, **kw):
            self.notes.append("Are you sure you want to proceed? (y/n)")
            return ""

        def take_notes(self):
            notes, self.notes = self.notes, []
            return notes

    events = []
    conn = ProgressConnection(Session(), events.append, "192.0.2.30", "lab-wlc-01",
                              clock=Clock(1.0))
    conn.send_command("show run-config commands")
    conn.send_command("show sysinfo")
    assert _issues(events) == [("unexpected_question", "show run-config commands"),
                               ("unexpected_question", "show sysinfo")]


def test_a_mock_connection_is_not_mistaken_for_a_session_with_notes():
    conn, _, events, _ = _wrapped(lambda cmd, **kw: "")
    conn.send_command("show clock")
    assert _issues(events) == []


def test_other_attributes_pass_through():
    conn, raw, _, _ = _wrapped(lambda cmd, **kw: "")
    raw.find_prompt.return_value = "lab-sw-01#"
    assert conn.find_prompt() == "lab-sw-01#"
    conn.disconnect()
    raw.disconnect.assert_called_once()


@pytest.fixture
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def test_scan_reports_commands_and_saves_issues(_no_snmp_network):
    events = []
    conn = MagicMock()
    conn.find_prompt.return_value = "lab-sw-01#"

    def send(cmd, **kw):
        if cmd == "show version":
            return ""
        if cmd == "show running-config":
            raise TimeoutError("Pattern not detected: 'lab-sw-01#' in output.")
        return "% Permission denied" if cmd == "show inventory" else ""
    conn.send_command.side_effect = send

    def connect(self):
        self.effective_device_type = self.device_type
        self.credential = self.credentials[0]
        return ConnectionResult(connection=conn, protocol_used="ssh", fallback_occurred=False)

    engine = DiscoveryEngine(
        seed_ip="192.0.2.10", seed_device_type="cisco_ios", username="admin",
        password="admin", max_depth=0, protocol="ssh", inventory_dir=None, max_workers=1,
        progress_callback=events.append)
    with patch.object(ConnectionManager, "connect", autospec=True, side_effect=connect):
        inventory = engine.discover()
    running = [e for e in events if e["event"] == "command_running"]
    assert [e["count"] for e in running] == list(range(1, len(running) + 1))
    # The probe after login is reported under the address; the rest under the name.
    assert (running[0]["command"], running[0]["hostname"]) == (ASA_PROBE, "192.0.2.10")
    split = next(n for n, e in enumerate(events) if e["event"] == "collecting_data")
    before = [e for e in events[:split] if e["event"] == "command_running"]
    after = [e for e in events[split:] if e["event"] == "command_running"]
    assert all(e["hostname"] == "192.0.2.10" for e in before)
    assert after and all(e["hostname"] == "lab-sw-01" for e in after)

    summary = inventory.to_dict()["scan_summary"]
    kinds = {(i["kind"], i["command"]) for i in summary["command_issues"]}
    assert ("timeout", "show running-config") in kinds
    assert ("unauthorized", "show inventory") in kinds
    assert summary["command_issue_counts"]["timeout"] >= 1
