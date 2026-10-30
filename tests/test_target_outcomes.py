"""Every requested target ends the run with an explicit outcome."""
import socket
import threading

import pytest

import app.connection_manager as cmod
from app import target_outcomes as to
from app.discovery_engine import DiscoveryEngine
from app.inventory import DiscoveryInventory
from app.reports.device_inventory import (DeviceInventoryReport,
                                          extract_targets_data)


# --- pure reconciliation ----------------------------------------------------

def test_target_list_adds_address_lines_and_unresolved_names():
    resolution = {
        "targets": [{"input": "sw1.example.com", "resolved_ip": "192.0.2.1"}],
        "unresolved": [{"input": "gone.example.com", "error": "not found"}],
    }
    hosts = [("192.0.2.1", None), ("192.0.2.2", "cisco_ios")]
    targets = to.target_list(resolution, hosts)
    assert targets == [
        {"input": "sw1.example.com", "resolved_ip": "192.0.2.1"},
        {"input": "192.0.2.2", "resolved_ip": "192.0.2.2"},
        {"input": "gone.example.com", "resolved_ip": None, "error": "not found"},
    ]


def test_reconcile_assigns_each_outcome():
    targets = [
        {"input": "a", "resolved_ip": "192.0.2.1"},
        {"input": "b", "resolved_ip": "192.0.2.2"},
        {"input": "c", "resolved_ip": "192.0.2.3"},
        {"input": "d", "resolved_ip": "192.0.2.4"},
        {"input": "e", "resolved_ip": None, "error": "not found"},
        {"input": "f", "resolved_ip": "192.0.2.6"},
    ]
    devices = {"SW1": {"mgmt_ip": "192.0.2.1"}}
    out = to.reconcile(
        targets, devices,
        collected={"192.0.2.1": {"hostname": "SW1", "serial": None}},
        merged={"192.0.2.2": "SW1"},
        failed={"192.0.2.3": {"hostname": None, "reason": "timeout"}},
        skipped={"192.0.2.4": {"hostname": "LEAF1", "reason": "controller_managed"}},
        cancelled=True)
    got = {t["input"]: t for t in out}
    assert got["a"]["outcome"] == "collected" and got["a"]["hostname"] == "SW1"
    assert got["b"]["outcome"] == "merged_into" and got["b"]["hostname"] == "SW1"
    assert got["c"]["outcome"] == "failed" and got["c"]["reason"] == "timeout"
    assert got["d"]["outcome"] == "skipped"
    assert got["d"]["reason"] == "controller_managed"
    assert got["e"]["outcome"] == "unresolved"
    assert "error" not in got["e"]
    assert got["f"] == {"input": "f", "resolved_ip": "192.0.2.6",
                        "outcome": "not_attempted", "reason": "scan cancelled"}


def test_collected_record_folded_away_reads_as_merged():
    """Duplicate folding at the end of a run can absorb a collected record
    into another one with the same serial."""
    devices = {"SW1": {"mgmt_ip": "192.0.2.1", "serial": "SER0001"}}
    out = to.reconcile(
        [{"input": "192.0.2.9", "resolved_ip": "192.0.2.9"}], devices,
        collected={"192.0.2.9": {"hostname": "SW1-ALT", "serial": "SER0001"}},
        merged={}, failed={}, skipped={})
    assert out[0]["outcome"] == "merged_into"
    assert out[0]["hostname"] == "SW1"


def test_prior_string_failure_still_reconciles():
    out = to.reconcile([{"input": "x", "resolved_ip": "192.0.2.5"}], {},
                       {}, {}, {"192.0.2.5": "timed out"}, {})
    assert out[0]["outcome"] == "failed"


def test_summary_line():
    targets = [{"outcome": "collected"}, {"outcome": "collected"},
               {"outcome": "merged_into"}, {"outcome": "failed"},
               {"outcome": "not_attempted"}]
    assert to.summary_line(targets) == (
        "Targets: 2 collected, 1 merged, 1 failed, 0 unresolved, "
        "1 not attempted")
    assert to.summary_line([]) is None


# --- a mixed fake run -------------------------------------------------------

class _FakeConn:
    def __init__(self, hostname):
        self.hostname = hostname

    def find_prompt(self):
        return self.hostname + "#"

    def send_command(self, cmd, **kwargs):
        return ""

    def disconnect(self):
        pass


# Two addresses on one chassis, one filtered address, one refused address.
_HOSTS = {"192.0.2.1": "SW1", "192.0.2.2": "SW1", "192.0.2.5": "RTR-A"}


def _fake_network(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)

    def connect(**params):
        host = params["host"]
        if host in _HOSTS:
            return _FakeConn(_HOSTS[host])
        if host == "192.0.2.4":
            raise ConnectionRefusedError(111, "Connection refused")
        raise socket.timeout("timed out")
    monkeypatch.setattr(cmod, "_connect_handler", connect)


def _controller_managed_base():
    base = DiscoveryInventory.create(seed_ip="192.0.2.1")
    base.add_device("LEAF1", mgmt_ip="192.0.2.40", platform="N9K-C93180YC-EX")
    base.set_controller_managed("LEAF1", "aci")
    return base


def test_every_target_gets_an_outcome_in_a_mixed_run(monkeypatch, tmp_path):
    _fake_network(monkeypatch)
    resolution = {
        "targets": [{"input": "sw1.example.com", "resolved_ip": "192.0.2.1"},
                    {"input": "sw1-alt.example.com", "resolved_ip": "192.0.2.2"},
                    {"input": "leaf1.example.com", "resolved_ip": "192.0.2.40"}],
        "unresolved": [{"input": "gone.example.com", "error": "not found"}],
    }
    hosts = [(ip, "cisco_ios") for ip in
             ("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
              "192.0.2.5", "192.0.2.40")]
    events = []
    engine = DiscoveryEngine(
        seed_ip="192.0.2.1", seed_device_type="cisco_ios",
        username="u", password="p", target_hosts=hosts,
        target_resolution=resolution, base_inventory=_controller_managed_base(),
        inventory_dir=str(tmp_path), max_workers=1,
        progress_callback=events.append)
    inv = engine.discover()
    summary = inv.to_dict()["scan_summary"]
    targets = summary["targets"]

    # The invariant: one entry per requested host, each with an outcome.
    assert len(targets) == len(hosts) + 1
    assert all(t.get("outcome") in to.OUTCOMES for t in targets)

    got = {t["input"]: t for t in targets}
    first, second = got["sw1.example.com"], got["sw1-alt.example.com"]
    # Whichever address logged in second is folded into the first.
    assert {first["outcome"], second["outcome"]} == {"collected", "merged_into"}
    assert first["hostname"] == second["hostname"] == "SW1"
    assert got["192.0.2.3"]["outcome"] == "failed"
    assert got["192.0.2.3"]["reason"] == "timeout"
    assert got["192.0.2.4"]["outcome"] == "failed"
    assert got["192.0.2.4"]["reason"] == "refused"
    assert got["192.0.2.5"] == {"input": "192.0.2.5", "resolved_ip": "192.0.2.5",
                                "outcome": "collected", "hostname": "RTR-A"}
    assert got["leaf1.example.com"]["outcome"] == "skipped"
    assert got["gone.example.com"]["outcome"] == "unresolved"

    assert summary["target_outcomes"]["collected"] == 2
    assert summary["target_outcomes"]["merged_into"] == 1
    done = [e for e in events if e["event"] == "scan_complete"][0]
    assert done["target_summary"] == (
        "Targets: 2 collected, 1 merged, 2 failed, 1 unresolved, 1 skipped")


def test_cancelled_run_marks_the_rest_not_attempted(monkeypatch, tmp_path):
    _fake_network(monkeypatch)
    cancelled = threading.Event()

    def on_event(event):
        if event["event"] == "device_connecting":
            cancelled.set()
    hosts = [("192.0.2.5", "cisco_ios"), ("192.0.2.6", "cisco_ios")]
    engine = DiscoveryEngine(
        seed_ip="192.0.2.5", seed_device_type="cisco_ios",
        username="u", password="p", target_hosts=hosts,
        inventory_dir=str(tmp_path), progress_callback=on_event,
        cancelled=cancelled)
    targets = engine.discover().to_dict()["scan_summary"]["targets"]
    got = {t["input"]: t for t in targets}
    assert got["192.0.2.5"]["outcome"] == "collected"
    assert got["192.0.2.6"]["outcome"] == "not_attempted"
    assert got["192.0.2.6"]["reason"] == "scan cancelled"


def test_discovery_scan_without_targets_records_none(tmp_path):
    engine = DiscoveryEngine(
        seed_ip="192.0.2.5", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0, inventory_dir=str(tmp_path))
    engine._discover_device = lambda *a, **k: []
    summary = engine.discover().to_dict()["scan_summary"]
    assert "targets" not in summary


# --- Targets sheet ----------------------------------------------------------

def _inventory_with_targets():
    return {
        "devices": {},
        "scan_summary": {"targets": [
            {"input": "sw1.example.com", "resolved_ip": "192.0.2.1",
             "outcome": "collected", "hostname": "SW1"},
            {"input": "192.0.2.3", "resolved_ip": "192.0.2.3",
             "outcome": "failed", "reason": "timeout"},
        ]},
    }


def test_targets_sheet_rows():
    headers, rows = extract_targets_data(_inventory_with_targets())
    assert headers[:3] == ["Target", "Resolved IP", "Outcome"]
    assert rows[0] == ["sw1.example.com", "192.0.2.1", "Collected", "SW1", ""]
    assert rows[1][2] == "Failed"
    assert rows[1][4] == "Timeout"


def test_targets_sheet_absent_without_outcomes():
    assert extract_targets_data({"scan_summary": {}}) is None
    old = {"scan_summary": {"targets": [{"input": "a", "resolved_ip": "192.0.2.1"}]}}
    assert extract_targets_data(old) is None


def test_targets_sheet_in_workbook():
    from io import BytesIO
    from openpyxl import load_workbook
    data = DeviceInventoryReport().generate(_inventory_with_targets(), "xlsx")
    assert "Targets" in load_workbook(BytesIO(data)).sheetnames
