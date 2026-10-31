import io
import json

import pytest
from openpyxl import load_workbook

from app.collectors.environment import EnvironmentCollector
from app.collectors.interface_counters import InterfaceCountersCollector
from app.reports import get_report
from app.reports.findings import CRITICAL, WARNING, INFO, DETAIL_SHEET
from app.reports.platform_health import (
    PlatformHealthReport, analyze, stack_degraded, interface_issues,
)


def _intf(name, **counters):
    row = {"interface": name, "status": "up", "protocol": "up", "description": "",
           "input_packets": 1000000, "output_packets": 1000000, "input_errors": 0,
           "crc": 0, "frame": 0, "runts": 0, "giants": 0, "output_errors": 0,
           "collisions": 0, "interface_resets": 0, "output_drops": 0,
           "input_drops": 0, "last_input": "00:00:01", "last_output": "00:00:00",
           "counters_cleared": "never", "last_flap": ""}
    row.update(counters)
    return row


def _device(hostname, **collectors):
    return {"hostname": hostname, "mgmt_ip": "192.0.2.10",
            "collector_data": {k: {"raw": {}, "parsed": v} for k, v in collectors.items()}}


HEALTHY = _device(
    "lab-sw-01",
    environment={"items": [{"component": "fan", "name": "Switch 1 FAN 1",
                            "status": "OK", "reading": "", "state": "ok"}],
                 "faults": [],
                 "power_inline": {"budgets": [{"module": "", "available_w": 370.0,
                                               "used_w": 20.0, "remaining_w": 350.0}],
                                  "ports_by_state": {"on": 2}, "problem_ports": []}},
    redundancy={"redundancy": {"hardware_mode": "Simplex", "configured_mode": "sso",
                               "operating_mode": "Non-redundant", "peer_state": "Empty",
                               "switchovers": "0"},
                "stack_ports": [{"switch": "1", "port1": "DOWN", "port2": "DOWN"}],
                "stack_ring": {"speed": "480G", "configuration": "Half"}},
    mgmt_security={"ssh": {"enabled": True, "version": "2.0", "v1_enabled": False,
                           "key_bits": 2048, "min_dh_bits": 2048},
                   "smart_install": {"smart_install_enabled": False, "role": "Client"}},
    cpu_memory={"cpu": {"cpu_5s": 4, "cpu_1m": 3, "cpu_5m": 3},
                "memory": {"pools": [{"pool": "Processor", "total": 100, "used": 40,
                                      "free": 60, "used_pct": 40.0}],
                           "top_processes": [{"pid": "0", "holding": 30,
                                              "process": "*Init*"}]}},
    interface_counters={"interfaces": [_intf("GigabitEthernet1/0/1")]},
)

UNHEALTHY = _device(
    "lab-sw-02",
    environment={"items": [], "faults": [
        {"component": "fan", "name": "Switch 1 FAN 2", "status": "NOT OK",
         "reading": "", "state": "fault"},
        {"component": "temperature", "name": "System", "status": "RED",
         "reading": "", "state": "fault"}],
        "power_inline": {"budgets": [{"module": "1", "available_w": 370.0,
                                      "used_w": 362.5, "remaining_w": 7.5}],
                         "ports_by_state": {"on": 20, "power-deny": 1},
                         "problem_ports": [{"interface": "Gi1/0/4", "oper": "power-deny"}]}},
    redundancy={"redundancy": {"hardware_mode": "Duplex", "configured_mode": "sso",
                               "operating_mode": "rpr", "peer_state": "STANDBY COLD",
                               "switchovers": "2",
                               "last_switchover_reason": "active unit removed"},
                "stack_ports": [{"switch": "1", "port1": "OK", "port2": "DOWN"},
                                {"switch": "2", "port1": "OK", "port2": "OK"}],
                "stack_ring": {"speed": "240G", "configuration": "Half"}},
    mgmt_security={"ssh": {"enabled": True, "version": "1.99", "v1_enabled": True,
                           "key_bits": 1024, "min_dh_bits": 1024},
                   "smart_install": {"smart_install_enabled": True, "role": "Client"}},
    cpu_memory={"cpu": {"cpu_5s": 90, "cpu_1m": 88, "cpu_5m": 85},
                "memory": {"pools": [{"pool": "Processor", "total": 100, "used": 95,
                                      "free": 5, "used_pct": 95.0}],
                           "top_processes": []}},
    interface_counters={"interfaces": [
        _intf("GigabitEthernet1/0/1", crc=500, input_errors=520),
        _intf("GigabitEthernet1/0/2", output_drops=5000),
        _intf("GigabitEthernet1/0/3", crc=3),
    ]},
)


def _inventory(*devices):
    return {"devices": {d["hostname"]: d for d in devices}}


def _types(findings, hostname=None):
    return {(f["type"], f["severity"]) for f in findings
            if hostname is None or f["hostname"] == hostname}


def test_registered():
    assert isinstance(get_report("platform_health"), PlatformHealthReport)


def test_can_generate_needs_any_health_collector():
    report = PlatformHealthReport()
    assert report.can_generate(_inventory(HEALTHY))
    assert not report.can_generate(_inventory(_device("lab-rtr-01", arp={"entries": []})))
    only_env = _device("lab-sw-03", environment={"items": [], "faults": []})
    assert report.can_generate(_inventory(only_env))


def test_healthy_device_has_no_findings():
    # A standalone switch reports its stack ports DOWN and a Half ring;
    # that is not a degraded stack.
    assert analyze(_inventory(HEALTHY))["findings"] == []


def test_unhealthy_device_findings():
    findings = analyze(_inventory(UNHEALTHY))["findings"]
    assert _types(findings) == {
        ("env:fan", WARNING),
        ("env:temperature", CRITICAL),
        ("poe:problem_ports", WARNING),
        ("poe:budget", WARNING),
        ("redundancy:peer_state", WARNING),
        ("redundancy:mode_mismatch", WARNING),
        ("redundancy:switchover", INFO),
        ("stack:ring", WARNING),
        ("ssh:v1", WARNING),
        ("ssh:key_size", WARNING),
        ("smart_install", CRITICAL),
        ("cpu:high", WARNING),
        ("memory:high", WARNING),
        ("interface:crc", WARNING),
        ("interface:output_drops", INFO),
    }
    crc = [f for f in findings if f["type"] == "interface:crc"]
    assert [f["interface"] for f in crc] == ["GigabitEthernet1/0/1"]


def test_ssh_v1_only_is_critical():
    dev = _device("lab-sw-04", mgmt_security={
        "ssh": {"enabled": True, "version": "1.5", "v1_enabled": True,
                "key_bits": 2048}, "smart_install": {}})
    assert _types(analyze(_inventory(dev))["findings"]) == {("ssh:v1", CRITICAL)}


def test_ssh_disabled():
    dev = _device("lab-sw-05", mgmt_security={
        "ssh": {"enabled": False, "version": "", "v1_enabled": False,
                "key_bits": None}, "smart_install": {}})
    assert _types(analyze(_inventory(dev))["findings"]) == {("ssh:disabled", WARNING)}


def test_nxos_standby_supervisor_is_healthy():
    ok = _device("lab-nx-01", redundancy={
        "redundancy": {"configured_mode": "HA", "operating_mode": "HA",
                       "active_state": "Active", "peer_state": "Standby"}})
    bad = _device("lab-nx-02", redundancy={
        "redundancy": {"configured_mode": "HA", "operating_mode": "None",
                       "active_state": "Active", "peer_state": "Offline"}})
    single = _device("lab-nx-03", redundancy={
        "redundancy": {"configured_mode": "HA", "operating_mode": "None",
                       "active_state": "Active", "peer_state": "Not present"}})
    findings = analyze(_inventory(ok, bad, single))["findings"]
    assert _types(findings) == {("redundancy:peer_state", WARNING)}
    assert {f["hostname"] for f in findings} == {"lab-nx-02"}


def test_stack_degraded():
    assert stack_degraded([{"switch": "1", "port1": "DOWN", "port2": "DOWN"}],
                          {"configuration": "Half"}) == []
    issues = stack_degraded([{"switch": "1", "port1": "OK", "port2": "OK"},
                             {"switch": "2", "port1": "OK", "port2": "OK"}],
                            {"configuration": "Full"})
    assert issues == []


def test_interface_thresholds():
    assert interface_issues(_intf("Gi1", crc=100, input_packets=1000000)) == (True, False)
    assert interface_issues(_intf("Gi1", crc=99, input_packets=1000000)) == (False, False)
    assert interface_issues(_intf("Gi1", crc=20000, input_packets=None)) == (True, False)
    assert interface_issues(_intf("Gi1", output_drops=999, output_packets=1000)) == (False, False)
    assert interface_issues(_intf("Gi1", output_drops=1000, output_packets=1000000)) == (False, True)


def test_xlsx_sheets():
    data = PlatformHealthReport().generate(_inventory(HEALTHY, UNHEALTHY), "xlsx")
    wb = load_workbook(io.BytesIO(data))
    assert wb.sheetnames == ["Summary", "Findings", DETAIL_SHEET, "Environment",
                             "PoE Budget", "Redundancy & Stack", "Management Plane",
                             "CPU & Memory", "Interface Health"]
    ih = wb["Interface Health"]
    headers = [c.value for c in ih[1]]
    rows = [dict(zip(headers, [c.value for c in r])) for r in ih.iter_rows(min_row=2)]
    assert len(rows) == 4
    flagged = {(r["Device"], r["Interface"]): r["Flagged"] for r in rows}
    assert flagged[("lab-sw-02", "GigabitEthernet1/0/1")] == "CRC"
    assert flagged[("lab-sw-02", "GigabitEthernet1/0/2")] == "Drops"
    mgmt = wb["Management Plane"]
    mrows = {r[0].value: [c.value for c in r] for r in mgmt.iter_rows(min_row=2)}
    assert mrows["lab-sw-02"][3] == "Yes"
    assert mrows["lab-sw-02"][4] == 1024
    assert mrows["lab-sw-02"][7] == "Yes"


def test_json_export_from_collector_output():
    """End to end: parse real-shaped output, then report on it."""
    env = EnvironmentCollector().parse({
        "show environment all": "Switch 1 FAN 1 is OK\nSwitch 1 FAN 2 is NOT OK\n",
        "show power inline": "Available:370.0(w)  Used:12.0(w)  Remaining:358.0(w)\n",
    }, "cisco_ios")
    counters = InterfaceCountersCollector().parse({"show interfaces": (
        "GigabitEthernet0/1 is up, line protocol is up (connected)\n"
        "     500000 packets input, 1 bytes, 0 no buffer\n"
        "     90 input errors, 90 CRC, 0 frame, 0 overrun, 0 ignored\n"
        "     10 packets output, 1 bytes, 0 underruns\n")}, "cisco_ios")
    inv = _inventory(_device("lab-sw-06", environment=env, interface_counters=counters))
    out = json.loads(PlatformHealthReport().generate(inv, "json"))
    assert {r["Finding"] for r in out["Findings"]} == {"Environmental fault: fan",
                                                       "Interface CRC errors"}
    assert out["PoE Budget"][0]["Used %"] == 3.2


def test_tolerates_failed_and_not_applicable_collectors():
    dev = _device("lab-sw-07",
                  environment={"not_applicable": True, "reason": "x"},
                  cpu_memory={"collector_failed": True, "collector_error": "timeout"},
                  interface_counters={})
    inv = _inventory(dev)
    assert analyze(inv)["findings"] == []
    PlatformHealthReport().generate(inv, "xlsx")


@pytest.mark.parametrize("fmt", ["csv", "xml"])
def test_other_formats(fmt):
    assert PlatformHealthReport().generate(_inventory(UNHEALTHY), fmt)
