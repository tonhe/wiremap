"""Collection Issues report sheets."""
import io
import json

import openpyxl

from app.reports import get_report
from app.reports import collection_issues as rep

INVENTORY = {
    "timestamp": "2026-11-12T10:00:00Z",
    "devices": {
        "lab-wlc-01": {"reached_ip": "192.0.2.30", "collector_data": {
            "wlc": {"raw": {
                "show sysinfo": "System Name.... lab-wlc-01",
                "show mesh summary": "Incorrect usage. Use the '?' or <TAB> key to list commands.",
                "show msglog": "%% command not completed (WlcReadTimeout: no prompt after 120s)",
            }},
            "config": {"raw": {
                "show msglog": "%% command not completed (WlcReadTimeout: no prompt after 120s)",
            }},
        }},
        "lab-sw-01": {"mgmt_ip": "192.0.2.10", "collector_data": {
            "inventory": {"raw": {"show inventory": "% Permission denied"}},
        }},
    },
    "scan_summary": {
        "command_issues": [
            {"time": "2026-11-12T10:01:00Z", "hostname": "lab-wlc-01", "ip": "192.0.2.30",
             "command": "show msglog", "kind": "pager_stuck", "severity": "error",
             "seconds": 120.0, "detail": "WlcReadTimeout: ... last line: '--More--'"},
            {"time": "2026-11-12T10:03:00Z", "hostname": "lab-wlc-01", "ip": "192.0.2.30",
             "command": "show traplog", "kind": "pager_stuck", "severity": "error",
             "seconds": 120.0, "detail": "..."},
            {"time": "2026-11-12T10:04:00Z", "hostname": "lab-sw-01", "ip": "192.0.2.10",
             "command": "show tech", "kind": "slow", "severity": "info",
             "seconds": 45.0, "detail": "took 45.0s"},
        ],
        "failed": {"192.0.2.99": {"hostname": "lab-sw-09", "reason": "auth",
                                  "message": "Authentication failed"}},
    },
}


def _rows(sheet, data=INVENTORY):
    headers, rows = rep.build_tabular(data)[sheet]
    return [dict(zip(headers, r)) for r in rows]


def test_sheets():
    assert list(rep.build_tabular(INVENTORY)) == [
        "Summary", "Command Issues", "Refused Commands", "Device Failures"]


def test_summary_counts_by_severity_then_size():
    rows = _rows("Summary")
    assert [(r["Item"], r["Count"]) for r in rows[:2]] == [("pager_stuck", 2), ("slow", 1)]
    assert rows[0]["Severity"] == "error" and "pager" in rows[0]["Meaning"]
    items = {r["Item"]: r["Count"] for r in rows}
    assert items["refused commands (not applicable)"] == 1
    assert items["refused commands (unauthorized)"] == 1
    assert items["refused commands (failed)"] == 1
    assert items["devices not logged into"] == 1


def test_command_issues_listed_as_recorded():
    rows = _rows("Command Issues")
    assert len(rows) == 3
    assert rows[0]["Device"] == "lab-wlc-01" and rows[0]["Kind"] == "pager_stuck"
    assert rows[0]["Seconds"] == 120.0


def test_refused_commands_read_from_saved_outputs_once_per_device():
    rows = _rows("Refused Commands")
    keys = [(r["Device"], r["Command"], r["Kind"]) for r in rows]
    assert keys == [
        ("lab-sw-01", "show inventory", "unauthorized"),
        ("lab-wlc-01", "show msglog", "failed"),
        ("lab-wlc-01", "show mesh summary", "not applicable"),
    ]
    assert rows[0]["IP"] == "192.0.2.10" and rows[1]["Collector"] == "config"


def test_device_failures():
    rows = _rows("Device Failures")
    assert rows == [{"IP": "192.0.2.99", "Device": "lab-sw-09", "Reason": "auth",
                     "Hint": rows[0]["Hint"], "Message": "Authentication failed"}]


def test_old_scan_without_recorded_issues():
    old = {"devices": INVENTORY["devices"]}
    assert _rows("Command Issues", old) == []
    assert len(_rows("Refused Commands", old)) == 3
    assert _rows("Device Failures", old) == []


def test_registered_and_renders_every_format():
    report = get_report("collection_issues")
    assert report.can_generate(INVENTORY)
    assert not report.can_generate({"devices": {}})
    wb = openpyxl.load_workbook(io.BytesIO(report.generate(INVENTORY, "xlsx")))
    assert wb.sheetnames == ["Summary", "Command Issues", "Refused Commands", "Device Failures"]
    assert "Command Issues" in json.loads(report.generate(INVENTORY, "json"))
    assert b"--- Sheet: Refused Commands ---" in report.generate(INVENTORY, "csv")
