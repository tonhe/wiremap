"""Failed Devices and controller-managed sheets in the device inventory."""
import io
import json

from openpyxl import load_workbook

from app.reports.device_inventory import (DeviceInventoryReport,
                                          extract_failed_devices_data,
                                          extract_skipped_devices_data)


def _inventory():
    return {
        "devices": {
            "core1": {"hostname": "core1", "mgmt_ip": "192.0.2.1",
                      "login_succeeded": True, "collector_data": {
                          "device_inventory": {"parsed": {}}}},
            "dist7": {"hostname": "dist7", "mgmt_ip": "192.0.2.7",
                      "platform": "cisco WS-C3850-48P",
                      "login_succeeded": False, "collector_data": {}},
            "leaf101(FDO12345ABC)": {
                "hostname": "leaf101(FDO12345ABC)", "mgmt_ip": "192.0.2.101",
                "platform": "N9K-C93180YC-EX", "managed_by": "aci",
                "login_succeeded": False, "collector_data": {}},
        },
        "scan_summary": {
            "failed": {
                "192.0.2.7": {
                    "hostname": "dist7", "reason": "refused",
                    "hint": "TCP port 22 refused by host (likely vty access-class)",
                    "message": "Connection failed to 192.0.2.7",
                    "attempts": [
                        {"protocol": "ssh", "port": 22, "device_type": "cisco_ios",
                         "exception_class": "NetmikoTimeoutException",
                         "message": "TCP connection to device failed.",
                         "elapsed_ms": 12, "reason": "refused"},
                        {"protocol": "telnet", "port": 23,
                         "device_type": "cisco_ios_telnet",
                         "exception_class": "ConnectionRefusedError",
                         "message": "[Errno 111] Connection refused",
                         "elapsed_ms": 3, "reason": "refused"},
                    ]},
                # Saved before failures were structured
                "192.0.2.30": "Authentication failed to 192.0.2.30",
            },
            "skipped": {
                "192.0.2.101": {"hostname": "leaf101(FDO12345ABC)",
                                "reason": "controller_managed",
                                "managed_by": "aci",
                                "platform": "N9K-C93180YC-EX"},
            },
        },
    }


def test_failed_rows_explain_each_failure():
    headers, rows = extract_failed_devices_data(_inventory())
    assert headers == ["Category", "Mgmt IP", "Hostname", "Platform",
                       "Likely cause", "Attempts", "Error"]
    by_ip = {r[1]: dict(zip(headers, r)) for r in rows}
    refused = by_ip["192.0.2.7"]
    assert refused["Hostname"] == "dist7"
    assert refused["Platform"] == "cisco WS-C3850-48P"
    assert refused["Category"] == "Port refused"
    assert "access-class" in refused["Likely cause"]
    assert refused["Attempts"] == (
        "ssh/22 (cisco_ios): Connection refused, 12ms; "
        "telnet/23 (cisco_ios_telnet): Connection refused, 3ms")
    assert "\n" not in refused["Attempts"]


def test_old_string_failure_still_gets_a_row():
    headers, rows = extract_failed_devices_data(_inventory())
    row = dict(zip(headers, [r for r in rows if r[1] == "192.0.2.30"][0]))
    assert row["Category"] == "Auth rejected"
    assert "Credentials rejected" in row["Likely cause"]
    assert row["Error"] == "Authentication failed to 192.0.2.30"
    assert row["Attempts"] == ""


def test_failed_rows_sorted_by_category_then_address():
    inv = _inventory()
    inv["scan_summary"]["failed"]["192.0.2.9"] = {"reason": "refused"}
    inv["scan_summary"]["failed"]["192.0.2.10"] = {"reason": "timeout"}
    inv["scan_summary"]["failed"]["192.0.2.8"] = {"reason": "legacy_crypto"}
    inv["scan_summary"]["failed"]["192.0.2.11"] = {"reason": "no_telnet_driver"}
    inv["scan_summary"]["failed"]["192.0.2.12"] = {"reason": "other"}
    _, rows = extract_failed_devices_data(inv)
    assert [(r[0], r[1]) for r in rows] == [
        ("Auth rejected", "192.0.2.30"),
        ("Port refused", "192.0.2.7"),
        ("Port refused", "192.0.2.9"),
        ("No response", "192.0.2.10"),
        ("Legacy crypto", "192.0.2.8"),
        ("No telnet driver", "192.0.2.11"),
        ("Other", "192.0.2.12"),
    ]


def test_unresolved_targets_are_dns_failures():
    inv = _inventory()
    inv["scan_summary"]["unresolved"] = [
        {"input": "sw9.example.net", "error": "Name or service not known"}]
    headers, rows = extract_failed_devices_data(inv)
    row = dict(zip(headers, rows[-1]))
    assert row["Category"] == "DNS failure"
    assert row["Mgmt IP"] == ""
    assert row["Hostname"] == "sw9.example.net"
    assert "did not resolve" in row["Likely cause"]
    assert row["Error"] == "Name or service not known"


def test_skipped_rows():
    headers, rows = extract_skipped_devices_data(_inventory())
    row = dict(zip(headers, rows[0]))
    assert row["Category"] == "Controller-managed"
    assert row["Mgmt IP"] == "192.0.2.101"
    assert row["Managed By"] == "ACI (APIC)"
    assert "APIC" in row["Likely cause"]


def test_not_attempted_listed_apart_from_failures():
    inv = _inventory()
    inv["scan_summary"]["not_attempted"] = {
        "192.0.2.40": {"hostname": "SW4", "reason": "device limit"}}
    _, failed = extract_failed_devices_data(inv)
    assert "192.0.2.40" not in [r[1] for r in failed]
    headers, rows = extract_skipped_devices_data(inv)
    assert [(r[0], r[1]) for r in rows] == [
        ("Controller-managed", "192.0.2.101"), ("Not attempted", "192.0.2.40")]
    row = dict(zip(headers, rows[1]))
    assert row["Hostname"] == "SW4"
    assert "device limit" in row["Likely cause"]


def test_not_attempted_as_plain_list():
    inv = _inventory()
    inv["scan_summary"].pop("skipped")
    inv["scan_summary"]["not_attempted"] = ["192.0.2.7"]
    headers, rows = extract_skipped_devices_data(inv)
    row = dict(zip(headers, rows[0]))
    assert row["Category"] == "Not attempted"
    # hostname and platform come from the neighbour record
    assert row["Hostname"] == "dist7"
    assert row["Platform"] == "cisco WS-C3850-48P"


def test_no_skipped_sheet_without_skipped_devices():
    inv = _inventory()
    inv["scan_summary"].pop("skipped")
    assert extract_skipped_devices_data(inv) is None


def test_workbook_has_both_sheets():
    data = DeviceInventoryReport().generate(_inventory())
    wb = load_workbook(io.BytesIO(data))
    assert "Failed Devices" in wb.sheetnames
    assert "Not Collected" in wb.sheetnames
    ws = wb["Failed Devices"]
    assert ws.cell(row=1, column=1).value == "Category"
    assert ws.cell(row=1, column=2).value == "Mgmt IP"
    assert ws.max_row == 3


def test_scan_without_summary_has_empty_failed_sheet():
    inv = _inventory()
    inv.pop("scan_summary")
    wb = load_workbook(io.BytesIO(DeviceInventoryReport().generate(inv)))
    assert wb["Failed Devices"].max_row == 1
    assert "Not Collected" not in wb.sheetnames


def test_json_export_includes_failed_devices():
    out = json.loads(DeviceInventoryReport().generate(_inventory(), fmt="json"))
    assert "Failed Devices" in json.dumps(out)
