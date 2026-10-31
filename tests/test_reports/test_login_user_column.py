"""Which credential set logged in, and how auth failures across sets read."""
from app.reports.device_inventory import (DeviceInventoryReport,
                                          extract_failed_devices_data)


def _devices_sheet(inventory):
    headers, rows = DeviceInventoryReport()._extract_devices_data(inventory)
    return headers, {r[0]: dict(zip(headers, r)) for r in rows}


def test_login_user_column_shows_the_account_that_logged_in():
    headers, rows = _devices_sheet({"devices": {
        "SW-A": {"hostname": "SW-A", "mgmt_ip": "192.0.2.1",
                 "login_succeeded": True, "login_user": "backup-admin",
                 "credential_set": 2, "collector_data": {}},
        "SW-B": {"hostname": "SW-B", "mgmt_ip": "192.0.2.2",
                 "login_succeeded": False, "collector_data": {}},
    }})
    assert headers[-1] == "Login User"
    assert rows["SW-A"]["Login User"] == "backup-admin"
    assert rows["SW-B"]["Login User"] == ""


def test_login_user_sits_before_source_scan_on_merged_inventory():
    headers, _ = _devices_sheet({"merged_from": [{"file": "a.json"}],
                                 "devices": {}})
    assert headers[-2:] == ["Login User", "Source Scan"]


def _failed(attempts):
    return {"devices": {}, "scan_summary": {"failed": {"192.0.2.9": {
        "hostname": "SW-C", "reason": "auth", "message": "x",
        "hint": "Credentials rejected", "attempts": attempts}}}}


def test_auth_failure_across_sets_says_all_were_rejected():
    headers, rows = extract_failed_devices_data(_failed([
        {"protocol": "ssh", "port": 22, "device_type": "cisco_ios",
         "reason": "auth", "credential_set": 1, "username": "netops"},
        {"protocol": "ssh", "port": 22, "device_type": "cisco_ios",
         "reason": "auth", "credential_set": 2, "username": "backup-admin"},
    ]))
    row = dict(zip(headers, rows[0]))
    assert row["Likely cause"].startswith("All 2 credential sets were rejected")
    assert "as netops (set 1)" in row["Attempts"]
    assert "as backup-admin (set 2)" in row["Attempts"]


def test_single_set_auth_failure_keeps_the_plain_hint():
    headers, rows = extract_failed_devices_data(_failed([
        {"protocol": "ssh", "port": 22, "device_type": "cisco_ios",
         "reason": "auth"}]))
    row = dict(zip(headers, rows[0]))
    assert row["Likely cause"] == "Credentials rejected"


def test_single_set_scan_does_not_label_every_attempt():
    data = _failed([{"protocol": "ssh", "port": 22, "device_type": "cisco_ios",
                     "reason": "timeout", "credential_set": 1,
                     "username": "netops"}])
    data["params"] = {"credential_usernames": ["netops"]}
    headers, rows = extract_failed_devices_data(data)
    assert "set 1" not in dict(zip(headers, rows[0]))["Attempts"]

    data["params"] = {"credential_usernames": ["netops", "backup-admin"]}
    headers, rows = extract_failed_devices_data(data)
    assert "as netops (set 1)" in dict(zip(headers, rows[0]))["Attempts"]
