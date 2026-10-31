import io
import pytest
from openpyxl import load_workbook
from app.reports.device_inventory import DeviceInventoryReport


def test_report_attrs():
    r = DeviceInventoryReport()
    assert r.name == "device_inventory"
    assert "device_inventory" in r.required_collectors


def test_generate_xlsx_devices_sheet(sample_inventory):
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    ws = wb["Devices"]
    # Header includes new Platform Description column
    headers = [ws.cell(row=1, column=c).value for c in range(1, 9)]
    assert "Platform Description" in headers
    assert "Software Version" in headers
    # SW1 data
    assert ws.cell(row=2, column=1).value == "SW1"
    # Software version should be populated
    assert ws.cell(row=2, column=7).value == "15.2(4)E10"
    # Serial should be populated
    assert ws.cell(row=2, column=8).value == "FOC1234ABCD"


def test_devices_sheet_platform_description(sample_inventory):
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    ws = wb["Devices"]
    # SW1 platform is WS-C3750X-48 -> should match description
    desc_col = None
    for c in range(1, 10):
        if ws.cell(row=1, column=c).value == "Platform Description":
            desc_col = c
            break
    assert desc_col is not None
    desc = ws.cell(row=2, column=desc_col).value
    assert desc and "3750" in desc


def test_generate_xlsx_stack_members_sheet(sample_inventory):
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "Stack Members" in wb.sheetnames
    ws = wb["Stack Members"]
    # Headers
    assert ws.cell(row=1, column=1).value == "Hostname"
    assert ws.cell(row=1, column=3).value == "Member #"
    assert ws.cell(row=1, column=4).value == "Role"
    # SW1 has 2 stack members
    assert ws.cell(row=2, column=1).value == "SW1"
    assert ws.cell(row=2, column=3).value == "1"
    assert ws.cell(row=2, column=4).value == "Active"
    assert ws.cell(row=3, column=1).value == "SW1"
    assert ws.cell(row=3, column=3).value == "2"
    assert ws.cell(row=3, column=4).value == "Standby"
    # SW2 has no stack members -- should not appear
    hostnames = [ws.cell(row=r, column=1).value for r in range(2, ws.max_row + 1)]
    assert "SW2" not in hostnames


def test_stack_members_sheet_empty_when_no_stacks(sample_inventory):
    for dev in sample_inventory["devices"].values():
        dev["collector_data"]["device_inventory"]["parsed"]["stack_members"] = []
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    ws = wb["Stack Members"]
    assert ws.max_row == 1  # header only


def test_generate_xlsx_modules_sheet(sample_inventory):
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "Modules" in wb.sheetnames
    ws = wb["Modules"]
    # Headers
    assert ws.cell(row=1, column=1).value == "Hostname"
    assert ws.cell(row=1, column=3).value == "Slot"
    assert ws.cell(row=1, column=4).value == "Type"
    # Chassis PIDs (WS-C3750X-48) should be filtered out;
    # only real NM modules should appear
    assert ws.cell(row=2, column=1).value == "SW1"
    assert ws.cell(row=2, column=3).value == "3"
    assert ws.cell(row=2, column=4).value == "FRULink 1G Module"
    assert ws.cell(row=2, column=5).value == "C3KX-NM-1G"


def test_modules_sheet_uses_inventory_fallback(sample_inventory):
    for dev in sample_inventory["devices"].values():
        dev["collector_data"]["device_inventory"]["parsed"]["modules"] = []
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    ws = wb["Modules"]
    assert ws is not None


def test_can_generate(sample_inventory):
    r = DeviceInventoryReport()
    assert r.can_generate(sample_inventory) is True
    assert r.can_generate({"devices": {}}) is False


def test_three_sheets_present(sample_inventory):
    r = DeviceInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert wb.sheetnames == ["Devices", "Stack Members", "Modules",
                             "Failed Devices"]


def test_devices_sheet_exposes_provenance():
    """Consumers must be able to tell a collected device from a neighbour."""
    from app.reports.device_inventory import DeviceInventoryReport
    inventory = {
        "devices": {
            "SW1": {
                "hostname": "SW1", "mgmt_ip": "10.0.0.1",
                "discovery_source": "login", "login_succeeded": True,
                "collector_data": {},
            },
            "SW2": {
                "hostname": "SW2", "mgmt_ip": "10.0.0.2",
                "discovery_source": "cdp", "login_succeeded": False,
                "login_error": "ssh/cisco_ios: timeout",
                "collector_data": {},
            },
        }
    }
    headers, rows = DeviceInventoryReport()._extract_devices_data(inventory)
    assert "Discovery Source" in headers
    assert "Logged In" in headers
    src = headers.index("Discovery Source")
    logged = headers.index("Logged In")
    by_host = {r[0]: r for r in rows}
    assert by_host["SW1"][src] == "login"
    assert by_host["SW1"][logged] == "Yes"
    assert by_host["SW2"][src] == "cdp"
    assert by_host["SW2"][logged] == "No"


def test_merged_inventory_gets_a_sources_sheet():
    """A merged workbook should say what it was built from."""
    from app.reports.device_inventory import DeviceInventoryReport
    inventory = {
        "devices": {"SW1": {"hostname": "SW1", "mgmt_ip": "10.0.0.1",
                            "source_scan": "scan-a", "collector_data": {}}},
        "merged_from": [
            {"discovery_id": "scan-a", "filename": "a.json", "seed_ip": "10.0.0.1",
             "timestamp": "2026-08-25T10:00:00+00:00", "device_count": 12},
            {"discovery_id": "scan-b", "filename": "b.json", "seed_ip": "10.1.0.1",
             "timestamp": "2026-08-26T10:00:00+00:00", "device_count": 30},
        ],
        "merge_conflicts": [
            {"hostname": "SW1", "also_named": "", "kept_from": "scan-a",
             "discarded_from": "scan-b", "reason": "newer scan"},
        ],
    }
    data = DeviceInventoryReport().generate_tabular_data(inventory)
    assert "Merge Sources" in data
    headers, rows = data["Merge Sources"]
    assert len(rows) == 2
    assert "scan-a" in rows[0]


def test_unmerged_inventory_has_no_sources_sheet():
    from app.reports.device_inventory import DeviceInventoryReport
    inventory = {"devices": {"SW1": {"hostname": "SW1", "collector_data": {}}}}
    assert "Merge Sources" not in DeviceInventoryReport().generate_tabular_data(inventory)


def test_devices_sheet_shows_source_scan_when_merged():
    from app.reports.device_inventory import DeviceInventoryReport
    inventory = {
        "devices": {"SW1": {"hostname": "SW1", "source_scan": "scan-a",
                            "collector_data": {}}},
        "merged_from": [{"discovery_id": "scan-a", "filename": "a.json",
                         "seed_ip": "", "timestamp": "", "device_count": 1}],
    }
    headers, rows = DeviceInventoryReport().generate_tabular_data(inventory)["Devices"]
    assert "Source Scan" in headers
    assert rows[0][headers.index("Source Scan")] == "scan-a"


def test_merge_conflicts_get_their_own_sheet():
    from app.reports.device_inventory import DeviceInventoryReport
    inventory = {
        "devices": {},
        "merged_from": [{"discovery_id": "scan-a", "filename": "a.json",
                         "seed_ip": "", "timestamp": "", "device_count": 1}],
        "merge_conflicts": [
            {"hostname": "N5K-A", "also_named": "N5K-A(SSI1).example.net",
             "kept_from": "scan-a", "discarded_from": "scan-b",
             "reason": "logged-in record preferred over a neighbour sighting"},
        ],
    }
    data = DeviceInventoryReport().generate_tabular_data(inventory)
    headers, rows = data["Merge Conflicts"]
    assert rows[0][headers.index("Device")] == "N5K-A"
    assert rows[0][headers.index("Also Seen As")] == "N5K-A(SSI1).example.net"
    assert "neighbour" in rows[0][headers.index("Why")]


def test_no_conflicts_sheet_when_none():
    from app.reports.device_inventory import DeviceInventoryReport
    inventory = {"devices": {},
                 "merged_from": [{"discovery_id": "a", "filename": "a.json",
                                  "seed_ip": "", "timestamp": "",
                                  "device_count": 0}]}
    data = DeviceInventoryReport().generate_tabular_data(inventory)
    assert "Merge Sources" in data
    assert "Merge Conflicts" not in data


def _merged_xlsx_inventory():
    return {
        "devices": {"SW1": {"hostname": "SW1", "mgmt_ip": "192.0.2.1",
                            "source_scan": "scan-a", "collector_data": {}}},
        "merged_from": [
            {"discovery_id": "scan-a", "filename": "a.json",
             "seed_ip": "192.0.2.1", "timestamp": "2026-08-25T10:00:00+00:00",
             "device_count": 1},
            {"discovery_id": "scan-b", "filename": "b.json",
             "seed_ip": "198.51.100.1", "timestamp": "2026-08-26T10:00:00+00:00",
             "device_count": 1},
        ],
        "merge_conflicts": [
            {"hostname": "SW1", "also_named": "", "kept_from": "scan-a",
             "discarded_from": "scan-b", "reason": "newer scan"},
        ],
    }


def test_merged_xlsx_has_merge_sheets():
    data = DeviceInventoryReport().generate(_merged_xlsx_inventory(), "xlsx")
    wb = load_workbook(io.BytesIO(data))
    assert "Merge Sources" in wb.sheetnames
    assert "Merge Conflicts" in wb.sheetnames
    rows = list(wb["Merge Sources"].iter_rows(min_row=2, values_only=True))
    assert [r[0] for r in rows] == ["scan-a", "scan-b"]
    rows = list(wb["Merge Conflicts"].iter_rows(min_row=2, values_only=True))
    assert rows[0][0] == "SW1"


def test_unmerged_xlsx_has_no_merge_sheets():
    inventory = {"devices": {"SW1": {"hostname": "SW1", "collector_data": {}}}}
    data = DeviceInventoryReport().generate(inventory, "xlsx")
    wb = load_workbook(io.BytesIO(data))
    assert "Merge Sources" not in wb.sheetnames
    assert "Merge Conflicts" not in wb.sheetnames
