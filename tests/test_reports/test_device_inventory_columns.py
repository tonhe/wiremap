"""Devices sheet: redundancy, show version facts, how found, what collected."""
import io

from openpyxl import load_workbook

from app.reports.device_inventory import DeviceInventoryReport


def _device(hostname, ip, **extra):
    record = {"hostname": hostname, "mgmt_ip": ip, "device_type": "cisco_xe",
              "login_succeeded": False, "collector_data": {}}
    record.update(extra)
    return record


def _inv_parsed(**parsed):
    return {"device_inventory": {"raw": {}, "parsed": parsed}}


def _rows(inventory):
    headers, rows = DeviceInventoryReport()._extract_devices_data(inventory)
    return {r[0]: dict(zip(headers, r)) for r in rows}


SVL_PARSED = {
    "version": [{"version": "17.6.5", "hardware": ["C9500-48Y4C", "C9500-48Y4C"],
                 "serial": ["FCW0000A1AA", "FCW0000B2BB"],
                 "software_image": "CAT9K_IOSXE", "uptime": "2 weeks",
                 "reload_reason": "Reload Command",
                 "running_image": "packages.conf"}],
    "inventory": [{"name": "Chassis 1", "descr": "Cisco Catalyst 9500 Series Chassis",
                   "pid": "C9500-48Y4C", "sn": "FCW0000A1AA"}],
    "version_details": {"image": "flash:packages.conf", "uptime": "1 year, 2 weeks",
                        "reload_reason": "Reload Command",
                        "license": "network-advantage, dna-advantage"},
    "stackwise_virtual": {
        "enabled": True, "domain": "10", "switches": ["1", "2"],
        "links": [{"switch": "1", "svl": "1", "port": "TenGigabitEthernet1/0/39"},
                  {"switch": "1", "svl": "1", "port": "TenGigabitEthernet1/0/40"},
                  {"switch": "2", "svl": "1", "port": "TenGigabitEthernet2/0/39"}],
        "dad_ports": [{"switch": "1", "port": "TenGigabitEthernet1/0/38",
                       "status": "up"}],
    },
    "stack_members": [
        {"switch": "1", "role": "Active", "model": "C9500-48Y4C",
         "serial": "FCW0000A1AA", "state": "Ready",
         "stack_type": "stackwise-virtual"},
        {"switch": "2", "role": "Standby", "model": "C9500-48Y4C",
         "serial": "FCW0000B2BB", "state": "Ready",
         "stack_type": "stackwise-virtual"},
    ],
}


def _svl_inventory():
    return {
        "seed_ip": "192.0.2.1",
        "params": {},
        "devices": {
            "SW-CORE-1": _device("SW-CORE-1", "192.0.2.1", login_succeeded=True,
                                 discovery_source="login",
                                 platform="C9500-48Y4C, C9500-48Y4C",
                                 collector_data=_inv_parsed(**SVL_PARSED)),
        },
    }


def test_new_columns_follow_existing_ones():
    headers, _ = DeviceInventoryReport()._extract_devices_data({"devices": {}})
    assert headers[:11] == [
        "Hostname", "Mgmt IP", "Device Type", "Category",
        "Platform", "Platform Description", "Software Version",
        "Serial Number", "Discovery Source", "Logged In", "Login Error"]
    for col in ("Redundancy", "HA State", "Uptime", "Last Reload Reason",
                "Image", "License", "Discovered Via", "Collection Status"):
        assert col in headers


def test_svl_pair_row():
    row = _rows(_svl_inventory())["SW-CORE-1"]
    assert row["Redundancy"] == "stackwise-virtual"
    # Platform lists both members; the description uses the first PID.
    assert row["Platform Description"] == "Cisco Catalyst 9500 48-Port 25G"
    assert row["Uptime"] == "1 year, 2 weeks"
    assert row["Last Reload Reason"] == "Reload Command"
    assert row["Image"] == "flash:packages.conf"
    assert row["License"] == "network-advantage, dna-advantage"
    assert row["Discovered Via"] == "seed"
    assert row["Collection Status"] == "collected"


def test_svl_stack_sheet_lists_both_chassis_with_links():
    inv = _svl_inventory()
    headers, rows = DeviceInventoryReport()._extract_stack_data(inv)
    by_member = {r[2]: dict(zip(headers, r)) for r in rows}
    assert set(by_member) == {"1", "2"}
    assert by_member["1"]["Serial"] == "FCW0000A1AA"
    assert by_member["2"]["Serial"] == "FCW0000B2BB"
    assert by_member["2"]["Role"] == "Standby"
    assert by_member["1"]["Stack Type"] == "stackwise-virtual"
    assert by_member["1"]["Domain"] == "10"
    assert by_member["1"]["Interconnect Ports"] == \
        "TenGigabitEthernet1/0/39, TenGigabitEthernet1/0/40"
    assert by_member["1"]["DAD Ports"] == "TenGigabitEthernet1/0/38"


def test_xlsx_sheets_match_tabular_data():
    data = DeviceInventoryReport().generate(_svl_inventory())
    wb = load_workbook(io.BytesIO(data))
    ws = wb["Devices"]
    headers = [c.value for c in ws[1]]
    assert "Collection Status" in headers
    assert ws.cell(row=2, column=headers.index("Redundancy") + 1).value \
        == "stackwise-virtual"
    assert wb["Stack Members"].max_row == 3


def test_redundancy_values():
    devices = {
        "SW-ACC-1": _device("SW-ACC-1", "192.0.2.11", login_succeeded=True,
                            collector_data=_inv_parsed(stack_members=[
                                {"switch": "1"}, {"switch": "2"}])),
        "SW-ACC-2": _device("SW-ACC-2", "192.0.2.12", login_succeeded=True,
                            collector_data=_inv_parsed(stack_members=[
                                {"switch": "1"}], version=[{"version": "1"}])),
        "SW-VSS-1": _device("SW-VSS-1", "192.0.2.13", login_succeeded=True,
                            collector_data=_inv_parsed(vss={"domain": "100",
                                                            "links": ["Te1/5/4"]})),
        "SW-DC-1": _device("SW-DC-1", "192.0.2.14", login_succeeded=True,
                           collector_data=_inv_parsed(vpc={"domain": "20"})),
        "RTR-1": dict(_device("RTR-1", "192.0.2.15", login_succeeded=True,
                              collector_data={
                                  **_inv_parsed(version=[{"version": "1"}]),
                                  "hsrp": {"raw": {}, "parsed": {"entries": [
                                      {"interface": "Vlan10", "state": "Active"}]}},
                              })),
        "FW-1": _device("FW-1", "192.0.2.16", login_succeeded=True,
                        ha_state="active",
                        collector_data=_inv_parsed(version=[{"version": "1"}])),
        "SW-NBR": _device("SW-NBR", "192.0.2.17", discovery_source="cdp_lldp"),
    }
    rows = _rows({"devices": devices})
    assert rows["SW-ACC-1"]["Redundancy"] == "stack"
    assert rows["SW-ACC-2"]["Redundancy"] == "standalone"
    assert rows["SW-VSS-1"]["Redundancy"] == "vss"
    assert rows["SW-DC-1"]["Redundancy"] == "vpc"
    assert rows["RTR-1"]["Redundancy"] == "hsrp-pair"
    assert rows["FW-1"]["Redundancy"] == "ha-pair"
    assert rows["FW-1"]["HA State"] == "active"
    # Never logged in: unknown, not "standalone".
    assert rows["SW-NBR"]["Redundancy"] == ""


def test_platform_description_falls_back_to_show_inventory_and_version():
    devices = {
        "RTR-1": _device("RTR-1", "192.0.2.21", login_succeeded=True,
                         platform="ISR9999",
                         collector_data=_inv_parsed(inventory=[
                             {"name": "Chassis", "descr": "Cisco ISR9999 Chassis",
                              "pid": "ISR9999", "sn": "FCW0000C3CC"}])),
        "SW-1": _device("SW-1", "192.0.2.22", login_succeeded=True,
                        collector_data=_inv_parsed(version=[
                            {"hardware": ["C9999-24P"],
                             "software_image": "CAT9K_IOSXE"}])),
        "SW-2": _device("SW-2", "192.0.2.23", platform="WS-C3750X-48"),
    }
    rows = _rows({"devices": devices})
    assert rows["RTR-1"]["Platform Description"] == "Cisco ISR9999 Chassis"
    assert rows["SW-1"]["Platform Description"] == "C9999-24P (CAT9K_IOSXE)"
    # The hard-coded table still wins where it knows the PID.
    assert "3750" in rows["SW-2"]["Platform Description"]


def test_discovered_via():
    inventory = {
        "seed_ip": "192.0.2.1",
        "params": {"target_ips": ["192.0.2.50"]},
        "devices": {
            "SW-CORE-1": _device("SW-CORE-1", "192.0.2.1", discovery_source="login",
                                 login_succeeded=True, collector_data={
                                     "cdp_lldp": {"raw": {}, "parsed": {"neighbors": [
                                         {"remote_device": "SW-ACC-1.example.net",
                                          "protocols": ["CDP", "LLDP"]},
                                         {"remote_device": "AP-1",
                                          "remote_ip": "192.0.2.31",
                                          "protocols": ["LLDP"]},
                                     ]}}}),
            "SW-ACC-1": _device("SW-ACC-1", "192.0.2.30", discovery_source="cdp_lldp",
                                evidence=[{"source": "cdp_lldp",
                                           "seen_from": "SW-CORE-1"}]),
            "AP-1": _device("AP-1", "192.0.2.31", discovery_source="cdp_lldp",
                            evidence=[{"source": "cdp_lldp",
                                       "seen_from": "SW-CORE-1"}]),
            "SW-OLD": _device("SW-OLD", "192.0.2.32", discovery_source="cdp_lldp"),
            "SW-TGT": _device("SW-TGT", "192.0.2.50", discovery_source="login"),
            "SW-SNMP": _device("SW-SNMP", "192.0.2.51", discovery_source="snmp"),
            "RTR-2": _device("RTR-2", "192.0.2.52",
                             discovery_source="routing_adjacency"),
        },
    }
    rows = _rows(inventory)
    assert rows["SW-CORE-1"]["Discovered Via"] == "seed"
    assert rows["SW-ACC-1"]["Discovered Via"] == "cdp+lldp"
    assert rows["AP-1"]["Discovered Via"] == "lldp"
    assert rows["SW-OLD"]["Discovered Via"] == "cdp/lldp"
    assert rows["SW-TGT"]["Discovered Via"] == "target-list"
    assert rows["SW-SNMP"]["Discovered Via"] == "snmp"
    assert rows["RTR-2"]["Discovered Via"] == "routing"
    # The raw source column is unchanged.
    assert rows["SW-ACC-1"]["Discovery Source"] == "cdp_lldp"


def test_collection_status():
    inventory = {
        "devices": {
            "SW-OK": _device("SW-OK", "192.0.2.1", login_succeeded=True,
                             collector_data=_inv_parsed(version=[])),
            "SW-PART": _device("SW-PART", "192.0.2.2", login_succeeded=True,
                               collector_data={
                                   **_inv_parsed(version=[]),
                                   "vrf": {"raw": {}, "parsed": {
                                       "collector_failed": True}},
                               }),
            # New-style failure record
            "SW-AUTH": _device("SW-AUTH", "192.0.2.3"),
            # Old-style plain string failure
            "SW-TO": _device("SW-TO", "192.0.2.4"),
            "SW-LOGERR": _device("SW-LOGERR", "192.0.2.5",
                                 login_error="ssh/cisco_ios: connection refused"),
            "APIC-1": _device("APIC-1", "192.0.2.6"),
            "LEAF-1": _device("LEAF-1", "192.0.2.7", managed_by="APIC-1"),
            "SW-FAR": _device("SW-FAR", "192.0.2.8"),
            "SW-DEEP": _device("SW-DEEP", "192.0.2.9"),
            "PHONE-1": _device("PHONE-1", None),
        },
        "scan_summary": {
            "failed": {
                "192.0.2.3": {"hostname": "SW-AUTH", "reason": "auth_failed",
                              "hint": "", "message": "Authentication failed",
                              "attempts": []},
                "192.0.2.4": "ssh/cisco_ios: TCP connection timed out",
            },
            "skipped": {
                "192.0.2.6": {"hostname": "APIC-1", "reason": "controller_managed",
                              "managed_by": "APIC-1", "platform": "APIC"},
            },
            "out_of_scope": ["192.0.2.8"],
        },
    }
    rows = _rows(inventory)
    assert rows["SW-OK"]["Collection Status"] == "collected"
    assert rows["SW-PART"]["Collection Status"] == "partial:vrf"
    assert rows["SW-AUTH"]["Collection Status"] == "failed:auth_failed"
    assert rows["SW-TO"]["Collection Status"] == "failed:timeout"
    assert rows["SW-LOGERR"]["Collection Status"] == "failed:connection_refused"
    assert rows["APIC-1"]["Collection Status"] == "skipped:controller_managed"
    assert rows["LEAF-1"]["Collection Status"] == "skipped:controller_managed"
    assert rows["SW-FAR"]["Collection Status"] == "skipped:out_of_scope"
    assert rows["SW-DEEP"]["Collection Status"] == "skipped:not_crawled"
    assert rows["PHONE-1"]["Collection Status"] == "skipped:no_mgmt_ip"


LICENSED_PARSED = {
    "version_details": {"license": "network-advantage"},
    "licenses": [
        {"name": "network-advantage", "entitlement": "C9300-48 Network Advan...",
         "count": "2", "status": "IN USE"},
        {"name": "dna-advantage", "entitlement": "C9300-48 DNA Advantage",
         "count": "2", "status": "IN USE"},
    ],
    "smart_licensing": {"mode": "Smart Licensing Using Policy",
                          "status": "ENABLED", "registration": "",
                          "authorization": "", "transport": "Smart",
                          "last_ack": "Mar 01 08:00:12 2026 UTC"},
    "call_home": {"enabled": True, "transport": "http", "profiles": []},
}


def _licensed_inventory():
    return {"devices": {
        "ACC-SW-01": _device("ACC-SW-01", "192.0.2.21", login_succeeded=True,
                             collector_data=_inv_parsed(**LICENSED_PARSED)),
        "ACC-SW-02": _device("ACC-SW-02", "192.0.2.22", login_succeeded=True,
                             collector_data=_inv_parsed(call_home={
                                 "enabled": False, "transport": "",
                                 "profiles": []})),
        "OLD-SW-03": _device("OLD-SW-03", "192.0.2.23", login_succeeded=True,
                             collector_data=_inv_parsed()),
    }}


def test_license_column_carries_in_use_licenses_and_slp_state():
    row = _rows(_licensed_inventory())["ACC-SW-01"]
    assert row["License"] == "network-advantage, dna-advantage [SLP: ENABLED]"


def test_licenses_sheet_rows():
    headers, rows = DeviceInventoryReport()._extract_licenses_data(
        _licensed_inventory())
    table = [dict(zip(headers, r)) for r in rows]
    acc1 = [r for r in table if r["Hostname"] == "ACC-SW-01"]
    assert [r["License"] for r in acc1] == ["network-advantage", "dna-advantage"]
    assert acc1[0]["Smart Licensing"] == "Smart Licensing Using Policy"
    assert acc1[0]["Last Usage ACK"] == "Mar 01 08:00:12 2026 UTC"
    assert acc1[0]["Call-Home"] == "enabled"
    assert acc1[0]["Call-Home Transport"] == "http"
    # Call-home state alone still gets a row; no data at all gets none.
    acc2 = [r for r in table if r["Hostname"] == "ACC-SW-02"]
    assert len(acc2) == 1 and acc2[0]["Call-Home"] == "disabled"
    assert not any(r["Hostname"] == "OLD-SW-03" for r in table)


def test_licenses_sheet_in_workbook_and_tabular():
    inv = _licensed_inventory()
    report = DeviceInventoryReport()
    wb = load_workbook(io.BytesIO(report.generate(inv)))
    assert "Licenses" in wb.sheetnames
    assert "Licenses" in report.generate_tabular_data(inv)


def test_site_and_site_naming_columns(monkeypatch):
    monkeypatch.setattr("app.site_mapping._configured_rules", lambda: [])
    names = ["AB001-IDF-SWA-01", "AB002-MDF-STK-01", "CD103-IDF-SWA-02",
             "EF204-MDF-RTR-01", "GH305-IDF-SWA-01", "Switch-exec"]
    inventory = {"devices": {n: _device(n, f"192.0.2.{i}")
                             for i, n in enumerate(names, 1)}}

    rows = _rows(inventory)

    assert rows["AB001-IDF-SWA-01"]["Site"] == "AB001"
    assert rows["AB001-IDF-SWA-01"]["Site Naming"] == ""
    assert rows["Switch-exec"]["Site"] == "Switch"
    assert "unlike most" in rows["Switch-exec"]["Site Naming"]
