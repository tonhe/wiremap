from app.reports.diagram_data import DiagramDataReport


def _inventory():
    return {
        "devices": {
            "CORE1": {
                "hostname": "CORE1",
                "mgmt_ip": "10.0.0.1",
                "device_type": "cisco_nxos",
                "device_category": "switch",
                "platform": "cisco Nexus9000 N9K-C93180YC-EX",
                "serial": "FOC1111",
                "model": "N9K-C93180YC-EX",
                "software_version": "9.3(8)",
                "discovery_source": "login",
                "login_succeeded": True,
                "collector_data": {
                    "cdp_lldp": {"parsed": {"neighbors": [
                        {"remote_device": "ACCESS1", "remote_ip": "10.0.0.2",
                         "local_intf": "Eth1/1", "remote_intf": "Gi1/0/48",
                         "remote_platform": "cisco WS-C3850-48P"},
                    ]}},
                    "interfaces": {"parsed": {"ip_interfaces": [
                        {"interface": "Vlan10", "ip_address": "10.10.0.1",
                         "prefix_length": "24"},
                    ]}},
                    "l3_routing": {"parsed": {"neighbors": [
                        {"remote_ip": "10.0.0.3", "protocol": "OSPF",
                         "local_intf": "Eth1/5"},
                    ]}},
                },
            },
            "ACCESS1": {
                "hostname": "ACCESS1",
                "mgmt_ip": "10.0.0.2",
                "device_type": "cisco_ios",
                "device_category": "switch",
                "platform": "cisco WS-C3850-48P",
                "serial": None,
                "discovery_source": "cdp_lldp",
                "login_succeeded": False,
                "login_error": "ssh/cisco_ios: timeout",
                "collector_data": {},
            },
        }
    }


def _sheet(report, inventory, name):
    return report.generate_tabular_data(inventory)[name]


def test_report_is_registered():
    from app.reports import get_registry
    assert "diagram_data" in get_registry()


def test_devices_sheet_carries_diagram_fields():
    """A diagram needs hostname, management IP and model per node."""
    headers, rows = _sheet(DiagramDataReport(), _inventory(), "Devices")
    for col in ("Hostname", "Mgmt IP", "Model", "Device Type", "Role",
                "Serial", "Software Version", "Discovery Source", "Logged In"):
        assert col in headers, f"missing {col}"

    by_host = {r[headers.index("Hostname")]: r for r in rows}
    core = by_host["CORE1"]
    assert core[headers.index("Mgmt IP")] == "10.0.0.1"
    assert core[headers.index("Model")] == "N9K-C93180YC-EX"
    assert core[headers.index("Logged In")] == "Yes"

    access = by_host["ACCESS1"]
    assert access[headers.index("Logged In")] == "No"


def test_model_falls_back_to_platform():
    inv = _inventory()
    inv["devices"]["CORE1"]["model"] = None
    headers, rows = _sheet(DiagramDataReport(), inv, "Devices")
    core = [r for r in rows if r[0] == "CORE1"][0]
    assert "Nexus9000" in core[headers.index("Model")]


def test_l2_links_sheet_has_both_endpoints():
    headers, rows = _sheet(DiagramDataReport(), _inventory(), "L2 Links")
    for col in ("Device A", "Port A", "Device B", "Port B"):
        assert col in headers
    assert len(rows) == 1
    row = rows[0]
    assert row[headers.index("Device A")] == "CORE1"
    assert row[headers.index("Port A")] == "Eth1/1"
    assert row[headers.index("Device B")] == "ACCESS1"
    assert row[headers.index("Port B")] == "Gi1/0/48"


def test_l2_links_deduplicates_bidirectional():
    """Both ends report the same link; a diagram wants one edge."""
    inv = _inventory()
    inv["devices"]["ACCESS1"]["collector_data"] = {
        "cdp_lldp": {"parsed": {"neighbors": [
            {"remote_device": "CORE1", "remote_ip": "10.0.0.1",
             "local_intf": "Gi1/0/48", "remote_intf": "Eth1/1"},
        ]}}
    }
    _, rows = _sheet(DiagramDataReport(), inv, "L2 Links")
    assert len(rows) == 1


def test_l3_links_sheet_lists_adjacencies():
    headers, rows = _sheet(DiagramDataReport(), _inventory(), "L3 Links")
    assert "Protocol" in headers
    assert any(r[headers.index("Protocol")] == "OSPF" for r in rows)


def test_subnets_sheet_lists_ip_interfaces():
    headers, rows = _sheet(DiagramDataReport(), _inventory(), "Subnets")
    assert "Network" in headers
    nets = [r[headers.index("Network")] for r in rows]
    assert "10.10.0.0/24" in nets


def test_empty_inventory_produces_sheets_not_errors():
    data = DiagramDataReport().generate_tabular_data({"devices": {}})
    assert set(data) >= {"Devices", "L2 Links", "L3 Links", "Subnets"}
    for headers, rows in data.values():
        assert headers
        assert rows == []


def test_xlsx_generates():
    out = DiagramDataReport().generate(_inventory(), fmt="xlsx")
    assert out[:2] == b"PK"
    assert len(out) > 1000


def test_csv_generates():
    out = DiagramDataReport().generate(_inventory(), fmt="csv")
    assert b"CORE1" in out


def test_neighbour_only_device_still_appears_as_node():
    """A diagram must show devices that were only ever seen, not just those
    that were logged into."""
    _, rows = _sheet(DiagramDataReport(), _inventory(), "Devices")
    assert any(r[0] == "ACCESS1" for r in rows)
