import io
from openpyxl import load_workbook
from app.reports.interface_summary import InterfaceSummaryReport


def test_report_attrs():
    r = InterfaceSummaryReport()
    assert r.name == "interface_summary"
    assert "interfaces" in r.required_collectors


def test_generate_xlsx(sample_inventory):
    r = InterfaceSummaryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "Interface Status" in wb.sheetnames
    assert "IP Interfaces" in wb.sheetnames
    ws = wb["Interface Status"]
    assert ws.cell(row=2, column=1).value == "SW1"
    assert ws.cell(row=2, column=2).value == "Gi0/1"


def test_vlan_column_reads_ntc_vlan_id():
    """ntc-templates names the field vlan_id; reading vlan left it empty."""
    inventory = {"devices": {"SW1": {"collector_data": {"interfaces": {"parsed": {
        "interfaces_status": [
            {"port": "Gi1/0/1", "status": "connected", "vlan_id": "10"},
            {"port": "Gi1/0/2", "status": "connected", "vlan": "20"},
        ]}}}}}}
    _, rows = InterfaceSummaryReport().generate_tabular_data(inventory)["Interface Status"]
    assert [r[4] for r in rows] == ["10", "20"]
def test_interface_status_neighbor_column():
    inv = {"devices": {"SW1": {"collector_data": {
        "interfaces": {"parsed": {"interfaces_status": [
            {"port": "Gi1/0/1", "status": "connected"},
            {"port": "Te1/1/1", "status": "connected"},
            {"port": "Gi1/0/2", "status": "notconnect"},
        ]}},
        "cdp_lldp": {"parsed": {"neighbors": [
            {"remote_device": "SW2", "local_intf": "GigabitEthernet1/0/1"},
            {"remote_device": "LEAF-A", "local_intf": "Te1/1/1"},
            {"remote_device": "PHONE-1", "local_intf": "GigabitEthernet1/0/1"},
        ]}},
    }}}}
    headers, rows = InterfaceSummaryReport().generate_tabular_data(
        inv)["Interface Status"]
    col = headers.index("Neighbor")
    by_port = {r[1]: r[col] for r in rows}
    assert by_port == {"Gi1/0/1": "SW2, PHONE-1", "Te1/1/1": "LEAF-A",
                       "Gi1/0/2": ""}
