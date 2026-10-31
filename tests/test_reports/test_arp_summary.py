import io
from openpyxl import load_workbook
from app.reports.arp_summary import ArpSummaryReport


def test_report_attrs():
    r = ArpSummaryReport()
    assert r.name == "arp_summary"
    assert "arp" in r.required_collectors


def test_generate_xlsx(sample_inventory):
    r = ArpSummaryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "Summary" in wb.sheetnames
    assert "Detail" in wb.sheetnames
    ws = wb["Detail"]
    assert ws.cell(row=1, column=1).value == "Device"
    # SW1 has 2 ARP entries
    assert ws.cell(row=2, column=1).value == "SW1"
    assert ws.cell(row=3, column=1).value == "SW1"
    assert ws.cell(row=1, column=2).value == "VRF"
    assert ws.cell(row=2, column=2).value == "default"


def _vrf_inventory():
    return {"devices": {"RTR-A": {"collector_data": {
        "arp": {"parsed": {"entries": [
            {"ip": "192.0.2.10", "mac": "00:50:56:aa:00:10", "age": "5",
             "interface": "GigabitEthernet0/0/0", "incomplete": False},
        ]}},
        "vrf": {"parsed": {"vrf_arp": {
            "TENANT-A": [
                {"ip_address": "198.51.100.10", "mac_address": "00:50:56:aa:bb:01",
                 "age": "00:01:23", "interface": "Vlan210", "incomplete": False},
                {"ip_address": "198.51.100.12", "mac_address": "",
                 "age": "00:00:05", "interface": "Vlan210", "incomplete": True},
            ],
            # Same entry as the global table: must not be listed twice.
            "default": [
                {"ip_address": "192.0.2.10", "mac_address": "0050.56aa.0010",
                 "age": "5", "interface": "GigabitEthernet0/0/0"},
            ],
        }}},
    }}}}


def test_vrf_arp_entries_listed_with_vrf():
    _, detail = ArpSummaryReport().generate_tabular_data(_vrf_inventory())["Detail"]
    by_ip = {r[3]: r for r in detail}
    assert by_ip["192.0.2.10"][1] == "default"
    assert by_ip["198.51.100.10"][1] == "TENANT-A"
    assert by_ip["198.51.100.10"][4] == "00:50:56:aa:bb:01"
    assert by_ip["198.51.100.12"][4] == "Incomplete"


def test_default_vrf_entries_not_duplicated():
    _, detail = ArpSummaryReport().generate_tabular_data(_vrf_inventory())["Detail"]
    assert [r[3] for r in detail].count("192.0.2.10") == 1
    assert len(detail) == 3


def test_summary_counts_per_vrf():
    _, summary = ArpSummaryReport().generate_tabular_data(_vrf_inventory())["Summary"]
    assert ["RTR-A", "TENANT-A", "Vlan210", 2] in summary
    assert ["RTR-A", "default", "GigabitEthernet0/0/0", 1] in summary


def test_vrf_entry_on_same_ip_and_interface_as_global_skipped():
    inv = _vrf_inventory()
    inv["devices"]["RTR-A"]["collector_data"]["vrf"]["parsed"]["vrf_arp"] = {
        "TENANT-A": [{"ip_address": "192.0.2.10", "mac_address": "x",
                      "age": "1", "interface": "GigabitEthernet0/0/0"}]}
    _, detail = ArpSummaryReport().generate_tabular_data(inv)["Detail"]
    assert len(detail) == 1
