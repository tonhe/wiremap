import io
from openpyxl import load_workbook
from app.reports.link_inventory import LinkInventoryReport


def test_report_attrs():
    r = LinkInventoryReport()
    assert r.name == "link_inventory"
    assert "cdp_lldp" in r.required_collectors


def test_generate_xlsx(sample_inventory):
    r = LinkInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    ws = wb["Links"]
    assert ws.cell(row=1, column=1).value == "Local Device"
    # Should have 1 unique link (SW1-SW2, deduplicated)
    assert ws.cell(row=2, column=1).value is not None
    assert ws.cell(row=3, column=1).value is None  # no second link row


def test_by_device_tab(sample_inventory):
    r = LinkInventoryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "By Device" in wb.sheetnames


def _two_switch_inventory():
    """SW1 runs CDP and LLDP to LEAF-A over two links; LEAF-A reports the
    same two links back over LLDP with short interface names."""
    from app.collectors.cdp_lldp import CdpLldpCollector
    collector = CdpLldpCollector()
    sw1_cdp = """
Device ID: LEAF-A
  IP address: 192.0.2.21
Platform: Arista DCS-7280SR3-48YC8,  Capabilities: Router Switch
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): Ethernet49/1
-------------------------
Device ID: LEAF-A
  IP address: 192.0.2.21
Platform: Arista DCS-7280SR3-48YC8,  Capabilities: Router Switch
Interface: TenGigabitEthernet1/1/2,  Port ID (outgoing port): Ethernet50/1
"""
    sw1_lldp = """
------------------------------------------------
Local Intf: Te1/1/1
Chassis id: 001c.7300.0a01
Port id: Ethernet49/1
System Name: LEAF-A
------------------------------------------------
Local Intf: Te1/1/2
Chassis id: 001c.7300.0a01
Port id: Ethernet50/1
System Name: LEAF-A
"""
    leaf_lldp = """
Chassis id: 00aa.bb00.0c01
Port id: Te1/1/1
Local Port id: Et49/1
System Name: SW1

Chassis id: 00aa.bb00.0c01
Port id: Te1/1/2
Local Port id: Et50/1
System Name: SW1
"""
    sw1 = collector.parse({"show cdp neighbors detail": sw1_cdp,
                           "show lldp neighbors detail": sw1_lldp}, "cisco_xe")
    leaf = collector.parse({"show lldp neighbors detail": leaf_lldp},
                           "arista_eos")
    return {"devices": {
        "SW1": {"collector_data": {"cdp_lldp": {"parsed": sw1}}},
        "LEAF-A": {"collector_data": {"cdp_lldp": {"parsed": leaf}}},
    }}


def test_parallel_links_both_listed_once_each():
    """Regression: the second of two links to one neighbour disappeared."""
    headers, rows = LinkInventoryReport().generate_tabular_data(
        _two_switch_inventory())["Links"]
    # LEAF-A sorts first, so its view of each link is the one kept and SW1's
    # long-name view of the same link is recognised as a duplicate.
    assert len(rows) == 2
    assert {(r[1], r[3]) for r in rows} == {("Et49/1", "Te1/1/1"),
                                            ("Et50/1", "Te1/1/2")}


def test_cdp_and_lldp_of_one_link_share_a_row():
    inv = _two_switch_inventory()
    del inv["devices"]["LEAF-A"]
    headers, rows = LinkInventoryReport().generate_tabular_data(inv)["Links"]
    assert len(rows) == 2
    for r in rows:
        assert r[5] == "CDP, LLDP"


def test_diagram_l2_links_dedupe_across_spellings():
    from app.reports.diagram_data import DiagramDataReport
    headers, rows = DiagramDataReport()._l2_links_sheet(_two_switch_inventory())
    assert len(rows) == 2
