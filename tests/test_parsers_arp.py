from app.parsers import parse_arp_table
from app.reports.arp_summary import ArpSummaryReport

IOS_ARP = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.0.2.1               -   aabb.cc00.0100  ARPA   GigabitEthernet0/0/0
Internet  192.0.2.20              3   aabb.cc00.0200  ARPA   GigabitEthernet0/0/0
Internet  192.0.2.30              0   Incomplete      ARPA
Internet  198.51.100.9            -   aabb.cc00.0300  ARPA
"""

NXOS_ARP = """\
IP ARP Table for context default
Total number of entries: 2
Address         Age       MAC Address     Interface       Flags
10.0.0.5        00:01:10  aabb.cc00.0400  Vlan10
10.0.0.6        00:00:02  INCOMPLETE      Vlan10
"""


def _by_ip(entries):
    return {e["ip"]: e for e in entries}


def test_ios_incomplete_entry_has_no_mac():
    e = _by_ip(parse_arp_table(IOS_ARP))["192.0.2.30"]
    assert e["incomplete"] is True
    assert e["mac"] == ""
    assert e["interface"] == ""


def test_ios_complete_entries_unchanged():
    entries = _by_ip(parse_arp_table(IOS_ARP))
    assert entries["192.0.2.20"]["mac"] == "aa:bb:cc:00:02:00"
    assert entries["192.0.2.20"]["interface"] == "GigabitEthernet0/0/0"
    assert entries["192.0.2.20"]["incomplete"] is False


def test_ios_entry_without_interface_column():
    e = _by_ip(parse_arp_table(IOS_ARP))["198.51.100.9"]
    assert e["mac"] == "aa:bb:cc:00:03:00"
    assert e["interface"] == ""
    assert e["incomplete"] is False


def test_nxos_incomplete_entry():
    e = _by_ip(parse_arp_table(NXOS_ARP))["10.0.0.6"]
    assert e["incomplete"] is True
    assert e["mac"] == ""
    assert e["interface"] == "Vlan10"


def test_arp_summary_labels_incomplete_entries():
    inventory = {"devices": {"RTR-A": {"collector_data": {"arp": {
        "parsed": {"entries": parse_arp_table(IOS_ARP)}}}}}}
    tab = ArpSummaryReport().generate_tabular_data(inventory)
    _, detail = tab["Detail"]
    row = next(r for r in detail if r[3] == "192.0.2.30")
    assert row[2] == "(unresolved)"
    assert row[4] == "Incomplete"
    _, summary = tab["Summary"]
    assert all(r[2] for r in summary)
