import pytest

from app.discovery_engine import DiscoveryEngine
from app.inventory import DiscoveryInventory
from app.neighbors import CrawlScope
from app.parsers import parse_lldp_neighbors_detail

ARISTA_DESC = ("Arista Networks EOS version 4.30.1F running on an Arista "
               "Networks DCS-7280SR3-48YC8")


def _engine():
    return DiscoveryEngine(
        seed_ip="192.0.2.1", seed_device_type="cisco_xe",
        username="u", password="p", max_depth=1,
        crawl_scope=CrawlScope(allow_cidrs=["192.0.2.0/24"]),
        filters={"include_routers": True, "include_switches": True},
    )


def _engine_with_neighbors(neighbors):
    engine = _engine()
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("SW1", mgmt_ip="192.0.2.1", discovery_source="login")
    inv.set_collector_data("SW1", "cdp_lldp", {}, {"neighbors": neighbors})
    return engine, inv


@pytest.mark.parametrize("desc, expected", [
    (ARISTA_DESC, "arista_eos"),
    ("Cisco Nexus Operating System (NX-OS) Software 9.3(8)", "cisco_nxos"),
    ("Cisco IOS XR Software, Version 7.5.2", "cisco_xr"),
    ("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
     "(CAT9K_IOSXE), Version 17.9.4, RELEASE SOFTWARE (fc5)", "cisco_xe"),
    ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
     "Version 15.2(7)E8", "cisco_ios"),
    ("Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 21.4R3",
     "juniper_junos"),
    ("Palo Alto Networks PA-3220 running PAN-OS 10.2.3", "paloalto_panos"),
    ("ArubaOS-CX Version FL.10.10.1020", "aruba_os"),
    ("FortiGate-100F v7.2.4,build1396", "fortinet"),
    ("Cisco Controller", "cisco_wlc"),
    ("Meraki MS225-48LP Cloud Managed Switch", "meraki"),
])
def test_description_keyword_map(desc, expected):
    dt, _, _ = _engine()._detect_neighbor_type({
        "system_description": desc, "remote_capabilities": "B,R"})
    assert dt == expected


def test_description_wins_over_unmatched_platform():
    """Regression: detect_from_cdp fell back to cisco_ios for any platform it
    did not know, so the description was never consulted."""
    dt, _, _ = _engine()._detect_neighbor_type({
        "remote_platform": "XYZ-1000",
        "system_description": ARISTA_DESC,
        "remote_capabilities": "B,R",
    })
    assert dt == "arista_eos"


def test_unmatched_platform_still_gets_default_type():
    engine = _engine()
    dt, _, _ = engine._detect_neighbor_type({
        "remote_platform": "XYZ-1000", "remote_capabilities": "Switch"})
    assert dt == engine._detector.default_type


def test_lldp_arista_neighbor_end_to_end():
    out = """
------------------------------------------------
Local Intf: Te1/1/1
Chassis id: 001c.7300.0a01
Port id: Ethernet49/1
System Name: LEAF-A

System Description:
Arista Networks EOS version 4.30.1F running on an Arista Networks
DCS-7280SR3-48YC8

Time remaining: 102 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 192.0.2.21

Peer Source MAC: 001c.7300.0a05
"""
    engine, inv = _engine_with_neighbors(parse_lldp_neighbors_detail(out))
    engine._extract_neighbors(inv, "SW1", "192.0.2.1", "cisco_xe", 0)
    dev = inv.devices["LEAF-A"]
    assert dev["device_type"] == "arista_eos"
    assert dev["platform"] == "DCS-7280SR3-48YC8"
    assert dev["remote_chassis_id"] == "001c.7300.0a01"


def test_evidence_records_remote_intf():
    """Regression: evidence read remote_port, which parsers never set."""
    engine, inv = _engine_with_neighbors([{
        "remote_device": "SW2", "remote_ip": "192.0.2.6",
        "remote_platform": "cisco WS-C3850-48P",
        "remote_capabilities": "Switch", "remote_intf": "Gi1/0/1",
    }])
    engine._extract_neighbors(inv, "SW1", "192.0.2.1", "cisco_xe", 0)
    assert inv.devices["SW2"]["evidence"][0]["remote_port"] == "Gi1/0/1"


def test_unresolved_neighbour_records_remote_intf():
    engine, inv = _engine_with_neighbors([{
        "remote_ip": "192.0.2.9", "remote_platform": "cisco N9K-C93180YC-EX",
        "remote_capabilities": "Router Switch", "remote_intf": "mgmt0",
    }])
    engine._extract_neighbors(inv, "SW1", "192.0.2.1", "cisco_xe", 0)
    assert inv.devices["SW1"]["unresolved_neighbours"][0]["remote_port"] == "mgmt0"


def test_meraki_is_recorded_but_not_crawled():
    engine, inv = _engine_with_neighbors([{
        "remote_device": "MS-1", "remote_ip": "192.0.2.40",
        "remote_platform": "Meraki MS225-48LP Cloud Managed Switch",
        "remote_capabilities": "Switch", "remote_intf": "Port 1",
    }])
    queued = engine._extract_neighbors(inv, "SW1", "192.0.2.1", "cisco_xe", 0)
    assert "MS-1" in inv.devices
    assert inv.devices["MS-1"]["device_type"] == "meraki"
    assert queued == []


def test_parallel_links_each_record_evidence():
    engine, inv = _engine_with_neighbors([
        {"remote_device": "LEAF-A", "remote_ip": "192.0.2.21",
         "local_intf": "Te1/1/1", "remote_intf": "Ethernet49/1",
         "system_description": ARISTA_DESC, "remote_capabilities": "B,R"},
        {"remote_device": "LEAF-A", "remote_ip": "192.0.2.21",
         "local_intf": "Te1/1/2", "remote_intf": "Ethernet50/1",
         "system_description": ARISTA_DESC, "remote_capabilities": "B,R"},
    ])
    queued = engine._extract_neighbors(inv, "SW1", "192.0.2.1", "cisco_xe", 0)
    ports = {e["remote_port"] for e in inv.devices["LEAF-A"]["evidence"]}
    assert ports == {"Ethernet49/1", "Ethernet50/1"}
    assert ("192.0.2.21", "arista_eos") in queued
