from app.parsers import (
    _platform_from_lldp_description,
    merge_neighbor_info,
    parse_cdp_neighbors_detail,
    parse_lldp_neighbors_detail,
)

# Shape of IOS-XE 17.x `show lldp neighbors detail`: a capability legend,
# ---- separators, Local Intf first, wrapped System Description, Peer Source
# MAC after the record body, and a Total entries footer.
IOS_XE_LLDP_DETAIL = """
Capability codes:
    (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
    (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other

------------------------------------------------
Local Intf: Te1/1/1
Local Intf service instance: -
Chassis id: 001c.7300.0a01
Port id: Ethernet49/1
Port Description: uplink to SW1
System Name: LEAF-A.example.net

System Description:
Arista Networks EOS version 4.30.1F running on an Arista Networks
DCS-7280SR3-48YC8

Time remaining: 102 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 192.0.2.21
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised

Peer Source MAC: 001c.7300.0a05

------------------------------------------------
Local Intf: Te1/1/2
Local Intf service instance: -
Chassis id: 001c.7300.0a01
Port id: Ethernet50/1
Port Description: uplink to SW1
System Name: LEAF-A.example.net

System Description:
Arista Networks EOS version 4.30.1F running on an Arista Networks
DCS-7280SR3-48YC8

Time remaining: 98 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 192.0.2.21
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised

Peer Source MAC: 001c.7300.0a06

------------------------------------------------
Local Intf: Gi1/0/48
Local Intf service instance: -
Chassis id: 00aa.bb00.0c01
Port id: Gi2/0/1
Port Description: GigabitEthernet2/0/1
System Name: DIST-1

System Description:
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4, RELEASE SOFTWARE (fc5)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Wed 26-Jul-23 10:20 by mcpre

Time remaining: 110 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 192.0.2.1
Auto Negotiation - supported, enabled
Physical media capabilities:
    1000baseT(FD)
    100base-TX(FD)
Media Attachment Unit type: 30
Vlan ID: 1

Peer Source MAC: 00aa.bb00.0c30


Total entries displayed: 3
"""

NXOS_LLDP_DETAIL = """
Chassis id: 00be.7500.0001
Port id: Eth1/1
Local Port id: Eth1/49
Port Description: Ethernet1/1
System Name: N9K-B
System Description: Cisco Nexus Operating System (NX-OS) Software 9.3(8)
TAC support: http://www.cisco.com/tac
Copyright (c) 2002-2021, Cisco Systems, Inc. All rights reserved.
Time remaining: 99 seconds
System Capabilities: B, R
Enabled Capabilities: B, R
Management Address: 198.51.100.5
Management Address IPV6: not advertised
Vlan ID: 1

Chassis id: 00be.7500.0002
Port id: Eth1/2
Local Port id: Eth1/50
Port Description: Ethernet1/2
System Name: N9K-C
System Description: Cisco Nexus Operating System (NX-OS) Software 9.3(8)
Time remaining: 99 seconds
System Capabilities: B, R
Enabled Capabilities: B, R
Management Address: 198.51.100.6
Vlan ID: 1

Total entries displayed: 2
"""


def _by_local(neighbors):
    return {n["local_intf"]: n for n in neighbors}


def test_ios_xe_records_split_on_separator():
    neighbors = parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL)
    assert len(neighbors) == 3
    assert set(_by_local(neighbors)) == {"Te1/1/1", "Te1/1/2", "Gi1/0/48"}


def test_description_does_not_swallow_next_record():
    """Regression: the description ran on into the next record's header and
    that record lost its local interface."""
    neighbors = _by_local(parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL))
    arista = neighbors["Te1/1/1"]
    assert arista["system_description"] == (
        "Arista Networks EOS version 4.30.1F running on an Arista Networks "
        "DCS-7280SR3-48YC8")
    assert "Peer Source MAC" not in arista["system_description"]
    assert "Local Intf" not in arista["system_description"]
    cisco = neighbors["Gi1/0/48"]
    assert cisco["system_description"].startswith("Cisco IOS Software")
    assert "Total entries" not in cisco["system_description"]
    assert "Time remaining" not in cisco["system_description"]


def test_ios_xe_fields_per_record():
    n = _by_local(parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL))["Te1/1/2"]
    assert n["remote_device"] == "LEAF-A"
    assert n["remote_intf"] == "Ethernet50/1"
    assert n["remote_ip"] == "192.0.2.21"
    assert n["remote_capabilities"] == "B,R"
    assert n["chassis_id"] == "001c.7300.0a01"


def test_service_instance_line_is_not_an_interface():
    for n in parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL):
        assert n["local_intf"] != "-"
        assert "service" not in n["local_intf"]


def test_platform_is_model_from_description_never_chassis_mac():
    neighbors = _by_local(parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL))
    assert neighbors["Te1/1/1"]["remote_platform"] == "DCS-7280SR3-48YC8"
    # No model in a CAT9K description: leave it empty, not the chassis MAC.
    assert neighbors["Gi1/0/48"]["remote_platform"] == ""


def test_nxos_output_without_separators():
    neighbors = parse_lldp_neighbors_detail(NXOS_LLDP_DETAIL)
    assert len(neighbors) == 2
    first = neighbors[0]
    assert first["local_intf"] == "Eth1/49"
    assert first["remote_intf"] == "Eth1/1"
    assert first["remote_ip"] == "198.51.100.5"
    assert first["system_description"].endswith("All rights reserved.")
    assert neighbors[1]["remote_device"] == "N9K-C"
    assert neighbors[1]["remote_ip"] == "198.51.100.6"


def test_legacy_local_port_id_still_parsed():
    out = """
Chassis id: 0011.2233.4455
Port id: Gi0/3
Local Port id: Gi0/1
System Name: SW3
System Capabilities: B
"""
    n = parse_lldp_neighbors_detail(out)[0]
    assert n["local_intf"] == "Gi0/1"
    assert n["remote_intf"] == "Gi0/3"


def test_empty_output():
    assert parse_lldp_neighbors_detail("") == []
    assert parse_lldp_neighbors_detail(None) == []


def test_platform_from_description_variants():
    f = _platform_from_lldp_description
    assert f("Arista Networks EOS version 4.28.3M running on an Arista "
             "DCS-7050SX3-48YC8") == "DCS-7050SX3-48YC8"
    assert f("cisco C9300-48P running IOS-XE") == "C9300-48P"
    assert f("Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), "
             "Version 15.2(4)E10") == "C3750E"
    assert f("Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel "
             "JUNOS 21.4R3") == "ex4300-48t"
    assert f("Cisco Nexus Operating System (NX-OS) Software 9.3(8)") == ""
    assert f("") == ""
    assert f(None) == ""


# --- merge -----------------------------------------------------------------

CDP_TWO_LINKS = """
-------------------------
Device ID: LEAF-A.example.net
Entry address(es):
  IP address: 192.0.2.21
Platform: Arista DCS-7280SR3-48YC8,  Capabilities: Router Switch
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): Ethernet49/1
-------------------------
Device ID: LEAF-A.example.net
Entry address(es):
  IP address: 192.0.2.21
Platform: Arista DCS-7280SR3-48YC8,  Capabilities: Router Switch
Interface: TenGigabitEthernet1/1/2,  Port ID (outgoing port): Ethernet50/1
"""


def test_parallel_links_to_same_neighbor_survive_merge():
    """Regression: two links to one neighbour collapsed into one record."""
    lldp = parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL)
    merged = merge_neighbor_info([], lldp)
    leaf = [n for n in merged if n["remote_device"] == "LEAF-A"]
    assert len(leaf) == 2
    assert {n["remote_intf"] for n in leaf} == {"Ethernet49/1", "Ethernet50/1"}


def test_cdp_and_lldp_sightings_of_one_link_merge():
    cdp = parse_cdp_neighbors_detail(CDP_TWO_LINKS)
    lldp = parse_lldp_neighbors_detail(IOS_XE_LLDP_DETAIL)
    merged = merge_neighbor_info(cdp, lldp)
    leaf = [n for n in merged if n["remote_device"] == "LEAF-A"]
    assert len(leaf) == 2
    for n in leaf:
        # Regression: protocols came out as ["CDP", "LLDP", "LLDP"].
        assert n["protocols"] == ["CDP", "LLDP"]
        assert n["system_description"].startswith("Arista Networks EOS")
    assert len(merged) == 3


def test_cdp_serial_suffix_still_matches_lldp_name():
    cdp = [{"remote_device": "N9K-B(FDO00000001)", "local_intf": "Ethernet1/49",
            "remote_intf": "Ethernet1/1", "remote_platform": "N9K-C93180YC-EX"}]
    lldp = [{"remote_device": "N9K-B", "local_intf": "Eth1/49",
             "remote_intf": "Eth1/1", "system_description": "NX-OS"}]
    merged = merge_neighbor_info(cdp, lldp)
    assert len(merged) == 1
    assert merged[0]["protocols"] == ["CDP", "LLDP"]


def test_lldp_fills_cdp_gaps_without_overwriting_platform():
    cdp = [{"remote_device": "SW2", "local_intf": "GigabitEthernet0/1",
            "remote_intf": "GigabitEthernet0/2", "remote_platform": "cisco WS-C3750"}]
    lldp = [{"remote_device": "SW2", "local_intf": "Gi0/1", "remote_intf": "Gi0/2",
             "remote_ip": "192.0.2.2", "remote_platform": "", "chassis_id": "0011.2233.4455"}]
    n = merge_neighbor_info(cdp, lldp)[0]
    assert n["remote_platform"] == "cisco WS-C3750"
    assert n["remote_ip"] == "192.0.2.2"
    assert n["chassis_id"] == "0011.2233.4455"


def test_lldp_matches_cdp_when_remote_port_spelled_differently():
    """Some peers advertise a port description as the LLDP port id. Same
    local port and same neighbour is still the same link."""
    cdp = [{"remote_device": "SW2", "local_intf": "GigabitEthernet0/1",
            "remote_intf": "GigabitEthernet0/2"}]
    lldp = [{"remote_device": "SW2", "local_intf": "Gi0/1",
             "remote_intf": "uplink-port"}]
    merged = merge_neighbor_info(cdp, lldp)
    assert len(merged) == 1
    assert merged[0]["protocols"] == ["CDP", "LLDP"]


def test_l3_protocol_added_once():
    cdp = [{"remote_device": "RTR-A", "remote_ip": "203.0.113.1",
            "local_intf": "Gi0/0", "remote_intf": "Gi0/0"}]
    l3 = [{"remote_ip": "203.0.113.1", "protocol": "OSPF", "local_intf": "Gi0/0"},
          {"remote_ip": "203.0.113.1", "protocol": "OSPF", "local_intf": "Gi0/0"},
          {"remote_ip": "203.0.113.9", "protocol": "BGP"}]
    merged = merge_neighbor_info(cdp, [], l3)
    rtr = [n for n in merged if n.get("remote_device") == "RTR-A"][0]
    assert rtr["protocols"] == ["CDP", "OSPF"]
    assert any(n.get("remote_ip") == "203.0.113.9" for n in merged)
