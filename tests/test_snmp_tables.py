"""SNMP standard-MIB table collection.

The walk function is injected, so these exercise real OID layouts without
touching a network.
"""
from app.snmp_tables import (
    collect_all, collect_arp, collect_cdp_neighbors, collect_interfaces,
    collect_ip_addresses, collect_lldp_neighbors, collect_routes,
    index_of, build_rows, IF_COLUMNS,
)

# A small Firebox-shaped device: two physical ports, one loopback.
WALK_DATA = {
    # ifDescr
    "1.3.6.1.2.1.2.2.1.2.1": "eth0",
    "1.3.6.1.2.1.2.2.1.2.2": "eth1",
    "1.3.6.1.2.1.2.2.1.2.3": "lo",
    # ifType -- 6 ethernet, 24 softwareLoopback
    "1.3.6.1.2.1.2.2.1.3.1": "6",
    "1.3.6.1.2.1.2.2.1.3.2": "6",
    "1.3.6.1.2.1.2.2.1.3.3": "24",
    # ifSpeed
    "1.3.6.1.2.1.2.2.1.5.1": "1000000000",
    "1.3.6.1.2.1.2.2.1.5.2": "1000000000",
    # ifAdminStatus / ifOperStatus
    "1.3.6.1.2.1.2.2.1.7.1": "1",
    "1.3.6.1.2.1.2.2.1.8.1": "1",
    "1.3.6.1.2.1.2.2.1.7.2": "1",
    "1.3.6.1.2.1.2.2.1.8.2": "2",
    # ifName / ifAlias / ifHighSpeed
    "1.3.6.1.2.1.31.1.1.1.1.1": "External",
    "1.3.6.1.2.1.31.1.1.1.1.2": "Trusted",
    "1.3.6.1.2.1.31.1.1.1.18.1": "WAN uplink",
    "1.3.6.1.2.1.31.1.1.1.15.1": "1000",
    # ipAddrTable
    "1.3.6.1.2.1.4.20.1.1.12.202.247.129": "12.202.247.129",
    "1.3.6.1.2.1.4.20.1.2.12.202.247.129": "1",
    "1.3.6.1.2.1.4.20.1.3.12.202.247.129": "255.255.255.252",
    "1.3.6.1.2.1.4.20.1.1.10.254.254.1": "10.254.254.1",
    "1.3.6.1.2.1.4.20.1.2.10.254.254.1": "2",
    "1.3.6.1.2.1.4.20.1.3.10.254.254.1": "255.255.255.0",
    # ipCidrRouteTable -- default route plus a connected
    "1.3.6.1.2.1.4.24.4.1.1.0.0.0.0.0": "0.0.0.0",
    "1.3.6.1.2.1.4.24.4.1.2.0.0.0.0.0": "0.0.0.0",
    "1.3.6.1.2.1.4.24.4.1.4.0.0.0.0.0": "12.202.247.130",
    "1.3.6.1.2.1.4.24.4.1.5.0.0.0.0.0": "1",
    "1.3.6.1.2.1.4.24.4.1.7.0.0.0.0.0": "2",
    "1.3.6.1.2.1.4.24.4.1.11.0.0.0.0.0": "1",
    "1.3.6.1.2.1.4.24.4.1.1.10.254.254.0.1": "10.254.254.0",
    "1.3.6.1.2.1.4.24.4.1.2.10.254.254.0.1": "255.255.255.0",
    "1.3.6.1.2.1.4.24.4.1.4.10.254.254.0.1": "0.0.0.0",
    "1.3.6.1.2.1.4.24.4.1.5.10.254.254.0.1": "2",
    "1.3.6.1.2.1.4.24.4.1.7.10.254.254.0.1": "2",
    # ipNetToMediaTable
    "1.3.6.1.2.1.4.22.1.2.2.10.254.254.5": "00:1b:17:aa:bb:cc",
    "1.3.6.1.2.1.4.22.1.3.2.10.254.254.5": "10.254.254.5",
    # lldpRemTable -- index is timeMark.localPortNum.remIndex
    "1.0.8802.1.1.2.1.4.1.1.9.0.2.1": "DCN5K-8A",
    "1.0.8802.1.1.2.1.4.1.1.7.0.2.1": "Eth1/20",
    "1.0.8802.1.1.2.1.4.1.1.8.0.2.1": "Ethernet1/20",
    "1.0.8802.1.1.2.1.4.1.1.5.0.2.1": "00:1b:17:dd:ee:ff",
    "1.0.8802.1.1.2.1.4.1.1.10.0.2.1": "Cisco Nexus Operating System",
    # lldpLocPortTable
    "1.0.8802.1.1.2.1.3.7.1.3.2": "Trusted",
    "1.0.8802.1.1.2.1.3.7.1.4.2": "Trusted interface",
}


def walk(oid):
    prefix = oid.rstrip(".") + "."
    return {k: v for k, v in WALK_DATA.items() if k.startswith(prefix)}


def test_index_of_extracts_row_index():
    assert index_of("1.3.6.1.2.1.2.2.1.2.7", "1.3.6.1.2.1.2.2.1.2") == "7"
    assert index_of("1.3.6.1.2.1.4.20.1.1.10.0.0.1",
                    "1.3.6.1.2.1.4.20.1.1") == "10.0.0.1"


def test_index_of_ignores_other_columns():
    assert index_of("1.3.6.1.2.1.2.2.1.3.7", "1.3.6.1.2.1.2.2.1.2") == ""


def test_build_rows_collates_columns_by_index():
    rows = build_rows(walk("1.3.6.1.2.1.2.2.1.2"), {"ifDescr": IF_COLUMNS["ifDescr"]})
    assert rows["1"]["ifDescr"] == "eth0"
    assert rows["3"]["ifDescr"] == "lo"


def test_interfaces_prefer_ifname_over_ifdescr():
    """ifName is the operator-facing name; ifDescr is often the kernel name."""
    interfaces = collect_interfaces(walk)
    names = [i["port"] for i in interfaces]
    assert "External" in names
    assert "Trusted" in names
    assert "eth0" not in names


def test_loopback_is_excluded():
    assert "lo" not in [i["port"] for i in collect_interfaces(walk)]


def test_interface_status_and_alias():
    external = [i for i in collect_interfaces(walk) if i["port"] == "External"][0]
    assert external["status"] == "up"
    assert external["admin_status"] == "up"
    assert external["name"] == "WAN uplink"


def test_interface_down_state_reported():
    trusted = [i for i in collect_interfaces(walk) if i["port"] == "Trusted"][0]
    assert trusted["status"] == "down"


def test_speed_prefers_ifhighspeed():
    external = [i for i in collect_interfaces(walk) if i["port"] == "External"][0]
    assert external["speed"] == "1000 Mbps"


def test_speed_falls_back_to_ifspeed():
    trusted = [i for i in collect_interfaces(walk) if i["port"] == "Trusted"][0]
    assert trusted["speed"] == "1000 Mbps"


def test_ip_addresses_resolve_interface_names():
    interfaces = collect_interfaces(walk)
    names = {i["if_index"]: i["port"] for i in interfaces}
    addresses = collect_ip_addresses(walk, names)
    by_ip = {a["ipaddr"]: a for a in addresses}
    assert by_ip["12.202.247.129"]["intf"] == "External"
    assert by_ip["10.254.254.1"]["intf"] == "Trusted"


def test_netmask_converted_to_prefix_length():
    addresses = collect_ip_addresses(walk)
    by_ip = {a["ipaddr"]: a for a in addresses}
    assert by_ip["12.202.247.129"]["prefix_length"] == "30"
    assert by_ip["10.254.254.1"]["prefix_length"] == "24"


def test_default_route_identifies_the_circuit():
    """Which circuit a site actually uses is the point of collecting routes."""
    routes = collect_routes(walk, {"1": "External", "2": "Trusted"})
    default = [r for r in routes if r["network"] == "0.0.0.0"][0]
    assert default["nexthop_ip"] == "12.202.247.130"
    assert default["interface"] == "External"
    assert default["protocol"] == "local"


def test_connected_route_has_no_nexthop():
    routes = collect_routes(walk)
    connected = [r for r in routes if r["network"] == "10.254.254.0"][0]
    assert connected["nexthop_ip"] == ""


def test_arp_entries_collected():
    entries = collect_arp(walk, {"2": "Trusted"})
    assert len(entries) == 1
    assert entries[0]["ip"] == "10.254.254.5"
    assert entries[0]["mac"] == "00:1b:17:aa:bb:cc"
    assert entries[0]["interface"] == "Trusted"


def test_lldp_gives_a_port_name_at_both_ends():
    """The reason to collect LLDP over SNMP at all."""
    neighbors = collect_lldp_neighbors(walk, {"2": "Trusted"})
    assert len(neighbors) == 1
    n = neighbors[0]
    assert n["local_intf"] == "Trusted interface"
    assert n["remote_device"] == "DCN5K-8A"
    assert n["remote_intf"] == "Ethernet1/20"
    assert n["source"] == "snmp"


def test_cdp_hex_address_decoded():
    cdp = {
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6.2.1": "SW-CORE-01",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7.2.1": "GigabitEthernet1/0/1",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4.2.1": "0x0a01010a",
    }
    neighbors = collect_cdp_neighbors(
        lambda oid: {k: v for k, v in cdp.items() if k.startswith(oid.rstrip(".") + ".")},
        {"2": "eth1"})
    assert neighbors[0]["remote_ip"] == "10.1.1.10"
    assert neighbors[0]["remote_device"] == "SW-CORE-01"


def test_collect_all_shapes_data_like_the_cli_collectors():
    """Reports must consume SNMP data without knowing where it came from."""
    data = collect_all(walk)
    assert set(data) >= {"interfaces", "l3_routing", "arp", "cdp_lldp"}
    assert data["interfaces"]["interfaces_status"]
    assert data["interfaces"]["ip_interfaces"]
    assert data["l3_routing"]["routes"]
    assert data["arp"]["entries"]
    assert data["cdp_lldp"]["neighbors"]


def test_collect_all_marks_its_origin():
    for section in collect_all(walk).values():
        assert section["collected_via"] == "snmp"


def test_collect_all_on_silent_device_returns_nothing():
    assert collect_all(lambda oid: {}) == {}


def test_walk_failure_does_not_abort_collection():
    """One unsupported table must not lose the others."""
    def flaky(oid):
        if oid.startswith("1.3.6.1.2.1.4.24"):
            raise OSError("noSuchName")
        return walk(oid)

    data = collect_all(flaky)
    assert "interfaces" in data
    assert "l3_routing" not in data
