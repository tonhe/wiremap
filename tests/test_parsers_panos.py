from app.parsers_panos import parse_routes, parse_lldp_neighbors

ROUTES = """flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp, E:ecmp, M:multicast

VIRTUAL ROUTER: default (id 1)
  ==========
destination         nexthop         metric flags   age     interface         next-AS
0.0.0.0/0           203.0.113.1    10     A S             ethernet1/1
10.1.0.0/16         10.1.1.2        10     A B             ethernet1/2       65001
172.21.0.0/24       0.0.0.0         0      A C             ethernet1/3
172.21.0.10/32      0.0.0.0         0      A H             ethernet1/3
192.168.50.0/24     10.1.1.9        110    A Oi            ethernet1/2

total routes shown: 5
"""

LLDP_BLOCKS = """LLDP neighbors:
------------------------------------------------------------------------
Interface: ethernet1/1
  Chassis ID: 00:1b:17:aa:bb:cc  (MAC address)
  Port ID: GigabitEthernet1/0/24  (Interface name)
  System Name: N5K-8A
  System Description: Cisco Nexus Operating System
  Management Address: 172.21.0.20
  System Capabilities: Bridge, Router
------------------------------------------------------------------------
Interface: ethernet1/2
  Chassis ID: 00:1b:17:dd:ee:ff  (MAC address)
  Port ID: Ethernet1/5  (Interface name)
  System Name: N5K-8B
"""

LLDP_TABLE = """Local Interface   Remote Chassis ID     Port ID          System Name
ethernet1/1       00:1b:17:aa:bb:cc     Gi1/0/24         N5K-8A
ethernet1/2       00:1b:17:dd:ee:ff     Eth1/5           N5K-8B
"""


def test_parses_all_routes():
    routes = parse_routes(ROUTES)
    assert len(routes) == 5


def test_default_route_carries_nexthop_and_interface():
    route = [r for r in parse_routes(ROUTES) if r["network"] == "0.0.0.0"][0]
    assert route["prefix_length"] == "0"
    assert route["nexthop_ip"] == "203.0.113.1"
    assert route["interface"] == "ethernet1/1"
    assert route["protocol"] == "static"


def test_connected_route_has_no_nexthop():
    """0.0.0.0 as nexthop means connected, not a real gateway."""
    route = [r for r in parse_routes(ROUTES) if r["network"] == "172.21.0.0"][0]
    assert route["nexthop_ip"] == ""
    assert route["protocol"] == "connected"


def test_protocols_are_identified():
    by_net = {r["network"]: r["protocol"] for r in parse_routes(ROUTES)}
    assert by_net["10.1.0.0"] == "bgp"
    assert by_net["192.168.50.0"] == "ospf"
    assert by_net["172.21.0.10"] == "host"


def test_virtual_router_recorded():
    assert all(r["vrf"] == "default" for r in parse_routes(ROUTES))


def test_route_legend_and_totals_ignored():
    for route in parse_routes(ROUTES):
        assert route["network"][0].isdigit()


def test_empty_route_output():
    assert parse_routes("") == []
    assert parse_routes("total routes shown: 0") == []


def test_lldp_block_format_gives_both_port_names():
    """Ports at both ends are the whole point of collecting this."""
    neighbors = parse_lldp_neighbors(LLDP_BLOCKS)
    assert len(neighbors) == 2
    first = neighbors[0]
    assert first["local_intf"] == "ethernet1/1"
    assert first["remote_intf"] == "GigabitEthernet1/0/24"
    assert first["remote_device"] == "N5K-8A"
    assert first["remote_ip"] == "172.21.0.20"


def test_lldp_strips_annotations():
    first = parse_lldp_neighbors(LLDP_BLOCKS)[0]
    assert "(MAC address)" not in first["remote_chassis_id"]
    assert "(Interface name)" not in first["remote_intf"]


def test_lldp_table_format():
    neighbors = parse_lldp_neighbors(LLDP_TABLE)
    assert len(neighbors) == 2
    assert neighbors[0]["local_intf"] == "ethernet1/1"
    assert neighbors[0]["remote_intf"] == "Gi1/0/24"
    assert neighbors[0]["remote_device"] == "N5K-8A"


def test_lldp_header_not_parsed_as_neighbour():
    for n in parse_lldp_neighbors(LLDP_TABLE):
        assert n["local_intf"].lower().startswith("ethernet")


def test_lldp_empty_output():
    assert parse_lldp_neighbors("") == []
    assert parse_lldp_neighbors("LLDP neighbors:\n") == []
