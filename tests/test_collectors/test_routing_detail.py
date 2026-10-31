import pytest
from app.collectors.routing_detail import RoutingDetailCollector


@pytest.fixture
def collector():
    return RoutingDetailCollector()


def test_attrs(collector):
    assert collector.name == "routing_detail"
    assert collector.label == "Routing Detail"
    assert collector.enabled_by_default is True


def test_get_commands_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show ip route summary" in cmds
    assert "show ip ospf" in cmds
    assert "show ip ospf interface brief" in cmds
    assert "show ip bgp summary" in cmds
    assert "show ip eigrp topology" in cmds
    assert "show ip eigrp neighbors detail" in cmds
    assert "show ip bgp" in cmds
    assert "show bgp vpnv4 unicast all summary" in cmds
    # older IOS fallback syntax
    assert "show ip bgp vpnv4 all summary" in cmds
    assert "show ip ospf database database-summary" in cmds
    assert "show ip eigrp topology summary" in cmds
    assert len(cmds) == 13


def test_get_commands_xe_has_vpnv4_without_old_fallback(collector):
    cmds = collector.get_commands("cisco_xe")
    assert "show bgp vpnv4 unicast all summary" in cmds
    assert "show ip bgp vpnv4 all summary" not in cmds


def test_get_commands_nxos_vrf_all(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert "show bgp vrf all all summary" in cmds
    assert "show ip route summary vrf all" in cmds


def test_get_commands_unknown_platform_skips_vpnv4(collector):
    cmds = collector.get_commands("some_unknown_os")
    assert "show ip bgp summary" in cmds
    assert not any("vpnv4" in c for c in cmds)


def test_parse_empty(collector):
    result = collector.parse({}, "cisco_ios")
    assert result["route_summary"] == []
    assert result["ospf_processes"] == []
    assert result["ospf_interfaces"] == []
    assert result["bgp_summary"] == []
    assert result["eigrp_topology"] == []
    assert result["eigrp_neighbors"] == []
    assert result["bgp_table"] == []


def test_parse_route_summary(collector):
    raw = """IP routing table name is default (0x0)
IP routing table maximum-paths is 32
Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
connected       5           5           0           0           0
static          2           2           0           0           0
ospf 1          15          12          3           0           0
  Intra-area: 8 Inter-area: 4 External-1: 0 External-2: 3
bgp 65001       30          25          5           0           0
  Internal: 10 External: 20
Total           52          44          8           0           0"""

    result = collector.parse({"show ip route summary": raw}, "cisco_ios")
    summary = result["route_summary"]
    assert len(summary) >= 3
    sources = [s["source"] for s in summary]
    assert "connected" in sources
    assert "static" in sources
    # Check a count value
    # A source's route count is networks + subnets
    for entry in summary:
        if entry["source"] == "connected":
            assert entry["count"] == 10
            break


def test_parse_bgp_summary(collector):
    raw = """BGP router identifier 10.0.0.1, local AS number 65001
BGP table version is 120, main routing table version 120
50 network entries using 7200 bytes of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65002     100     120       50    0    0 01:02:03  300
10.0.0.3        4 65003      80      90       50    0    0 00:45:00  Active"""

    result = collector.parse({"show ip bgp summary": raw}, "cisco_ios")
    bgp = result["bgp_summary"]
    assert len(bgp) == 2
    assert bgp[0]["neighbor"] == "10.0.0.2"
    assert bgp[0]["asn"] == "65002"
    assert bgp[0]["prefixes_received"] == 300
    assert bgp[0]["state"] == "Established"
    assert bgp[1]["neighbor"] == "10.0.0.3"
    assert bgp[1]["state"] == "Active"


# --- BGP in VRFs (issue #9) ---

_GLOBAL_SUMMARY = """BGP router identifier 10.255.0.1, local AS number 64500
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.255.0.2      4        64500    1200    1199       25    0    0 18:01:12        6"""

_VPNV4_SUMMARY = """BGP router identifier 10.255.0.1, local AS number 64500
BGP table version is 25, main routing table version 25
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.255.0.2      4        64500    1200    1199       25    0    0 18:01:12        6
192.0.2.1       4        64496    1500    1400       25    0    0 1w2d            4
198.51.100.1    4        64497       0       0        1    0    0 never    Idle (Admin)
10.9.9.1        4        64501     300     310       25    0    0 2d01h           2
10.9.9.1        4        64502     300     310       25    0    0 2d01h           3"""

_VPNV4_NEIGHBORS = """BGP neighbor is 10.255.0.2,  remote AS 64500, internal link
BGP neighbor is 192.0.2.1,  vrf INET,  remote AS 64496, external link
BGP neighbor is 198.51.100.1,  vrf INET,  remote AS 64497, external link
BGP neighbor is 10.9.9.1,  vrf CUST-A,  remote AS 64501, external link
BGP neighbor is 10.9.9.1,  vrf CUST-B,  remote AS 64502, external link"""


def _peer(peers, neighbor, vrf):
    for p in peers:
        if p["neighbor"] == neighbor and p["vrf"] == vrf:
            return p
    return None


def test_parse_vpnv4_peers_carry_vrf(collector):
    result = collector.parse({
        "show ip bgp summary": _GLOBAL_SUMMARY,
        "show bgp vpnv4 unicast all summary": _VPNV4_SUMMARY,
        "show bgp vpnv4 unicast all neighbors | include BGP neighbor is": _VPNV4_NEIGHBORS,
    }, "cisco_xe")
    peers = result["bgp_summary"]
    # global iBGP peer appears once even though it is in both tables
    assert len([p for p in peers if p["neighbor"] == "10.255.0.2"]) == 1
    assert _peer(peers, "10.255.0.2", "default") is not None
    inet = _peer(peers, "192.0.2.1", "INET")
    assert inet["asn"] == "64496"
    assert inet["prefixes_received"] == 4
    assert inet["state"] == "Established"
    idle = _peer(peers, "198.51.100.1", "INET")
    assert idle["state"] == "Idle (Admin)"
    # same CE address in two VRFs stays two peers
    assert _peer(peers, "10.9.9.1", "CUST-A")["asn"] == "64501"
    assert _peer(peers, "10.9.9.1", "CUST-B")["asn"] == "64502"
    assert len(peers) == 5


def test_parse_vpnv4_rd_headers(collector):
    raw = """For address family: VPNv4 Unicast
Route Distinguisher: 64500:10 (default for vrf WAN)
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
203.0.113.9     4        64498     100     100       25    0    0 01:00:00        7"""
    result = collector.parse({"show bgp vpnv4 unicast all summary": raw}, "cisco_xe")
    peer = result["bgp_summary"][0]
    assert peer["vrf"] == "WAN"
    assert peer["prefixes_received"] == 7


def test_parse_vpnv4_falls_back_to_old_ios_syntax(collector):
    rejected = """                  ^
% Invalid input detected at '^' marker."""
    result = collector.parse({
        "show bgp vpnv4 unicast all summary": rejected,
        "show bgp vpnv4 unicast all neighbors | include BGP neighbor is": rejected,
        "show ip bgp vpnv4 all summary": _VPNV4_SUMMARY,
        "show ip bgp vpnv4 all neighbors | include BGP neighbor is": _VPNV4_NEIGHBORS,
    }, "cisco_ios")
    peers = result["bgp_summary"]
    assert _peer(peers, "192.0.2.1", "INET") is not None
    # error text never becomes a peer row
    assert all(p["neighbor"][0].isdigit() for p in peers)


def test_parse_global_peers_marked_default_vrf(collector):
    result = collector.parse({"show ip bgp summary": _GLOBAL_SUMMARY}, "cisco_ios")
    assert result["bgp_summary"][0]["vrf"] == "default"


def test_parse_nxos_bgp_vrf_all(collector):
    raw = """BGP summary information for VRF default, address family IPv4 Unicast
BGP router identifier 10.255.0.1, local AS number 64500
Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.255.0.2      4 64500     100     120        5    0    0 01:02:03  3

BGP summary information for VRF INET, address family IPv4 Unicast
Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.1       4 64496     100     120        5    0    0 1d02h     12
198.51.100.1    4 64497       0       0        0    0    0 00:10:00  Active

BGP summary information for VRF INET, address family IPv6 Unicast
Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.1       4 64496     100     120        5    0    0 1d02h     4"""
    result = collector.parse({"show bgp vrf all all summary": raw}, "cisco_nxos")
    peers = result["bgp_summary"]
    assert len(peers) == 3
    assert _peer(peers, "192.0.2.1", "INET")["prefixes_received"] == 12
    assert _peer(peers, "198.51.100.1", "INET")["state"] == "Active"
    assert _peer(peers, "10.255.0.2", "default") is not None


def test_parse_nxos_route_summary_vrf_all(collector):
    raw = """IP Route Table for VRF "default"
Total number of routes: 8
Total number of paths:  8

Best paths per protocol:      Backup paths per protocol:
  am             : 2            None
  local          : 3
  direct         : 3

Number of routes per mask-length:
  /24: 3   /32: 5

IP Route Table for VRF "INET"
Total number of routes: 5

Best paths per protocol:      Backup paths per protocol:
  direct         : 1            None
  bgp-64500      : 4
"""
    result = collector.parse({"show ip route summary vrf all": raw}, "cisco_nxos")
    vrs = result["vrf_route_summary"]
    assert set(vrs) == {"default", "INET"}
    assert {"source": "bgp-64500", "count": 4} in vrs["INET"]
    assert {"source": "direct", "count": 3} in vrs["default"]
    assert not any(e["source"].startswith("/") for e in vrs["default"])
