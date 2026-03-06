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
    assert len(cmds) == 7


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
    for entry in summary:
        if entry["source"] == "connected":
            assert entry["count"] == 5
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
