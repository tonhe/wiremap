import pytest
from app.collectors.l3_routing import L3RoutingCollector


@pytest.fixture
def collector():
    return L3RoutingCollector()


def test_name_and_attrs(collector):
    assert collector.name == "l3_routing"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show ip ospf neighbor" in cmds
    assert "show ip eigrp neighbors" in cmds
    assert "show ip bgp neighbors" in cmds
    assert "show isis neighbors" in cmds
    assert "show ip route" in cmds
    assert "show ip protocols" in cmds


def test_get_commands_cisco_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert "show ip ospf neighbors" in cmds
    assert "show bgp ipv4 unicast neighbors" in cmds
    assert "show isis adjacency" in cmds


def test_get_commands_arista_no_eigrp(collector):
    cmds = collector.get_commands("arista_eos")
    assert "show ip eigrp neighbors" not in cmds
    assert "show ip ospf neighbor" in cmds


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert "show ospf neighbor" in cmds
    assert "show route" in cmds


def test_get_commands_unknown_device_gets_defaults(collector):
    cmds = collector.get_commands("some_unknown_type")
    assert len(cmds) >= 4


def test_parse_empty_outputs(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    result = collector.parse(raw, "cisco_ios")
    assert "neighbors" in result
    assert "routes" in result
    assert result["neighbors"] == []


def test_parse_ospf_output(collector):
    ospf_output = """Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.1          1   FULL/DR         00:00:39    10.1.1.1        GigabitEthernet0/1"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip ospf neighbor"] = ospf_output
    result = collector.parse(raw, "cisco_ios")
    assert len(result["neighbors"]) == 1
    assert result["neighbors"][0]["protocol"] == "OSPF"
    assert result["neighbors"][0]["remote_ip"] == "10.1.1.1"


def test_parse_bgp_output(collector):
    bgp_output = """BGP neighbor is 10.0.0.2,  remote AS 65001, internal link
  BGP state = Established, up for 1d2h
  Local host: 10.0.0.1, Local port: 179"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip bgp neighbors"] = bgp_output
    result = collector.parse(raw, "cisco_ios")
    assert len(result["neighbors"]) == 1
    assert result["neighbors"][0]["protocol"] == "BGP"


def test_parse_route_output_stored_in_routes(collector):
    route_output = """Codes: C - connected, S - static, R - RIP
Gateway of last resort is 10.0.0.1 to network 0.0.0.0

C    10.1.1.0/24 is directly connected, GigabitEthernet0/1
S    192.168.0.0/16 [1/0] via 10.0.0.1"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip route"] = route_output
    result = collector.parse(raw, "cisco_ios")
    assert "routes" in result


def test_parse_protocols_stored_raw(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip protocols"] = "Routing Protocol is ospf 1"
    result = collector.parse(raw, "cisco_ios")
    assert result["ip_protocols_raw"] == "Routing Protocol is ospf 1"
