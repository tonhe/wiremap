import pytest
from app.collectors.stp_vlan import StpVlanCollector


@pytest.fixture
def collector():
    return StpVlanCollector()


def test_name_and_attrs(collector):
    assert collector.name == "stp_vlan"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show spanning-tree" in cmds
    assert "show spanning-tree root" in cmds
    assert "show spanning-tree blockedports" in cmds
    assert "show vlan brief" in cmds
    assert "show vtp status" in cmds


def test_get_commands_cisco_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert "show spanning-tree" in cmds
    assert "show vlan brief" in cmds


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert "show spanning-tree bridge" in cmds
    assert "show vlans" in cmds


def test_get_commands_unknown(collector):
    cmds = collector.get_commands("some_unknown")
    assert len(cmds) >= 3


def test_parse_empty_outputs(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    result = collector.parse(raw, "cisco_ios")
    assert "spanning_tree" in result
    assert "spanning_tree_root" in result
    assert "blocked_ports" in result
    assert "vlans" in result
    assert "vtp_status" in result


def test_parse_vlan_brief(collector):
    output = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/1, Gi0/2
10   USERS                            active    Gi0/3, Gi0/4
20   SERVERS                          active    Gi0/5"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show vlan brief"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "vlans" in result


def test_parse_spanning_tree(collector):
    output = """VLAN0001
  Spanning tree enabled protocol ieee
  Root ID    Priority    32769
             Address     0050.56aa.0001
  Bridge ID  Priority    32769
             Address     0050.56aa.0002"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show spanning-tree"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "spanning_tree" in result


def test_parse_vtp_status(collector):
    output = """VTP Version capable             : 1 to 3
VTP version running             : 1
VTP Domain Name                 : MYDOMAIN
VTP Pruning Mode                : Disabled
VTP Traps Generation            : Disabled
Configuration last modified by 10.0.0.1"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show vtp status"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "vtp_status" in result
