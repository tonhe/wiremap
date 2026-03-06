import pytest
from app.collectors.interfaces import InterfacesCollector


@pytest.fixture
def collector():
    return InterfacesCollector()


def test_name_and_attrs(collector):
    assert collector.name == "interfaces"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show interfaces status" in cmds
    assert "show ip interface brief" in cmds
    assert "show interfaces description" in cmds
    assert "show etherchannel summary" in cmds


def test_get_commands_arista(collector):
    cmds = collector.get_commands("arista_eos")
    assert "show interfaces status" in cmds
    assert "show ip interface brief" in cmds


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert "show interfaces terse" in cmds


def test_get_commands_unknown_device(collector):
    cmds = collector.get_commands("some_unknown")
    assert len(cmds) >= 2


def test_parse_empty_outputs(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    result = collector.parse(raw, "cisco_ios")
    assert "interfaces_status" in result
    assert "ip_interfaces" in result
    assert result["interfaces_status"] == []


def test_parse_ip_interface_brief(collector):
    output = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     10.1.1.1        YES NVRAM  up                    up
GigabitEthernet0/2     unassigned      YES NVRAM  administratively down down"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip interface brief"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "ip_interfaces" in result


def test_parse_etherchannel(collector):
    output = """Flags:  D - down        P - bundled in port-channel
Group  Port-channel  Protocol    Ports
------+-------------+-----------+-------
1      Po1(SU)         LACP      Gi0/1(P)    Gi0/2(P)"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show etherchannel summary"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "etherchannel" in result
