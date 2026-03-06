import pytest
from app.collectors.arp import ArpCollector


@pytest.fixture
def collector():
    return ArpCollector()


def test_name_and_attrs(collector):
    assert collector.name == "arp"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert cmds == ["show ip arp"]


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert cmds == ["show arp"]


def test_get_commands_extreme(collector):
    cmds = collector.get_commands("extreme")
    assert cmds == ["show iparp"]


def test_get_commands_unknown_device(collector):
    cmds = collector.get_commands("some_unknown")
    assert cmds == ["show ip arp"]


def test_parse_empty_output(collector):
    result = collector.parse({"show ip arp": ""}, "cisco_ios")
    assert "entries" in result
    assert result["entries"] == []


def test_parse_cisco_ios_output(collector):
    arp_output = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.1.1.100            15  0050.56aa.bb01  ARPA   GigabitEthernet0/1
Internet  10.1.1.101             5  0050.56aa.bb02  ARPA   GigabitEthernet0/2"""
    result = collector.parse({"show ip arp": arp_output}, "cisco_ios")
    assert len(result["entries"]) == 2
    assert result["entries"][0]["ip"] == "10.1.1.100"
    assert result["entries"][0]["interface"] == "GigabitEthernet0/1"


def test_parse_juniper_output(collector):
    arp_output = """MAC Address       Address         Name      Interface        Flags
00:50:56:aa:bb:cc 10.1.1.100      host1     ge-0/0/1.0       none"""
    result = collector.parse({"show arp": arp_output}, "juniper_junos")
    assert len(result["entries"]) == 1
    assert result["entries"][0]["ip"] == "10.1.1.100"
