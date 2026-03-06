import pytest
from app.collectors.mac_table import MacTableCollector


@pytest.fixture
def collector():
    return MacTableCollector()


def test_name_and_attrs(collector):
    assert collector.name == "mac_table"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert cmds == ["show mac address-table"]


def test_get_commands_arista(collector):
    cmds = collector.get_commands("arista_eos")
    assert cmds == ["show mac address-table"]


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert cmds == ["show ethernet-switching table"]


def test_get_commands_unknown(collector):
    cmds = collector.get_commands("some_unknown")
    assert cmds == ["show mac address-table"]


def test_parse_empty_output(collector):
    result = collector.parse({"show mac address-table": ""}, "cisco_ios")
    assert "entries" in result
    assert result["entries"] == []


def test_parse_cisco_ios_output(collector):
    output = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0050.56aa.bb01    DYNAMIC     Gi0/1
  10    0050.56aa.bb02    DYNAMIC     Gi0/2
Total Mac Addresses for this criterion: 2"""
    result = collector.parse({"show mac address-table": output}, "cisco_ios")
    assert "entries" in result
