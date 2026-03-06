import pytest
from app.collectors.cdp_lldp import CdpLldpCollector


@pytest.fixture
def collector():
    return CdpLldpCollector()


def test_name_and_attrs(collector):
    assert collector.name == "cdp_lldp"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show cdp neighbors detail" in cmds
    assert "show lldp neighbors detail" in cmds


def test_get_commands_arista_lldp_only(collector):
    cmds = collector.get_commands("arista_eos")
    assert "show lldp neighbors detail" in cmds


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert "show lldp neighbors" in cmds


def test_get_commands_unknown_device_returns_defaults(collector):
    cmds = collector.get_commands("some_unknown_type")
    assert len(cmds) >= 1


def test_parse_empty_outputs(collector):
    result = collector.parse(
        {"show cdp neighbors detail": "", "show lldp neighbors detail": ""},
        "cisco_ios",
    )
    assert "neighbors" in result
    assert result["neighbors"] == []


def test_parse_cdp_output(collector):
    cdp_output = """
Device ID: SW2.example.com
  IP address: 10.0.0.2
  Platform: cisco WS-C3750-48P,  Capabilities: Switch IGMP
  Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/2
"""
    result = collector.parse(
        {"show cdp neighbors detail": cdp_output, "show lldp neighbors detail": ""},
        "cisco_ios",
    )
    assert len(result["neighbors"]) == 1
    n = result["neighbors"][0]
    assert n["remote_device"] == "SW2"
    assert n["remote_ip"] == "10.0.0.2"
    assert "CDP" in n["protocols"]


def test_parse_lldp_output(collector):
    lldp_output = """
Chassis id: 0011.2233.4455
System Name: SW3.example.com
Port id: Gi0/3
Local Port id: Gi0/1
System Capabilities: Bridge, Router
Management Addresses:
    IP: 10.0.0.3
"""
    result = collector.parse(
        {"show cdp neighbors detail": "", "show lldp neighbors detail": lldp_output},
        "cisco_ios",
    )
    assert len(result["neighbors"]) == 1
    n = result["neighbors"][0]
    assert n["remote_device"] == "SW3"
    assert "LLDP" in n["protocols"]


def test_parse_merges_cdp_and_lldp(collector):
    cdp_output = """
Device ID: SW2
  IP address: 10.0.0.2
  Platform: cisco WS-C3750,  Capabilities: Switch
  Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/2
"""
    lldp_output = """
Chassis id: 0011.2233.4455
System Name: SW2
Port id: Gi0/2
Local Port id: Gi0/1
System Capabilities: Bridge
Management Addresses:
    IP: 10.0.0.2
"""
    result = collector.parse(
        {
            "show cdp neighbors detail": cdp_output,
            "show lldp neighbors detail": lldp_output,
        },
        "cisco_ios",
    )
    # Should merge into single neighbor
    assert len(result["neighbors"]) == 1
    n = result["neighbors"][0]
    assert "CDP" in n["protocols"]
    assert "LLDP" in n["protocols"]
