import pytest
from app.collectors.switchport import SwitchportCollector


@pytest.fixture
def collector():
    return SwitchportCollector()


def test_attrs(collector):
    assert collector.name == "switchport"
    assert collector.label == "Switchport Configuration"
    assert collector.enabled_by_default is True


def test_get_commands_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert len(cmds) == 5
    assert cmds[0] == "show interfaces switchport"
    assert "show port-security" in cmds
    assert "show storm-control" in cmds


def test_get_commands_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert cmds[0] == "show interface switchport"
    assert len(cmds) == 5


def test_parse_empty(collector):
    result = collector.parse({}, "cisco_ios")
    assert result["switchports"] == []
    assert result["port_security"] == []
    assert result["port_security_addresses"] == []
    assert result["errdisable_recovery"] == []
    assert result["storm_control"] == []


def test_parse_switchport_basic(collector):
    switchport_output = """Name: GigabitEthernet0/1
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: negotiate
Access Mode VLAN: 10 (VLAN0010)
Trunking Native Mode VLAN: 1 (default)
Trunking VLANs Enabled: ALL
Voice VLAN: 20

Name: GigabitEthernet0/2
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Administrative Trunking Encapsulation: dot1q
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 99 (native99)
Trunking VLANs Enabled: 10,20,30
Voice VLAN: none"""

    raw_outputs = {"show interfaces switchport": switchport_output}
    result = collector.parse(raw_outputs, "cisco_ios")

    assert len(result["switchports"]) == 2

    port1 = result["switchports"][0]
    assert port1["interface"] == "GigabitEthernet0/1"
    assert port1["mode"] == "static access"
    assert port1["voice_vlan"] == "20"

    port2 = result["switchports"][1]
    assert port2["interface"] == "GigabitEthernet0/2"
    assert port2["mode"] == "trunk"
    assert port2["native_vlan"] == "99"
    assert "10,20,30" in port2["allowed_vlans"]
    assert port2["voice_vlan"] == ""
