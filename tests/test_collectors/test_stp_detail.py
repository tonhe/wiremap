import pytest
from app.collectors.stp_detail import StpDetailCollector


@pytest.fixture
def collector():
    return StpDetailCollector()


def test_attrs(collector):
    assert collector.name == "stp_detail"
    assert collector.label == "STP Detail"
    assert collector.enabled_by_default is True


def test_get_commands_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert len(cmds) == 3
    assert "show spanning-tree detail" in cmds
    assert "show spanning-tree inconsistentports" in cmds
    assert "show spanning-tree root" in cmds


def test_get_commands_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert len(cmds) == 2
    assert "show spanning-tree detail" in cmds
    assert "show spanning-tree root" in cmds
    assert "show spanning-tree inconsistentports" not in cmds


def test_parse_empty(collector):
    result = collector.parse({}, "cisco_ios")
    assert result["stp_detail"] == []
    assert result["inconsistent_ports"] == []
    assert result["stp_root_summary"] == []


def test_parse_stp_detail_basic(collector):
    output = """\
 VLAN0010 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 32768, sysid 10, address 0050.56aa.bb02
  Configured hello time 2, max age 20, forward delay 15
  Number of topology changes 7 last change occurred 1:00:00 ago

  Port 1 (GigabitEthernet0/1) of VLAN0010 is designated forwarding
   Port path cost 4, Port priority 128, Port Identifier 128.1.
   Designated root has priority 32778, address 0050.56aa.bb02

  Port 2 (GigabitEthernet0/2) of VLAN0010 is root forwarding
   Port path cost 19, Port priority 128, Port Identifier 128.2.
   Designated root has priority 32778, address 0050.56aa.bb02

 VLAN0020 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 32768, sysid 20, address 0050.56aa.bb02
  Number of topology changes 2 last change occurred 0:30:00 ago

  Port 1 (GigabitEthernet0/1) of VLAN0020 is designated forwarding
   Port path cost 4, Port priority 128, Port Identifier 128.1.
"""
    result = collector.parse(
        {"show spanning-tree detail": output}, "cisco_ios"
    )
    detail = result["stp_detail"]
    assert len(detail) == 3

    assert detail[0]["vlan"] == 10
    assert detail[0]["interface"] == "GigabitEthernet0/1"
    assert detail[0]["role"] == "designated"
    assert detail[0]["state"] == "forwarding"
    assert detail[0]["cost"] == 4
    assert detail[0]["topology_changes"] == 7

    assert detail[1]["vlan"] == 10
    assert detail[1]["interface"] == "GigabitEthernet0/2"
    assert detail[1]["role"] == "root"
    assert detail[1]["cost"] == 19
    assert detail[1]["topology_changes"] == 7

    assert detail[2]["vlan"] == 20
    assert detail[2]["interface"] == "GigabitEthernet0/1"
    assert detail[2]["topology_changes"] == 2


def test_parse_stp_detail_vpc_interface(collector):
    """Port names with commas like 'port-channel1, vPC Peer-link'."""
    output = """\
 VLAN0001 is executing the rstp compatible Spanning Tree protocol
  Bridge Identifier has priority 4096, sysid 1, address d867.d970.3e44
  Number of topology changes 369 last change occurred 8:03:47 ago

 Port 4096 (port-channel1, vPC Peer-link) of VLAN0001 is designated forwarding
   Port path cost 1, Port priority 128, Port Identifier 128.4096
"""
    result = collector.parse(
        {"show spanning-tree detail": output}, "cisco_ios"
    )
    detail = result["stp_detail"]
    assert len(detail) == 1
    assert detail[0]["interface"] == "port-channel1"
    assert detail[0]["topology_changes"] == 369


def test_parse_inconsistent_ports(collector):
    output = """\
Name                 Interface              Inconsistency
-------------------- ---------------------- ------------------
VLAN0010             GigabitEthernet0/1     Port Type Inconsistent
VLAN0020             GigabitEthernet0/3     Port Type Inconsistent
"""
    result = collector.parse(
        {"show spanning-tree inconsistentports": output}, "cisco_ios"
    )
    ports = result["inconsistent_ports"]
    assert len(ports) == 2
    assert ports[0]["interface"] == "GigabitEthernet0/1"
    assert ports[0]["vlan"] == 10
    assert ports[0]["type"] == "Port Type Inconsistent"
    assert ports[1]["vlan"] == 20
