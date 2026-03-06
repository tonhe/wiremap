import pytest
from app.collectors.device_inventory import DeviceInventoryCollector


@pytest.fixture
def collector():
    return DeviceInventoryCollector()


def test_name_and_attrs(collector):
    assert collector.name == "device_inventory"
    assert collector.label
    assert collector.enabled_by_default is True


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show version" in cmds
    assert "show inventory" in cmds


def test_get_commands_cisco_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert "show version" in cmds
    assert "show module" in cmds


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert "show version" in cmds
    assert "show chassis hardware" in cmds


def test_get_commands_unknown_device(collector):
    cmds = collector.get_commands("some_unknown")
    assert "show version" in cmds


def test_parse_empty_outputs(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    result = collector.parse(raw, "cisco_ios")
    assert "version" in result
    assert "inventory" in result
    assert result["version"] == []


def test_parse_show_version(collector):
    output = """Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 15.0(2)SE11
ROM: Bootstrap program is C3750 boot loader
Switch uptime is 1 year, 2 weeks"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show version"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "version" in result


def test_parse_cisco_xe_uses_ios_templates(collector):
    """cisco_xe should parse successfully using cisco_ios templates."""
    output = """Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 15.0(2)SE11
ROM: Bootstrap program is C3750 boot loader
Switch uptime is 1 year, 2 weeks"""
    cmds = collector.get_commands("cisco_xe")
    raw = {cmd: "" for cmd in cmds}
    raw["show version"] = output
    result = collector.parse(raw, "cisco_xe")
    # Must not be empty — cisco_xe must fall back to cisco_ios templates
    assert len(result["version"]) > 0


def test_parse_show_inventory(collector):
    output = """NAME: "1", DESCR: "WS-C3750-48P"
PID: WS-C3750-48P-S  , VID: V05, SN: FOC1234X5YZ"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show inventory"] = output
    result = collector.parse(raw, "cisco_ios")
    assert "inventory" in result


def test_get_commands_cisco_ios_includes_stack(collector):
    cmds = collector.get_commands("cisco_ios")
    assert "show switch detail" in cmds
    assert "show module" in cmds


def test_get_commands_cisco_xe_includes_stack(collector):
    cmds = collector.get_commands("cisco_xe")
    assert "show switch detail" in cmds
    assert "show module" in cmds


def test_get_commands_juniper_includes_virtual_chassis(collector):
    cmds = collector.get_commands("juniper_junos")
    assert "show virtual-chassis" in cmds


def test_get_commands_arista_includes_module(collector):
    cmds = collector.get_commands("arista_eos")
    assert "show module" in cmds


def test_parse_returns_stack_members_key(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    result = collector.parse(raw, "cisco_ios")
    assert "stack_members" in result


def test_parse_show_switch_detail(collector):
    output = """Switch/Stack Mac Address : 0cd0.f8e4.8f00 - Local Mac Address
Mac persistance wait time: Indefinite
                                           H/W   Current
Switch#  Role   Mac Address     Priority Version  State
------------------------------------------------------------
*1       Active 0cd0.f8e4.8f00     15     V05     Ready
 2       Standby 0cd0.f8e5.9e00    14     V05     Ready
 3       Member 0cd0.f8e6.ad00     1      V05     Ready"""
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    raw["show switch detail"] = output
    result = collector.parse(raw, "cisco_ios")
    assert len(result["stack_members"]) == 3
    assert result["stack_members"][0]["switch"] == "1"
    assert result["stack_members"][0]["role"] == "Active"


def test_parse_show_module_cisco_nxos(collector):
    output = """Mod Ports  Module-Type                     Model              Status
--- -----  ------------------------------- ----------------   ----------
1   48     Supervisor Module-2             N7K-SUP2           active *
3   48     1/10 Gbps Ethernet Module       N7K-F248XP-25E     ok
4   48     1/10 Gbps Ethernet Module       N7K-F248XP-25E     ok"""
    cmds = collector.get_commands("cisco_nxos")
    raw = {cmd: "" for cmd in cmds}
    raw["show module"] = output
    result = collector.parse(raw, "cisco_nxos")
    assert len(result["modules"]) >= 3


def test_parse_empty_stack_returns_empty_list(collector):
    cmds = collector.get_commands("cisco_ios")
    raw = {cmd: "" for cmd in cmds}
    result = collector.parse(raw, "cisco_ios")
    assert result["stack_members"] == []
