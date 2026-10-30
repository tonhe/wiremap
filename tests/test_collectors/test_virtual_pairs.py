"""StackWise Virtual, VSS and vPC: two chassis acting as one device."""
from app.collectors.device_inventory import (
    DeviceInventoryCollector,
    _parse_license,
    _parse_stackwise_virtual,
    _parse_switch_virtual,
    _parse_version_details,
    _parse_vpc,
)

C9500_SVL_VERSION = """Cisco IOS XE Software, Version 17.06.05
Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.6.5, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Wed 25-Jan-23 16:15 by mcpre


ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.6.1r[FC2], RELEASE SOFTWARE (P)

SW-CORE-1 uptime is 1 year, 12 weeks, 3 days, 4 hours, 5 minutes
Uptime for this control processor is 1 year, 12 weeks, 3 days, 4 hours, 7 minutes
System returned to ROM by Reload Command
System image file is "flash:packages.conf"
Last reload reason: Reload Command



Technology Package License Information:

------------------------------------------------------------------------------
Technology-package                                     Technology-package
Current                        Type                       Next reboot
------------------------------------------------------------------------------
network-advantage       Smart License                    network-advantage
dna-advantage           Subscription Smart License       dna-advantage
AIR License Level: AIR DNA Advantage
Next reload AIR license Level: AIR DNA Advantage


Smart Licensing Status: UNREGISTERED/EVAL EXPIRED

cisco C9500-48Y4C (X86) processor with 1863110K/6147K bytes of memory.
Processor board ID FCW0000A1AA
32768K bytes of non-volatile configuration memory.

Base Ethernet MAC Address          : 00:00:5e:00:53:01
Model Number                       : C9500-48Y4C
System Serial Number               : FCW0000A1AA


Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 52    C9500-48Y4C        17.06.05          CAT9K_IOSXE           INSTALL
     2 52    C9500-48Y4C        17.06.05          CAT9K_IOSXE           INSTALL


Switch 02
---------
Switch uptime                      : 1 year, 12 weeks, 3 days, 4 hours, 2 minutes
Base Ethernet MAC Address          : 00:00:5e:00:53:02
Model Number                       : C9500-48Y4C
System Serial Number               : FCW0000B2BB

Configuration register is 0x102
"""

C9500_SVL_INVENTORY = """NAME: "Chassis 1", DESCR: "Cisco Catalyst 9500 Series Chassis"
PID: C9500-48Y4C       , VID: V02  , SN: FCW0000A1AA

NAME: "Chassis 2", DESCR: "Cisco Catalyst 9500 Series Chassis"
PID: C9500-48Y4C       , VID: V02  , SN: FCW0000B2BB

NAME: "Chassis 1 Power Supply Module 0", DESCR: "Cisco Catalyst 9500 Series 650W AC Power Supply"
PID: C9K-PWR-650WAC-R  , VID: V02  , SN: ART0000A1AA
"""

SVL_CONFIG = """Stackwise Virtual Configuration:
--------------------------------
Stackwise Virtual : Enabled
Domain Number : 10

Switch  Stackwise Virtual Link  Ports
------  ----------------------  ------
1       1                       TenGigabitEthernet1/0/39
                                TenGigabitEthernet1/0/40
2       1                       TenGigabitEthernet2/0/39
                                TenGigabitEthernet2/0/40
"""

SVL_LINK = """Stackwise Virtual Link(SVL) Information:
----------------------------------------
Flags:
------
Link Status
-----------
U-Up D-Down
Protocol Status
---------------
S-Suspended P-Pending E-Error T-Timeout R-Ready

-----------------------------------------------------------------------
Switch  SVL     Ports                           Link-Status     Protocol-Status
------  ---     -----                           -----------     ---------------
1       1       TenGigabitEthernet1/0/39        U               R
                TenGigabitEthernet1/0/40        U               R
2       1       TenGigabitEthernet2/0/39        U               R
                TenGigabitEthernet2/0/40        D               T
"""

SVL_DAD = """In dual-active recovery mode: No
Recovery Reload: Enabled

Dual-Active-Detection Configuration:
-------------------------------------
Switch  Dad port                        Status
------  ------------                    ---------
1       TenGigabitEthernet1/0/38        up
2       TenGigabitEthernet2/0/38        up
"""

SVL_DISABLED = """Stackwise Virtual Configuration:
--------------------------------
Stackwise Virtual : Disabled
"""

INVALID = """                    ^
% Invalid input detected at '^' marker.
"""

VSS_SWITCH_VIRTUAL = """Executing the command on VSS member switch role = VSS Active, id = 1

Switch mode                  : Virtual Switch
Virtual switch domain number : 100
Local switch number          : 1
Local switch operational role: Virtual Switch Active
Peer switch number           : 2
Peer switch operational role : Virtual Switch Standby

Executing the command on VSS member switch role = VSS Standby, id = 2

Switch mode                  : Virtual Switch
Virtual switch domain number : 100
Local switch number          : 2
Local switch operational role: Virtual Switch Standby
Peer switch number           : 1
Peer switch operational role : Virtual Switch Active
"""

VSS_LINK = """VSL Status : UP
VSL Uptime : 12 weeks, 3 days, 4 hours, 5 minutes
VSL Control Link : Te1/5/4
VSL Encryption : Configured Mode - Off, Operational Mode - Off
VSL Ports      : Te1/5/4 Te1/5/5
"""

VSS_INVENTORY = """NAME: "WS-C6509-E 1", DESCR: "Chassis 1 Cisco Systems, Inc. Catalyst 6500 9-slot Chassis System"
PID: WS-C6509-E        , VID: V05, SN: SMG0000A1AA

NAME: "WS-C6509-E 2", DESCR: "Chassis 2 Cisco Systems, Inc. Catalyst 6500 9-slot Chassis System"
PID: WS-C6509-E        , VID: V05, SN: SMG0000B2BB
"""

STANDALONE_SWITCH_VIRTUAL = """Switch mode                  : Standalone
"""

VPC = """Legend:
                (*) - local vPC is down, forwarding via vPC peer-link

vPC domain id                     : 20
Peer status                       : peer adjacency formed ok
vPC keep-alive status             : peer is alive
Configuration consistency status  : success
vPC role                          : primary
Number of vPCs configured         : 4

vPC Peer-link status
---------------------------------------------------------------------
id    Port   Status Active vlans
--    ----   ------ -------------------------------------------------
1     Po1    up     1,10,20
"""


def _xe_raw(**overrides):
    cmds = DeviceInventoryCollector().get_commands("cisco_xe")
    raw = {cmd: "" for cmd in cmds}
    raw.update(overrides)
    return raw


def test_xe_and_ios_collect_virtual_pair_commands():
    c = DeviceInventoryCollector()
    xe = c.get_commands("cisco_xe")
    assert "show stackwise-virtual" in xe
    assert "show stackwise-virtual link" in xe
    assert "show stackwise-virtual dual-active-detection" in xe
    ios = c.get_commands("cisco_ios")
    assert "show switch virtual" in ios
    assert "show switch virtual link" in ios
    assert "show vpc" in c.get_commands("cisco_nxos")


def test_parse_stackwise_virtual_config_links_and_dad():
    svl = _parse_stackwise_virtual(SVL_CONFIG, SVL_LINK, SVL_DAD)
    assert svl["domain"] == "10"
    assert svl["switches"] == ["1", "2"]
    ports = [(l["switch"], l["port"]) for l in svl["links"]]
    assert ports == [
        ("1", "TenGigabitEthernet1/0/39"), ("1", "TenGigabitEthernet1/0/40"),
        ("2", "TenGigabitEthernet2/0/39"), ("2", "TenGigabitEthernet2/0/40"),
    ]
    down = [l for l in svl["links"] if l["port"] == "TenGigabitEthernet2/0/40"][0]
    assert down["link_status"] == "D"
    assert down["protocol_status"] == "T"
    assert [d["port"] for d in svl["dad_ports"]] == [
        "TenGigabitEthernet1/0/38", "TenGigabitEthernet2/0/38"]


def test_stackwise_virtual_disabled_or_rejected_is_not_a_pair():
    assert _parse_stackwise_virtual(SVL_DISABLED) is None
    assert _parse_stackwise_virtual(INVALID, INVALID, INVALID) is None
    assert _parse_stackwise_virtual("") is None


def test_svl_pair_populates_both_chassis_as_stack_members():
    raw = _xe_raw(**{
        "show version": C9500_SVL_VERSION,
        "show inventory": C9500_SVL_INVENTORY,
        "show stackwise-virtual": SVL_CONFIG,
        "show stackwise-virtual link": SVL_LINK,
        "show stackwise-virtual dual-active-detection": SVL_DAD,
    })
    result = DeviceInventoryCollector().parse(raw, "cisco_xe")
    members = result["stack_members"]
    assert [m["switch"] for m in members] == ["1", "2"]
    assert [m["role"] for m in members] == ["Active", "Standby"]
    assert [m["serial"] for m in members] == ["FCW0000A1AA", "FCW0000B2BB"]
    assert all(m["model"] == "C9500-48Y4C" for m in members)
    assert all(m["stack_type"] == "stackwise-virtual" for m in members)
    assert result["stackwise_virtual"]["domain"] == "10"


def test_svl_members_fall_back_to_show_version_without_inventory():
    raw = _xe_raw(**{
        "show version": C9500_SVL_VERSION,
        "show stackwise-virtual": SVL_CONFIG,
    })
    members = DeviceInventoryCollector().parse(raw, "cisco_xe")["stack_members"]
    assert [m["serial"] for m in members] == ["FCW0000A1AA", "FCW0000B2BB"]
    assert [m["model"] for m in members] == ["C9500-48Y4C", "C9500-48Y4C"]


def test_svl_keeps_show_switch_rows_and_fills_serials():
    show_switch = """Switch/Stack Mac Address : 0000.5e00.5301 - Local Mac Address
Mac persistency wait time: Indefinite
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
-------------------------------------------------------------------------------------
*1       Active   0000.5e00.5301     15     V02     Ready
 2       Standby  0000.5e00.5302     1      V02     Ready
"""
    raw = _xe_raw(**{
        "show version": C9500_SVL_VERSION,
        "show inventory": C9500_SVL_INVENTORY,
        "show switch detail": show_switch,
        "show stackwise-virtual": SVL_CONFIG,
    })
    members = DeviceInventoryCollector().parse(raw, "cisco_xe")["stack_members"]
    assert len(members) == 2
    assert members[1]["mac_address"] == "0000.5e00.5302"
    assert members[1]["serial"] == "FCW0000B2BB"
    assert members[0]["stack_type"] == "stackwise-virtual"


def test_rejected_svl_commands_are_not_applicable_not_failed():
    """A C9300 or 2960 rejecting the SVL probe is just not a virtual pair."""
    raw = _xe_raw(**{
        "show version": C9500_SVL_VERSION,
        "show stackwise-virtual": INVALID,
        "show stackwise-virtual link": INVALID,
        "show stackwise-virtual dual-active-detection": INVALID,
    })
    result = DeviceInventoryCollector().parse(raw, "cisco_xe")
    assert "stackwise_virtual" not in result
    assert result["stack_members"] == []
    assert not result.get("collector_failed")


def test_parse_switch_virtual_vss():
    vss = _parse_switch_virtual(VSS_SWITCH_VIRTUAL, VSS_LINK)
    assert vss["domain"] == "100"
    assert vss["switches"] == {"1": "Active", "2": "Standby"}
    assert vss["vsl_status"] == "UP"
    assert "Te1/5/4" in vss["links"]
    assert "Te1/5/5" in vss["links"]


def test_standalone_or_rejected_switch_virtual_is_not_vss():
    assert _parse_switch_virtual(STANDALONE_SWITCH_VIRTUAL) is None
    assert _parse_switch_virtual(INVALID) is None


def test_vss_pair_populates_both_chassis():
    c = DeviceInventoryCollector()
    raw = {cmd: "" for cmd in c.get_commands("cisco_ios")}
    raw["show inventory"] = VSS_INVENTORY
    raw["show switch virtual"] = VSS_SWITCH_VIRTUAL
    raw["show switch virtual link"] = VSS_LINK
    raw["show switch detail"] = INVALID
    result = c.parse(raw, "cisco_ios")
    members = result["stack_members"]
    assert [(m["switch"], m["role"], m["serial"]) for m in members] == [
        ("1", "Active", "SMG0000A1AA"), ("2", "Standby", "SMG0000B2BB")]
    assert all(m["model"] == "WS-C6509-E" for m in members)
    assert result["vss"]["domain"] == "100"


def test_vss_pair_found_when_typed_ios_xe():
    """A 4500-X VSS on IOS-XE 3.x is typed cisco_xe; SVL commands reject."""
    c = DeviceInventoryCollector()
    raw = {cmd: INVALID for cmd in c.get_commands("cisco_xe")}
    raw["show version"] = ""
    raw["show inventory"] = VSS_INVENTORY
    raw["show switch virtual"] = VSS_SWITCH_VIRTUAL
    raw["show switch virtual link"] = VSS_LINK
    result = c.parse(raw, "cisco_xe")
    assert result["vss"]["domain"] == "100"
    assert len(result["stack_members"]) == 2


def test_parse_vpc():
    vpc = _parse_vpc(VPC)
    assert vpc["domain"] == "20"
    assert vpc["role"] == "primary"
    assert vpc["peer_status"] == "peer adjacency formed ok"
    assert vpc["peer_link"] == "Po1"
    assert _parse_vpc("vPC domain id                     : Not configured") is None
    assert _parse_vpc("% Invalid command at '^' marker.") is None


def test_version_details_from_c9k_show_version():
    d = _parse_version_details(C9500_SVL_VERSION)
    assert d["image"] == "flash:packages.conf"
    assert d["uptime"].startswith("1 year, 12 weeks")
    assert d["reload_reason"] == "Reload Command"
    assert d["license"] == "network-advantage, dna-advantage"
    assert [s["switch"] for s in d["switches"]] == ["1", "2"]
    assert d["switches"][0]["local"] is True


def test_license_isr_layout_and_legacy_level():
    isr = """Technology Package License Information:

-----------------------------------------------------------------
Technology    Technology-package           Technology-package
              Current       Type           Next reboot
------------------------------------------------------------------
appxk9           None             None             None
securityk9       securityk9       Permanent        securityk9
ipbase           ipbasek9         Permanent        ipbasek9

cisco ISR4331/K9 (1RU) processor
"""
    assert _parse_license(isr) == "securityk9, ipbasek9"
    assert _parse_license("License Level: ipservices\nLicense Type: Permanent") == "ipservices"
    assert _parse_license("") == ""


def test_version_details_nxos():
    nxos = """Software
  BIOS: version 07.69
  NXOS: version 9.3(10)
  NXOS image file is: bootflash:///nxos.9.3.10.bin

Kernel uptime is 120 day(s), 3 hour(s), 4 minute(s), 5 second(s)

Last reset at 123456 usecs after Mon Jan  1 00:00:00 2024
  Reason: Reset Requested by CLI command reload
"""
    d = _parse_version_details(nxos)
    assert d["image"] == "bootflash:///nxos.9.3.10.bin"
    assert d["uptime"].startswith("120 day(s)")
