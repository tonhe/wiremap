from app.collectors.base import NOT_APPLICABLE
from app.collectors.hsrp import (
    HsrpCollector,
    _parse_glbp_brief_raw,
    _parse_vrrp_brief_raw,
    command_protocol,
)

GLBP_BRIEF = """\
Interface   Grp  Fwd Pri State    Address         Active router   Standby router
Vl10        10   -   110 Active   192.0.2.1       local           192.0.2.3
Vl10        10   1   -   Active   0007.b400.0a01  local           -
Vl10        10   2   -   Listen   0007.b400.0a02  192.0.2.3       -
Vl20        20   -   100 Standby  198.51.100.1    198.51.100.3    local
Vl20        20   1   -   Listen   0007.b400.1401  198.51.100.3    -
Vl20        20   2   -   Active   0007.b400.1402  local           -
TenGigabitEthernet1/0/48
            30   -   100 Init     203.0.113.1     unknown         unknown
"""

VRRP_BRIEF_V2 = """\
Interface          Grp Pri Time  Own Pre State   Master addr     Group addr
Vl30               30  110 3570       Y  Master  198.51.100.66   198.51.100.65
Vl31               31  100 3609       Y  Backup  198.51.100.98   198.51.100.97
"""

VRRP_BRIEF_V3 = """\
  Interface          Grp  A-F Pri  Time Own Pre State   Master addr/Group addr
  Vl40                40 IPv4 110     0  N   Y  MASTER  192.0.2.130(local) 192.0.2.129
  Vl41                41 IPv4 100     0  N   Y  BACKUP  192.0.2.162 192.0.2.161
"""

STANDBY_BRIEF = """\
                     P indicates configured to preempt.
                     |
Interface   Grp  Pri P State    Active          Standby         Virtual IP
Vl50        50   110 P Active   local           192.0.2.67      192.0.2.65
Vl60        60   100 P Standby  192.0.2.98      local           192.0.2.97
"""

INVALID = "                ^\n% Invalid input detected at '^' marker.\n"


def test_glbp_brief_groups_and_forwarders():
    entries = _parse_glbp_brief_raw(GLBP_BRIEF)
    assert [(e["interface"], e["group"]) for e in entries] == [
        ("Vlan10", "10"), ("Vlan20", "20"), ("TenGigabitEthernet1/0/48", "30")]
    avg = entries[0]
    assert avg["protocol"] == "GLBP"
    assert avg["priority"] == "110"
    assert avg["state"] == "Active"
    assert avg["virtual_ip"] == "192.0.2.1"
    assert avg["active"] == "local"
    assert avg["standby"] == "192.0.2.3"
    assert [(f["forwarder"], f["state"], f["mac"]) for f in avg["forwarders"]] == [
        ("1", "Active", "0007.b400.0a01"), ("2", "Listen", "0007.b400.0a02")]
    standby = entries[1]
    assert standby["state"] == "Standby"
    assert standby["active"] == "198.51.100.3"
    assert standby["standby"] == "local"
    assert [f["state"] for f in standby["forwarders"]] == ["Listen", "Active"]
    wrapped = entries[2]
    assert wrapped["state"] == "Init"
    assert wrapped["virtual_ip"] == "203.0.113.1"


def test_glbp_brief_ignores_noise():
    assert _parse_glbp_brief_raw("") == []
    assert _parse_glbp_brief_raw("RTR-A#show glbp brief\n") == []


def test_vrrp_brief_v2_and_v3_layouts():
    v2 = _parse_vrrp_brief_raw(VRRP_BRIEF_V2)
    assert [(e["interface"], e["group"], e["priority"], e["state"],
             e["virtual_ip"], e["active"]) for e in v2] == [
        ("Vlan30", "30", "110", "Master", "198.51.100.65", "local"),
        ("Vlan31", "31", "100", "Backup", "198.51.100.97", "198.51.100.98"),
    ]
    v3 = _parse_vrrp_brief_raw(VRRP_BRIEF_V3)
    assert [(e["interface"], e["priority"], e["state"], e["virtual_ip"],
             e["active"]) for e in v3] == [
        ("Vlan40", "110", "Master", "192.0.2.129", "local"),
        ("Vlan41", "100", "Backup", "192.0.2.161", "192.0.2.162"),
    ]
    assert all(e["protocol"] == "VRRP" for e in v2 + v3)


def test_command_protocol():
    assert command_protocol("show standby brief") == "HSRP"
    assert command_protocol("show hsrp brief") == "HSRP"
    assert command_protocol("show glbp brief") == "GLBP"
    assert command_protocol("show vrrp brief") == "VRRP"


def test_ios_commands_cover_all_three_fhrps():
    c = HsrpCollector()
    for dt in ("cisco_ios", "cisco_xe"):
        cmds = c.get_commands(dt)
        assert "show standby brief" in cmds
        assert "show glbp brief" in cmds
        assert "show vrrp brief" in cmds
    assert "show glbp brief" in c.get_commands("cisco_nxos")


def test_parse_keeps_entries_from_every_command():
    parsed = HsrpCollector().parse_collected({
        "show standby brief": STANDBY_BRIEF,
        "show glbp brief": GLBP_BRIEF,
        "show vrrp brief": VRRP_BRIEF_V2,
    }, "cisco_xe")
    protos = [e["protocol"] for e in parsed["entries"]]
    assert protos.count("HSRP") == 2
    assert protos.count("GLBP") == 3
    assert protos.count("VRRP") == 2


def test_ios_standby_brief_keeps_vip_and_peers():
    # ntc-templates names the VIP field virtual_ip_address; entries used to
    # be dropped because only virtual_ip/virtualip were read.
    entries = HsrpCollector().parse({"show standby brief": STANDBY_BRIEF},
                                    "cisco_xe")["entries"]
    assert [(e["interface"], e["virtual_ip"], e["state"], e["active"],
             e["standby"]) for e in entries] == [
        ("Vlan50", "192.0.2.65", "Active", "local", "192.0.2.67"),
        ("Vlan60", "192.0.2.97", "Standby", "192.0.2.98", "local"),
    ]


def test_glbp_only_device_with_rejected_commands():
    parsed = HsrpCollector().parse_collected({
        "show standby brief": "",
        "show glbp brief": GLBP_BRIEF,
        "show vrrp brief": INVALID,
    }, "cisco_xe")
    assert [e["protocol"] for e in parsed["entries"]] == ["GLBP"] * 3
    assert parsed["command_error_kinds"] == {"show vrrp brief": NOT_APPLICABLE}
