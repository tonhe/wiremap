import pytest

from app.collectors.redundancy import (
    RedundancyCollector, parse_redundancy, parse_nxos_redundancy,
    parse_stack_ports, parse_stack_ring,
)


@pytest.fixture
def collector():
    return RedundancyCollector()


SVL_REDUNDANCY = """\
Redundant System Information :
------------------------------
       Available system uptime = 1 year, 2 weeks, 3 days, 4 hours, 5 minutes
Switchovers system experienced = 1
              Standby failures = 0
        Last switchover reason = active unit removed

                 Hardware Mode = Duplex
    Configured Redundancy Mode = sso
     Operating Redundancy Mode = rpr
              Maintenance Mode = Disabled
                Communications = Up

Current Processor Information :
-------------------------------
               Active Location = slot 1
        Current Software state = ACTIVE
       Uptime in current state = 2 weeks, 1 day
                 Image Version = Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software

Peer Processor Information :
----------------------------
              Standby Location = slot 2
        Current Software state = STANDBY COLD
       Uptime in current state = 2 weeks, 1 day
"""

SIMPLEX_REDUNDANCY = """\
Redundant System Information :
------------------------------
       Available system uptime = 10 weeks, 2 days, 1 hour, 7 minutes
Switchovers system experienced = 0
              Standby failures = 0
        Last switchover reason = none

                 Hardware Mode = Simplex
    Configured Redundancy Mode = sso
     Operating Redundancy Mode = Non-redundant
              Maintenance Mode = Disabled
                Communications = Down      Reason: Failure

Current Processor Information :
-------------------------------
               Active Location = slot 1
        Current Software state = ACTIVE

Peer (slot: unavailable) : Empty
"""

NXOS_REDUNDANCY = """\
Redundancy mode
---------------
      administrative:   HA
         operational:   HA

This supervisor (sup-1)
-----------------------
    Redundancy state:   Active
    Supervisor state:   Active
      Internal state:   Active with HA standby

Other supervisor (sup-2)
------------------------
    Redundancy state:   Standby
    Supervisor state:   HA standby
      Internal state:   HA standby
"""

STACK_PORTS = """\
  Switch #    Port 1       Port 2
  --------    ------       ------
    1           OK           OK
    2           OK          DOWN
    3          DOWN          OK
"""

STACK_RING = """\
Stack Ring Speed        : 240G
Stack Ring Configuration: Half
Stack Ring Protocol     : StackWise
"""


def test_commands(collector):
    assert collector.get_commands("cisco_xe") == [
        "show redundancy", "show switch stack-ports", "show switch stack-ring speed"]
    assert collector.get_commands("cisco_nxos") == ["show system redundancy status"]
    assert collector.get_commands("vyos") == []
    assert collector.switching_commands == {"show switch stack-ports",
                                            "show switch stack-ring speed"}


def test_parse_svl_redundancy():
    r = parse_redundancy(SVL_REDUNDANCY)
    assert r["hardware_mode"] == "Duplex"
    assert r["configured_mode"] == "sso"
    assert r["operating_mode"] == "rpr"
    assert r["active_state"] == "ACTIVE"
    assert r["peer_state"] == "STANDBY COLD"
    assert r["peer_location"] == "slot 2"
    assert r["switchovers"] == "1"
    assert r["last_switchover_reason"] == "active unit removed"


def test_parse_simplex_redundancy():
    r = parse_redundancy(SIMPLEX_REDUNDANCY)
    assert r["hardware_mode"] == "Simplex"
    assert r["peer_state"] == "Empty"


def test_parse_nxos_redundancy():
    r = parse_nxos_redundancy(NXOS_REDUNDANCY)
    assert r == {"configured_mode": "HA", "operating_mode": "HA",
                 "active_state": "Active", "peer_state": "Standby"}


def test_parse_stack():
    members = parse_stack_ports(STACK_PORTS)
    assert members == [
        {"switch": "1", "port1": "OK", "port2": "OK"},
        {"switch": "2", "port1": "OK", "port2": "DOWN"},
        {"switch": "3", "port1": "DOWN", "port2": "OK"},
    ]
    assert parse_stack_ring(STACK_RING) == {"speed": "240G", "configuration": "Half",
                                            "protocol": "StackWise"}


def test_parse_by_platform(collector):
    parsed = collector.parse({"show system redundancy status": NXOS_REDUNDANCY},
                             "cisco_nxos")
    assert parsed["redundancy"]["peer_state"] == "Standby"
    parsed = collector.parse({"show redundancy": SVL_REDUNDANCY,
                              "show switch stack-ports": "",
                              "show switch stack-ring speed": ""}, "cisco_xe")
    assert parsed["redundancy"]["hardware_mode"] == "Duplex"
    assert parsed["stack_ports"] == []


def test_stack_commands_rejected_keep_redundancy(collector):
    invalid = "                     ^\n% Invalid input detected at '^' marker."
    parsed = collector.parse_collected({"show redundancy": SIMPLEX_REDUNDANCY,
                                        "show switch stack-ports": invalid,
                                        "show switch stack-ring speed": invalid},
                                       "cisco_ios")
    assert parsed["redundancy"]["hardware_mode"] == "Simplex"
    assert set(parsed["failed_commands"]) == {"show switch stack-ports",
                                              "show switch stack-ring speed"}
    assert set(parsed["command_error_kinds"].values()) == {"not_applicable"}
