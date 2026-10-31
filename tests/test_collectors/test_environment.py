import pytest

from app.collectors.base import BaseCollector
from app.collectors.environment import (
    EnvironmentCollector, parse_environment, parse_power_inline,
)


@pytest.fixture
def collector():
    return EnvironmentCollector()


CAT9K_ENV_ALL = """\
Switch 1 FAN 1 is OK
Switch 1 FAN 2 is NOT OK
Switch 1 FAN 3 is OK
FAN PS-1 is OK
FAN PS-2 is NOT PRESENT
Switch 1: SYSTEM TEMPERATURE is OK
Inlet Temperature Value: 31 Degree Celsius
Temperature State: GREEN
Yellow Threshold : 46 Degree Celsius
Red Threshold    : 56 Degree Celsius

SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
--  ------------------  ----------  ---------------  -------  -------  -----
1A  PWR-C1-715WAC       LAB0000X0A1 OK               Good     Good     715
1B  PWR-C1-715WAC       LAB0000X0A2 No Input Power   Bad      Bad      715
2A  Not Present
"""

ISR4K_ENV = """\
Number of Critical alarms:  0
Number of Major alarms:     0
Number of Minor alarms:     1

 Slot    Sensor          Current State   Reading        Threshold(Minor,Major,Critical,Shutdown)
 ----    ------          -------------   -------        ---------------------------------------
 P0      Temp: Temp 1    Normal          30 Celsius     (na ,na ,na ,na )(Celsius)
 P0      Vin             Normal          228 V AC       (na ,na ,na ,na )(V AC)
 P0      Fan 1           Fail            0 RPM          (na ,na ,na ,na )(RPM)
 R0      Temp: CPU Die   Normal          44 Celsius     (80 ,90 ,95 ,100)(Celsius)
"""

NXOS_ENV = """\
Power Supply:
Voltage: 12 Volts
Power                              Actual        Actual        Total
Supply    Model                    Output     Input        Capacity    Status
                                   (Watts )     (Watts )     (Watts )
-------  -------------------  -----------  -----------  -----------  ----------
1        NXA-PAC-650W-PE             101 W        112 W        650 W     Ok
2        NXA-PAC-650W-PE               0 W          0 W        650 W     Shutdown

Fan:
---------------------------------------------------------------------------
Fan             Model                Hw     Direction       Status
---------------------------------------------------------------------------
Fan1(sys_fan1)  NXA-FAN-30CFM-B      --     front-to-back   Ok
Fan2(sys_fan2)  NXA-FAN-30CFM-B      --     front-to-back   Ok

Temperature:
--------------------------------------------------------------------
Module   Sensor        MajorThresh   MinorThres   CurTemp     Status
                       (Celsius)     (Celsius)    (Celsius)
--------------------------------------------------------------------
1        FRONT           80              70          29         Normal
1        CPU             90              80          41         Normal
"""

POWER_INLINE_STANDALONE = """\
Available:370.0(w)  Used:362.5(w)  Remaining:7.5(w)

Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/1   auto   on         6.5     IP Phone 8845       2     30.0
Gi1/0/2   auto   on         15.4    Ieee PD             4     30.0
Gi1/0/3   auto   off        0.0     n/a                 n/a   30.0
Gi1/0/4   auto   power-deny 0.0     n/a                 n/a   30.0
Gi1/0/5   auto   faulty     0.0     n/a                 n/a   30.0
"""

POWER_INLINE_STACK = """\
Module   Available     Used     Remaining
          (Watts)     (Watts)    (Watts)
------   ---------   --------   ---------
1          1100.0      120.5       979.5
2           715.0        0.0       715.0
Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/1   auto   on         6.5     IP Phone 8845       2     30.0
Gi2/0/1   auto   off        0.0     n/a                 n/a   30.0
"""


def _by_name(items):
    return {i["name"]: i for i in items}


def test_attrs(collector):
    assert collector.name == "environment"
    assert "show power inline" in collector.switching_commands
    assert not collector.needs_custom_collect


def test_commands_per_platform(collector):
    assert collector.get_commands("cisco_xe") == ["show environment all", "show power inline"]
    assert collector.get_commands("cisco_ios") == ["show environment all", "show power inline"]
    assert collector.get_commands("cisco_nxos") == ["show environment"]
    assert collector.get_commands("paloalto_panos") == []


def test_cat9k_fans_temperature_and_psus():
    items = parse_environment(CAT9K_ENV_ALL)
    names = _by_name(items)
    assert names["Switch 1 FAN 1"]["state"] == "ok"
    assert names["Switch 1 FAN 2"]["state"] == "fault"
    assert names["Switch 1 FAN 2"]["component"] == "fan"
    assert names["FAN PS-2"]["state"] == "absent"
    assert names["Switch 1: SYSTEM TEMPERATURE"]["component"] == "temperature"
    psus = [i for i in items if i["component"] == "power"]
    assert [(p["name"], p["state"]) for p in psus] == [
        ("PS 1A PWR-C1-715WAC", "ok"),
        ("PS 1B PWR-C1-715WAC", "fault"),
        ("PS 2A", "absent"),
    ]
    # Thresholds are not components.
    assert not any("Threshold" in i["name"] for i in items)


def test_isr4k_sensor_table():
    items = parse_environment(ISR4K_ENV)
    names = _by_name(items)
    assert names["P0 Temp: Temp 1"]["component"] == "temperature"
    assert names["P0 Temp: Temp 1"]["reading"] == "30 Celsius"
    assert names["P0 Vin"]["component"] == "power"
    assert names["P0 Fan 1"]["state"] == "fault"
    assert len(items) == 4


def test_nxos_sections():
    items = parse_environment(NXOS_ENV)
    power = [i for i in items if i["component"] == "power"]
    fans = [i for i in items if i["component"] == "fan"]
    temps = [i for i in items if i["component"] == "temperature"]
    assert len(power) == 2 and len(fans) == 2 and len(temps) == 2
    assert [p["state"] for p in power] == ["ok", "fault"]
    assert all(t["state"] == "ok" for t in temps)


def test_power_inline_budget_and_problem_ports():
    poe = parse_power_inline(POWER_INLINE_STANDALONE)
    assert poe["budgets"] == [{"module": "", "available_w": 370.0,
                               "used_w": 362.5, "remaining_w": 7.5}]
    assert poe["ports_by_state"] == {"on": 2, "off": 1, "power-deny": 1, "faulty": 1}
    assert [p["interface"] for p in poe["problem_ports"]] == ["Gi1/0/4", "Gi1/0/5"]


def test_power_inline_stack_modules():
    poe = parse_power_inline(POWER_INLINE_STACK)
    assert [b["module"] for b in poe["budgets"]] == ["1", "2"]
    assert poe["budgets"][0]["used_w"] == 120.5
    assert poe["problem_ports"] == []


def test_parse_collects_faults(collector):
    parsed = collector.parse({"show environment all": CAT9K_ENV_ALL,
                              "show power inline": POWER_INLINE_STANDALONE},
                             "cisco_xe")
    assert {f["name"] for f in parsed["faults"]} == {"Switch 1 FAN 2",
                                                     "PS 1B PWR-C1-715WAC"}
    assert parsed["power_inline"]["budgets"]


def test_unsupported_commands_are_not_applicable(collector):
    raw = {"show environment all": "                   ^\n% Invalid input detected at '^' marker.",
           "show power inline": "                   ^\n% Invalid input detected at '^' marker."}
    parsed = collector.parse_collected(raw, "cisco_ios")
    assert parsed["not_applicable"] is True


def test_no_commands_is_not_applicable(collector):
    assert collector.parse({}, "vyos")["not_applicable"] is True


def test_is_a_batch_collector():
    assert issubclass(EnvironmentCollector, BaseCollector)
