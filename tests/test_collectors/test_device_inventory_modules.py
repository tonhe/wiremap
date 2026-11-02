"""Modules sheet Status: show module status tables, stack member state and
the IOS-XE show platform slot table."""
import pytest

from app.collectors.device_inventory import DeviceInventoryCollector
from app.reports.device_inventory import DeviceInventoryReport


@pytest.fixture
def collector():
    return DeviceInventoryCollector()


SHOW_MODULE_4500X = """Chassis Type : WS-C4500X-32

Power consumed by backplane : 0 Watts

Mod Ports Card Type                              Model              Serial No.
---+-----+--------------------------------------+------------------+-----------
 1    32  4500X-32 10GE (SFP+)                   WS-C4500X-32       JAE00000AAA
 2     8  4500X 8 port 10GE (SFP+) Uplink Module C4KX-NM-8SFP+      JAE00000AAB

 M MAC addresses                    Hw  Fw           Sw               Status
--+--------------------------------+---+------------+----------------+---------
 1 00aa.bb00.0100 to 00aa.bb00.011f 1.0 15.0(1r)SG10 03.11.03.E       Ok
 2 00aa.bb00.0120 to 00aa.bb00.0127 1.0                               Ok
"""

SHOW_MODULE_4500X_VSS = """ Switch Number:     1   Role:  Virtual Switch Active
----------------------  -----------------------------
Chassis Type : WS-C4500X-16

Mod Ports Card Type                              Model              Serial No.
---+-----+--------------------------------------+------------------+-----------
 1    16  4500X-16 10GE (SFP+)                   WS-C4500X-16       JAE00000AAC
 2     8  4500X 8 port 10GE (SFP+) Uplink Module C4KX-NM-8SFP+      JAE00000AAD

 M MAC addresses                    Hw  Fw           Sw               Status
--+--------------------------------+---+------------+----------------+---------
 1 00aa.bb00.0200 to 00aa.bb00.020f 1.0 15.0(1r)SG10 03.11.03.E       Ok
 2 00aa.bb00.0210 to 00aa.bb00.0217 1.0                               Ok

 Switch Number:     2   Role:  Virtual Switch Standby
----------------------  -----------------------------
Chassis Type : WS-C4500X-16

Mod Ports Card Type                              Model              Serial No.
---+-----+--------------------------------------+------------------+-----------
 1    16  4500X-16 10GE (SFP+)                   WS-C4500X-16       JAE00000AAE
 2     8  4500X 8 port 10GE (SFP+) Uplink Module C4KX-NM-8SFP+      JAE00000AAF

 M MAC addresses                    Hw  Fw           Sw               Status
--+--------------------------------+---+------------+----------------+---------
 1 00aa.bb00.0300 to 00aa.bb00.030f 1.0 15.0(1r)SG10 03.11.03.E       Ok
 2 00aa.bb00.0310 to 00aa.bb00.0317 1.0                               PwrDown
"""

SHOW_MODULE_6500 = """Mod Ports Card Type                              Model              Serial No.
--- ----- -------------------------------------- ------------------ -----------
  1   48  CEF720 48 port 10/100/1000mb Ethernet  WS-X6748-GE-TX     SAL00000AAA
  5    5  Supervisor Engine 720 10GE (Active)    VS-S720-10G        SAL00000AAB

Mod MAC addresses                       Hw    Fw           Sw           Status
--- ---------------------------------- ------ ------------ ------------ -------
  1  00aa.bb00.0400 to 00aa.bb00.042f   3.4   12.2(18r)S1  12.2(33)SXJ9 Ok
  5  00aa.bb00.0430 to 00aa.bb00.0437   2.0   8.5(4)       12.2(33)SXJ9 Other

Mod  Sub-Module                  Model              Serial       Hw     Status
---- --------------------------- ------------------ ----------- ------- -------
  1  Centralized Forwarding Card WS-F6700-CFC       SAL00000AAC  4.1    Ok
  5  Policy Feature Card 3       VS-F6K-PFC3C       SAL00000AAD  1.1    Ok

Mod  Online Diag Status
---- -------------------
  1  Pass
  5  Pass
"""

SHOW_MODULE_9400 = """Chassis Type: C9407R

Mod Ports Card Type                                   Model          Serial No.
---+-----+--------------------------------------+--------------+--------------
1   48   48-Port UPOE 10/100/1000 (RJ-45)            C9400-LC-48U   JAE00000AB0
3   10   Supervisor 1 Module                         C9400-SUP-1    JAE00000AB1

Mod MAC addresses                    Hw   Fw           Sw                 Status
---+--------------------------------+----+------------+------------------+--------
1   00AA.BB00.0500 to 00AA.BB00.052F 1.0  17.3.1r[FC2]  17.06.05           ok
3   00AA.BB00.0530 to 00AA.BB00.053F 1.0  17.3.1r[FC2]  17.06.05           ok

Mod Redundancy Role     Operating Redundancy Mode Configured Redundancy Mode
---+-------------------+-------------------------+---------------------------
3   Active              non-redundant             sso

Chassis MAC address range: 64 addresses from 00aa.bb00.0580 to 00aa.bb00.05bf
"""

ASR_SHOW_PLATFORM = """Chassis type: ASR1001-X

Slot      Type                State                 Insert time (ago)
--------- ------------------- --------------------- -----------------
0         ASR1001-X           ok                    1y2w
 0/0      BUILT-IN-2T+6X1GE   ok                    1y2w
 0/1      SPA-2X1GE-V2        out of service        3d04h
R0        ASR1001-X           ok, active            1y2w
F0        ASR1001-X           ok, active            1y2w
P0        ASR1001-X-PWR-AC    ok                    1y2w

Slot      CPLD Version        Firmware Version
--------- ------------------- ---------------------------------------
0         1507                16.9(1r)
R0        1507                16.9(1r)
"""

ASR_SHOW_INVENTORY = '''NAME: "Chassis", DESCR: "Cisco ASR1001-X Chassis"
PID: ASR1001-X         , VID: V07  , SN: FXS0000A0AA

NAME: "Power Supply Module 0", DESCR: "Cisco ASR1001-X AC Power Supply"
PID: ASR1001-X-PWR-AC  , VID: V02  , SN: ART0000A0AB

NAME: "module 0", DESCR: "Cisco ASR1001-X SPA Interface Processor"
PID: ASR1001-X         , VID:      , SN:

NAME: "SPA subslot 0/0", DESCR: "6-port Built-in GE SPA"
PID: BUILT-IN-2T+6X1GE , VID: N/A  , SN: JAE0000A0AC

NAME: "SPA subslot 0/1", DESCR: "2-port GE SPA"
PID: SPA-2X1GE-V2      , VID: V01  , SN: JAE0000A0AD

NAME: "module R0", DESCR: "Cisco ASR1001-X Route Processor"
PID: ASR1001-X         , VID: V07  , SN: JAE0000A0AE

NAME: "module F0", DESCR: "Cisco ASR1001-X Embedded Services Processor"
PID: ASR1001-X         , VID:      , SN:
'''

C9300_SHOW_INVENTORY = '''NAME: "c93xx Stack", DESCR: "c93xx Stack"
PID: C9300-24P         , VID: V02  , SN: FOC0000X0AA

NAME: "Switch 1", DESCR: "C9300-24P"
PID: C9300-24P         , VID: V02  , SN: FOC0000X0AA

NAME: "Switch 1 - FRU Uplink Module 1", DESCR: "8x10G Uplink Module"
PID: C9300-NM-8X       , VID: V02  , SN: FOC0000X0AB

NAME: "Switch 2", DESCR: "C9300-24P"
PID: C9300-24P         , VID: V02  , SN: FOC0000X0AC
'''

C9300_SHOW_SWITCH_DETAIL = """Switch/Stack Mac Address : 00aa.bb00.0600 - Local Mac Address
Mac persistency wait time: Indefinite
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
-------------------------------------------------------------
*1       Active   00aa.bb00.0600     15     V02     Ready
 2       Standby  00aa.bb00.0700     14     V02     Provisioned
"""

REJECTED = "% Invalid input detected at '^' marker.\n"


def _raw(collector, device_type, **outputs):
    raw = {cmd: "" for cmd in collector.get_commands(device_type)}
    raw.update(outputs)
    return raw


def _module_rows(parsed, hostname="SW1"):
    inv = {"devices": {hostname: {"mgmt_ip": "192.0.2.10", "collector_data": {
        "device_inventory": {"raw": {}, "parsed": parsed}}}}}
    return DeviceInventoryReport().generate_tabular_data(inv)["Modules"][1]


def _status_by_slot(rows):
    return {r[2]: r[6] for r in rows}


def test_4500x_status_from_m_mac_table(collector):
    parsed = collector.parse(_raw(collector, "cisco_xe",
                                  **{"show module": SHOW_MODULE_4500X}), "cisco_xe")
    status = {m["module"]: m["status"] for m in parsed["modules"]}
    assert status == {"1": "Ok", "2": "Ok"}
    rows = _module_rows(parsed)
    # Chassis row is filtered; the uplink module keeps type, ports and status
    assert rows == [["SW1", "192.0.2.10", "2",
                     "4500X 8 port 10GE (SFP+) Uplink Module", "C4KX-NM-8SFP+",
                     "JAE00000AAB", "Ok", "8"]]


def test_4500x_vss_status_per_switch(collector):
    parsed = collector.parse(_raw(collector, "cisco_xe",
                                  **{"show module": SHOW_MODULE_4500X_VSS}), "cisco_xe")
    status = {(m["switch_number"], m["module"]): m["status"]
              for m in parsed["modules"]}
    assert status[("1", "2")] == "Ok"
    assert status[("2", "2")] == "PwrDown"
    rows = _module_rows(parsed)
    assert sorted(r[6] for r in rows) == ["Ok", "PwrDown"]


def test_6500_status(collector):
    parsed = collector.parse(_raw(collector, "cisco_ios",
                                  **{"show module": SHOW_MODULE_6500}), "cisco_ios")
    assert _status_by_slot(_module_rows(parsed)) == {"1": "Ok", "5": "Other"}


def test_9400_status(collector):
    parsed = collector.parse(_raw(collector, "cisco_xe",
                                  **{"show module": SHOW_MODULE_9400}), "cisco_xe")
    rows = _module_rows(parsed)
    assert _status_by_slot(rows) == {"1": "ok", "3": "ok"}
    assert {r[3] for r in rows} == {"48-Port UPOE 10/100/1000 (RJ-45)",
                                    "Supervisor 1 Module"}


def test_nxos_status_passes_through(collector):
    output = """Mod  Ports  Module-Type                         Model              Status
---  -----  ----------------------------------- ------------------ ----------
1    48     1/10 Gbps Ethernet Module           N7K-F248XP-25E     ok
5    0      Supervisor Module-2                 N7K-SUP2E          active *
6    0      Supervisor Module-2                 N7K-SUP2E          ha-standby
"""
    parsed = collector.parse(_raw(collector, "cisco_nxos",
                                  **{"show module": output}), "cisco_nxos")
    assert _status_by_slot(_module_rows(parsed)) == {
        "1": "ok", "5": "active *", "6": "ha-standby"}


def test_asr_status_from_show_platform(collector):
    assert "show platform" in collector.get_commands("cisco_xe")
    assert "show platform" in collector.get_commands("cisco_ios")
    parsed = collector.parse(_raw(collector, "cisco_xe", **{
        "show module": REJECTED,
        "show inventory": ASR_SHOW_INVENTORY,
        "show platform": ASR_SHOW_PLATFORM,
    }), "cisco_xe")
    slots = {s["slot"]: s["state"] for s in parsed["platform_slots"]}
    assert slots["R0"] == "ok, active"
    assert slots["0/1"] == "out of service"
    assert "1507" not in slots.values()
    status = _status_by_slot(_module_rows(parsed, "RTR-A"))
    assert status["module R0"] == "ok, active"
    assert status["SPA subslot 0/1"] == "out of service"
    assert status["module 0"] == "ok"
    assert "Power Supply Module 0" not in status


def test_stack_member_state_fills_inventory_rows(collector):
    parsed = collector.parse(_raw(collector, "cisco_xe", **{
        "show module": REJECTED,
        "show inventory": C9300_SHOW_INVENTORY,
        "show switch detail": C9300_SHOW_SWITCH_DETAIL,
        "show platform": REJECTED,
    }), "cisco_xe")
    status = _status_by_slot(_module_rows(parsed))
    assert status["Switch 1"] == "Ready"
    assert status["Switch 2"] == "Provisioned"
    # Show switch has no per-uplink-module state
    # The uplink takes its member's state, not a slot lookup on "Module 1"
    assert status["Switch 1 - FRU Uplink Module 1"] == "Ready"
    assert "platform_slots" not in parsed


def test_modules_xlsx_status_column(collector):
    import io
    from openpyxl import load_workbook
    parsed = collector.parse(_raw(collector, "cisco_xe",
                                  **{"show module": SHOW_MODULE_4500X}), "cisco_xe")
    inv = {"devices": {"SW1": {"mgmt_ip": "192.0.2.10", "collector_data": {
        "device_inventory": {"raw": {}, "parsed": parsed}}}}}
    ws = load_workbook(io.BytesIO(DeviceInventoryReport().generate(inv)))["Modules"]
    assert ws.cell(row=1, column=7).value == "Status"
    assert ws.cell(row=2, column=7).value == "Ok"
