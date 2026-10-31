"""Scans saved by older builds: category, module status, targets and source
addresses are worked out again from what the file still holds."""
from app.inventory import DiscoveryInventory, refresh_categories
from app.inventory_merge import merge_inventories
from app.reports.device_inventory import DeviceInventoryReport, extract_targets_data
from tests.test_collectors.test_device_inventory_modules import (
    C9300_SHOW_SWITCH_DETAIL, SHOW_MODULE_4500X)


def _logged_in(category, platform=None, show_version="", parsed=None):
    return {"login_succeeded": True, "device_category": category,
            "platform": platform, "mgmt_ip": "192.0.2.10",
            "collector_data": {"device_inventory": {
                "raw": {"show version": show_version},
                "parsed": parsed or {}}}}


def test_cube_router_saved_as_switch_becomes_router():
    data = {"devices": {"RTR-A": _logged_in(
        "switch", show_version="cisco ISR4351/K9 (2RU) processor with "
                               "1795999K/6147K bytes of memory.\n")}}
    assert refresh_categories(data) == ["RTR-A"]
    assert data["devices"]["RTR-A"]["device_category"] == "router"


def test_voice_gateway_saved_as_router_becomes_voice_gateway():
    data = {"devices": {"VG-A": _logged_in("router", platform="cisco VG310")}}
    DiscoveryInventory(data)
    assert data["devices"]["VG-A"]["device_category"] == "voice-gateway"


def test_stack_with_no_platform_takes_category_from_parsed_model():
    data = {"devices": {"STK-A": _logged_in(
        "", parsed={"version_details": {"model": "C9300-48P, C9300-48P"}})}}
    refresh_categories(data)
    assert data["devices"]["STK-A"]["device_category"] == "switch"


def test_unknown_model_is_left_alone():
    data = {"devices": {
        "FW-A": _logged_in("firewall", platform="PA-3220"),
        "SEEN": {"login_succeeded": False, "device_category": "phone",
                 "platform": "Cisco IP Phone 8851"},
    }}
    assert refresh_categories(data) == []
    assert data["devices"]["FW-A"]["device_category"] == "firewall"
    assert data["devices"]["SEEN"]["device_category"] == "phone"


def test_merge_refreshes_categories_from_older_inputs():
    old = {"discovery_id": "a", "timestamp": "2026-10-01T00:00:00+00:00",
           "devices": {"VG-A": dict(_logged_in("router", platform="VG310"),
                                    hostname="VG-A")}}
    other = {"discovery_id": "b", "timestamp": "2026-10-02T00:00:00+00:00",
             "devices": {}}
    merged = merge_inventories([old, other])
    assert merged["devices"]["VG-A"]["device_category"] == "voice-gateway"
    assert old["devices"]["VG-A"]["device_category"] == "router"


def _modules_sheet(device):
    inv = {"devices": {"SW1": device}}
    return DeviceInventoryReport().generate_tabular_data(inv)["Modules"][1]


def test_module_status_read_from_raw_show_module_when_parsed_has_none():
    device = _logged_in("switch", parsed={"modules": [
        {"module": "2", "ports": "8", "type": "4500X 8 port 10GE (SFP+) Uplink Module",
         "model": "C4KX-NM-8SFP+", "serial": "JAE00000AAB"}]})
    device["collector_data"]["device_inventory"]["raw"]["show module"] = SHOW_MODULE_4500X
    # The parsed modules held only the uplink; the raw card table has the
    # chassis too, and both have a status.
    assert [(r[2], r[4], r[6]) for r in _modules_sheet(device)] == [
        ("1", "WS-C4500X-32", "Ok"), ("2", "C4KX-NM-8SFP+", "Ok")]


def test_4500x_without_an_uplink_card_still_lists_its_chassis():
    device = _logged_in("switch")
    device["collector_data"]["device_inventory"]["raw"]["show module"] = (
        SHOW_MODULE_4500X.replace(
            " 2     8  4500X 8 port 10GE (SFP+) Uplink Module C4KX-NM-8SFP+      JAE00000AAB\n", "")
        .replace(" 2 00aa.bb00.0120 to 00aa.bb00.0127 1.0                               Ok\n", ""))
    assert [(r[2], r[4], r[6]) for r in _modules_sheet(device)] == [
        ("1", "WS-C4500X-32", "Ok")]


def test_stack_member_state_read_from_raw_show_switch_detail():
    device = _logged_in("switch", parsed={
        "stack_members": [{"switch": "1", "role": "Active"},
                          {"switch": "2", "role": "Standby"}],
        "inventory": [{"name": "Switch 1", "descr": "C9300-48P", "pid": "C9300-48P"},
                      {"name": "Switch 2", "descr": "C9300-48P", "pid": "C9300-48P"}]})
    device["collector_data"]["device_inventory"]["raw"][
        "show switch detail"] = C9300_SHOW_SWITCH_DETAIL
    status = {r[2]: r[6] for r in _modules_sheet(device)}
    assert status == {"Switch 1": "Ready", "Switch 2": "Provisioned"}


def _old_targeted(discovery_id, ips, devices, failed=None, source_ip=None):
    summary = {"failed": failed or {},
               "targets": [{"input": "sw9.example.net", "resolved_ip": ips[0]}]}
    if source_ip:
        summary["source_ip"] = source_ip
    return {"discovery_id": discovery_id,
            "timestamp": "2026-10-01T00:00:00+00:00",
            "params": {"target_ips": ips},
            "devices": devices, "scan_summary": summary}


def test_merge_rebuilds_targets_from_scans_without_outcomes():
    a = _old_targeted("scan-a", ["192.0.2.9", "192.0.2.20", "192.0.2.30"], {
        "SW9": {"hostname": "SW9", "mgmt_ip": "192.0.2.9", "login_succeeded": True}},
        failed={"192.0.2.20": {"reason": "auth", "hostname": "SW20"}},
        source_ip="198.51.100.5")
    b = _old_targeted("scan-b", ["192.0.2.9"], {}, source_ip="198.51.100.6")
    merged = merge_inventories([a, b], filenames=["a.json", "b.json"])
    summary = merged["scan_summary"]
    outcomes = {t["input"]: t["outcome"] for t in summary["targets"]}
    assert outcomes == {"sw9.example.net": "collected", "192.0.2.20": "failed",
                        "192.0.2.30": "not_attempted"}
    assert summary["target_outcomes"]["collected"] == 1
    assert extract_targets_data(merged) is not None
    assert summary["source_ips"] == [
        {"filename": "a.json", "source_ip": "198.51.100.5"},
        {"filename": "b.json", "source_ip": "198.51.100.6"}]
    assert "source_ip" not in summary


def _router_with_loopback(hostname, mgmt_ip, loopback):
    return {"hostname": hostname, "mgmt_ip": mgmt_ip, "login_succeeded": True,
            "collector_data": {"interfaces": {"parsed": {"ip_interfaces": [
                {"interface": "GigabitEthernet0/0/0", "ip_address": mgmt_ip},
                {"interface": "GigabitEthernet0/0/1", "ip_address": f"{loopback}/24"}]}}}}


def test_merged_target_on_a_collected_device_interface_is_collected():
    a = _old_targeted("scan-a", ["192.0.2.4", "192.0.2.19"], {
        "RTR-A": _router_with_loopback("RTR-A", "192.0.2.4", "192.0.2.19")})
    b = _old_targeted("scan-b", ["192.0.2.4"], {})
    merged = merge_inventories([a, b])
    by_input = {t["input"]: t for t in merged["scan_summary"]["targets"]}
    owned = by_input["192.0.2.19"]
    assert owned["outcome"] == "collected"
    assert owned["hostname"] == "RTR-A"
    assert owned["reason"] == "collected via 192.0.2.4"


def test_scan_reconcile_counts_a_target_on_a_collected_device_interface():
    from app import target_outcomes as to
    devices = {"RTR-A": _router_with_loopback("RTR-A", "192.0.2.4", "192.0.2.19")}
    out = to.reconcile([{"input": "192.0.2.19", "resolved_ip": "192.0.2.19"}],
                       devices, {}, {}, {}, {})
    assert out[0]["outcome"] == "collected"
    assert out[0]["hostname"] == "RTR-A"


SHOW_MODULE_4500X_VSS_PAIR = """ Switch Number:     1   Role:  Virtual Switch Active
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
 2 00aa.bb00.0310 to 00aa.bb00.0317 1.0                               Ok
"""


def test_vss_pair_lists_both_uplink_cards_when_ntc_kept_only_the_first():
    # ntc's template ends at the first status table: one card, no switch.
    device = _logged_in("switch", parsed={"modules": [
        {"module": "2", "port": "8", "cardtype": "4500X 8 port 10GE (SFP+) Uplink Module",
         "model": "C4KX-NM-8SFP+", "serial": "JAE00000AAD", "switch_number": ""}]})
    device["collector_data"]["device_inventory"]["raw"][
        "show module"] = SHOW_MODULE_4500X_VSS_PAIR
    rows = _modules_sheet(device)
    assert [(r[2], r[5], r[6]) for r in rows] == [
        ("1/1", "JAE00000AAC", "Ok"), ("1/2", "JAE00000AAD", "Ok"),
        ("2/1", "JAE00000AAE", "Ok"), ("2/2", "JAE00000AAF", "Ok")]


STACK_WITH_REMOVED = """Switch/Stack Mac Address : 00aa.bb00.0600 - Local Mac Address
Mac persistency wait time: Indefinite
                                             H/W   Current
Switch#   Role    Mac Address     Priority Version  State
-------------------------------------------------------------
*1       Active   00aa.bb00.0600     15     V02     Ready
 2       Standby  00aa.bb00.0700     14     V02     Ready
 3       Member   0000.0000.0000     0      V02     Removed
"""


def test_every_stack_member_has_a_modules_row_with_its_state():
    # 9300 show module: one row per present member, no status column.
    device = _logged_in("switch", parsed={"modules": [
        {"module": "1", "port": "41", "model": "C9300-48P", "serial": "FOC0000X0AA"},
        {"module": "2", "port": "41", "model": "C9300-48P", "serial": "FOC0000X0AB"}]})
    device["collector_data"]["device_inventory"]["raw"][
        "show switch detail"] = STACK_WITH_REMOVED
    rows = _modules_sheet(device)
    assert [(r[2], r[4], r[6]) for r in rows] == [
        ("Switch 1", "C9300-48P", "Ready"), ("Switch 2", "C9300-48P", "Ready"),
        ("Switch 3", "", "Removed")]


C2960X_SHOW_SWITCH_DETAIL = """Switch/Stack Mac Address : 00aa.bb00.e380 - Local Mac Address
Mac persistency wait time: Indefinite
                                           H/W   Current
Switch#  Role   Mac Address     Priority Version  State
------------------------------------------------------------
*1       Master 00aa.bb00.e380     1      4       Ready
 2       Member 00aa.bb00.e400     1      4       Ready
 3       Member 00aa.bb00.e480     1      4       Removed
"""


def test_2960x_stack_members_take_state_with_classic_master_role():
    from app.collectors.device_inventory import DeviceInventoryCollector
    from tests.test_collectors.stack_fixtures import (C2960X_STACK_INVENTORY,
                                                      C2960X_STACK_VERSION)
    collector = DeviceInventoryCollector()
    raw = {cmd: "" for cmd in collector.get_commands("cisco_ios")}
    raw.update({"show version": C2960X_STACK_VERSION,
                "show inventory": C2960X_STACK_INVENTORY,
                "show module": "% Invalid input detected at '^' marker.\n",
                "show switch detail": C2960X_SHOW_SWITCH_DETAIL})
    device = _logged_in("switch", parsed=collector.parse(raw, "cisco_ios"))
    device["collector_data"]["device_inventory"]["raw"] = raw
    status = {r[2]: r[6] for r in _modules_sheet(device)}
    assert status["1"] == "Ready"
    assert status["3"] == "Removed"


def test_standalone_switch_gets_no_member_row():
    device = _logged_in("switch", parsed={"stack_members": [
        {"switch": "1", "role": "Active", "state": "Ready"}]})
    assert _modules_sheet(device) == []
