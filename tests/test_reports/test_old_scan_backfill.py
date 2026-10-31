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


def test_unknown_model_and_neighbour_only_devices_are_left_alone():
    data = {"devices": {
        "FW-A": _logged_in("firewall", platform="PA-3220"),
        "SEEN": {"login_succeeded": False, "device_category": "switch",
                 "platform": "cisco ISR4351/K9"},
    }}
    assert refresh_categories(data) == []
    assert data["devices"]["FW-A"]["device_category"] == "firewall"
    assert data["devices"]["SEEN"]["device_category"] == "switch"


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
    assert [r[6] for r in _modules_sheet(device)] == ["Ok"]


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
