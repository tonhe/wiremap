import json
import os
import pytest
from app.inventory import DiscoveryInventory


def test_create_new_inventory():
    inv = DiscoveryInventory.create(seed_ip="192.168.1.1", params={"max_depth": 3})
    assert inv.seed_ip == "192.168.1.1"
    assert inv.discovery_id is not None
    assert "max_depth" in inv.params


def test_add_device():
    inv = DiscoveryInventory.create(seed_ip="192.168.1.1")
    inv.add_device("SW1", mgmt_ip="192.168.1.1", device_type="cisco_ios",
                   device_category="switch")
    assert "SW1" in inv.devices


def test_set_collector_data():
    inv = DiscoveryInventory.create(seed_ip="192.168.1.1")
    inv.add_device("SW1", mgmt_ip="192.168.1.1")
    inv.set_collector_data("SW1", "cdp_lldp",
                           raw={"show cdp neighbors detail": "..."},
                           parsed={"neighbors": []})
    data = inv.devices["SW1"]["collector_data"]["cdp_lldp"]
    assert "raw" in data
    assert "parsed" in data


def test_save_and_load(tmp_path):
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("R1", mgmt_ip="10.0.0.1", device_type="cisco_ios")
    inv.set_collector_data("R1", "arp",
                           raw={"show ip arp": "Internet 10.0.0.2 ..."},
                           parsed={"entries": [{"ip": "10.0.0.2"}]})
    filepath = inv.save(str(tmp_path))
    assert os.path.exists(filepath)

    loaded = DiscoveryInventory.load(filepath)
    assert loaded.seed_ip == "10.0.0.1"
    assert "R1" in loaded.devices
    assert "arp" in loaded.devices["R1"]["collector_data"]


def test_to_dict_roundtrip():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("R1", mgmt_ip="10.0.0.1")
    d = inv.to_dict()
    assert d["seed_ip"] == "10.0.0.1"
    assert "R1" in d["devices"]


def test_list_inventories(tmp_path):
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("R1", mgmt_ip="10.0.0.1")
    inv.save(str(tmp_path))
    listing = DiscoveryInventory.list_inventories(str(tmp_path))
    assert len(listing) == 1
    assert listing[0]["seed_ip"] == "10.0.0.1"


def test_reparse(tmp_path):
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("R1", mgmt_ip="10.0.0.1")
    inv.set_collector_data("R1", "arp",
                           raw={"show ip arp": "raw data here"},
                           parsed={"old": True})
    assert inv.devices["R1"]["collector_data"]["arp"]["raw"] is not None


def test_new_device_defaults_to_not_logged_in():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="cdp")
    dev = inv.devices["SW1"]
    assert dev["discovery_source"] == "cdp"
    assert dev["login_succeeded"] is False
    assert dev["serial"] is None
    assert dev["evidence"] == []


def test_login_promotes_neighbour_record():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="cdp")
    inv.mark_login_succeeded("SW1", serial="FOC1234", model="WS-C3850",
                             software_version="16.9.4",
                             platform="cisco WS-C3850")
    dev = inv.devices["SW1"]
    assert dev["login_succeeded"] is True
    assert dev["serial"] == "FOC1234"
    assert dev["platform"] == "cisco WS-C3850"
    assert dev["discovery_source"] == "cdp"


def test_login_sets_source_when_absent():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1")
    inv.mark_login_succeeded("SW1")
    assert inv.devices["SW1"]["discovery_source"] == "login"


def test_collected_platform_overwrites_neighbour_reported():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", platform="wrong from cdp", discovery_source="cdp")
    inv.mark_login_succeeded("SW1", platform="cisco WS-C3850")
    assert inv.devices["SW1"]["platform"] == "cisco WS-C3850"


def test_evidence_accumulates():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="cdp")
    inv.add_evidence("SW1", source="cdp", seen_from="CORE1",
                     remote_port="Gi1/0/1")
    inv.add_evidence("SW1", source="lldp", seen_from="CORE2",
                     remote_port="Gi1/0/2")
    assert len(inv.devices["SW1"]["evidence"]) == 2
    assert inv.devices["SW1"]["evidence"][0]["seen_from"] == "CORE1"


def test_login_error_recorded():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="cdp")
    inv.mark_login_failed("SW1", "ssh/cisco_ios: timeout")
    assert inv.devices["SW1"]["login_succeeded"] is False
    assert "timeout" in inv.devices["SW1"]["login_error"]


def test_set_collector_data_creates_same_record_shape():
    """A record created by set_collector_data must carry provenance fields."""
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.set_collector_data("SW9", "arp", {"cmd": "out"}, {"entries": []})
    dev = inv.devices["SW9"]
    assert dev["login_succeeded"] is False
    assert dev["evidence"] == []
    assert dev["serial"] is None


def test_merges_serial_suffixed_duplicate():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1(FOC1234)", discovery_source="cdp")
    inv.add_device("SW1", mgmt_ip="10.0.0.1", discovery_source="login")
    inv.mark_login_succeeded("SW1", serial="FOC1234")
    merged = inv.merge_duplicates()
    assert merged == 1
    assert len(inv.devices) == 1
    survivor = list(inv.devices.values())[0]
    assert survivor["login_succeeded"] is True
    assert survivor["serial"] == "FOC1234"


def test_does_not_merge_distinct_devices():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="login")
    inv.add_device("SW2", discovery_source="login")
    assert inv.merge_duplicates() == 0
    assert len(inv.devices) == 2


def test_merge_prefers_logged_in_record():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1(FOC1)", platform="cisco WS-C3850",
                   discovery_source="cdp")
    inv.add_device("SW1", discovery_source="login")
    inv.mark_login_succeeded("SW1")
    inv.merge_duplicates()
    survivor = list(inv.devices.values())[0]
    assert survivor["login_succeeded"] is True
    assert survivor["platform"] == "cisco WS-C3850"


def test_different_serials_never_merge():
    """Two chassis with the same normalized hostname are still two chassis."""
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="login")
    inv.mark_login_succeeded("SW1", serial="AAA")
    inv.add_device("SW1.example.local", discovery_source="login")
    inv.mark_login_succeeded("SW1.example.local", serial="BBB")
    assert inv.merge_duplicates() == 0
    assert len(inv.devices) == 2


def test_merge_carries_collector_data_and_evidence():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1(FOC1)", discovery_source="cdp")
    inv.add_evidence("SW1(FOC1)", source="cdp", seen_from="CORE1")
    inv.add_device("SW1", discovery_source="login")
    inv.mark_login_succeeded("SW1")
    inv.set_collector_data("SW1", "arp", {}, {"entries": [1]})
    inv.merge_duplicates()
    survivor = list(inv.devices.values())[0]
    assert "arp" in survivor["collector_data"]
    assert len(survivor["evidence"]) == 1


def test_out_of_scope_addresses_are_reported():
    """A bounded scan that does not say what it skipped reads as complete."""
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.set_scan_summary(elapsed=1.0, failed={},
                         out_of_scope={"8.8.8.8", "1.1.1.1"},
                         ceiling_hit=True)
    summary = inv.to_dict()["scan_summary"]
    assert summary["out_of_scope_count"] == 2
    assert "8.8.8.8" in summary["out_of_scope"]
    assert summary["device_ceiling_hit"] is True


def test_scan_summary_defaults_are_empty():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.set_scan_summary(elapsed=1.0, failed={})
    summary = inv.to_dict()["scan_summary"]
    assert summary["out_of_scope"] == []
    assert summary["device_ceiling_hit"] is False


def test_snmp_facts_fill_model_and_serial():
    """A Palo Alto identified only by SNMP should still carry model and serial
    into the report, not five null columns."""
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("pa-fw01", mgmt_ip="172.21.0.13", discovery_source="snmp")
    inv.set_snmp_facts("pa-fw01", {
        "model": "PA-440", "serial": "012345678901",
        "software_version": "10.2.3", "sys_descr": "Palo Alto Networks",
        "sys_object_id": "1.3.6.1.4.1.25461.2.3.20", "sys_location": "MDF",
    })
    dev = inv.devices["pa-fw01"]
    assert dev["model"] == "PA-440"
    assert dev["serial"] == "012345678901"
    assert dev["software_version"] == "10.2.3"
    assert dev["platform"] == "PA-440"
    assert dev["login_succeeded"] is False


def test_snmp_facts_never_overwrite_collected_data():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", discovery_source="login")
    inv.mark_login_succeeded("SW1", serial="REAL123", model="WS-C3850")
    inv.set_snmp_facts("SW1", {"model": "WRONG", "serial": "WRONG"})
    assert inv.devices["SW1"]["serial"] == "REAL123"
    assert inv.devices["SW1"]["model"] == "WS-C3850"


def test_continue_from_copies_devices():
    base = DiscoveryInventory.create(seed_ip="10.0.0.1")
    base.add_device("SW1", mgmt_ip="10.0.0.1", discovery_source="login")
    base.mark_login_succeeded("SW1", serial="FOC1")
    cont = DiscoveryInventory.continue_from(base, seed_ip="10.0.0.9")
    assert "SW1" in cont.devices
    assert cont.devices["SW1"]["serial"] == "FOC1"


def test_continue_from_is_a_new_scan():
    """The original must survive untouched -- a continuation writes its own
    file rather than overwriting the scan it builds on."""
    base = DiscoveryInventory.create(seed_ip="10.0.0.1")
    cont = DiscoveryInventory.continue_from(base, seed_ip="10.0.0.9")
    assert cont.discovery_id != base.discovery_id
    assert cont.to_dict()["continued_from"] == base.discovery_id


def test_continue_from_does_not_alias_the_base():
    base = DiscoveryInventory.create(seed_ip="10.0.0.1")
    base.add_device("SW1", mgmt_ip="10.0.0.1", discovery_source="login")
    cont = DiscoveryInventory.continue_from(base, seed_ip="10.0.0.9")
    cont.add_device("SW2", discovery_source="login")
    cont.devices["SW1"]["platform"] = "changed"
    assert "SW2" not in base.devices
    assert base.devices["SW1"]["platform"] is None


def test_continue_from_carries_prior_failures():
    base = DiscoveryInventory.create(seed_ip="10.0.0.1")
    base.set_scan_summary(elapsed=1.0, failed={"10.0.0.5": "timeout"})
    cont = DiscoveryInventory.continue_from(base, seed_ip="10.0.0.9")
    assert cont.prior_failures() == {"10.0.0.5": "timeout"}


def test_prior_failures_empty_for_fresh_scan():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    assert inv.prior_failures() == {}


def test_collected_ips_lists_only_successful_logins():
    """A continuation should skip what was collected and retry what failed."""
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("SW1", mgmt_ip="10.0.0.1", discovery_source="login")
    inv.mark_login_succeeded("SW1")
    inv.add_device("SW2", mgmt_ip="10.0.0.2", discovery_source="cdp_lldp")
    inv.add_device("SW3", discovery_source="cdp_lldp")
    assert inv.collected_ips() == {"10.0.0.1"}


def test_collected_hostnames_are_normalized():
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("N5K-A(SSI1).example.net", mgmt_ip="10.0.0.1")
    inv.mark_login_succeeded("N5K-A(SSI1).example.net")
    assert inv.collected_hostnames() == {"n5k-a"}
