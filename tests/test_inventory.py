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
