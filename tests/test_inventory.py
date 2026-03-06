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
