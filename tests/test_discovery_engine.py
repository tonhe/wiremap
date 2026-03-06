"""
Tests for the new discovery engine using collector-based architecture.
Uses mock mode to test without real devices.
"""
import pytest
from app.discovery_engine import DiscoveryEngine, DiscoveryError
from app.inventory import DiscoveryInventory
from app.collectors import get_registry


def test_discovery_engine_creates_inventory():
    """Discovery engine should produce a DiscoveryInventory with devices."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    inventory = engine.discover()
    assert isinstance(inventory, DiscoveryInventory)
    assert "CORE-NX-01" in inventory.devices


def test_discovery_collects_all_enabled_collectors():
    """Each discovered device should have collector_data for all enabled collectors."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    inventory = engine.discover()
    device = inventory.devices["CORE-NX-01"]
    collector_data = device["collector_data"]

    # Should have data from cdp_lldp at minimum
    assert "cdp_lldp" in collector_data
    # Each collector entry should have raw and parsed
    for cname, cdata in collector_data.items():
        assert "raw" in cdata, f"Collector {cname} missing 'raw'"
        assert "parsed" in cdata, f"Collector {cname} missing 'parsed'"


def test_discovery_bfs_traversal():
    """Discovery with depth > 0 should find neighbors."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=1,
        filters={"include_routers": True, "include_switches": True},
    )
    inventory = engine.discover()
    # Should have discovered CORE-NX-01 and at least one neighbor
    assert len(inventory.devices) > 1


def test_discovery_respects_max_depth_zero():
    """With max_depth=0, only the seed device is SSH'd into (neighbors are placeholders)."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    inventory = engine.discover()
    # Only seed was visited via SSH
    assert len(engine.visited) == 1
    # Seed device should have collector_data, neighbors should not
    seed = inventory.devices["CORE-NX-01"]
    assert len(seed["collector_data"]) > 0
    for name, dev in inventory.devices.items():
        if name != "CORE-NX-01":
            assert len(dev["collector_data"]) == 0, f"{name} should have no collector data"


def test_discovery_stores_device_metadata():
    """Discovered devices should have hostname, mgmt_ip, device_type."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    inventory = engine.discover()
    device = inventory.devices["CORE-NX-01"]
    assert device["hostname"] == "CORE-NX-01"
    assert device["mgmt_ip"] == "192.168.1.1"
    assert device["device_type"] == "cisco_nxos"


def test_discovery_runs_all_collectors():
    """All registered collectors should run for each device."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    inventory = engine.discover()
    device = inventory.devices["CORE-NX-01"]
    collector_data = device["collector_data"]
    registry = get_registry()
    for name in registry:
        assert name in collector_data, f"Collector {name} should have run"


def test_discovery_saves_inventory(tmp_path):
    """Discovery engine should save inventory to disk."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
        inventory_dir=str(tmp_path),
    )
    inventory = engine.discover()
    # Should have saved a file
    json_files = list(tmp_path.glob("*.json"))
    assert len(json_files) == 1

    # Should be loadable
    loaded = DiscoveryInventory.load(str(json_files[0]))
    assert "CORE-NX-01" in loaded.devices


def test_discovery_params_stored():
    """Discovery params should be stored in the inventory."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=2,
        protocol="ssh",
    )
    inventory = engine.discover()
    assert inventory.params["max_depth"] == 2
    assert inventory.params["connection_protocol"] == "ssh"


def test_discovery_failed_devices_tracked():
    """Devices that fail to connect should be tracked."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    inventory = engine.discover()
    # failed is a dict on the engine
    assert isinstance(engine.failed, dict)
