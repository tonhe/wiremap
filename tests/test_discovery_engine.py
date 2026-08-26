"""
Tests for the new discovery engine using collector-based architecture.
Uses mock mode to test without real devices.
"""
import pytest
from app.discovery_engine import DiscoveryEngine, DiscoveryError
from app.inventory import DiscoveryInventory
from app.collectors import get_registry


@pytest.fixture(autouse=True)
def _enable_mock_mode(monkeypatch):
    """Mock mode is opt-in via WIREMAP_MOCK. Every test here targets the
    simulated 192.168.1.0/24 topology, so enable it for the whole module."""
    monkeypatch.setenv("WIREMAP_MOCK", "1")


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


def test_engine_accepts_disable_autodetect():
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0,
        disable_autodetect=True,
    )
    assert engine.disable_autodetect is True


def test_engine_disable_autodetect_defaults_false():
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0,
    )
    assert engine.disable_autodetect is False


def test_mac_platform_is_not_written_to_platform_field():
    from app.discovery_engine import _neighbour_platform_fields
    platform, chassis_id = _neighbour_platform_fields("009a.d2d4.9700")
    assert platform is None
    assert chassis_id == "009a.d2d4.9700"


def test_real_platform_is_kept():
    from app.discovery_engine import _neighbour_platform_fields
    platform, chassis_id = _neighbour_platform_fields("cisco WS-C3850-48P")
    assert platform == "cisco WS-C3850-48P"
    assert chassis_id is None


def test_empty_platform_yields_nothing():
    from app.discovery_engine import _neighbour_platform_fields
    assert _neighbour_platform_fields(None) == (None, None)
    assert _neighbour_platform_fields("") == (None, None)


def test_neighbour_without_name_is_not_created_as_device():
    """vPC peer-keepalive addresses became eight phantom Nexus 5548 rows."""
    from app.discovery_engine import _should_create_neighbour_device
    assert _should_create_neighbour_device({"remote_ip": "1.1.1.1"}) is False
    assert _should_create_neighbour_device({"remote_device": "   "}) is False
    assert _should_create_neighbour_device({}) is False


def test_neighbour_with_name_is_created():
    from app.discovery_engine import _should_create_neighbour_device
    assert _should_create_neighbour_device(
        {"remote_device": "SW2", "remote_ip": "10.0.0.2"}) is True


def _engine_with_neighbors(neighbors):
    """Build an engine plus inventory holding cdp_lldp data for CORE1."""
    from app.inventory import DiscoveryInventory
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_nxos",
        username="u", password="p", max_depth=1,
        filters={"include_routers": True, "include_switches": True},
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("CORE1", mgmt_ip="10.0.0.1", discovery_source="login")
    inv.set_collector_data("CORE1", "cdp_lldp", {}, {"neighbors": neighbors})
    return engine, inv


def test_lldp_mac_platform_never_reaches_platform_column():
    """Regression: Platform column held 009a.d2d4.9700 instead of a model."""
    engine, inv = _engine_with_neighbors([{
        "remote_device": "N5K-A",
        "remote_ip": "10.0.0.5",
        "remote_platform": "009a.d2d4.9700",
        "remote_capabilities": "Router Switch",
        "remote_port": "Eth1/1",
    }])
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_nxos", 0)
    dev = inv.devices.get("N5K-A")
    assert dev is not None
    assert dev["platform"] is None
    assert dev["remote_chassis_id"] == "009a.d2d4.9700"


def test_keepalive_address_does_not_become_a_device():
    """Regression: vPC peer-keepalive 1.1.1.1/1.1.1.2 became phantom rows."""
    engine, inv = _engine_with_neighbors([{
        "remote_ip": "1.1.1.1",
        "remote_platform": "cisco Nexus5548",
        "remote_capabilities": "Router Switch",
        "remote_port": "mgmt0",
    }])
    before = set(inv.devices)
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_nxos", 0)
    assert set(inv.devices) == before
    unresolved = inv.devices["CORE1"]["unresolved_neighbours"]
    assert unresolved[0]["remote_ip"] == "1.1.1.1"


def test_named_neighbour_records_evidence():
    engine, inv = _engine_with_neighbors([{
        "remote_device": "SW2",
        "remote_ip": "10.0.0.6",
        "remote_platform": "cisco WS-C3850-48P",
        "remote_capabilities": "Switch",
        "remote_port": "Gi1/0/1",
    }])
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_nxos", 0)
    dev = inv.devices["SW2"]
    assert dev["platform"] == "cisco WS-C3850-48P"
    assert dev["login_succeeded"] is False
    assert dev["discovery_source"] == "cdp"
    assert dev["evidence"][0]["seen_from"] == "CORE1"
    assert dev["evidence"][0]["remote_port"] == "Gi1/0/1"


def test_logged_in_device_is_marked_and_neighbours_are_not():
    """A collected device and a neighbour shell must be distinguishable."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0,
    )
    inventory = engine.discover()

    seed = inventory.devices["CORE-NX-01"]
    assert seed["login_succeeded"] is True
    assert seed["discovery_source"] == "login"

    neighbours = [d for name, d in inventory.devices.items()
                  if name != "CORE-NX-01"]
    assert neighbours, "expected neighbour-derived records"
    for dev in neighbours:
        assert dev["login_succeeded"] is False
        assert dev["discovery_source"] != "login"


def test_no_device_platform_holds_a_mac():
    """Regression: Platform column held a MAC for neighbour-derived rows."""
    from app.identity import looks_like_mac
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=1,
        filters={"include_routers": True, "include_switches": True},
    )
    inventory = engine.discover()
    for name, dev in inventory.devices.items():
        assert not looks_like_mac(dev.get("platform")), \
            f"{name} has a MAC in platform: {dev.get('platform')}"
