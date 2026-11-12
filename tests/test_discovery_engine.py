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


@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    """SNMP table collection walks real sockets and blocks on timeout.
    Neutralise it by default; tests that exercise it substitute their own."""
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


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
    json_files = list(tmp_path.glob("*.json.gz"))
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
    assert dev["discovery_source"] == "cdp_lldp"
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


def test_targeted_scan_pinned_to_depth_zero_by_default():
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="u", password="p", max_depth=3,
        target_hosts=[("192.168.1.1", "cisco_nxos")],
    )
    assert engine.max_depth == 0


def test_targeted_scan_crawls_when_enabled():
    """Targeted scan should be able to discover onward from each target."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="u", password="p", max_depth=2,
        target_hosts=[("192.168.1.1", "cisco_nxos")],
        crawl_from_targets=True,
    )
    assert engine.max_depth == 2


def test_discovery_scan_unaffected_by_crawl_flag():
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="u", password="p", max_depth=3,
    )
    assert engine.max_depth == 3


def test_targeted_crawl_does_not_reprocess_targets():
    """Targets already visited must not be rediscovered as neighbours."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=1,
        target_hosts=[("192.168.1.1", "cisco_nxos")],
        crawl_from_targets=True,
        filters={"include_routers": True, "include_switches": True},
    )
    engine.discover()
    assert len(engine.visited) == len(set(engine.visited))
    assert "192.168.1.1" in engine.visited


def test_targeted_scan_records_target_ips():
    """The inventory report needs to tell a host-list target from a seed."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin",
        target_hosts=[("192.168.1.1", "cisco_nxos")],
    )
    inventory = engine.discover()
    assert inventory.params["target_ips"] == ["192.168.1.1"]


def test_public_next_hop_is_not_crawled():
    """Regression: next-hop crawling must not walk into ISP space."""
    from app.inventory import DiscoveryInventory
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=1,
        neighbor_sources={"next_hop"},
        expand_non_cdp_neighbors=True,
        filters={"include_routers": True, "include_switches": True},
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("EDGE1", mgmt_ip="10.0.0.1", discovery_source="login")
    inv.set_collector_data("EDGE1", "l3_routing", {}, {"routes": [
        {"network": "0.0.0.0", "nexthop_ip": "8.8.8.8"},
        {"network": "10.5.0.0", "nexthop_ip": "10.0.0.9"},
    ]})
    next_layer = engine._extract_neighbors(inv, "EDGE1", "10.0.0.1",
                                           "cisco_ios", 0)
    next_layer += engine._resolve_non_cdp(inv)
    queued = {ip for ip, _ in next_layer}
    assert "10.0.0.9" in queued
    assert "8.8.8.8" not in queued
    assert "8.8.8.8" in engine._out_of_scope


def test_allow_list_scope_is_honoured():
    from app.inventory import DiscoveryInventory
    from app.neighbors import CrawlScope
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=1,
        neighbor_sources={"next_hop"},
        crawl_scope=CrawlScope(allow_cidrs=["10.1.0.0/16"]),
        expand_non_cdp_neighbors=True,
        filters={"include_routers": True, "include_switches": True},
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("EDGE1", mgmt_ip="10.0.0.1", discovery_source="login")
    inv.set_collector_data("EDGE1", "l3_routing", {}, {"routes": [
        {"network": "a", "nexthop_ip": "10.1.2.3"},
        {"network": "b", "nexthop_ip": "10.9.9.9"},
    ]})
    engine._extract_neighbors(inv, "EDGE1", "10.0.0.1", "cisco_ios", 0)
    queued = {ip for ip, _ in engine._resolve_non_cdp(inv)}
    assert queued == {"10.1.2.3"}


def test_routing_adjacency_feeds_the_crawl():
    """A device reachable only via OSPF must now be discovered."""
    from app.inventory import DiscoveryInventory
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=1,
        filters={"include_routers": True, "include_switches": True},
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    inv.add_device("CORE1", mgmt_ip="10.0.0.1", discovery_source="login")
    inv.set_collector_data("CORE1", "l3_routing", {}, {"neighbors": [
        {"remote_ip": "10.0.0.7", "protocol": "OSPF", "state": "FULL/-",
         "remote_capabilities": "Router"},
    ]})
    # The peer's ARP entry carries a Cisco OUI, which is what earns it a login.
    inv.set_collector_data("CORE1", "arp", {}, {"entries": [
        {"ip": "10.0.0.7", "mac": "00:00:0c:12:34:56", "incomplete": False},
    ]})
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_ios", 0)
    queued = {ip for ip, _ in engine._resolve_non_cdp(inv)}
    assert "10.0.0.7" in queued


def test_snmp_fallback_records_identified_device(monkeypatch):
    """A device that refuses login is still identified, not left anonymous."""
    from app.inventory import DiscoveryInventory
    from app.snmp_probe import SnmpCredentials
    import app.discovery_engine as mod

    monkeypatch.setattr(mod, "snmp_probe_outcome", lambda ip, creds: ({
        "hostname": "SW-NOLOGIN", "mgmt_ip": ip, "device_type": "cisco_ios",
        "software_version": "15.0(2)SE11", "sys_descr": "Cisco IOS Software",
        "sys_object_id": "1.3.6.1.4.1.9.1.516", "sys_location": "IDF-3",
        "discovery_source": "snmp", "login_succeeded": False,
    }, "v2c ok"))

    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        snmp_credentials=SnmpCredentials(version="v2c", community="public"),
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    ok = engine._snmp_fallback(inv, "10.0.0.50", "ssh/cisco_ios: timeout")

    assert ok == "v2c ok"
    dev = inv.devices["SW-NOLOGIN"]
    assert dev["discovery_source"] == "snmp"
    assert dev["login_succeeded"] is False
    assert "timeout" in dev["login_error"]
    assert dev["software_version"] == "15.0(2)SE11"
    assert dev["snmp"]["sys_location"] == "IDF-3"


def test_snmp_fallback_noop_without_credentials():
    from app.inventory import DiscoveryInventory
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    assert engine._snmp_fallback(inv, "10.0.0.50", "err") == "no credentials"
    assert inv.devices == {}


def test_snmp_fallback_noop_when_device_silent(monkeypatch):
    from app.inventory import DiscoveryInventory
    from app.snmp_probe import SnmpCredentials
    import app.discovery_engine as mod

    monkeypatch.setattr(mod, "snmp_probe_outcome",
                        lambda ip, creds: (None, "timeout"))
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        snmp_credentials=SnmpCredentials(version="v2c", community="public"),
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    assert engine._snmp_fallback(inv, "10.0.0.50", "err") == "timeout"


def test_server_nic_is_categorised_not_counted_as_device():
    """LLDP from a server NIC advertises the adapter description as the system
    name, so it arrived looking like a network device."""
    engine, inv = _engine_with_neighbors([{
        "remote_device": "10/25Gb 2-port SFP28 BCM57414 OCP3 Adapter fw_version:AFW_228",
        "remote_capabilities": "Station",
        "remote_port": "Eth1/20",
    }])
    engine.filters["include_other"] = True
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_nxos", 0)
    nic = [d for n, d in inv.devices.items() if "Adapter" in n]
    assert nic, "expected the NIC to be recorded"
    assert nic[0]["device_category"] == "host_nic"


def test_server_nic_excluded_when_other_devices_off():
    engine, inv = _engine_with_neighbors([{
        "remote_device": "Broadcom P225p NetXtreme-E Dual-port 10Gb/25Gb Ethernet Adapter",
        "remote_capabilities": "Station",
        "remote_port": "Eth1/21",
    }])
    engine.filters["include_other"] = False
    before = set(inv.devices)
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_nxos", 0)
    assert set(inv.devices) == before


def test_real_switch_neighbour_not_categorised_as_nic():
    engine, inv = _engine_with_neighbors([{
        "remote_device": "SW2",
        "remote_ip": "10.0.0.6",
        "remote_platform": "cisco WS-C3850-48P",
        "remote_capabilities": "Switch",
        "remote_port": "Gi1/0/1",
    }])
    engine._extract_neighbors(inv, "CORE1", "10.0.0.1", "cisco_nxos", 0)
    assert inv.devices["SW2"]["device_category"] != "host_nic"


def test_continuation_skips_already_collected_devices():
    """Adding to a previous scan should not redo work already done."""
    from app.inventory import DiscoveryInventory
    base = DiscoveryInventory.create(seed_ip="192.168.1.1")
    base.add_device("CORE-NX-01", mgmt_ip="192.168.1.1", discovery_source="login")
    base.mark_login_succeeded("CORE-NX-01")

    engine = DiscoveryEngine(
        seed_ip="192.168.1.10", seed_device_type="extreme",
        username="admin", password="admin", max_depth=1,
        base_inventory=base,
        filters={"include_routers": True, "include_switches": True},
    )
    inv = engine.discover()
    # Marked visited up front, which is how the BFS skips it.
    assert "192.168.1.1" in engine.visited
    assert "CORE-NX-01" in inv.devices
    assert inv.devices["CORE-NX-01"]["login_succeeded"] is True
    # Never re-collected: it carries only what the base scan had.
    assert inv.devices["CORE-NX-01"]["collector_data"] == {}
    # The new seed was scanned.
    assert "DIST-EXTREME-01" in inv.devices
    assert inv.devices["DIST-EXTREME-01"]["collector_data"]


def test_continuation_retries_previously_failed_devices():
    """A device that failed last time is not "already collected", so a
    continuation should attempt it again without being asked."""
    from app.inventory import DiscoveryInventory
    base = DiscoveryInventory.create(seed_ip="192.168.1.1")
    base.add_device("DIST-EXTREME-01", mgmt_ip="192.168.1.10",
                    discovery_source="cdp_lldp")
    base.mark_login_failed("DIST-EXTREME-01", "timeout")
    base.set_scan_summary(elapsed=1.0, failed={"192.168.1.10": "timeout"})

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=1,
        base_inventory=base,
        filters={"include_routers": True, "include_switches": True},
    )
    inv = engine.discover()
    assert "192.168.1.10" in engine.visited
    assert inv.devices["DIST-EXTREME-01"]["login_succeeded"] is True


def test_continuation_always_scans_explicit_targets():
    """An explicitly listed host is a request, so it runs even if the base
    scan already collected it -- that is how a refresh works."""
    from app.inventory import DiscoveryInventory
    base = DiscoveryInventory.create(seed_ip="192.168.1.1")
    base.add_device("CORE-NX-01", mgmt_ip="192.168.1.1", discovery_source="login")
    base.mark_login_succeeded("CORE-NX-01")

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0,
        base_inventory=base,
        target_hosts=[("192.168.1.1", "cisco_nxos")],
    )
    inv = engine.discover()
    assert "192.168.1.1" in engine.visited
    assert len(inv.devices["CORE-NX-01"]["collector_data"]) > 0


def test_continuation_preserves_the_original_inventory():
    from app.inventory import DiscoveryInventory
    base = DiscoveryInventory.create(seed_ip="10.0.0.1")
    base.add_device("OLD-DEVICE", mgmt_ip="10.0.0.99", discovery_source="login")
    base.mark_login_succeeded("OLD-DEVICE")
    before = set(base.devices)

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0,
        base_inventory=base,
    )
    inv = engine.discover()
    assert set(base.devices) == before, "base inventory was mutated"
    assert "OLD-DEVICE" in inv.devices
    assert "CORE-NX-01" in inv.devices


def test_continuation_merges_failure_records():
    from app.inventory import DiscoveryInventory
    base = DiscoveryInventory.create(seed_ip="10.0.0.1")
    base.set_scan_summary(elapsed=1.0, failed={"10.99.99.99": "unreachable"})

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0,
        base_inventory=base,
    )
    inv = engine.discover()
    failed = inv.to_dict()["scan_summary"]["failed"]
    assert "10.99.99.99" in failed, "a failure not retried must not vanish"


def test_snmp_fallback_collects_standard_mib_tables(monkeypatch):
    """A Firebox with SSH disabled should still yield interfaces, addressing,
    routes and neighbours."""
    from app.inventory import DiscoveryInventory
    from app.snmp_probe import SnmpCredentials
    import app.discovery_engine as mod

    monkeypatch.setattr(mod, "snmp_probe_outcome", lambda ip, creds: ({
        "hostname": "FW-EDGE-1", "mgmt_ip": ip,
        "device_type": "watchguard_fireware", "software_version": "12.10",
        "model": "M5800", "serial": "ABC123", "sys_descr": "WatchGuard Fireware",
        "sys_object_id": "1.3.6.1.4.1.3097", "sys_location": "DC",
        "discovery_source": "snmp", "login_succeeded": False,
    }, "v2c ok"))
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {
        "interfaces": {"interfaces_status": [{"port": "External", "status": "up"}],
                       "ip_interfaces": [{"intf": "External",
                                          "ipaddr": "203.0.113.129"}],
                       "collected_via": "snmp"},
        "l3_routing": {"routes": [{"network": "0.0.0.0",
                                   "nexthop_ip": "203.0.113.130"}],
                       "collected_via": "snmp"},
    })

    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        snmp_credentials=SnmpCredentials(version="v2c", community="public"),
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    assert engine._snmp_fallback(inv, "192.0.2.254", "no ssh listener") == "v2c ok"

    dev = inv.devices["FW-EDGE-1"]
    assert dev["login_succeeded"] is False
    assert dev["model"] == "M5800"
    cd = dev["collector_data"]
    assert cd["interfaces"]["parsed"]["interfaces_status"][0]["port"] == "External"
    assert cd["l3_routing"]["parsed"]["routes"][0]["nexthop_ip"] == "203.0.113.130"


def test_snmp_table_failure_keeps_the_identification(monkeypatch):
    """Table collection is enrichment; losing it must not lose the device."""
    from app.inventory import DiscoveryInventory
    from app.snmp_probe import SnmpCredentials
    import app.discovery_engine as mod

    monkeypatch.setattr(mod, "snmp_probe_outcome", lambda ip, creds: ({
        "hostname": "FW1", "mgmt_ip": ip, "device_type": "watchguard_fireware",
        "discovery_source": "snmp", "login_succeeded": False,
    }, "v2c ok"))

    def boom(*a, **k):
        raise OSError("timeout")

    monkeypatch.setattr(mod, "snmp_make_walker", boom)

    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        snmp_credentials=SnmpCredentials(version="v2c", community="public"),
    )
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
    assert engine._snmp_fallback(inv, "192.0.2.254", "no ssh") == "v2c ok"
    assert "FW1" in inv.devices


def _same_device_everywhere(monkeypatch, hostname="AB001-IDF-SWA-01"):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod.ConnectionManager, "get_prompt_facts",
                        staticmethod(lambda conn: {"hostname": hostname,
                                                   "ha_state": None}))


def test_two_targets_reaching_one_device_collect_once(monkeypatch):
    """Two listed addresses for the same chassis: the second is skipped."""
    _same_device_everywhere(monkeypatch)
    events = []
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin",
        target_hosts=[("192.168.1.1", "cisco_nxos"),
                      ("192.168.1.10", "extreme")],
        progress_callback=events.append,
    )
    engine.discover()
    skipped = [e for e in events
               if e.get("event") == "device_complete" and e.get("skipped")]
    assert len(skipped) == 1


def test_continuation_targets_reaching_one_device_collect_once(monkeypatch):
    """Explicit targets bypass dedupe against the base scan, but not
    against each other."""
    _same_device_everywhere(monkeypatch)
    base = DiscoveryInventory.create(seed_ip="192.168.1.1")
    base.add_device("AB001-IDF-SWA-01", mgmt_ip="192.168.1.1",
                    discovery_source="login")
    base.mark_login_succeeded("AB001-IDF-SWA-01")
    events = []
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin",
        base_inventory=base,
        target_hosts=[("192.168.1.1", "cisco_nxos"),
                      ("192.168.1.10", "extreme")],
        progress_callback=events.append,
    )
    engine.discover()
    done = [e for e in events if e.get("event") == "device_complete"]
    assert len(done) == 2
    assert sum(1 for e in done if e.get("skipped")) == 1


def test_target_resolution_recorded_in_scan_summary():
    resolution = {
        "targets": [{"input": "sw1.example.com", "resolved_ip": "192.168.1.1"}],
        "unresolved": [{"input": "gone.example.com", "error": "not found"}],
    }
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin",
        target_hosts=[("192.168.1.1", "cisco_nxos")],
        target_resolution=resolution,
    )
    inv = engine.discover()
    summary = inv.to_dict()["scan_summary"]
    by_input = {t["input"]: t for t in summary["targets"]}
    assert by_input["sw1.example.com"]["resolved_ip"] == "192.168.1.1"
    assert by_input["sw1.example.com"]["outcome"] in ("collected", "failed")
    assert by_input["gone.example.com"]["outcome"] == "unresolved"
    assert by_input["gone.example.com"]["reason"] == "not found"
    assert summary["unresolved"] == resolution["unresolved"]
    assert "failed" in summary
