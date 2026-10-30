"""Controller-managed devices (ACI fabric nodes, UCS Fabric Interconnects)
and structured failure recording in the discovery engine."""
import errno

import pytest
from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException

import app.connection_manager as cmod
import app.discovery_engine as engine_mod
from app.device_detector import DeviceTypeDetector
from app.discovery_engine import DiscoveryEngine
from app.inventory import DiscoveryInventory
from app.inventory_merge import merge_inventories


@pytest.fixture(autouse=True)
def _real_connections_faked(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(engine_mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(engine_mod, "snmp_collect_all", lambda walker: {})


@pytest.fixture
def detector():
    return DeviceTypeDetector()


# --- detection ---------------------------------------------------------------

def test_aci_leaf_detected(detector):
    m = detector.detect_controller_managed("N9K-C93180YC-EX", "leaf101(FDO12345ABC)")
    assert m == {"managed_by": "aci", "device_category": None}


def test_aci_spine_detected_with_cisco_prefix(detector):
    m = detector.detect_controller_managed("cisco N9K-C9336PQ", "spine201")
    assert m["managed_by"] == "aci"


def test_standalone_nexus_is_not_aci(detector):
    assert detector.detect_controller_managed("N9K-C93180YC-EX", "core-sw1") is None


def test_leaf_name_on_non_nexus_is_not_aci(detector):
    assert detector.detect_controller_managed("cisco WS-C3850-48P", "leaf101") is None


def test_ucs_fi_detected(detector):
    m = detector.detect_controller_managed("UCS-FI-6454", "fi-a")
    assert m == {"managed_by": "ucsm", "device_category": "fabric-interconnect"}


def test_ucs_fi_gets_nxos_type(detector):
    assert detector.detect_from_cdp("cisco UCS-FI-6332-16UP") == "cisco_nxos"


def test_detection_works_without_config_section(tmp_path):
    cfg = tmp_path / "p.yaml"
    cfg.write_text("device_types: {}\ndefault_device_type: cisco_ios\n")
    det = DeviceTypeDetector(config_path=str(cfg))
    assert det.detect_controller_managed("UCS-FI-6454", "fi-b")["managed_by"] == "ucsm"


# --- engine: neighbour handling ----------------------------------------------

def _engine(**kw):
    from app.neighbors import CrawlScope
    eng = DiscoveryEngine(
        seed_ip="192.0.2.1", seed_device_type="cisco_nxos",
        username="u", password="p", max_depth=1,
        filters={"include_routers": True, "include_switches": True},
        # Documentation addresses are not RFC 1918; allow them explicitly.
        crawl_scope=CrawlScope(allow_cidrs=["192.0.2.0/24"], rfc1918_only=False),
        **kw,
    )
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("core1", mgmt_ip="192.0.2.1", discovery_source="login")
    return eng, inv


ACI_LEAF = {
    "remote_device": "leaf101(FDO12345ABC)",
    "remote_ip": "192.0.2.101",
    "remote_platform": "N9K-C93180YC-EX",
    "remote_capabilities": "Router Switch",
    "remote_port": "Eth1/49",
}
UCS_FI = {
    "remote_device": "fi-a(SSI12345ABC)",
    "remote_ip": "192.0.2.111",
    "remote_platform": "UCS-FI-6454",
    "remote_capabilities": "Switch",
    "remote_port": "Eth1/1",
}


def test_controller_managed_neighbours_kept_but_not_queued():
    eng, inv = _engine()
    inv.set_collector_data("core1", "cdp_lldp", {}, {"neighbors": [ACI_LEAF, UCS_FI]})
    queued = eng._extract_neighbors(inv, "core1", "192.0.2.1", "cisco_nxos", 0)
    assert queued == []

    leaf = inv.devices["leaf101"]
    assert leaf["managed_by"] == "aci"
    assert leaf["serial"] == "FDO12345ABC"
    assert leaf["device_category"] == "switch"
    assert leaf["evidence"][0]["seen_from"] == "core1"

    fi = inv.devices["fi-a"]
    assert fi["managed_by"] == "ucsm"
    assert fi["device_category"] == "fabric-interconnect"
    assert fi["device_type"] == "cisco_nxos"

    assert eng.skipped["192.0.2.101"] == {
        "hostname": "leaf101", "reason": "controller_managed",
        "managed_by": "aci", "platform": "N9K-C93180YC-EX",
    }
    assert eng.skipped["192.0.2.111"]["managed_by"] == "ucsm"
    assert "192.0.2.101" not in eng.failed


def test_controller_managed_collected_when_enabled():
    eng, inv = _engine(collect_controller_managed=True)
    inv.set_collector_data("core1", "cdp_lldp", {}, {"neighbors": [ACI_LEAF]})
    queued = eng._extract_neighbors(inv, "core1", "192.0.2.1", "cisco_nxos", 0)
    assert [ip for ip, _ in queued] == ["192.0.2.101"]
    assert eng.skipped == {}
    assert inv.devices["leaf101"]["managed_by"] == "aci"


def test_known_controller_managed_target_is_not_logged_into(monkeypatch):
    """A continued scan or a host list naming an ACI node must not try it."""
    calls = []
    monkeypatch.setattr(cmod, "_connect_handler",
                        lambda **p: calls.append(p) or (_ for _ in ()).throw(AssertionError))
    base = DiscoveryInventory.create(seed_ip="192.0.2.1")
    base.add_device("leaf101", mgmt_ip="192.0.2.101", platform="N9K-C93180YC-EX")
    base.set_controller_managed("leaf101", "aci")
    base.set_scan_summary(elapsed=1.0, failed={
        "192.0.2.101": "Authentication failed to 192.0.2.101"})

    eng = DiscoveryEngine(
        seed_ip="192.0.2.101", seed_device_type="", username="u", password="p",
        target_hosts=[("192.0.2.101", None)], base_inventory=base)
    inv = eng.discover()
    assert calls == []
    summary = inv.to_dict()["scan_summary"]
    assert summary["failed"] == {}
    assert summary["skipped_count"] == 1
    assert summary["skipped"]["192.0.2.101"]["managed_by"] == "aci"


# --- engine: failure records -------------------------------------------------

def _refused(**params):
    try:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
    except ConnectionRefusedError:
        raise NetmikoTimeoutException("TCP connection to device failed.")


def test_failed_login_stored_as_structured_record(monkeypatch):
    monkeypatch.setattr(cmod, "_connect_handler", _refused)
    events = []
    eng = DiscoveryEngine(
        seed_ip="192.0.2.50", seed_device_type="cisco_xe",
        username="u", password="p", max_depth=0, protocol="auto",
        progress_callback=events.append)
    inv = eng.discover()

    rec = inv.to_dict()["scan_summary"]["failed"]["192.0.2.50"]
    assert rec["reason"] == "refused"
    assert "access-class" in rec["hint"]
    assert rec["attempts"][0]["exception_class"] == "NetmikoTimeoutException"
    assert rec["attempts"][0]["port"] == 22

    failed_evt = [e for e in events if e["event"] == "device_failed"][0]
    assert failed_evt["reason"] == "refused"
    assert failed_evt["hint"] == rec["hint"]

    done = [e for e in events if e["event"] == "scan_complete"][0]
    assert done["failed_count"] == 1
    assert done["failure_reasons"][0]["reason"] == "refused"
    assert done["failure_reasons"][0]["count"] == 1


def test_failed_record_carries_neighbour_hostname(monkeypatch):
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: (_ for _ in ()).throw(
        NetmikoAuthenticationException("Authentication to device failed.")))
    base = DiscoveryInventory.create(seed_ip="192.0.2.1")
    base.add_device("dist1", mgmt_ip="192.0.2.60", platform="cisco WS-C3850-48P")
    eng = DiscoveryEngine(
        seed_ip="192.0.2.60", seed_device_type="", username="u", password="p",
        target_hosts=[("192.0.2.60", None)], base_inventory=base)
    inv = eng.discover()
    rec = inv.to_dict()["scan_summary"]["failed"]["192.0.2.60"]
    assert rec["hostname"] == "dist1"
    assert rec["reason"] == "auth"


def test_prior_string_failure_is_normalised(monkeypatch):
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    base = DiscoveryInventory.create(seed_ip="192.0.2.1")
    base.set_scan_summary(elapsed=1.0, failed={"192.0.2.99": "timeout: no answer"})
    eng = DiscoveryEngine(
        seed_ip="192.168.1.1", seed_device_type="cisco_nxos",
        username="admin", password="admin", max_depth=0, base_inventory=base)
    inv = eng.discover()
    rec = inv.to_dict()["scan_summary"]["failed"]["192.0.2.99"]
    assert rec["reason"] == "timeout"
    assert rec["message"] == "timeout: no answer"


# --- summary and merge -------------------------------------------------------

def test_get_summary_breaks_down_old_string_failures():
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv._data["scan_summary"] = {"elapsed": 1, "failed_count": 2, "failed": {
        "192.0.2.5": "Authentication failed to 192.0.2.5",
        "192.0.2.6": "ssh/cisco_ios: timeout: TCP connection to device failed",
    }}
    s = inv.get_summary()
    assert {r["reason"] for r in s["failure_reasons"]} == {"auth", "timeout"}
    assert s["skipped_count"] == 0


def _scan(failed=None, skipped=None, ts="2026-01-01T00:00:00+00:00"):
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.set_scan_summary(elapsed=1.0, failed=failed or {}, skipped=skipped)
    data = inv.to_dict()
    data["timestamp"] = ts
    return data


def test_merge_prefers_structured_failure_over_string():
    rich = {"hostname": "sw1", "reason": "refused", "hint": "h",
            "message": "m", "attempts": []}
    a = _scan(failed={"192.0.2.7": rich}, ts="2026-01-01T00:00:00+00:00")
    b = _scan(failed={"192.0.2.7": "old string"}, ts="2026-01-02T00:00:00+00:00")
    merged = merge_inventories([a, b])
    assert merged["scan_summary"]["failed"]["192.0.2.7"] == rich
    assert merged["scan_summary"]["failure_reasons"][0]["reason"] == "refused"


def test_merge_carries_skipped_and_drops_matching_failure():
    skip = {"hostname": "leaf101", "reason": "controller_managed",
            "managed_by": "aci", "platform": "N9K-C93180YC-EX"}
    a = _scan(failed={"192.0.2.101": "Authentication failed to 192.0.2.101"})
    b = _scan(skipped={"192.0.2.101": skip})
    merged = merge_inventories([a, b])
    assert merged["scan_summary"]["skipped"] == {"192.0.2.101": skip}
    assert merged["scan_summary"]["failed"] == {}
