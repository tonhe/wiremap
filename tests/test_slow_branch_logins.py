"""Branches behind an SD-WAN edge: slow logins, and devices that were
collected before but fail on a later run."""
import app.discovery_engine as mod
from app.connection_manager import ConnectionError as WiremapConnectionError
from app.inventory import DiscoveryInventory


def _failing_cm(seen, reason="timeout"):
    class FakeCM:
        def __init__(self, **kwargs):
            seen.append(kwargs)

        def connect(self):
            raise WiremapConnectionError(
                f"Connection failed to {seen[-1]['host']}: {reason}",
                attempts=[], reason=reason)
    return FakeCM


def _collected_base():
    base = DiscoveryInventory.create(seed_ip="192.0.2.10")
    base.add_device("BR01-DIST-SW-01", mgmt_ip="192.0.2.10",
                    discovery_source="login")
    base.mark_login_succeeded("BR01-DIST-SW-01")
    base.devices["BR01-DIST-SW-01"]["collector_data"] = {
        "device_inventory": {"parsed": {"hostname": "BR01-DIST-SW-01"}}}
    return base


def test_connect_timeout_reaches_every_login_and_the_params(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(mod, "ConnectionManager", _failing_cm(seen))
    engine = mod.DiscoveryEngine(
        seed_ip="192.0.2.10", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0, connect_timeout=30,
        inventory_dir=str(tmp_path))
    inv = engine.discover()
    assert seen[0]["connect_timeout"] == 30
    params = inv.to_dict()["params"]
    assert params["connect_timeout_s"] == 30
    assert params["telnet_probe_timeout_s"] >= 5
    assert params["allow_telnet"] is False
    assert params["max_logins_per_minute"] == 0


def test_connect_timeout_defaults_to_ten_seconds(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(mod, "ConnectionManager", _failing_cm(seen))
    mod.DiscoveryEngine(
        seed_ip="192.0.2.10", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        inventory_dir=str(tmp_path)).discover()
    assert seen[0]["connect_timeout"] == 10


def test_refresh_failure_keeps_the_collected_record(monkeypatch, tmp_path):
    """A distribution switch collected last run that times out this run
    keeps its data, and the operator is told its neighbours were not
    crawled from it."""
    seen, events = [], []
    monkeypatch.setattr(mod, "ConnectionManager", _failing_cm(seen))
    engine = mod.DiscoveryEngine(
        seed_ip="192.0.2.10", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        base_inventory=_collected_base(),
        target_hosts=[("192.0.2.10", "cisco_ios")],
        progress_callback=events.append, inventory_dir=str(tmp_path))
    inv = engine.discover()
    dev = inv.devices["BR01-DIST-SW-01"]
    assert dev["login_succeeded"] is True
    assert dev["collector_data"]["device_inventory"]
    assert "timeout" in dev["last_login_error"]
    kept = [e for e in events if e.get("event") == "device_kept"]
    assert len(kept) == 1
    assert "BR01-DIST-SW-01" in kept[0]["message"]
    assert "neighbours were not crawled" in kept[0]["message"]
    assert engine.failed["192.0.2.10"]["kept_collected"] is True


def test_failed_neighbour_is_still_marked_failed():
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("BR01-ACC-SW-01", mgmt_ip="192.0.2.20",
                   discovery_source="cdp")
    assert inv.mark_login_failed_by_ip("192.0.2.20", "timeout") is None
    dev = inv.devices["BR01-ACC-SW-01"]
    assert dev["login_succeeded"] is False
    assert dev["login_error"] == "timeout"


def test_collected_device_is_not_downgraded_by_a_failed_address():
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("BR01-DIST-SW-01", mgmt_ip="192.0.2.10",
                   discovery_source="login")
    inv.mark_login_succeeded("BR01-DIST-SW-01")
    assert inv.mark_login_failed_by_ip("192.0.2.10", "refused") == \
        "BR01-DIST-SW-01"
    dev = inv.devices["BR01-DIST-SW-01"]
    assert dev["login_succeeded"] is True
    assert dev["last_login_error"] == "refused"
    assert not dev.get("login_error")


def test_peak_logins_per_minute_is_recorded(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(mod, "ConnectionManager", _failing_cm(seen))

    class Limiter:
        per_minute = 0
        peak_per_minute = 7

        def acquire(self):
            return 0.0
    engine = mod.DiscoveryEngine(
        seed_ip="192.0.2.10", seed_device_type="cisco_ios",
        username="u", password="p", max_depth=0,
        inventory_dir=str(tmp_path))
    engine._login_limiter = Limiter()
    summary = engine.discover().to_dict()["scan_summary"]
    assert summary["peak_logins_per_minute"] == 7
