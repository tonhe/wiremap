"""The reports summary API explains failures, not just counts them."""
from unittest.mock import patch

import pytest

with patch("logging.FileHandler"):
    from app.app import app
    import app.app as app_module

from app.inventory import DiscoveryInventory


@pytest.fixture
def client(tmp_path):
    app.config["TESTING"] = True
    original_dir = app_module.INVENTORY_DIR
    app_module.INVENTORY_DIR = str(tmp_path)
    try:
        with app.test_client() as c:
            yield c, str(tmp_path)
    finally:
        app_module.INVENTORY_DIR = original_dir


def test_summary_includes_reason_breakdown_and_skipped(client):
    c, inventory_dir = client
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1", params={})
    inv.add_device("sw1", mgmt_ip="192.0.2.1", device_type="cisco_ios")
    inv.set_scan_summary(
        elapsed=2.0,
        failed={
            "192.0.2.20": {"hostname": "sw20", "reason": "refused",
                           "hint": "h", "message": "m", "attempts": []},
            "192.0.2.21": "Authentication failed to 192.0.2.21",
        },
        skipped={"192.0.2.101": {"hostname": "leaf101", "reason": "controller_managed",
                                 "managed_by": "aci", "platform": "N9K-C93180YC-EX"}},
    )
    inv.save(inventory_dir)

    data = c.get(f"/api/reports/available/{inv.discovery_id}").get_json()
    summary = data["summary"]
    assert summary["failed_count"] == 2
    assert summary["skipped_count"] == 1
    reasons = {r["reason"]: r for r in summary["failure_reasons"]}
    assert reasons["refused"]["count"] == 1
    assert reasons["auth"]["count"] == 1
    assert "access-class" in reasons["refused"]["hint"]


def test_settings_api_round_trips_controller_managed(client, tmp_path, monkeypatch):
    import sys
    settings_module = sys.modules.get("settings") or sys.modules["app.settings"]
    monkeypatch.setattr(settings_module, "DEFAULT_CONFIG_DIR", str(tmp_path / "cfg"))
    c, _ = client
    rv = c.post("/api/settings/discovery",
                json={"max_workers": 4, "collect_controller_managed": True})
    assert rv.status_code == 200
    assert c.get("/api/settings/discovery").get_json()["collect_controller_managed"] is True
