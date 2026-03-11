import json
import os
from unittest.mock import patch

import pytest

# Patch the FileHandler before importing app.app so the module-level
# logging.basicConfig() call doesn't try to open /app/logs/app.log.
with patch("logging.FileHandler"):
    from app.app import app
    import app.app as app_module

# Import the settings module the same way app/app.py does (bare import via
# the app/ path added to sys.path by conftest), so monkeypatching
# DEFAULT_CONFIG_DIR actually affects the module the route functions use.
import importlib, sys
settings_module = sys.modules.get("settings") or importlib.import_module("settings")


@pytest.fixture
def inventory_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture
def client(inventory_dir):
    app.config["TESTING"] = True
    original_dir = app_module.INVENTORY_DIR
    app_module.INVENTORY_DIR = inventory_dir
    try:
        with app.test_client() as c:
            yield c
    finally:
        app_module.INVENTORY_DIR = original_dir


def test_delete_inventory(inventory_dir, client):
    """Test DELETE /inventories/<filename> removes the file."""
    filepath = os.path.join(inventory_dir, "test123.json")
    with open(filepath, "w") as f:
        json.dump({"devices": {}}, f)

    assert os.path.exists(filepath)

    resp = client.delete("/inventories/test123.json")
    assert resp.status_code == 200
    assert not os.path.exists(filepath)


def test_delete_inventory_not_found(client):
    """Test DELETE /inventories/<filename> returns 404 for missing file."""
    resp = client.delete("/inventories/nonexistent.json")
    assert resp.status_code == 404


def test_delete_inventory_path_traversal(client):
    """Test DELETE /inventories/<filename> rejects path traversal."""
    # Flask decodes %2F to / before routing, so use a filename with '..'
    # that still matches the <filename> route segment.
    resp = client.delete("/inventories/..secret.json")
    assert resp.status_code == 400


def test_get_discovery_settings(client, tmp_path, monkeypatch):
    """GET /api/settings/discovery returns defaults."""
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    rv = client.get('/api/settings/discovery')
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["max_workers"] == 10


def test_save_discovery_settings(client, tmp_path, monkeypatch):
    """POST /api/settings/discovery persists settings."""
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    rv = client.post('/api/settings/discovery',
                     json={"max_workers": 5})
    assert rv.status_code == 200
    rv2 = client.get('/api/settings/discovery')
    assert rv2.get_json()["max_workers"] == 5


def test_save_discovery_settings_invalid(client, tmp_path, monkeypatch):
    """POST /api/settings/discovery rejects invalid values."""
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    rv = client.post('/api/settings/discovery',
                     json={"max_workers": 100})
    assert rv.status_code == 400


def test_load_inventory_returns_json(inventory_dir, client):
    """POST /load-inventory should return JSON, not HTML."""
    from app.inventory import DiscoveryInventory
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1", params={})
    inv.add_device("TEST-SW", mgmt_ip="10.0.0.1", device_type="cisco_ios")
    inv.save(inventory_dir)

    files = [f for f in os.listdir(inventory_dir) if f.endswith('.json')]
    rv = client.post('/load-inventory', data={"filename": files[0]})
    assert rv.status_code == 200
    data = rv.get_json()
    assert "inventory_key" in data
    assert "available_reports" in data


def test_reports_available_valid_key(inventory_dir, client):
    """GET /api/reports/available/<key> returns available report names."""
    from app.inventory import DiscoveryInventory
    inv = DiscoveryInventory.create(seed_ip="10.0.0.1", params={})
    inv.add_device("TEST-SW", mgmt_ip="10.0.0.1", device_type="cisco_ios")
    inv.save(inventory_dir)

    rv = client.get(f'/api/reports/available/{inv.discovery_id}')
    assert rv.status_code == 200
    data = rv.get_json()
    assert "inventory_key" in data
    assert "available_reports" in data
    assert isinstance(data["available_reports"], list)


def test_reports_available_missing_key(client):
    """GET /api/reports/available/<key> returns 404 for missing inventory."""
    rv = client.get('/api/reports/available/nonexistent')
    assert rv.status_code == 404
