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


def _point_at_repo_templates():
    """In Docker the app runs from /app with templates alongside; from the
    repo root the folder is one level up."""
    import pathlib
    repo = pathlib.Path(__file__).resolve().parent.parent
    app.template_folder = str(repo / "templates")


def test_index_renders_with_neighbor_sources(client):
    _point_at_repo_templates()
    """The discovery form needs the source list; a missing variable would
    render an empty checkbox grid rather than erroring."""
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Discover Neighbours Via" in body
    assert "routing_adjacency" in body
    assert "next_hop" in body
    assert "Crawl boundaries" in body


def test_index_lists_new_device_types(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    for dt in ("vyos", "cisco_wlc", "watchguard_fireware"):
        assert dt in body
    assert "barracuda" not in body


def test_snmp_fields_on_both_scan_forms(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    assert body.count("Fall back to SNMP when login fails") == 2
    assert "disc_snmp_enabled" in body
    assert "ts_snmp_enabled" in body
    assert "snmp_community" in body
    assert "snmp_priv_key" in body


def test_snmp_credentials_built_from_form():
    from app.app import _build_snmp_credentials
    assert _build_snmp_credentials({}) is None
    creds = _build_snmp_credentials({
        "snmp_enabled": "true", "snmp_version": "v2c",
        "snmp_community": "public",
    })
    assert creds.is_configured() is True
    assert creds.version == "v2c"


def test_snmp_v3_credentials_built_from_form():
    from app.app import _build_snmp_credentials
    creds = _build_snmp_credentials({
        "snmp_enabled": "true", "snmp_version": "v3",
        "snmp_username": "netadmin", "snmp_auth_key": "authpass",
        "snmp_priv_key": "privpass",
    })
    assert creds.version == "v3"
    assert creds.username == "netadmin"


def test_snmp_v2c_without_community_is_rejected():
    import pytest
    from app.app import _build_snmp_credentials
    with pytest.raises(ValueError):
        _build_snmp_credentials({"snmp_enabled": "true", "snmp_version": "v2c"})


def test_split_cidrs_handles_commas_and_newlines():
    from app.app import _split_cidrs
    assert _split_cidrs("10.0.0.0/8, 192.168.0.0/16") == ["10.0.0.0/8", "192.168.0.0/16"]
    assert _split_cidrs("10.0.0.0/8\n172.16.0.0/12") == ["10.0.0.0/8", "172.16.0.0/12"]
    assert _split_cidrs("") == []
