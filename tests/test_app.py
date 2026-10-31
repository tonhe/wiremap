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


def test_save_site_rules_from_text(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    rv = client.post('/api/settings/discovery',
                     json={"max_workers": 5, "site_rules": "^AB001- => HQ"})
    assert rv.status_code == 200
    assert rv.get_json()["site_rules"] == [{"pattern": "^AB001-", "site": "HQ"}]


def test_save_site_rules_rejects_bad_regex(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    rv = client.post('/api/settings/discovery', json={"site_rules": "( => X"})
    assert rv.status_code == 400
    assert "invalid regex" in rv.get_json()["error"]


def test_settings_ui_has_site_rules(client):
    _point_at_repo_templates()
    assert b'id="settings-site-rules"' in client.get('/').data
def test_discovery_settings_redact_secrets_toggle(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    assert client.get('/api/settings/discovery').get_json()["redact_secrets"] is True
    rv = client.post('/api/settings/discovery',
                     json={"max_workers": 5, "redact_secrets": False})
    assert rv.status_code == 200
    assert rv.get_json()["redact_secrets"] is False


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


def test_continue_from_option_on_both_forms(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    assert body.count("Add results to a previous scan") == 2
    assert "disc_continue_from" in body
    assert "ts_continue_from" in body


def test_continue_from_rejects_missing_scan(client):
    resp = client.post("/scan/start", data={
        "scan_type": "discovery", "seed_ip": "10.0.0.1",
        "device_type": "cisco_ios", "username": "u", "password": "p",
        "continue_from": "does-not-exist.json",
    })
    assert resp.status_code == 400
    assert "not found" in resp.get_json()["error"].lower()


def test_continue_from_cannot_escape_inventory_dir(client):
    """The filename is attacker-adjacent input; it must not traverse."""
    resp = client.post("/scan/start", data={
        "scan_type": "discovery", "seed_ip": "10.0.0.1",
        "device_type": "cisco_ios", "username": "u", "password": "p",
        "continue_from": "../../etc/passwd",
    })
    assert resp.status_code == 400


def test_merge_requires_two_scans(client):
    resp = client.post("/inventories/merge", json={"filenames": ["one.json"]})
    assert resp.status_code == 400
    assert "at least two" in resp.get_json()["error"].lower()


def test_merge_rejects_missing_file(client):
    resp = client.post("/inventories/merge",
                       json={"filenames": ["a.json", "nope.json"]})
    assert resp.status_code in (400, 404)


def test_merge_cannot_escape_inventory_dir(client):
    resp = client.post("/inventories/merge",
                       json={"filenames": ["../../etc/passwd", "../../etc/hosts"]})
    assert resp.status_code in (400, 404)


def _scan_file(inventory_dir, discovery_id, hostnames, timestamp):
    data = {
        "discovery_id": discovery_id, "seed_ip": "192.0.2.1",
        "timestamp": timestamp, "params": {},
        "devices": {h: {"hostname": h, "login_succeeded": True,
                        "collector_data": {}} for h in hostnames},
    }
    with open(os.path.join(inventory_dir, f"{discovery_id}.json"), "w") as f:
        json.dump(data, f)
    return data


def test_remerge_lists_originals_in_saved_scans(inventory_dir, client):
    """Merging a merge again lists the original scans, so the Saved Scans
    badge counts them rather than counting the merge file as one."""
    from app.inventory_merge import merge_inventories
    a = _scan_file(inventory_dir, "scan-a", ["SW1", "SW2"],
                   "2026-08-25T10:00:00+00:00")
    b = _scan_file(inventory_dir, "scan-b", ["SW1", "SW3"],
                   "2026-08-27T10:00:00+00:00")
    first = merge_inventories([a, b], filenames=["scan-a.json", "scan-b.json"])
    first["discovery_id"] = "2026-08-28_00-00-00_merged"
    with open(os.path.join(inventory_dir, "2026-08-28_00-00-00_merged.json"),
              "w") as f:
        json.dump(first, f)

    resp = client.post("/inventories/merge", json={
        "filenames": ["2026-08-28_00-00-00_merged.json", "scan-b.json"]})
    assert resp.status_code == 200
    body = resp.get_json()
    assert [m["discovery_id"] for m in body["merged_from"]] == ["scan-a", "scan-b"]

    listed = {i["discovery_id"]: i for i in client.get("/inventories").get_json()}
    assert len(listed[body["inventory_key"]]["merged_from"]) == 2


def test_merge_ui_present_in_saved_scans(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    assert "merge-bar" in body
    assert "mergeSelectedScans" in body
    assert "Merge selected" in body


def test_summed_elapsed_is_labelled_in_the_ui(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    assert "elapsed_summed" in body
    assert "ELAPSED (SUMMED)" in body


class _CapturedScan:
    def __init__(self, monkeypatch):
        self.engine_kwargs = None
        captured = self

        class FakeEngine:
            def __init__(self, **kwargs):
                captured.engine_kwargs = kwargs

            def discover(self):
                class Inv:
                    def save(self, d):
                        return None
                return Inv()

        def fake_start(scan_type, fn):
            fn(lambda e: None, None)
            return "scan-1"

        monkeypatch.setattr(app_module, "DiscoveryEngine", FakeEngine)
        monkeypatch.setattr(app_module.scan_manager, "is_running", lambda: False)
        monkeypatch.setattr(app_module.scan_manager, "start_scan", fake_start)


def _fake_dns(monkeypatch, table):
    import socket

    def resolve(host, port, family=0, type=0, *a, **k):
        if host not in table:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], 0))]
    monkeypatch.setattr(socket, "getaddrinfo", resolve)


TARGETED = {"scan_type": "targeted", "username": "u", "password": "p"}


def test_targeted_scan_resolves_hostnames(client, monkeypatch):
    scan = _CapturedScan(monkeypatch)
    _fake_dns(monkeypatch, {"sw1.example.com": "192.0.2.1"})
    resp = client.post("/scan/start", data=dict(
        TARGETED, host_list="sw1.example.com cisco_ios\ngone.example.com\n192.0.2.2"))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["target_count"] == 2
    assert [u["input"] for u in body["unresolved"]] == ["gone.example.com"]
    kw = scan.engine_kwargs
    assert kw["target_hosts"] == [("192.0.2.1", "cisco_ios"), ("192.0.2.2", None)]
    assert kw["seed_ip"] == "192.0.2.1"
    assert kw["target_resolution"]["targets"] == [
        {"input": "sw1.example.com", "resolved_ip": "192.0.2.1"}]
    assert kw["target_resolution"]["unresolved"][0]["input"] == "gone.example.com"


def test_targeted_scan_with_nothing_resolvable_is_rejected(client, monkeypatch):
    _CapturedScan(monkeypatch)
    _fake_dns(monkeypatch, {})
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="gone.example.com"))
    assert resp.status_code == 400
    assert "gone.example.com" in resp.get_json()["error"]


def test_targeted_scan_accepts_uploaded_csv_with_paste(client, monkeypatch):
    import io
    scan = _CapturedScan(monkeypatch)
    _fake_dns(monkeypatch, {"AB001-IDF-SWA-01.example.net": "192.0.2.20"})
    csv_body = b"hostname,ip,device_type\nAB001-IDF-SWA-01.example.net,,cisco_ios\n,192.0.2.21,\n"
    resp = client.post("/scan/start", content_type="multipart/form-data", data=dict(
        TARGETED, host_list="192.0.2.22",
        host_file=(io.BytesIO(csv_body), "hosts.csv")))
    assert resp.status_code == 200, resp.get_json()
    assert scan.engine_kwargs["target_hosts"] == [
        ("192.0.2.22", None), ("192.0.2.20", "cisco_ios"), ("192.0.2.21", None)]


def test_targeted_scan_accepts_upload_alone(client, monkeypatch):
    import io
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", content_type="multipart/form-data", data=dict(
        TARGETED, host_file=(io.BytesIO(b"# list\n192.0.2.30\n"), "hosts.txt")))
    assert resp.status_code == 200
    assert scan.engine_kwargs["target_hosts"] == [("192.0.2.30", None)]


def test_targeted_scan_records_uploaded_filename(client, monkeypatch):
    import io
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", content_type="multipart/form-data", data=dict(
        TARGETED, host_file=(io.BytesIO(b"192.0.2.31\n"), "site-a-hosts.txt")))
    assert resp.status_code == 200
    assert scan.engine_kwargs["target_resolution"]["targets_file"] == "site-a-hosts.txt"


def test_pasted_target_list_has_no_targets_file(client, monkeypatch):
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="192.0.2.32"))
    assert resp.status_code == 200
    assert scan.engine_kwargs["target_resolution"]["targets_file"] is None


def test_expand_non_cdp_setting_reaches_the_engine(client, monkeypatch):
    scan = _CapturedScan(monkeypatch)
    monkeypatch.setattr(app_module, "get_discovery_settings",
                        lambda: {"expand_non_cdp_neighbors": True})
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="192.0.2.33"))
    assert resp.status_code == 200
    assert scan.engine_kwargs["expand_non_cdp_neighbors"] is True


def test_targeted_scan_upload_errors_name_the_file(client, monkeypatch):
    import io
    _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", content_type="multipart/form-data", data=dict(
        TARGETED, host_file=(io.BytesIO(b"192.0.2.999\n"), "hosts.txt")))
    assert resp.status_code == 400
    assert "hosts.txt" in resp.get_json()["error"]


def test_targeted_scan_requires_some_hosts(client, monkeypatch):
    _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(TARGETED))
    assert resp.status_code == 400


def test_large_target_list_warns(client, monkeypatch):
    _CapturedScan(monkeypatch)
    monkeypatch.setattr(app_module, "WARN_TARGET_COUNT", 2)
    resp = client.post("/scan/start", data=dict(
        TARGETED, host_list="192.0.2.1\n192.0.2.2\n192.0.2.3"))
    assert resp.status_code == 200
    assert resp.get_json()["warnings"]


def test_targeted_form_has_file_upload(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    assert 'name="host_file"' in body
    assert 'accept=".txt,.csv' in body


def test_scan_passes_login_rate_limit_to_engine(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    settings_module.save_discovery_settings({"max_logins_per_minute": 90},
                                            config_dir=str(tmp_path))
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="192.0.2.1"))
    assert resp.status_code == 200
    assert scan.engine_kwargs["max_logins_per_minute"] == 90


def test_login_rate_setting_saved_and_validated(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    assert client.get('/api/settings/discovery').get_json()["max_logins_per_minute"] == 0
    rv = client.post('/api/settings/discovery', json={"max_logins_per_minute": 30})
    assert rv.get_json()["max_logins_per_minute"] == 30
    rv = client.post('/api/settings/discovery', json={"max_logins_per_minute": 1000})
    assert rv.status_code == 400


def test_settings_ui_has_login_rate_control(client):
    _point_at_repo_templates()
    body = client.get('/').get_data(as_text=True)
    assert 'id="settings-max-logins"' in body
    assert "source_access_warning" in body


def test_scan_source_ip_from_form_overrides_setting(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    settings_module.save_discovery_settings({"source_ip": "198.51.100.20"},
                                            config_dir=str(tmp_path))
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="192.0.2.1"))
    assert resp.status_code == 200
    assert scan.engine_kwargs["source_ip"] == "198.51.100.20"
    resp = client.post("/scan/start", data=dict(
        TARGETED, host_list="192.0.2.1", source_ip="192.0.2.50"))
    assert resp.status_code == 200
    assert scan.engine_kwargs["source_ip"] == "192.0.2.50"


def test_scan_without_source_ip_leaves_it_to_the_seed(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="192.0.2.1"))
    assert resp.status_code == 200
    assert scan.engine_kwargs["source_ip"] is None


def test_scan_rejects_a_bad_source_ip(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(
        TARGETED, host_list="192.0.2.1", source_ip="192.0.2.0/24"))
    assert resp.status_code == 400
    assert "Source IP" in resp.get_json()["error"]


def test_source_ip_setting_saved_and_validated(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, 'DEFAULT_CONFIG_DIR', str(tmp_path))
    assert client.get('/api/settings/discovery').get_json()["source_ip"] == ""
    rv = client.post('/api/settings/discovery', json={"source_ip": " 192.0.2.50 "})
    assert rv.get_json()["source_ip"] == "192.0.2.50"
    rv = client.post('/api/settings/discovery', json={"source_ip": "not-an-ip"})
    assert rv.status_code == 400
    rv = client.post('/api/settings/discovery', json={"source_ip": ""})
    assert rv.get_json()["source_ip"] == ""


def test_ui_has_source_ip_fields_and_console_line(client):
    _point_at_repo_templates()
    body = client.get('/').get_data(as_text=True)
    assert 'id="settings-source-ip"' in body
    assert 'id="disc_source_ip"' in body
    assert 'id="ts_source_ip"' in body
    assert "addEventListener('source_access'" in body
    assert "source_access_line" in body


# --- multiple credential sets ---------------------------------------------

DISCOVERY = {"scan_type": "discovery", "seed_ip": "192.0.2.1",
             "device_type": "cisco_ios"}


def test_scan_start_passes_extra_credential_sets(client, monkeypatch):
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(
        DISCOVERY, username="netops", password="pw-one",
        username_2="", password_2="",
        username_3="backup-admin", password_3="pw-three"))
    assert resp.status_code == 200, resp.get_json()
    creds = scan.engine_kwargs["credentials"]
    assert [(c.number, c.username) for c in creds] == [(1, "netops"), (3, "backup-admin")]
    assert scan.engine_kwargs["username"] == "netops"


def test_scan_start_single_set_still_works(client, monkeypatch):
    scan = _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(TARGETED, host_list="192.0.2.5"))
    assert resp.status_code == 200, resp.get_json()
    assert [c.username for c in scan.engine_kwargs["credentials"]] == ["u"]


def test_scan_start_rejects_username_without_password(client, monkeypatch):
    _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(
        TARGETED, host_list="192.0.2.5", username_2="backup-admin"))
    assert resp.status_code == 400
    assert "set 2" in resp.get_json()["error"]


def test_scan_start_requires_a_complete_set(client, monkeypatch):
    _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(DISCOVERY, username="", password=""))
    assert resp.status_code == 400
    assert "required" in resp.get_json()["error"].lower()


def test_scan_start_error_never_echoes_a_password(client, monkeypatch):
    _CapturedScan(monkeypatch)
    resp = client.post("/scan/start", data=dict(
        DISCOVERY, username="netops", password="pw-one",
        password_2="Sekr1t-Echo-55"))
    assert resp.status_code == 400
    assert "Sekr1t-Echo-55" not in resp.get_data(as_text=True)


def test_index_offers_add_credentials_on_both_forms(client):
    _point_at_repo_templates()
    body = client.get("/").get_data(as_text=True)
    assert body.count('class="btn-sm cred-add"') == 2
    assert 'data-prefix="disc"' in body and 'data-prefix="ts"' in body
