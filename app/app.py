"""
Wiremap Flask Application
Web interface for network topology discovery
"""

import io
import json
import logging
import os
import zipfile
from flask import Flask, render_template, request, jsonify, send_file
import requests
from device_detector import DeviceTypeDetector
from discovery_engine import DiscoveryEngine, DiscoveryError
from inventory import DiscoveryInventory
from inventory_merge import claim_unused_id, merge_inventories as merge_inventory_dicts
from neighbors import CrawlScope, get_registry as get_neighbor_sources
from snmp_probe import SnmpCredentials
from scan_manager import ScanManager
from plugins import get_plugin_config, save_plugin_config, get_plugin_status, list_plugins
from settings import get_discovery_settings, save_discovery_settings
from source_access import clean_source_ip
from target_list import (WARN_TARGET_COUNT, make_resolver, parse_targets,
                         resolve_targets)
try:
    from app.collectors import get_registry as get_collector_registry
    from app.reports import get_registry as get_report_registry, get_report
except ImportError:
    from collectors import get_registry as get_collector_registry
    from reports import get_registry as get_report_registry, get_report
try:
    from app.credentials import parse_credential_form
except ImportError:
    from credentials import parse_credential_form

# Read version
VERSION = "0.2"
try:
    with open('/app/VERSION', 'r') as f:
        VERSION = f.read().strip()
except:
    pass

# Configure logging
logging.getLogger("eox_client").setLevel(logging.DEBUG)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)

scan_manager = ScanManager()

# Initialize device type detector
detector = DeviceTypeDetector()

INVENTORY_DIR = "/app/inventories"

# Common device types for dropdown
DEVICE_TYPES = [
    ('cisco_ios', 'Cisco IOS'),
    ('cisco_xe', 'Cisco IOS-XE'),
    ('cisco_nxos', 'Cisco NX-OS'),
    ('cisco_xr', 'Cisco IOS-XR'),
    ('arista_eos', 'Arista EOS'),
    ('juniper_junos', 'Juniper JunOS'),
    ('paloalto_panos', 'Palo Alto PAN-OS'),
    ('mikrotik_routeros', 'MikroTik RouterOS'),
    ('fortinet', 'Fortinet FortiGate'),
    ('hp_procurve', 'HP ProCurve'),
    ('hp_comware', 'HPE Comware'),
    ('aruba_os', 'Aruba OS-CX'),
    ('dell_os10', 'Dell OS10'),
    ('dell_force10', 'Dell Force10'),
    ('extreme', 'Extreme ExtremeXOS'),
    ('extreme_vsp', 'Extreme VOSS'),
    ('ubiquiti_edge', 'Ubiquiti EdgeOS'),
    # 'barracuda' was offered here but is not a netmiko platform in any
    # version -- selecting it could only ever raise ValueError.
    ('vyos', 'VyOS'),
    ('cisco_wlc', 'Cisco AireOS WLC'),
    ('watchguard_fireware', 'WatchGuard Firebox'),
]


@app.route('/')
def index():
    """Main page with discovery form"""
    sources = [
        {"name": s.name, "label": s.label, "description": s.description,
         "enabled_by_default": s.enabled_by_default}
        for s in sorted(get_neighbor_sources().values(), key=lambda s: s.name)
    ]
    return render_template('index.html', device_types=DEVICE_TYPES, version=VERSION,
                         report_registry=_get_report_info(),
                         neighbor_sources=sources)


@app.route('/scan/start', methods=['POST'])
def scan_start():
    """Start a scan in the background, return scan_id."""
    if scan_manager.is_running():
        return jsonify({"error": "A scan is already running"}), 409

    scan_type = request.form.get('scan_type', 'discovery')
    protocol = request.form.get('protocol', 'ssh')
    disc_settings = get_discovery_settings()
    max_workers = disc_settings.get("max_workers", 10)
    disable_autodetect = disc_settings.get("disable_autodetect", False)
    collect_controller_managed = bool(
        disc_settings.get("collect_controller_managed", False))
    max_logins_per_minute = int(disc_settings.get("max_logins_per_minute") or 0)
    allow_telnet = bool(disc_settings.get("allow_telnet", False))
    connect_timeout = int(disc_settings.get("connect_timeout_s") or 10)
    # Per-scan source address overrides the saved one; blank learns it.
    try:
        source_ip = (clean_source_ip(request.form.get('source_ip', ''))
                     or clean_source_ip(disc_settings.get('source_ip') or ''))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Up to five sets: username/password, then username_2/password_2 ...
    try:
        credentials = parse_credential_form(request.form)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    target_resolution = None
    if scan_type == 'targeted':
        has_file = bool(getattr(request.files.get('host_file'), 'filename', ''))
        if not request.form.get('host_list', '').strip() and not has_file:
            return jsonify({"error": "Host list is required"}), 400
        valid_types = {dt[0] for dt in DEVICE_TYPES}
        try:
            target_hosts, target_resolution = _build_target_hosts(
                request.form, request.files, valid_types)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        seed_ip = target_hosts[0][0]
        seed_type = target_hosts[0][1] or 'cisco_ios'
    else:
        seed_ip = request.form.get('seed_ip', '').strip()
        seed_type = request.form.get('device_type', '').strip()
        if not seed_ip or not seed_type:
            return jsonify({"error": "Seed IP and device type are required"}), 400
        target_hosts = None

    max_depth = int(request.form.get('max_depth', 3))
    crawl_from_targets = request.form.get('crawl_from_targets') == 'true'

    # Neighbour sources: which sightings are allowed to feed the crawl.
    submitted_sources = request.form.getlist('neighbor_sources')
    neighbor_sources = set(submitted_sources) if submitted_sources else None

    try:
        crawl_scope = CrawlScope(
            allow_cidrs=_split_cidrs(request.form.get('scope_allow', '')),
            deny_cidrs=_split_cidrs(request.form.get('scope_deny', '')),
            rfc1918_only=request.form.get('scope_private_only', 'true') != 'false',
            max_devices=int(request.form.get('max_devices') or 0) or None,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # SNMP is a fallback for hosts that refuse SSH and telnet, so credentials
    # are supplied per run alongside the login credentials.
    try:
        snmp_credentials = _build_snmp_credentials(request.form)
    except ValueError as e:
        return jsonify({"error": f"SNMP: {e}"}), 400

    # Adding to a previous scan: load it and hand it to the engine, which
    # treats its collected devices as already visited.
    base_inventory = None
    continue_from = request.form.get('continue_from', '').strip()
    if continue_from:
        base_path = os.path.join(INVENTORY_DIR, os.path.basename(continue_from))
        if not os.path.exists(base_path):
            return jsonify({"error": f"Previous scan not found: {continue_from}"}), 400
        try:
            base_inventory = DiscoveryInventory.load(base_path)
        except Exception as e:
            return jsonify({"error": f"Could not load previous scan: {e}"}), 400
    filters = {
        'include_routers': request.form.get('include_routers') == 'true',
        'include_switches': request.form.get('include_switches') == 'true',
        'include_phones': request.form.get('include_phones') == 'true',
        'include_servers': request.form.get('include_servers') == 'true',
        'include_aps': request.form.get('include_aps') == 'true',
        'include_other': request.form.get('include_other') == 'true',
    } if (scan_type == 'discovery' or crawl_from_targets) else None

    def run_scan(progress_cb, cancelled):
        det = DeviceTypeDetector()
        engine = DiscoveryEngine(
            seed_ip=seed_ip,
            seed_device_type=seed_type,
            username=credentials[0].username,
            password=credentials[0].password,
            credentials=credentials,
            max_depth=max_depth,
            protocol=protocol,
            filters=filters,
            inventory_dir=INVENTORY_DIR,
            device_detector=det,
            max_workers=max_workers,
            target_hosts=target_hosts,
            progress_callback=progress_cb,
            cancelled=cancelled,
            disable_autodetect=disable_autodetect,
            crawl_from_targets=crawl_from_targets,
            neighbor_sources=neighbor_sources,
            crawl_scope=crawl_scope,
            expand_non_cdp_neighbors=bool(
                disc_settings.get("expand_non_cdp_neighbors", False)),
            snmp_credentials=snmp_credentials,
            base_inventory=base_inventory,
            target_resolution=target_resolution,
            collect_controller_managed=collect_controller_managed,
            max_logins_per_minute=max_logins_per_minute,
            allow_telnet=allow_telnet,
            source_ip=source_ip or None,
            connect_timeout=connect_timeout,
        )
        inventory = engine.discover()
        inventory.save(INVENTORY_DIR)
        return inventory

    scan_id = scan_manager.start_scan(scan_type, run_scan)
    if scan_id is None:
        return jsonify({"error": "A scan is already running"}), 409

    response = {"scan_id": scan_id}
    if target_resolution:
        response["target_count"] = len(target_hosts)
        response["resolved"] = len(target_resolution["targets"])
        response["unresolved"] = target_resolution["unresolved"]
        response["warnings"] = target_resolution["warnings"]
        response["resolver"] = target_resolution.get("resolver")
    return jsonify(response)


@app.route('/scan/<scan_id>/stream')
def scan_stream(scan_id):
    """SSE endpoint -- streams scan events until completion."""
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    def generate():
        for chunk in scan_manager.event_stream(scan_id):
            yield chunk

    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )


@app.route('/scan/<scan_id>/cancel', methods=['POST'])
def scan_cancel(scan_id):
    """Cancel a running scan."""
    scan = scan_manager.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    scan_manager.cancel_scan(scan_id)
    return jsonify({"status": "cancelling"})


@app.route('/inventories')
def list_inventories():
    """List saved discovery inventories."""
    try:
        inventories = DiscoveryInventory.list_inventories(INVENTORY_DIR)
    except FileNotFoundError:
        inventories = []
    return jsonify(inventories)


@app.route('/inventories/merge', methods=['POST'])
def merge_inventories_route():
    """Merge two or more saved scans into a new one.

    The sources are left in place -- a merge adds a scan, it never consumes
    the ones it was built from.
    """
    payload = request.get_json(silent=True) or {}
    filenames = payload.get('filenames') or request.form.getlist('filenames')
    if not isinstance(filenames, list) or len(filenames) < 2:
        return jsonify({"error": "Select at least two scans to merge"}), 400

    loaded = []
    for name in filenames:
        path = os.path.join(INVENTORY_DIR, os.path.basename(name))
        if not os.path.exists(path):
            return jsonify({"error": f"Scan not found: {name}"}), 404
        try:
            loaded.append(DiscoveryInventory.load(path).to_dict())
        except Exception as e:
            return jsonify({"error": f"Could not read {name}: {e}"}), 400

    try:
        merged_data = merge_inventory_dicts(
            loaded, filenames=[os.path.basename(n) for n in filenames])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    claim_unused_id(merged_data, INVENTORY_DIR)
    merged = DiscoveryInventory(merged_data)
    merged.save(INVENTORY_DIR)

    registry = get_report_registry()
    available = [r.name for r in registry.values() if r.can_generate(merged_data)]

    return jsonify({
        "inventory_key": merged.discovery_id,
        "filename": f"{merged.discovery_id}.json",
        "device_count": len(merged.devices),
        "merged_from": merged_data.get("merged_from", []),
        "merge_conflicts": merged_data.get("merge_conflicts", []),
        "available_reports": available,
    })


@app.route('/inventories/<filename>', methods=['DELETE'])
def delete_inventory(filename):
    """Delete a saved inventory file."""
    if '..' in filename or '/' in filename:
        return jsonify({"error": "Invalid filename"}), 400
    filepath = os.path.join(INVENTORY_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Inventory not found"}), 404
    os.remove(filepath)
    return jsonify({"status": "deleted"})


@app.route('/load-inventory', methods=['POST'])
def load_inventory():
    """Load an inventory file for report generation. Returns JSON."""
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        data = json.load(f)
        inventory = DiscoveryInventory(data)
        check_path = os.path.join(INVENTORY_DIR, f"{inventory.discovery_id}.json")
        if not os.path.exists(check_path):
            inventory.save(INVENTORY_DIR)
    elif 'filename' in request.form:
        filepath = os.path.join(INVENTORY_DIR, request.form['filename'])
        if not os.path.exists(filepath):
            return jsonify({"error": "Inventory file not found"}), 404
        inventory = DiscoveryInventory.load(filepath)
    else:
        return jsonify({"error": "No file or filename provided"}), 400

    inventory_data = inventory.to_dict()
    registry = get_report_registry()
    available = [r.name for r in registry.values() if r.can_generate(inventory_data)]

    return jsonify({
        "inventory_key": inventory.discovery_id,
        "available_reports": available,
        "summary": inventory.get_summary(),
    })


@app.route('/api/reports/available/<key>')
def api_reports_available(key):
    """Return which reports can be generated for this inventory."""
    filepath = os.path.join(INVENTORY_DIR, f"{key}.json")
    if not os.path.exists(filepath):
        return jsonify({"error": "Inventory not found"}), 404

    inventory = DiscoveryInventory.load(filepath)
    inventory_data = inventory.to_dict()
    registry = get_report_registry()

    available = []
    for r in registry.values():
        if r.can_generate(inventory_data):
            available.append(r.name)

    return jsonify({
        "inventory_key": key,
        "available_reports": available,
        "summary": inventory.get_summary(),
    })


@app.route('/export/inventory/<key>')
def export_inventory(key):
    """Download discovery inventory JSON."""
    filepath = os.path.join(INVENTORY_DIR, f"{key}.json")
    if not os.path.exists(filepath):
        return "Inventory not found", 404
    return send_file(filepath,
                     mimetype='application/json',
                     as_attachment=True,
                     download_name=f"{key}.json")


@app.route('/export/archive/<key>')
def export_archive(key):
    """Download full ZIP archive (inventory + configs)."""
    filepath = os.path.join(INVENTORY_DIR, f"{key}.json")
    if not os.path.exists(filepath):
        return "Inventory not found", 404

    inventory = DiscoveryInventory.load(filepath)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Include inventory JSON
        zf.write(filepath, "inventory.json")

        # Include device configs if available
        for hostname, device in inventory.devices.items():
            config_data = device.get("collector_data", {}).get("config", {})
            config_text = config_data.get("parsed", {}).get("config", "")
            if config_text:
                zf.writestr(f"configs/{hostname}.txt", config_text)

    buf.seek(0)
    return send_file(buf,
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name=f"discovery_{key}.zip")


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})


@app.route('/export/report/<key>/<report_name>')
def export_report(key, report_name):
    """Generate and download a report for a given inventory."""
    filepath = os.path.join(INVENTORY_DIR, f"{key}.json")
    if not os.path.exists(filepath):
        return "Inventory not found", 404

    report = get_report(report_name)
    if report is None:
        return "Unknown report type", 404

    inventory = DiscoveryInventory.load(filepath)
    inventory_data = inventory.to_dict()

    if not report.can_generate(inventory_data):
        return "Insufficient data for this report", 400

    fmt = request.args.get('format', report.supported_formats[0])
    if fmt not in report.supported_formats:
        return "Unsupported format", 400

    content = report.generate(inventory_data, fmt)

    mime_types = {
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "html": "text/html",
        "zip": "application/zip",
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
        "xml": "application/xml",
    }
    extensions = {
        "xlsx": "xlsx",
        "html": "html",
        "zip": "zip",
        "pdf": "pdf",
        "json": "json",
        "csv": "csv",
        "xml": "xml",
    }

    inline = request.args.get('inline')
    return send_file(
        io.BytesIO(content),
        mimetype=mime_types.get(fmt, "application/octet-stream"),
        as_attachment=not inline,
        download_name=f"{report_name}_{key}.{extensions.get(fmt, 'bin')}",
    )


# --- Plugin API ---

@app.route('/api/plugins')
def api_list_plugins():
    return jsonify(list_plugins())


@app.route('/api/plugins/cisco_eox', methods=['POST'])
def api_save_cisco_eox():
    data = request.get_json(force=True)
    has_creds = bool(data.get("client_id") and data.get("client_secret"))
    config = {"enabled": data.get("enabled", has_creds)}
    if data.get("client_id"):
        config["client_id"] = data["client_id"]
    if data.get("client_secret"):
        config["client_secret"] = data["client_secret"]
    save_plugin_config("cisco_eox", config)
    return jsonify(get_plugin_status("cisco_eox"))


@app.route('/api/plugins/cisco_eox/test', methods=['POST'])
def api_test_cisco_eox():
    cfg = get_plugin_config("cisco_eox")
    if not cfg or not cfg.get("client_id") or not cfg.get("client_secret"):
        return jsonify({"success": False, "error": "Plugin not configured"}), 400
    try:
        resp = requests.post(
            "https://id.cisco.com/oauth2/default/v1/token",
            data={"grant_type": "client_credentials"},
            auth=(cfg["client_id"], cfg["client_secret"]),
            timeout=10,
        )
        if resp.status_code == 200 and resp.json().get("access_token"):
            return jsonify({"success": True})
        else:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text[:500]
            return jsonify({"success": False, "error": f"HTTP {resp.status_code}", "detail": detail})
    except requests.RequestException as e:
        return jsonify({"success": False, "error": str(e)})


# --- Discovery Settings API ---

@app.route('/api/settings/discovery')
def api_get_discovery_settings():
    return jsonify(get_discovery_settings())


@app.route('/api/settings/discovery', methods=['POST'])
def api_save_discovery_settings():
    data = request.get_json(force=True)
    try:
        save_discovery_settings(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(get_discovery_settings())


# --- Helpers ---

def _build_snmp_credentials(form):
    """Build SNMP credentials from a scan form, or None when not enabled."""
    if form.get('snmp_enabled') != 'true':
        return None
    version = (form.get('snmp_version') or 'v2c').strip()
    return SnmpCredentials(
        version=version,
        community=form.get('snmp_community', '').strip(),
        username=form.get('snmp_username', '').strip(),
        auth_key=form.get('snmp_auth_key', ''),
        priv_key=form.get('snmp_priv_key', ''),
        auth_protocol=form.get('snmp_auth_protocol', 'sha'),
        priv_protocol=form.get('snmp_priv_protocol', 'aes'),
    )


def _split_cidrs(raw_text):
    """Split a comma or newline separated CIDR list."""
    if not raw_text:
        return []
    parts = raw_text.replace("\n", ",").split(",")
    return [p.strip() for p in parts if p.strip()]


def _parse_host_list(raw_text, valid_types, filename=None):
    """Parse a pasted or uploaded host list into unresolved host entries.

    Text: one `host [device_type]` per line, host an IPv4 address or a
    hostname/FQDN; blank lines and # comments ignored. CSV (by .csv name or
    a recognisable header): hostname and/or ip column, optional device_type.
    """
    return parse_targets(raw_text, valid_types, filename=filename)


MAX_HOST_FILE_BYTES = 5 * 1024 * 1024


def _read_host_file(storage):
    """Return (text, filename) from an uploaded host file, or ('', None)."""
    if storage is None or not storage.filename:
        return "", None
    data = storage.read(MAX_HOST_FILE_BYTES + 1)
    if len(data) > MAX_HOST_FILE_BYTES:
        raise ValueError("Host file is larger than 5 MB")
    return data.decode("utf-8-sig", errors="replace"), storage.filename


def _build_target_hosts(form, files, valid_types):
    """Parse paste and upload, resolve names. Returns (hosts, resolution)."""
    entries = []
    pasted = form.get('host_list', '').strip()
    if pasted:
        entries.extend(_parse_host_list(pasted, valid_types))
    file_text, filename = _read_host_file(files.get('host_file'))
    if file_text.strip():
        try:
            entries.extend(_parse_host_list(file_text, valid_types, filename))
        except ValueError as e:
            raise ValueError(f"{filename}: {e}")
    if not entries:
        raise ValueError("No valid hosts provided")
    disc_settings = get_discovery_settings()
    resolver, resolver_name = make_resolver(
        disc_settings.get("dns_server") or None,
        disc_settings.get("dns_search") or [])
    hosts, targets, unresolved = resolve_targets(entries, resolver=resolver)
    resolution = {"targets": targets, "unresolved": unresolved,
                  "warnings": [], "resolver": resolver_name}
    names = len(targets) + len(unresolved)
    if unresolved:
        resolution["warnings"].append(
            f"{len(unresolved)} of {names} hostname(s) did not resolve using "
            f"{resolver_name}. If they are in a customer zone, set DNS Server "
            f"and DNS Search Suffix in Settings")
    # Recorded in the scan params so a report says which list it ran from.
    resolution["targets_file"] = os.path.basename(filename) if filename else None
    if len(hosts) > WARN_TARGET_COUNT:
        resolution["warnings"].append(
            f"{len(hosts)} targets is more than {WARN_TARGET_COUNT}; "
            f"check the list is network devices only")
    if not hosts:
        names = ", ".join(u["input"] for u in unresolved[:10])
        raise ValueError(f"No hosts resolved using {resolver_name}: {names}")
    return hosts, resolution

def _get_report_info():
    """Return list of report dicts for the UI, grouped by category."""
    registry = get_report_registry()
    return [
        {
            "name": r.name,
            "label": r.label,
            "description": r.description,
            "format": r.supported_formats[0],
            "supported_formats": r.supported_formats,
            "category": r.category,
            "ui_options": r.get_ui_options(),
        }
        for r in sorted(registry.values(), key=lambda r: (r.category, r.label))
    ]


if __name__ == '__main__':
    logger.info("Starting Wiremap application")
    app.run(host='0.0.0.0', port=8000, debug=False)
