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
from scan_manager import ScanManager
from plugins import get_plugin_config, save_plugin_config, get_plugin_status, list_plugins
from settings import get_discovery_settings, save_discovery_settings
try:
    from app.collectors import get_registry as get_collector_registry
    from app.reports import get_registry as get_report_registry, get_report
except ImportError:
    from collectors import get_registry as get_collector_registry
    from reports import get_registry as get_report_registry, get_report

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
    ('barracuda', 'Barracuda'),
]


@app.route('/')
def index():
    """Main page with discovery form"""
    return render_template('index.html', device_types=DEVICE_TYPES, version=VERSION,
                         report_registry=_get_report_info())


@app.route('/scan/start', methods=['POST'])
def scan_start():
    """Start a scan in the background, return scan_id."""
    if scan_manager.is_running():
        return jsonify({"error": "A scan is already running"}), 409

    scan_type = request.form.get('scan_type', 'discovery')
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    protocol = request.form.get('protocol', 'ssh')
    disc_settings = get_discovery_settings()
    max_workers = disc_settings.get("max_workers", 10)

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if scan_type == 'targeted':
        host_list_raw = request.form.get('host_list', '').strip()
        if not host_list_raw:
            return jsonify({"error": "Host list is required"}), 400
        valid_types = {dt[0] for dt in DEVICE_TYPES}
        try:
            target_hosts = _parse_host_list(host_list_raw, valid_types)
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
    filters = {
        'include_routers': request.form.get('include_routers') == 'true',
        'include_switches': request.form.get('include_switches') == 'true',
        'include_phones': request.form.get('include_phones') == 'true',
        'include_servers': request.form.get('include_servers') == 'true',
        'include_aps': request.form.get('include_aps') == 'true',
        'include_other': request.form.get('include_other') == 'true',
    } if scan_type == 'discovery' else None

    def run_scan(progress_cb, cancelled):
        det = DeviceTypeDetector()
        engine = DiscoveryEngine(
            seed_ip=seed_ip,
            seed_device_type=seed_type,
            username=username,
            password=password,
            max_depth=max_depth,
            protocol=protocol,
            filters=filters,
            inventory_dir=INVENTORY_DIR,
            device_detector=det,
            max_workers=max_workers,
            target_hosts=target_hosts,
            progress_callback=progress_cb,
            cancelled=cancelled,
        )
        inventory = engine.discover()
        inventory.save(INVENTORY_DIR)
        return inventory

    scan_id = scan_manager.start_scan(scan_type, run_scan)
    if scan_id is None:
        return jsonify({"error": "A scan is already running"}), 409

    return jsonify({"scan_id": scan_id})


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

def _parse_host_list(raw_text, valid_types):
    """Parse textarea host list into [(ip, device_type_or_None), ...].

    Each line: IP [device_type]. Blank lines and # comments ignored.
    """
    hosts = []
    seen_ips = set()
    for lineno, line in enumerate(raw_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        ip = parts[0]
        octets = ip.split(".")
        if len(octets) != 4:
            raise ValueError(f"Line {lineno}: invalid IP address '{ip}'")
        for octet in octets:
            if not octet.isdigit() or not 0 <= int(octet) <= 255:
                raise ValueError(f"Line {lineno}: invalid IP address '{ip}'")
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        device_type = None
        if len(parts) >= 2:
            device_type = parts[1]
            if device_type not in valid_types:
                raise ValueError(f"Line {lineno}: unknown device type '{device_type}'")
        hosts.append((ip, device_type))
    if not hosts:
        raise ValueError("No valid hosts provided")
    return hosts

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
