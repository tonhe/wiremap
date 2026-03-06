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
from device_detector import DeviceTypeDetector
from discovery_engine import DiscoveryEngine, DiscoveryError
from inventory import DiscoveryInventory
from visualizer import NetworkVisualizer
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


@app.route('/discover', methods=['POST'])
def discover():
    """Handle discovery request using the new collector-based engine."""
    seed_ip = request.form.get('seed_ip', '').strip()
    device_type = request.form.get('device_type', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    max_depth = int(request.form.get('max_depth', 3))
    max_workers = int(request.form.get('max_workers', 10))
    protocol = request.form.get('protocol', 'ssh').strip()
    filters = {
        'include_routers': request.form.get('include_routers') == 'true',
        'include_switches': request.form.get('include_switches') == 'true',
        'include_phones': request.form.get('include_phones') == 'true',
        'include_servers': request.form.get('include_servers') == 'true',
        'include_aps': request.form.get('include_aps') == 'true',
        'include_other': request.form.get('include_other') == 'true',
        'include_l3': True,
    }

    if not all([seed_ip, device_type, username, password]):
        return render_template('index.html',
                             device_types=DEVICE_TYPES,
                             version=VERSION,
                             report_registry=_get_report_info(),
                             error="All fields are required")

    logger.info(f"Discovery request: seed={seed_ip}, type={device_type}, user={username}, depth={max_depth}")

    try:
        engine = DiscoveryEngine(
            seed_ip=seed_ip,
            seed_device_type=device_type,
            username=username,
            password=password,
            max_depth=max_depth,
            protocol=protocol,
            filters=filters,
            inventory_dir=INVENTORY_DIR,
            device_detector=detector,
            max_workers=max_workers,
        )

        inventory = engine.discover()
        inventory_data = inventory.to_dict()

        total_devices = len(inventory.devices)
        summary = {
            'devices': total_devices,
            'links': 0,
            'visited': list(engine.visited),
            'failed': engine.failed,
            'failed_count': len(engine.failed),
        }

        # Count links from cdp_lldp collector data
        unique_links = set()
        for device in inventory.devices.values():
            cdp_data = device.get("collector_data", {}).get("cdp_lldp", {})
            neighbors = cdp_data.get("parsed", {}).get("neighbors", [])
            hostname = device["hostname"]
            for n in neighbors:
                remote = n.get("remote_device", "Unknown")
                link_pair = tuple(sorted([hostname, remote]))
                unique_links.add(link_pair)
        summary['links'] = len(unique_links)

        logger.info(f"Discovery complete: {total_devices} devices, {summary['links']} links")

        # Generate visualization from inventory data
        viz_file = None
        try:
            viz_file = _generate_visualization(inventory_data, seed_ip)
        except Exception as e:
            logger.warning(f"Failed to generate visualization: {e}")

        # Determine which reports can be generated
        available_reports = _get_available_reports(inventory_data)

        return render_template('index.html',
                             device_types=DEVICE_TYPES,
                             version=VERSION,
                             summary=summary,
                             visualization=viz_file,
                             export_key=inventory.discovery_id,
                             available_reports=available_reports,
                             report_registry=_get_report_info(),
                             success=True)

    except DiscoveryError as e:
        logger.error(f"Discovery error: {e.message}")
        return render_template('index.html',
                             device_types=DEVICE_TYPES,
                             version=VERSION,
                             report_registry=_get_report_info(),
                             error=f"Discovery failed: {e.message}")

    except Exception as e:
        logger.exception("Unexpected error during discovery")
        return render_template('index.html',
                             device_types=DEVICE_TYPES,
                             version=VERSION,
                             report_registry=_get_report_info(),
                             error=f"Unexpected error: {str(e)}")


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
    """Load an inventory file for report generation."""
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        data = json.load(f)
        inventory = DiscoveryInventory(data)
        # Save uploaded inventory so export routes can find it
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
    total_devices = len(inventory.devices)

    # Count links
    unique_links = set()
    for device in inventory.devices.values():
        cdp_data = device.get("collector_data", {}).get("cdp_lldp", {})
        neighbors = cdp_data.get("parsed", {}).get("neighbors", [])
        hostname = device["hostname"]
        for n in neighbors:
            remote = n.get("remote_device", "Unknown")
            link_pair = tuple(sorted([hostname, remote]))
            unique_links.add(link_pair)

    summary = {
        'devices': total_devices,
        'links': len(unique_links),
        'visited': [],
        'failed': {},
        'failed_count': 0,
    }

    viz_file = None
    try:
        viz_file = _generate_visualization(inventory_data, inventory.seed_ip)
    except Exception as e:
        logger.warning(f"Failed to generate visualization: {e}")

    available_reports = _get_available_reports(inventory_data)

    return render_template('index.html',
                         device_types=DEVICE_TYPES,
                         version=VERSION,
                         summary=summary,
                         visualization=viz_file,
                         export_key=inventory.discovery_id,
                         available_reports=available_reports,
                         report_registry=_get_report_info(),
                         success=True)


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


@app.route('/visualization/<filename>')
def serve_visualization(filename):
    """Serve generated visualization files"""
    try:
        file_path = os.path.join('/tmp', filename)
        if os.path.exists(file_path):
            return send_file(file_path, mimetype='text/html')
        else:
            return "Visualization file not found", 404
    except Exception as e:
        logger.error(f"Error serving visualization: {e}")
        return "Error loading visualization", 500


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

    fmt = report.supported_formats[0]
    content = report.generate(inventory_data, fmt)

    mime_types = {
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "html": "text/html",
        "zip": "application/zip",
        "pdf": "application/pdf",
    }
    extensions = {
        "xlsx": "xlsx",
        "html": "html",
        "zip": "zip",
        "pdf": "pdf",
    }

    return send_file(
        io.BytesIO(content),
        mimetype=mime_types.get(fmt, "application/octet-stream"),
        as_attachment=True,
        download_name=f"{report_name}_{key}.{extensions.get(fmt, 'bin')}",
    )


# --- Helpers ---

def _get_report_info():
    """Return list of report dicts for the UI, grouped by category."""
    registry = get_report_registry()
    return [
        {
            "name": r.name,
            "label": r.label,
            "description": r.description,
            "format": r.supported_formats[0],
            "category": r.category,
            "ui_options": r.get_ui_options(),
        }
        for r in sorted(registry.values(), key=lambda r: (r.category, r.label))
    ]


def _get_available_reports(inventory_data):
    """Return list of reports that can be generated from this inventory."""
    registry = get_report_registry()
    available = []
    for r in sorted(registry.values(), key=lambda r: (r.category, r.label)):
        available.append({
            "name": r.name,
            "label": r.label,
            "description": r.description,
            "format": r.supported_formats[0],
            "category": r.category,
            "ui_options": r.get_ui_options(),
            "can_generate": r.can_generate(inventory_data),
        })
    return available


def _generate_visualization(inventory_data: dict, seed_ip: str):
    """Generate D3 topology visualization from inventory data. Returns filename or None."""
    topology_dict = {}
    for hostname, device in inventory_data.get("devices", {}).items():
        cdp_data = device.get("collector_data", {}).get("cdp_lldp", {})
        neighbors_parsed = cdp_data.get("parsed", {}).get("neighbors", [])

        neighbors = []
        for n in neighbors_parsed:
            neighbors.append({
                'neighbor_device': n.get('remote_device', 'Unknown'),
                'local_interface': n.get('local_intf', '?'),
                'remote_interface': n.get('remote_intf', '?'),
                'protocols': n.get('protocols', []),
            })

        device_category = device.get("device_category") or "unknown"
        topology_dict[hostname] = {
            'device_type': device_category,
            'has_routing': False,
            'neighbors': neighbors,
            'arp_entries': [],
            'arp_count': 0,
        }

    seed_hostname = None
    for hostname, device in inventory_data.get("devices", {}).items():
        if device.get("mgmt_ip") == seed_ip:
            seed_hostname = hostname
            break

    visualizer = NetworkVisualizer(topology_dict, seed_device=seed_hostname)
    viz_filename = f"topology_{seed_ip.replace('.', '_')}.html"
    viz_path = os.path.join('/tmp', viz_filename)
    visualizer.generate_html(viz_path)
    logger.info(f"Generated visualization: {viz_path} (seed: {seed_hostname})")
    return viz_filename


if __name__ == '__main__':
    logger.info("Starting Wiremap application")
    app.run(host='0.0.0.0', port=8000, debug=False)
