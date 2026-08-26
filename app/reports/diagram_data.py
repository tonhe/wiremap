"""Diagram Data report.

The existing topology reports render a picture or describe one layer. Drawing
an L2/L3 diagram by hand needs something different: a node list carrying the
labels that go in the box (hostname, management IP, model) and clean edge lists
for each layer, deduplicated so one physical link is one line.

Every device appears as a node, including those only ever seen in a neighbour
table -- a diagram that silently omits them is wrong -- with provenance columns
so the reader can tell which boxes were actually collected.
"""
import io
import ipaddress
from collections import OrderedDict

from openpyxl import Workbook

from .base import BaseReport
from .xlsx_utils import create_sheet

try:
    from app.device_facts import extract_device_facts
except ImportError:
    from device_facts import extract_device_facts


def _role(device):
    """Best-effort layer label for diagram placement."""
    category = (device.get("device_category") or "").lower()
    hostname = (device.get("hostname") or "").lower()
    platform = f"{device.get('platform') or ''} {device.get('model') or ''}".lower()

    for token, role in (("core", "Core"), ("dist", "Distribution"),
                        ("access", "Access"), ("edge", "Edge"),
                        ("wan", "WAN"), ("dmz", "DMZ")):
        if token in hostname:
            return role

    if category in ("firewall", "router"):
        return category.title()
    if "wlc" in platform or "controller" in platform:
        return "Wireless"
    if category:
        return category.title()
    return ""


def _network_for(ip, prefix):
    if not ip:
        return ""
    try:
        if prefix:
            return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        return str(ipaddress.ip_network(f"{ip}/32", strict=False))
    except ValueError:
        return ""


def _parsed(device, collector):
    data = device.get("collector_data", {}).get(collector, {}).get("parsed", {})
    if data.get("collector_failed") or data.get("not_applicable"):
        return {}
    return data


class DiagramDataReport(BaseReport):
    name = "diagram_data"
    label = "L2/L3 Diagram Data"
    description = ("Node and edge lists for drawing L2/L3 diagrams: device "
                   "details, deduplicated links, adjacencies and subnets")
    category = "Discovery & Topology"
    required_collectors = ["cdp_lldp"]
    supported_formats = ["xlsx", "csv", "json", "xml"]

    def _devices_sheet(self, inventory_data):
        headers = [
            "Hostname", "Mgmt IP", "Model", "Device Type", "Role", "Category",
            "Serial", "Software Version", "Site", "Discovery Source",
            "Logged In", "Login Error",
        ]
        rows = []
        for hostname, device in sorted(inventory_data.get("devices", {}).items()):
            facts = extract_device_facts(_parsed(device, "device_inventory"))
            model = (device.get("model") or facts["model"]
                     or device.get("platform") or "")
            version = device.get("software_version") or facts["software_version"] or ""
            serial = device.get("serial") or facts["serial"] or ""
            rows.append([
                hostname,
                device.get("mgmt_ip") or "",
                model,
                device.get("device_type") or "",
                _role(device),
                device.get("device_category") or "",
                serial,
                version,
                hostname.split("-")[0] if "-" in hostname else "",
                device.get("discovery_source") or "",
                "Yes" if device.get("login_succeeded") else "No",
                device.get("login_error") or "",
            ])
        return headers, rows

    def _l2_links_sheet(self, inventory_data):
        headers = ["Device A", "Port A", "Device B", "Port B",
                   "Device B IP", "Platform B", "Source"]
        rows = []
        seen = set()
        for hostname, device in sorted(inventory_data.get("devices", {}).items()):
            for n in _parsed(device, "cdp_lldp").get("neighbors", []):
                remote = n.get("remote_device") or n.get("remote_ip") or "Unknown"
                local_intf = n.get("local_intf") or ""
                remote_intf = n.get("remote_intf") or ""
                # One physical link is reported from both ends; a diagram
                # wants one edge.
                key = tuple(sorted([f"{hostname}:{local_intf}",
                                    f"{remote}:{remote_intf}"]))
                if key in seen:
                    continue
                seen.add(key)
                rows.append([
                    hostname, local_intf, remote, remote_intf,
                    n.get("remote_ip") or "",
                    n.get("remote_platform") or "",
                    n.get("source") or "cdp_lldp",
                ])
        return headers, rows

    def _l3_links_sheet(self, inventory_data):
        headers = ["Device A", "Interface A", "Neighbor IP", "Protocol",
                   "State", "Resolved Device"]
        rows = []
        seen = set()
        by_ip = {
            (d.get("mgmt_ip") or ""): name
            for name, d in inventory_data.get("devices", {}).items()
        }
        for hostname, device in sorted(inventory_data.get("devices", {}).items()):
            for n in _parsed(device, "l3_routing").get("neighbors", []):
                remote_ip = n.get("remote_ip") or ""
                protocol = n.get("protocol") or ""
                key = (hostname, remote_ip, protocol)
                if key in seen:
                    continue
                seen.add(key)
                rows.append([
                    hostname,
                    n.get("local_intf") or "",
                    remote_ip,
                    protocol,
                    n.get("state") or "",
                    by_ip.get(remote_ip, ""),
                ])
        return headers, rows

    def _subnets_sheet(self, inventory_data):
        headers = ["Device", "Interface", "IP Address", "Network", "Description"]
        rows = []
        for hostname, device in sorted(inventory_data.get("devices", {}).items()):
            parsed = _parsed(device, "interfaces")
            for entry in parsed.get("ip_interfaces", []):
                ip = entry.get("ip_address") or entry.get("ipaddr") or ""
                if not ip:
                    continue
                prefix = (entry.get("prefix_length") or entry.get("prefix")
                          or entry.get("mask") or "")
                rows.append([
                    hostname,
                    entry.get("interface") or entry.get("intf") or "",
                    ip,
                    _network_for(ip, prefix),
                    entry.get("description") or "",
                ])
        return headers, rows

    def generate_tabular_data(self, inventory_data):
        return OrderedDict([
            ("Devices", self._devices_sheet(inventory_data)),
            ("L2 Links", self._l2_links_sheet(inventory_data)),
            ("L3 Links", self._l3_links_sheet(inventory_data)),
            ("Subnets", self._subnets_sheet(inventory_data)),
        ])

    def generate(self, inventory_data: dict, fmt: str = "xlsx", **params) -> bytes:
        if fmt == "xlsx":
            tabular = self.generate_tabular_data(inventory_data)
            wb = Workbook()
            wb.remove(wb.active)
            for sheet_name, (headers, rows) in tabular.items():
                create_sheet(wb, sheet_name, headers, rows)
            buf = io.BytesIO()
            wb.save(buf)
            return buf.getvalue()

        return self._generate_for_format(inventory_data, fmt)
