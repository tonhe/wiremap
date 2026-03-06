"""
Routing Summary report -- protocol neighbors, route tables, and routed interfaces.
"""
import io
import re
from openpyxl import Workbook

from .base import BaseReport
from .xlsx_utils import create_sheet
from .l2_discovery import (
    _extract_ip_interfaces,
    _get_interface_description,
    _get_cdp_neighbor,
)


class RoutingSummaryReport(BaseReport):
    name = "routing_summary"
    label = "Routing Summary"
    description = "Routing protocol neighbors, route tables, and routed interfaces"
    category = "Layer 3 & Routing"
    required_collectors = ["l3_routing"]
    supported_formats = ["xlsx"]

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        wb = Workbook()
        wb.remove(wb.active)

        neighbor_rows = []
        route_rows = []
        routed_rows = []

        for hostname, device in sorted(inventory_data.get("devices", {}).items()):
            l3_data = device.get("collector_data", {}).get("l3_routing", {})
            parsed = l3_data.get("parsed", {})

            # Routing neighbors
            for n in parsed.get("neighbors", []):
                neighbor_rows.append([
                    hostname,
                    ", ".join(n.get("protocols", [])),
                    n.get("remote_ip", ""),
                    n.get("remote_device", ""),
                ])

            # Routes
            for r in parsed.get("routes", []):
                route_rows.append([
                    hostname,
                    r.get("network", r.get("destination", "")),
                    r.get("mask", r.get("prefix_length", "")),
                    r.get("nexthop_ip", r.get("next_hop", "")),
                    r.get("nexthop_if", r.get("interface", "")),
                    r.get("protocol", ""),
                    r.get("metric", ""),
                ])

            # Routed interfaces (non-SVI)
            interfaces = _extract_ip_interfaces(device)
            for intf in sorted(interfaces, key=lambda x: x["interface"]):
                iface_name = intf["interface"]
                if re.match(r"^[Vv]lan\d+$", iface_name):
                    continue
                for ip_info in intf["ips"]:
                    cidr = (f"{ip_info['ip']}/{ip_info['prefix']}"
                            if ip_info["prefix"] else ip_info["ip"])
                    desc = _get_interface_description(device, iface_name)
                    if not desc:
                        desc = _get_cdp_neighbor(device, iface_name)
                    iface_lower = iface_name.lower()
                    if "loopback" in iface_lower:
                        note = "Loopback"
                    elif "mgmt" in iface_lower or "management" in iface_lower:
                        note = "OOB management"
                    elif "port-channel" in iface_lower or "po" == iface_lower[:2]:
                        note = "Routed port-channel"
                    elif "tunnel" in iface_lower:
                        note = "Tunnel"
                    else:
                        note = "Routed interface"
                    if ip_info["secondary"]:
                        note += " (secondary)"
                    routed_rows.append([hostname, iface_name, cidr, desc, note])

        create_sheet(wb, "Protocol Neighbors",
                     ["Device", "Protocol", "Neighbor IP", "Neighbor Device"],
                     neighbor_rows)

        create_sheet(wb, "Routes",
                     ["Device", "Network", "Mask", "Next Hop", "Interface",
                      "Protocol", "Metric"],
                     route_rows)

        create_sheet(wb, "Routed Interfaces",
                     ["Device", "Interface", "IP / CIDR", "Description / Neighbor",
                      "Notes"],
                     routed_rows)

        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()
