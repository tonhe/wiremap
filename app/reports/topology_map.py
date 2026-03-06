"""
Topology Map report -- wraps existing NetworkVisualizer.
"""
import os
import tempfile

from .base import BaseReport


class TopologyMapReport(BaseReport):
    name = "topology_map"
    label = "Topology Map"
    description = "Interactive D3.js network topology visualization"
    category = "Discovery & Topology"
    required_collectors = ["cdp_lldp"]
    supported_formats = ["html"]

    def generate(self, inventory_data: dict, fmt: str = "html") -> bytes:
        try:
            from app.visualizer import NetworkVisualizer
        except ImportError:
            from visualizer import NetworkVisualizer

        topology_dict = {}
        for hostname, device in inventory_data.get("devices", {}).items():
            cdp_data = device.get("collector_data", {}).get("cdp_lldp", {})
            neighbors_parsed = cdp_data.get("parsed", {}).get("neighbors", [])
            neighbors = []
            for n in neighbors_parsed:
                neighbors.append({
                    "neighbor_device": n.get("remote_device", "Unknown"),
                    "local_interface": n.get("local_intf", "?"),
                    "remote_interface": n.get("remote_intf", "?"),
                    "protocols": n.get("protocols", []),
                })
            topology_dict[hostname] = {
                "device_type": device.get("device_category") or "unknown",
                "has_routing": False,
                "neighbors": neighbors,
                "arp_entries": [],
                "arp_count": 0,
            }

        seed_ip = inventory_data.get("seed_ip", "")
        seed_hostname = None
        for hostname, device in inventory_data.get("devices", {}).items():
            if device.get("mgmt_ip") == seed_ip:
                seed_hostname = hostname
                break

        visualizer = NetworkVisualizer(topology_dict, seed_device=seed_hostname)
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            visualizer.generate_html(f.name)
            f.seek(0)
            content = open(f.name, "rb").read()
        os.unlink(f.name)
        return content
