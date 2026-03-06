"""
L3 Routing protocol neighbor and route table collector.
Wraps existing L3 parsers from parsers.py, adds route table via ntc-templates.
"""
import logging

from .base import BaseCollector

try:
    from app.parsers import parse_l3_neighbors
except ImportError:
    from parsers import parse_l3_neighbors

logger = logging.getLogger(__name__)

# L3 neighbor commands per vendor (from discovery.py L3_COMMANDS)
_L3_NEIGHBOR_COMMANDS = {
    "cisco_ios": {
        "ospf": "show ip ospf neighbor",
        "eigrp": "show ip eigrp neighbors",
        "bgp": "show ip bgp neighbors",
        "isis": "show isis neighbors",
    },
    "cisco_xe": {
        "ospf": "show ip ospf neighbor",
        "eigrp": "show ip eigrp neighbors",
        "bgp": "show ip bgp neighbors",
        "isis": "show isis neighbors",
    },
    "cisco_nxos": {
        "ospf": "show ip ospf neighbors",
        "eigrp": "show ip eigrp neighbors",
        "bgp": "show bgp ipv4 unicast neighbors",
        "isis": "show isis adjacency",
    },
    "arista_eos": {
        "ospf": "show ip ospf neighbor",
        "bgp": "show ip bgp neighbors",
        "isis": "show isis neighbors",
    },
    "juniper_junos": {
        "ospf": "show ospf neighbor",
        "bgp": "show bgp neighbor",
        "isis": "show isis adjacency",
    },
    "extreme": {
        "ospf": "show ospf neighbor",
        "bgp": "show bgp neighbor",
    },
}
_DEFAULT_L3_NEIGHBOR_COMMANDS = {
    "ospf": "show ip ospf neighbor",
    "eigrp": "show ip eigrp neighbors",
    "bgp": "show ip bgp neighbors",
    "isis": "show isis neighbors",
}

# Route table commands per vendor
_ROUTE_COMMANDS = {
    "cisco_ios": "show ip route",
    "cisco_xe": "show ip route",
    "cisco_nxos": "show ip route",
    "arista_eos": "show ip route",
    "juniper_junos": "show route",
    "extreme": "show ip route",
}
_DEFAULT_ROUTE_COMMAND = "show ip route"

# IP protocols command per vendor (raw-only, no parsing)
_PROTOCOLS_COMMANDS = {
    "cisco_ios": "show ip protocols",
    "cisco_xe": "show ip protocols",
    "cisco_nxos": "show ip protocols",
    "arista_eos": "show ip protocols",
    "juniper_junos": "show protocols",
    "extreme": "show ip protocols",
}
_DEFAULT_PROTOCOLS_COMMAND = "show ip protocols"


_NTC_PLATFORM_MAP = {"cisco_xe": "cisco_ios", "cisco_xr": "cisco_ios"}


def _parse_routes_ntc(raw: str, device_type: str, command: str) -> list[dict]:
    """Parse route table output using ntc-templates."""
    if not raw:
        return []
    try:
        from ntc_templates.parse import parse_output
        platform = _NTC_PLATFORM_MAP.get(device_type, device_type)
        return parse_output(platform=platform, command=command, data=raw)
    except Exception:
        logger.debug(f"ntc-templates parse failed for {command} on {device_type}")
        return []


class L3RoutingCollector(BaseCollector):
    name = "l3_routing"
    label = "L3 Routing Neighbors"
    description = "Discover neighbors via OSPF, EIGRP, BGP, IS-IS and collect route tables"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        neighbor_cmds = _L3_NEIGHBOR_COMMANDS.get(
            device_type, _DEFAULT_L3_NEIGHBOR_COMMANDS
        )
        route_cmd = _ROUTE_COMMANDS.get(device_type, _DEFAULT_ROUTE_COMMAND)
        protocols_cmd = _PROTOCOLS_COMMANDS.get(device_type, _DEFAULT_PROTOCOLS_COMMAND)

        commands = list(neighbor_cmds.values())
        commands.append(route_cmd)
        commands.append(protocols_cmd)
        return commands

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        # Parse L3 neighbors using existing parsers
        neighbor_cmds = _L3_NEIGHBOR_COMMANDS.get(
            device_type, _DEFAULT_L3_NEIGHBOR_COMMANDS
        )
        all_neighbors = []
        for protocol, cmd in neighbor_cmds.items():
            output = raw_outputs.get(cmd, "")
            if output:
                neighbors = parse_l3_neighbors(output, protocol)
                all_neighbors.extend(neighbors)

        # Parse route table via ntc-templates
        route_cmd = _ROUTE_COMMANDS.get(device_type, _DEFAULT_ROUTE_COMMAND)
        route_raw = raw_outputs.get(route_cmd, "")
        routes = _parse_routes_ntc(route_raw, device_type, route_cmd)

        # Store ip protocols raw (no parser)
        protocols_cmd = _PROTOCOLS_COMMANDS.get(device_type, _DEFAULT_PROTOCOLS_COMMAND)
        protocols_raw = raw_outputs.get(protocols_cmd, "")

        return {
            "neighbors": all_neighbors,
            "routes": routes,
            "ip_protocols_raw": protocols_raw,
        }
