"""
L3 Routing protocol neighbor and route table collector.
Wraps existing L3 parsers from parsers.py, adds route table via ntc-templates.
"""
import logging
import re

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
    "vyos": {
        "ospf": "show ip ospf neighbor",
        "bgp": "show ip bgp summary",
    },
    "watchguard_fireware": {
        "ospf": "show ospf neighbor",
        "bgp": "show bgp neighbor",
    },
    "paloalto_panos": {
        "ospf": "show routing protocol ospf neighbor",
        "bgp": "show routing protocol bgp peer",
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
    "vyos": "show ip route",
    "watchguard_fireware": "show route",
    "paloalto_panos": "show routing route",
    # AireOS has only the controller's own routes, not a routing table.
    "cisco_wlc": "show route summary",
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
    "vyos": "show ip protocol",
    "paloalto_panos": "show routing summary",
}
_DEFAULT_PROTOCOLS_COMMAND = "show ip protocols"


_NTC_PLATFORM_MAP = {"cisco_xe": "cisco_ios", "cisco_xr": "cisco_ios"}

# --- show ip protocols -------------------------------------------------------
# One block per routing process:
#   Routing Protocol is "ospf 1"
#     Router ID 192.0.2.1
#    Redistributing External Routes from,
#       eigrp 100 with metric mapped to 20, includes subnets in redistribution
#     Maximum path: 4
#     Routing for Networks:
#       192.0.2.0 0.0.0.255 area 0
#     Passive Interface(s):
#       Loopback0
#     Distance: (default is 110)
_PROTO_BLOCK_RE = re.compile(r'^\s*Routing Protocol is "([^"]+)"', re.M)
_SECTION_HEADERS = {
    "routing for networks:": "networks",
    "passive interface(s):": "passive_interfaces",
    "redistributing external routes from,": "redistribute",
    "routing information sources:": "sources",
    "neighbor(s):": "neighbors",
    "address summarization:": "summarization",
}
# Lines inside the "Routing Information Sources" table and other sections
# that are column headers, not entries.
_SECTION_NOISE_RE = re.compile(r"^(Gateway\s+Distance|Address\s+FiltIn|None$)", re.I)
# Source of a redistribution entry: "eigrp 100 with metric ...",
# "static, includes subnets ...", "ospf 1 (internal, external 1 & 2)".
_REDIST_SOURCE_RE = re.compile(r"^([A-Za-z][A-Za-z-]*)(?:\s+(\d+|[A-Za-z][\w-]*(?=\s*(?:,|$))))?")
# Protocols whose second token is a process id / AS / tag.
_PROCESS_PROTOCOLS = {"ospf", "ospfv3", "eigrp", "bgp", "isis"}


def _split_top_level(text):
    """Split on commas not inside parentheses."""
    items, depth, cur = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if ch == "," and depth == 0:
            items.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        items.append(cur.strip())
    return items


def _redist_entry(text):
    """Parse one redistribution source description into a dict."""
    text = text.strip().rstrip(",")
    m = _REDIST_SOURCE_RE.match(text)
    if not m:
        return None
    proto = m.group(1).lower()
    process = m.group(2) or ""
    if proto not in _PROCESS_PROTOCOLS:
        process = ""
    route_map = re.search(r"route-map\s+(\S+?)(?:,|\s|$)", text)
    metric = re.search(r"metric\s+(?:mapped\s+to\s+)?(\d+)", text)
    return {
        "from": f"{proto} {process}".strip(),
        "route_map": route_map.group(1) if route_map else "",
        "metric": metric.group(1) if metric else "",
        "detail": text,
    }


def _filter_value(block, direction):
    m = re.search(rf"{direction} update filter list for all interfaces is (.+)",
                  block, re.I)
    if not m:
        return ""
    value = m.group(1).strip()
    return "" if value.lower().startswith("not set") else value


def _parse_protocol_block(name, block):
    parts = name.split()
    proto = parts[0].lower() if parts else ""
    process = parts[1] if len(parts) > 1 else ""
    entry = {
        "name": name,
        "protocol": proto,
        "process": process,
        "router_id": "",
        "networks": [],
        "passive_interfaces": [],
        "redistribute": [],
        "distance": "",
        "maximum_paths": "",
        "outgoing_filter": _filter_value(block, "Outgoing"),
        "incoming_filter": _filter_value(block, "Incoming"),
    }
    rid = re.search(r"Router[ -]ID:?\s+(\d+\.\d+\.\d+\.\d+)", block)
    if rid:
        entry["router_id"] = rid.group(1)
    paths = re.search(r"Maximum path:\s*(\d+)", block)
    if paths:
        entry["maximum_paths"] = paths.group(1)
    # The process-level Distance line is the last one; EIGRP repeats it
    # inside the topology section with the same values.
    distances = re.findall(r"^\s*Distance:\s*(.+?)\s*$", block, re.M)
    if distances:
        value = distances[-1]
        default = re.match(r"\(default is (\d+)\)", value)
        entry["distance"] = default.group(1) if default else value

    for m in re.finditer(r"^\s*Redistributing:\s*(.+?)\s*$", block, re.M):
        for item in _split_top_level(m.group(1)):
            red = _redist_entry(item)
            if red:
                entry["redistribute"].append(red)

    # Entries sit deeper than their header. The OSPF redistribution header
    # is indented one space, the lines after its entries two, so the first
    # entry's indent (not the header's) marks where the section ends.
    section, header_indent, entry_indent = None, 0, None
    for line in block.splitlines():
        if not line.strip():
            section = None
            continue
        indent = len(line) - len(line.lstrip())
        key = _SECTION_HEADERS.get(line.strip().lower())
        if key:
            section, header_indent, entry_indent = key, indent, None
            continue
        if section is None:
            continue
        if entry_indent is None and indent > header_indent:
            entry_indent = indent
        if entry_indent is None or indent < entry_indent:
            section = None
            continue
        text = line.strip()
        if _SECTION_NOISE_RE.match(text):
            continue
        if section == "networks":
            entry["networks"].append(text)
        elif section == "passive_interfaces":
            entry["passive_interfaces"].append(text)
        elif section == "redistribute":
            red = _redist_entry(text)
            if red:
                entry["redistribute"].append(red)
    return entry


def parse_ip_protocols(raw):
    """Parse IOS / IOS-XE 'show ip protocols' into one dict per process.

    The internal "application" process carries nothing an engineer can act
    on and is left out.
    """
    if not raw:
        return []
    matches = list(_PROTO_BLOCK_RE.finditer(raw))
    processes = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        name = " ".join(m.group(1).split())
        if name.lower() == "application":
            continue
        processes.append(_parse_protocol_block(name, raw[m.end():end]))
    return processes


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
        if device_type == "paloalto_panos":
            # No ntc-templates entry for "show routing route".
            try:
                from app.parsers_panos import parse_routes as _parse_panos_routes
            except ImportError:
                from parsers_panos import parse_routes as _parse_panos_routes
            routes = _parse_panos_routes(route_raw)
        else:
            routes = _parse_routes_ntc(route_raw, device_type, route_cmd)

        # Raw is kept for platforms whose protocols output has no parser.
        protocols_cmd = _PROTOCOLS_COMMANDS.get(device_type, _DEFAULT_PROTOCOLS_COMMAND)
        protocols_raw = raw_outputs.get(protocols_cmd, "")
        ip_protocols = (parse_ip_protocols(protocols_raw)
                        if protocols_cmd == "show ip protocols" else [])

        return {
            "neighbors": all_neighbors,
            "routes": routes,
            "ip_protocols_raw": protocols_raw,
            "ip_protocols": ip_protocols,
        }
