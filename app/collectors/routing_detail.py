"""
Routing detail collector.
Gathers route summaries, OSPF process info, OSPF interfaces, and BGP summaries.
"""
import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

# Commands per vendor
_COMMANDS = {
    "cisco_ios": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf interface brief",
        "show ip bgp summary",
        "show ip eigrp topology",
        "show ip eigrp neighbors detail",
        "show ip bgp",
    ],
    "cisco_xe": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf interface brief",
        "show ip bgp summary",
        "show ip eigrp topology",
        "show ip eigrp neighbors detail",
        "show ip bgp",
    ],
    "cisco_nxos": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf interface brief",
        "show ip bgp summary",
        "show ip eigrp topology",
        "show ip eigrp neighbors detail",
        "show ip bgp",
    ],
}
_DEFAULT_COMMANDS = _COMMANDS["cisco_ios"]


_NTC_PLATFORM_MAP = {"cisco_xe": "cisco_ios", "cisco_xr": "cisco_ios"}


def _parse_ntc(raw: str, device_type: str, command: str) -> list[dict]:
    """Attempt ntc-templates parsing; return empty list on failure."""
    if not raw:
        return []
    try:
        from ntc_templates.parse import parse_output
        platform = _NTC_PLATFORM_MAP.get(device_type, device_type)
        return parse_output(platform=platform, command=command, data=raw)
    except Exception:
        logger.debug(f"ntc-templates parse failed for {command} on {device_type}")
        return []


def _parse_route_summary_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip route summary'."""
    results = []
    # Match lines like: "ospf 1          15    12    3    0    0"
    # or "connected       5     5     0    0    0"
    for line in raw.splitlines():
        # Protocol with optional single-space process id, then 2+ spaces before numbers
        m = re.match(r"^(\w+(?:\s\d+)?)\s{2,}(\d+)\s+", line)
        if m:
            source = m.group(1).strip()
            count = int(m.group(2))
            # Skip header/total lines
            if source.lower() in ("route", "total", "maximum"):
                continue
            results.append({"source": source, "count": count})
    return results


def _parse_ospf_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip ospf'."""
    processes = []
    current = None
    for line in raw.splitlines():
        # "Routing Process "ospf 1" with ID 10.0.0.1"
        m = re.match(
            r".*[Rr]outing\s+[Pp]rocess\s+\"?ospf\s+(\d+)\"?\s+with\s+ID\s+(\S+)",
            line,
        )
        if m:
            current = {
                "process_id": m.group(1),
                "router_id": m.group(2),
                "areas": [],
            }
            processes.append(current)
            continue
        # "Area 0 (BACKBONE)"  or  "Area 1"
        m2 = re.match(r".*\bArea\s+(\S+)", line)
        if m2 and current is not None:
            area_id = m2.group(1)
            if area_id not in current["areas"]:
                current["areas"].append(area_id)
    return processes


def _parse_ospf_interfaces_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip ospf interface brief'."""
    results = []
    for line in raw.splitlines():
        # Typical: "Gi0/1    10.0.0.1   YES  0    1     DR     1"
        parts = line.split()
        if len(parts) >= 5 and not parts[0].lower().startswith("interface"):
            # Try to extract: interface, area, cost, state, neighbors
            try:
                results.append({
                    "interface": parts[0],
                    "area": parts[1],
                    "cost": parts[2],
                    "state": parts[3],
                    "neighbors": parts[4] if len(parts) > 4 else "0",
                })
            except (IndexError, ValueError):
                continue
    return results


def _parse_bgp_summary_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip bgp summary'."""
    results = []
    for line in raw.splitlines():
        # Neighbor lines:
        # "10.0.0.2        4 65002     100     120       50    0    0 01:02:03  300"
        # "10.0.0.3        4 65003      80      90       50    0    0 00:45:00  Active"
        m = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)"  # neighbor, version, ASN
            r"\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+"           # MsgRcvd MsgSent TblVer InQ OutQ
            r"\s+(\S+)\s+(\S+)\s*$",                      # Up/Down, State/PfxRcd
            line,
        )
        if m:
            neighbor = m.group(1)
            asn = m.group(2)
            up_down = m.group(3)
            state_or_pfx = m.group(4)
            # If last field is a number, it's prefixes_received; otherwise state
            try:
                prefixes = int(state_or_pfx)
                state = "Established"
            except ValueError:
                prefixes = 0
                state = state_or_pfx
            results.append({
                "neighbor": neighbor,
                "asn": asn,
                "state": state,
                "prefixes_received": prefixes,
                "up_down": up_down,
            })
    return results


def _parse_eigrp_topology_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip eigrp topology'."""
    results = []
    for line in raw.splitlines():
        # "P 10.0.0.0/24, 1 successors, FD is 28160"
        m = re.match(
            r"^([APUS])\s+(\d+\.\d+\.\d+\.\d+(/\d+)?),\s+(\d+)\s+successors?,\s+FD\s+is\s+(\d+)",
            line,
        )
        if m:
            results.append({
                "code": m.group(1),
                "network": m.group(2),
                "successors": int(m.group(4)),
                "feasible_distance": m.group(5),
            })
    return results


def _parse_eigrp_neighbors_detail_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip eigrp neighbors detail'."""
    results = []
    current = None
    for line in raw.splitlines():
        # "H   Address     Interface    Hold Uptime   SRTT   RTO  Q  Seq"
        # "0   10.0.0.2    Gi0/1          12 01:02:03  1   100  0  45"
        m = re.match(
            r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\d+\s+(\S+)",
            line,
        )
        if m:
            current = {
                "neighbor": m.group(1),
                "interface": m.group(2),
                "uptime": m.group(3),
                "stub": False,
                "stub_flags": "",
            }
            results.append(current)
            continue
        # "  Stub Peer Advertising (CONNECTED SUMMARY ) Routes"
        if current and "stub peer" in line.lower():
            current["stub"] = True
            sm = re.search(r"\(([^)]+)\)", line)
            if sm:
                current["stub_flags"] = sm.group(1).strip()
    return results


def _parse_bgp_table_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip bgp' full table.

    Extracts prefix entries with status, next-hop, metric, and path.
    """
    results = []
    if not raw:
        return results
    for line in raw.splitlines():
        # BGP table lines look like:
        # "*> 10.0.0.0/24      10.1.1.1       0   100  0 65001 i"
        # "*>i10.2.0.0/16      10.1.1.2       0   200  0 65002 65003 i"
        # "* i                 10.1.1.3       0   150  0 65002 65003 i"  (continuation)
        m = re.match(
            r"^\s*([*>sdhibSr ]{0,4})"       # status codes
            r"\s*(\d+\.\d+\.\d+\.\d+(?:/\d+)?)"  # network/prefix
            r"\s+(\d+\.\d+\.\d+\.\d+)"       # next-hop
            r"\s+(\d+)"                        # metric
            r"\s+(\d+)"                        # local pref
            r"\s+\d+"                          # weight
            r"\s+(.+?)\s*$",                   # path + origin
            line,
        )
        if m:
            status = m.group(1).strip()
            results.append({
                "status": status,
                "network": m.group(2),
                "next_hop": m.group(3),
                "metric": m.group(4),
                "local_pref": m.group(5),
                "path": m.group(6).strip(),
            })
    return results


def _normalize_bgp_ntc(entries: list[dict]) -> list[dict]:
    """Normalize ntc-templates BGP summary output to our schema."""
    results = []
    for e in entries:
        state_or_pfx = e.get("state_or_prefixes_received", e.get("state_pfxrcd", ""))
        try:
            prefixes = int(state_or_pfx)
            state = "Established"
        except (ValueError, TypeError):
            prefixes = 0
            state = str(state_or_pfx)
        results.append({
            "neighbor": e.get("bgp_neighbor", e.get("neighbor", "")),
            "asn": e.get("neighbor_as", e.get("asn", "")),
            "state": state,
            "prefixes_received": prefixes,
            "up_down": e.get("up_down", ""),
        })
    return results


class RoutingDetailCollector(BaseCollector):
    name = "routing_detail"
    label = "Routing Detail"
    description = "Collect route summaries, OSPF process details, OSPF interfaces, and BGP summaries"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, _DEFAULT_COMMANDS))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        # --- route summary ---
        route_sum_cmd = "show ip route summary"
        route_sum_raw = raw_outputs.get(route_sum_cmd, "")
        route_summary = _parse_ntc(route_sum_raw, device_type, route_sum_cmd)
        if not route_summary:
            route_summary = _parse_route_summary_regex(route_sum_raw)

        # --- ospf processes ---
        ospf_cmd = "show ip ospf"
        ospf_raw = raw_outputs.get(ospf_cmd, "")
        ospf_processes = _parse_ntc(ospf_raw, device_type, ospf_cmd)
        if not ospf_processes:
            ospf_processes = _parse_ospf_regex(ospf_raw)

        # --- ospf interfaces ---
        ospf_int_cmd = "show ip ospf interface brief"
        ospf_int_raw = raw_outputs.get(ospf_int_cmd, "")
        ospf_interfaces = _parse_ntc(ospf_int_raw, device_type, ospf_int_cmd)
        if not ospf_interfaces:
            ospf_interfaces = _parse_ospf_interfaces_regex(ospf_int_raw)

        # --- bgp summary ---
        bgp_cmd = "show ip bgp summary"
        bgp_raw = raw_outputs.get(bgp_cmd, "")
        bgp_summary = _parse_ntc(bgp_raw, device_type, bgp_cmd)
        if bgp_summary:
            bgp_summary = _normalize_bgp_ntc(bgp_summary)
        else:
            bgp_summary = _parse_bgp_summary_regex(bgp_raw)

        # --- eigrp topology ---
        eigrp_topo_cmd = "show ip eigrp topology"
        eigrp_topo_raw = raw_outputs.get(eigrp_topo_cmd, "")
        eigrp_topology = _parse_ntc(eigrp_topo_raw, device_type, eigrp_topo_cmd)
        if not eigrp_topology:
            eigrp_topology = _parse_eigrp_topology_regex(eigrp_topo_raw)

        # --- eigrp neighbors detail ---
        eigrp_nbr_cmd = "show ip eigrp neighbors detail"
        eigrp_nbr_raw = raw_outputs.get(eigrp_nbr_cmd, "")
        eigrp_neighbors = _parse_ntc(eigrp_nbr_raw, device_type, eigrp_nbr_cmd)
        if not eigrp_neighbors:
            eigrp_neighbors = _parse_eigrp_neighbors_detail_regex(eigrp_nbr_raw)

        # --- bgp table ---
        bgp_table_cmd = "show ip bgp"
        bgp_table_raw = raw_outputs.get(bgp_table_cmd, "")
        bgp_table = _parse_ntc(bgp_table_raw, device_type, bgp_table_cmd)
        if not bgp_table:
            bgp_table = _parse_bgp_table_regex(bgp_table_raw)

        return {
            "route_summary": route_summary,
            "ospf_processes": ospf_processes,
            "ospf_interfaces": ospf_interfaces,
            "bgp_summary": bgp_summary,
            "bgp_table": bgp_table,
            "eigrp_topology": eigrp_topology,
            "eigrp_neighbors": eigrp_neighbors,
        }
