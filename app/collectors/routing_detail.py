"""
Routing detail collector.
Gathers route summaries, OSPF process info, OSPF interfaces, and BGP summaries.
"""
import logging
import re

from .base import BaseCollector
from .errors import is_error_output

logger = logging.getLogger(__name__)

# BGP outside the global table (issue #9). "show ip bgp summary" only sees
# the default VRF, so a PE/edge router whose peers live under
# "address-family ipv4 vrf X" looked like it had one peer or none.
_VPNV4_SUMMARY = "show bgp vpnv4 unicast all summary"
_VPNV4_SUMMARY_OLD = "show ip bgp vpnv4 all summary"
# The full neighbors output is large; the header line alone carries the
# neighbor-to-VRF mapping that the summary table lacks.
_VPNV4_NEIGHBORS = "show bgp vpnv4 unicast all neighbors | include BGP neighbor is"
_VPNV4_NEIGHBORS_OLD = "show ip bgp vpnv4 all neighbors | include BGP neighbor is"
_NXOS_BGP_VRF_ALL = "show bgp vrf all all summary"
_NXOS_ROUTE_SUMMARY_VRF_ALL = "show ip route summary vrf all"
# LSDB and EIGRP topology size: how much state each process carries.
_OSPF_DB_SUMMARY = "show ip ospf database database-summary"
_NXOS_OSPF_DB_SUMMARY = "show ip ospf database database-summary vrf all"
_EIGRP_TOPO_SUMMARY = "show ip eigrp topology summary"

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
        _VPNV4_SUMMARY,
        _VPNV4_NEIGHBORS,
        # Pre-15.x IOS only knows the older "ip bgp vpnv4" form. When the
        # newer command is rejected, parse() falls back to these.
        _VPNV4_SUMMARY_OLD,
        _VPNV4_NEIGHBORS_OLD,
        _OSPF_DB_SUMMARY,
        _EIGRP_TOPO_SUMMARY,
    ],
    "cisco_xe": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf interface brief",
        "show ip bgp summary",
        "show ip eigrp topology",
        "show ip eigrp neighbors detail",
        "show ip bgp",
        _VPNV4_SUMMARY,
        _VPNV4_NEIGHBORS,
        _OSPF_DB_SUMMARY,
        _EIGRP_TOPO_SUMMARY,
    ],
    "cisco_nxos": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf interface brief",
        "show ip bgp summary",
        "show ip eigrp topology",
        "show ip eigrp neighbors detail",
        "show ip bgp",
        _NXOS_BGP_VRF_ALL,
        _NXOS_ROUTE_SUMMARY_VRF_ALL,
        _NXOS_OSPF_DB_SUMMARY,
        _EIGRP_TOPO_SUMMARY,
    ],
    # VyOS runs FRR, so the show syntax is close to IOS but has no EIGRP.
    "vyos": [
        "show ip route summary",
        "show ip ospf",
        "show ip ospf interface",
        "show ip bgp summary",
    ],
    "watchguard_fireware": [
        "show ospf",
        "show bgp",
    ],
    "paloalto_panos": [
        "show routing summary",
        "show routing protocol ospf summary",
        "show routing protocol bgp summary",
    ],
}
# Unknown platforms get the global-table commands only; the VPNv4, vrf-all
# and scale forms are Cisco-specific and would only add rejected-command noise.
_DEFAULT_COMMANDS = [c for c in _COMMANDS["cisco_ios"]
                     if c not in (_VPNV4_SUMMARY, _VPNV4_NEIGHBORS,
                                  _VPNV4_SUMMARY_OLD, _VPNV4_NEIGHBORS_OLD,
                                  _OSPF_DB_SUMMARY, _EIGRP_TOPO_SUMMARY)]


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


# Rows of the IOS summary table that are not a route source. "internal" is
# the RIB's own bookkeeping (memory), "Total" sums the other rows.
_SUMMARY_NON_SOURCES = {"total", "internal", "route", "maximum"}


def _to_int(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def normalize_route_summary(entries):
    """[{source, count}] from either our own rows or ntc-templates rows.

    The ntc template for 'show ip route summary' yields ROUTE_SOURCE,
    NETWORKS and SUBNETS, not source/count. A route source's route count is
    networks + subnets. Safe to run on already-normalized rows.
    """
    result = []
    for e in entries or []:
        e = {str(k).lower(): v for k, v in e.items()}
        source = str(e.get("source") or e.get("route_source") or "").strip()
        if not source or source.lower() in _SUMMARY_NON_SOURCES:
            continue
        if "count" in e:
            count = _to_int(e.get("count"))
        else:
            count = _to_int(e.get("networks")) + _to_int(e.get("subnets"))
        result.append({"source": source, "count": count})
    return result


def _parse_route_summary_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip route summary'.

    Columns are Route Source, Networks, Subnets, then Overhead/Memory on
    IOS 15 or Replicates/Overhead/Memory on IOS-XE 16+. Either way the
    route count is Networks + Subnets.
    """
    results = []
    for line in raw.splitlines():
        # "ospf 1          15    12    3    0    0", "connected   0   12 ..."
        m = re.match(r"^([A-Za-z][\w-]*(?:\s\d+)?)\s{2,}(\d+)(?:\s+(\d+))?", line)
        if m:
            source = m.group(1).strip()
            if source.lower() in _SUMMARY_NON_SOURCES:
                continue
            count = int(m.group(2)) + _to_int(m.group(3))
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


# IOS/IOS-XE: Interface PID Area IP Address/Mask Cost State Nbrs F/C
# "Lo4          100   0.0.0.0         10.0.0.4/32        1     LOOP  0/0"
_OSPF_BRIEF_IOS_RE = re.compile(
    r"^(\S+)\s+(\d+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+)\s+(\S+)"
    r"\s+(\d+)/(\d+)\s*$")
# NX-OS, per process: Interface ID Area Cost State Neighbors Status
# " Eth1/1                  2      0.0.0.0         40     P2P      1         up"
_OSPF_BRIEF_NXOS_RE = re.compile(
    r"^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(up|down)\s*$")
_OSPF_BRIEF_NXOS_PROC_RE = re.compile(r"OSPF Process ID (\S+) VRF (\S+)")


def parse_ospf_interfaces_brief(raw: str) -> list[dict]:
    """Parse 'show ip ospf interface brief' (IOS, IOS-XE and NX-OS).

    The ntc IOS template only accepts a decimal area, so any row whose area
    is dotted ("0.0.0.0") is silently dropped. Matching the whole row here
    keeps the columns where they belong.
    """
    results = []
    process, vrf = "", ""
    for line in (raw or "").splitlines():
        h = _OSPF_BRIEF_NXOS_PROC_RE.search(line)
        if h:
            process, vrf = h.group(1), h.group(2)
            continue
        m = _OSPF_BRIEF_IOS_RE.match(line)
        if m:
            results.append({
                "interface": m.group(1),
                "process": m.group(2),
                "area": m.group(3),
                "ip_address": m.group(4),
                "cost": m.group(5),
                "state": m.group(6),
                "neighbors": m.group(7),
                "neighbors_total": m.group(8),
            })
            continue
        m = _OSPF_BRIEF_NXOS_RE.match(line)
        if m:
            results.append({
                "interface": m.group(1),
                "process": process,
                "vrf": vrf,
                "area": m.group(3),
                "ip_address": "",
                "cost": m.group(4),
                "state": m.group(5),
                "neighbors": m.group(6),
                "status": m.group(7),
            })
    return results


def _normalize_ospf_interfaces_ntc(entries):
    """ntc rows use process/neighbors_fc; give them our field names."""
    result = []
    for e in entries or []:
        e = {str(k).lower(): v for k, v in e.items()}
        full, _, total = str(e.get("neighbors_fc", "")).partition("/")
        ip = e.get("ip_address", "")
        if ip and e.get("prefix_length"):
            ip = f"{ip}/{e['prefix_length']}"
        row = {
            "interface": e.get("interface", ""),
            "process": e.get("process", ""),
            "area": e.get("area", ""),
            "ip_address": ip,
            "cost": e.get("cost", ""),
            "state": e.get("state", ""),
            "neighbors": e.get("neighbors", full),
        }
        if total:
            row["neighbors_total"] = total
        if e.get("vrf"):
            row["vrf"] = e["vrf"]
        result.append(row)
    return result


# Neighbor row shared by IOS, IOS-XE and NX-OS summary tables:
# "10.0.0.2        4 65002     100     120       50    0    0 01:02:03  300"
# "10.0.0.3        4 65003      80      90       50    0    0 never    Idle (Admin)"
# ASNs may be asdot ("1.10").
_BGP_PEER_ROW_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+(?:\.\d+)?)"  # neighbor, version, ASN
    r"\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+"              # MsgRcvd MsgSent TblVer InQ OutQ
    r"\s+(\S+)\s+(\S.*?)\s*$"                               # Up/Down, State/PfxRcd
)

# IOS VPNv4 output may group neighbors under RD headers:
# "Route Distinguisher: 64500:1 (default for vrf CUST-A)"
_RD_VRF_RE = re.compile(r"Route Distinguisher:.*\(default for vrf (\S+?)\)")
_AF_HEADER_RE = re.compile(r"^\s*For address family:\s*(.+?)\s*$")
# "BGP neighbor is 192.0.2.1,  vrf CUST-A,  remote AS 64496, external link"
_NEIGHBOR_VRF_RE = re.compile(
    r"BGP neighbor is (\S+?),\s+(?:vrf (\S+?),\s+)?remote AS (\S+?),"
)
# NX-OS: "BGP summary information for VRF CUST-A, address family IPv4 Unicast"
_NXOS_VRF_HEADER_RE = re.compile(
    r"BGP summary information for VRF (\S+?), address family (.+?)\s*$"
)

DEFAULT_VRF = "default"


def _peer_from_row(m, vrf=DEFAULT_VRF, address_family="IPv4 Unicast"):
    state_or_pfx = m.group(4)
    # If last field is a number, it's prefixes_received; otherwise state
    try:
        prefixes = int(state_or_pfx)
        state = "Established"
    except ValueError:
        prefixes = 0
        state = state_or_pfx
    return {
        "neighbor": m.group(1),
        "asn": m.group(2),
        "state": state,
        "prefixes_received": prefixes,
        "up_down": m.group(3),
        "vrf": vrf,
        "address_family": address_family,
    }


def _parse_bgp_summary_regex(raw: str) -> list[dict]:
    """Regex fallback for 'show ip bgp summary' (global table)."""
    results = []
    for line in raw.splitlines():
        m = _BGP_PEER_ROW_RE.match(line)
        if m:
            results.append(_peer_from_row(m))
    return results


def _parse_vpnv4_neighbor_vrfs(raw: str) -> dict:
    """Map neighbor address -> list of VRF names, in output order.

    The same CE address can exist in several VRFs, so each occurrence is
    kept; global-table VPNv4 sessions map to the default VRF.
    """
    vrfs = {}
    for line in (raw or "").splitlines():
        m = _NEIGHBOR_VRF_RE.search(line)
        if m:
            vrfs.setdefault(m.group(1), []).append(m.group(2) or DEFAULT_VRF)
    return vrfs


def _parse_vpnv4_summary(raw: str, neighbor_vrfs=None) -> list[dict]:
    """Parse 'show bgp vpnv4 unicast all summary' (or the older
    'show ip bgp vpnv4 all summary') so each peer carries its VRF.

    The VRF comes from an RD header when the output has one, else from the
    neighbors-header mapping, else the peer is a global VPNv4 session.
    """
    remaining = {k: list(v) for k, v in (neighbor_vrfs or {}).items()}
    results = []
    current_vrf = None
    for line in (raw or "").splitlines():
        if _AF_HEADER_RE.match(line):
            current_vrf = None
            continue
        rd = _RD_VRF_RE.search(line)
        if rd:
            current_vrf = rd.group(1)
            continue
        m = _BGP_PEER_ROW_RE.match(line)
        if not m:
            continue
        neighbor = m.group(1)
        mapped = remaining.get(neighbor)
        mapped_vrf = mapped.pop(0) if mapped else None
        vrf = current_vrf or mapped_vrf or DEFAULT_VRF
        results.append(_peer_from_row(m, vrf=vrf, address_family="VPNv4 Unicast"))
    return results


def _parse_nxos_bgp_vrf_all(raw: str) -> list[dict]:
    """Parse NX-OS 'show bgp vrf all all summary'."""
    results = []
    vrf = DEFAULT_VRF
    af = "IPv4 Unicast"
    for line in (raw or "").splitlines():
        h = _NXOS_VRF_HEADER_RE.search(line)
        if h:
            vrf, af = h.group(1), h.group(2)
            continue
        m = _BGP_PEER_ROW_RE.match(line)
        if m:
            results.append(_peer_from_row(m, vrf=vrf, address_family=af))
    return results


def _merge_bgp_peers(base: list[dict], extra: list[dict]) -> list[dict]:
    """Append peers from extra that base lacks, keyed on (vrf, neighbor).

    A peer active in several address families is one session, so only its
    first appearance is kept.
    """
    merged = list(base)
    seen = {(p.get("vrf") or DEFAULT_VRF, p.get("neighbor")) for p in base}
    for p in extra:
        key = (p.get("vrf") or DEFAULT_VRF, p.get("neighbor"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(p)
    return merged


def _parse_nxos_route_summary_vrf_all(raw: str) -> dict:
    """Parse NX-OS 'show ip route summary vrf all' into {vrf: [{source, count}]}.

    IP Route Table for VRF "CUST-A"
    ...
    Best paths per protocol:      Backup paths per protocol:
      direct         : 3
      bgp-64500      : 4
    """
    result = {}
    vrf = None
    in_best = False
    for line in (raw or "").splitlines():
        h = re.search(r'IP Route Table for VRF "([^"]+)"', line)
        if h:
            vrf = h.group(1)
            result.setdefault(vrf, [])
            in_best = False
            continue
        if vrf is None:
            continue
        if "Best paths per protocol" in line:
            in_best = True
            continue
        if not line.strip() or "per mask-length" in line:
            in_best = False
            continue
        if in_best:
            m = re.match(r"^\s+(\S+)\s*:\s*(\d+)", line)
            if m:
                result[vrf].append({"source": m.group(1), "count": int(m.group(2))})
    return result


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
            "vrf": e.get("vrf") or DEFAULT_VRF,
            "address_family": "IPv4 Unicast",
        })
    return results


# "OSPF Router with ID (192.0.2.1) (Process ID 1)"            IOS / IOS-XE
# "OSPF Router with ID (192.0.2.11) (Process ID 10 VRF CUST-A)"  NX-OS
_OSPF_DB_PROCESS_RE = re.compile(
    r"OSPF Router with ID \((\S+?)\)\s+\(Process ID (\S+?)(?:,?\s+VRF\s+(\S+?))?\)")
# "Area 0 database summary" / " Area 0.0.0.0 database summary"
_OSPF_DB_AREA_RE = re.compile(r"^\s*Area\s+(\S+)\s+database summary", re.I)
# "Process 1 database summary"
_OSPF_DB_PROC_TOTAL_RE = re.compile(r"^\s*Process\s+(\S+)\s+database summary", re.I)
# "  Router        3        0        0" / "  Summary Network 3"
_OSPF_DB_COUNT_RE = re.compile(r"^\s+([A-Za-z][A-Za-z0-9 -]*?)\s+(\d+)(?:\s+\d+)*\s*$")


def _parse_ospf_db_summary(raw: str) -> list[dict]:
    """Parse 'show ip ospf database database-summary' (IOS, IOS-XE, NX-OS).

    One entry per area plus one per process ("scope": "process"), each with
    LSA counts by type and the area subtotal / process total.
    """
    results = []
    router_id = process = ""
    vrf = DEFAULT_VRF
    current = None
    for line in (raw or "").splitlines():
        m = _OSPF_DB_PROCESS_RE.search(line)
        if m:
            router_id, process = m.group(1), m.group(2)
            vrf = m.group(3) or DEFAULT_VRF
            current = None
            continue
        m = _OSPF_DB_AREA_RE.match(line)
        if m:
            current = {"process_id": process, "router_id": router_id,
                       "vrf": vrf, "scope": "area", "area": m.group(1),
                       "counts": {}, "total": 0}
            results.append(current)
            continue
        m = _OSPF_DB_PROC_TOTAL_RE.match(line)
        if m:
            current = {"process_id": m.group(1) or process,
                       "router_id": router_id, "vrf": vrf, "scope": "process",
                       "area": "", "counts": {}, "total": 0}
            results.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.lower().startswith(("lsa type", "prefixes redistributed")):
            continue
        m = _OSPF_DB_COUNT_RE.match(line)
        if not m:
            continue
        label, count = m.group(1).strip(), int(m.group(2))
        if label.lower() in ("subtotal", "total"):
            current["total"] = count
        else:
            current["counts"][label] = count
    for entry in results:
        if not entry["total"]:
            entry["total"] = sum(v for k, v in entry["counts"].items()
                                 if k.lower() != "non-self")
    return results


# "EIGRP-IPv4 Topology Table for AS(100)/ID(192.0.2.1)"
# "EIGRP-IPv4 VR(CORE) Topology Table for AS(100)/ID(192.0.2.1)"
# "IP-EIGRP topology summary for AS(100)/ID(192.0.2.11) VRF default"  NX-OS
_EIGRP_TOPO_HEADER_RE = re.compile(
    r"AS\((\d+)\)\s*/\s*ID\((\S+?)\)(?:.*?VRF[\s(]+([^)\s]+))?", re.I)


def _parse_eigrp_topology_summary(raw: str) -> list[dict]:
    """Parse 'show ip eigrp topology summary' into one entry per AS/VRF."""
    results = []
    current = None
    for line in (raw or "").splitlines():
        if "topology" in line.lower():
            m = _EIGRP_TOPO_HEADER_RE.search(line)
            if m:
                current = {"as_number": m.group(1), "router_id": m.group(2),
                           "vrf": m.group(3) or DEFAULT_VRF, "routes": 0,
                           "pending_replies": 0, "interfaces": 0,
                           "neighbors": 0}
                results.append(current)
                continue
        if current is None:
            continue
        m = re.search(r"(\d+)\s+routes?,\s+(\d+)\s+pending repl", line)
        if m:
            current["routes"] = int(m.group(1))
            current["pending_replies"] = int(m.group(2))
            continue
        m = re.search(r"enabled on (\d+) interfaces?,\s+(\d+) neighbors?", line)
        if m:
            current["interfaces"] = int(m.group(1))
            current["neighbors"] = int(m.group(2))
    return results


def _usable(raw_outputs: dict, *commands) -> str:
    """Return the first command output that is neither empty nor a CLI
    rejection. Lets an older-syntax command stand in for a newer one."""
    for cmd in commands:
        out = raw_outputs.get(cmd, "")
        if out and out.strip() and not is_error_output(out):
            return out
    return ""


class RoutingDetailCollector(BaseCollector):
    name = "routing_detail"
    label = "Routing Detail"
    description = "Collect route summaries, OSPF process details, OSPF interfaces, and BGP summaries"
    enabled_by_default = True
    routing_only = True
    # A WLC does not participate in routing protocols.
    unsupported_platforms = frozenset({"cisco_wlc"})

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, _DEFAULT_COMMANDS))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        # --- route summary ---
        route_sum_cmd = "show ip route summary"
        route_sum_raw = raw_outputs.get(route_sum_cmd, "")
        route_summary = normalize_route_summary(
            _parse_ntc(route_sum_raw, device_type, route_sum_cmd))
        if not route_summary and device_type == "cisco_nxos":
            # NX-OS prints "direct : 3" under 'Best paths per protocol'.
            nx = _parse_nxos_route_summary_vrf_all(
                _usable(raw_outputs, route_sum_cmd))
            route_summary = nx.get(DEFAULT_VRF) or (
                next(iter(nx.values())) if len(nx) == 1 else [])
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
        ospf_interfaces = parse_ospf_interfaces_brief(ospf_int_raw)
        if not ospf_interfaces:
            ospf_interfaces = _normalize_ospf_interfaces_ntc(
                _parse_ntc(ospf_int_raw, device_type, ospf_int_cmd))

        # --- bgp summary ---
        bgp_cmd = "show ip bgp summary"
        bgp_raw = raw_outputs.get(bgp_cmd, "")
        bgp_summary = _parse_ntc(bgp_raw, device_type, bgp_cmd)
        if bgp_summary:
            bgp_summary = _normalize_bgp_ntc(bgp_summary)
        else:
            bgp_summary = _parse_bgp_summary_regex(bgp_raw)

        # --- bgp peers outside the global table ---
        if device_type in ("cisco_ios", "cisco_xe"):
            vpnv4_raw = _usable(raw_outputs, _VPNV4_SUMMARY, _VPNV4_SUMMARY_OLD)
            nbr_raw = _usable(raw_outputs, _VPNV4_NEIGHBORS, _VPNV4_NEIGHBORS_OLD)
            vpnv4_peers = _parse_vpnv4_summary(
                vpnv4_raw, _parse_vpnv4_neighbor_vrfs(nbr_raw))
            bgp_summary = _merge_bgp_peers(bgp_summary, vpnv4_peers)
        elif device_type == "cisco_nxos":
            vrf_all_raw = _usable(raw_outputs, _NXOS_BGP_VRF_ALL)
            bgp_summary = _merge_bgp_peers(
                bgp_summary, _parse_nxos_bgp_vrf_all(vrf_all_raw))

        # --- per-VRF route summary (NX-OS has a vrf-all form) ---
        vrf_route_summary = {}
        if device_type == "cisco_nxos":
            vrf_route_summary = _parse_nxos_route_summary_vrf_all(
                _usable(raw_outputs, _NXOS_ROUTE_SUMMARY_VRF_ALL))

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

        # --- LSDB and EIGRP topology size ---
        ospf_db_summary = _parse_ospf_db_summary(
            _usable(raw_outputs, _NXOS_OSPF_DB_SUMMARY, _OSPF_DB_SUMMARY))
        eigrp_topology_summary = _parse_eigrp_topology_summary(
            _usable(raw_outputs, _EIGRP_TOPO_SUMMARY))

        return {
            "ospf_db_summary": ospf_db_summary,
            "eigrp_topology_summary": eigrp_topology_summary,
            "route_summary": route_summary,
            "ospf_processes": ospf_processes,
            "ospf_interfaces": ospf_interfaces,
            "bgp_summary": bgp_summary,
            "vrf_route_summary": vrf_route_summary,
            "bgp_table": bgp_table,
            "eigrp_topology": eigrp_topology,
            "eigrp_neighbors": eigrp_neighbors,
        }
