"""
Internet Edge report -- BGP peering, NAT, ACL audit, FHRP, edge interfaces.
"""
import io
import re
from collections import OrderedDict
from ipaddress import IPv4Address, IPv4Network, AddressValueError

from openpyxl import Workbook

from .base import BaseReport
from .acl_usage import classify_acls, UNKNOWN, UNREFERENCED, COUNTED, FILTERING
from .findings import (
    CRITICAL, WARNING, INFO, make_finding, overfire_check, summary_count_rows,
)
from .fhrp import FHRP_HEADERS, fhrp_rows, fhrp_state_findings, has_fhrp_data
from .l2_discovery import _derive_site, _has_collector_data, _extract_ip_interfaces
from .routing_summary import (
    HEADER_BG, _write_header_row, _write_row, _finalize,
    write_findings_sheets, findings_tabular_sheets,
)


# ---------------------------------------------------------------------------
# Edge classification helpers
# ---------------------------------------------------------------------------

# Address space that is never reachable from the internet. Documentation
# ranges (192.0.2.0/24 etc.) are deliberately absent: they stand in for
# public space in examples and tests.
_NON_PUBLIC_NETS = [IPv4Network(n) for n in (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",      # CGNAT
    "127.0.0.0/8",
    "169.254.0.0/16",     # link-local
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved / broadcast
)]

NAT_NOT_CONFIGURED = "NAT not configured"


def _is_public_ip(ip):
    try:
        addr = IPv4Address(str(ip).split("/")[0].strip())
    except (AddressValueError, ValueError):
        return False
    return not any(addr in net for net in _NON_PUBLIC_NETS)


def _asn_int(asn):
    """Parse asplain or asdot ASN text to an int, or None."""
    text = str(asn).strip()
    try:
        if "." in text:
            hi, lo = text.split(".", 1)
            return int(hi) * 65536 + int(lo)
        return int(text)
    except (ValueError, TypeError):
        return None


def _is_public_asn(asn):
    n = _asn_int(asn)
    if n is None:
        return False
    if n in (0, 23456, 65535, 4294967295):
        return False
    if 64512 <= n <= 65534 or 4200000000 <= n <= 4294967294:
        return False
    return True


def _device_config(device):
    cfg = (device.get("collector_data", {}).get("config", {})
           .get("parsed", {}).get("config", ""))
    return cfg if isinstance(cfg, str) else ""


_NAT_CONFIG_RE = re.compile(
    r"^\s*ip\s+nat\s+(?:inside|outside|pool|source)\b", re.MULTILINE)


def _nat_configured(device):
    """True when the device has NAT configured.

    Uses the running-config when collected, else the NAT statistics: a
    device with NAT has inside/outside interfaces or pools. Zero active
    translations on a device with no NAT at all is not the same thing as
    an idle NAT, and the summary must not conflate them.
    """
    if _NAT_CONFIG_RE.search(_device_config(device)):
        return True
    es = device.get("collector_data", {}).get("edge_services", {}).get("parsed", {})
    stats = es.get("nat_statistics") or {}
    return bool(stats.get("inside_interfaces") or stats.get("outside_interfaces")
                or stats.get("pools") or stats.get("active_translations"))


def _interface_vrfs(device):
    """Return ({ip: vrf}, {interface: vrf}) from the vrf and edge collectors."""
    by_ip, by_intf = {}, {}
    cd = device.get("collector_data", {})
    for e in cd.get("vrf", {}).get("parsed", {}).get("vrf_interfaces", []):
        vrf = e.get("vrf", "")
        if e.get("ip_address"):
            by_ip[e["ip_address"]] = vrf
        if e.get("interface"):
            by_intf[e["interface"]] = vrf
    for e in cd.get("edge_services", {}).get("parsed", {}).get("ip_interfaces", []):
        if e.get("vrf"):
            ip = str(e.get("ip_address", "")).split("/")[0]
            if ip:
                by_ip.setdefault(ip, e["vrf"])
            by_intf.setdefault(e.get("interface", ""), e["vrf"])
    return by_ip, by_intf


def _device_addresses(device):
    """All interface IPv4 addresses known for a device.

    Returns [{interface, ip, prefix, vrf}], deduplicated by IP. Draws on the
    interfaces collector (show ip interface / brief) and edge_services.
    """
    seen = OrderedDict()

    def add(intf, ip, prefix):
        ip = str(ip or "").strip()
        if not ip or ip in ("unassigned", "0.0.0.0"):
            return
        if ip in seen:
            if prefix and not seen[ip]["prefix"]:
                seen[ip]["prefix"] = str(prefix)
            return
        seen[ip] = {"interface": intf, "ip": ip, "prefix": str(prefix or "")}

    for entry in _extract_ip_interfaces(device):
        for ip_info in entry["ips"]:
            add(entry["interface"], ip_info.get("ip"), ip_info.get("prefix"))

    cd = device.get("collector_data", {})
    for e in cd.get("edge_services", {}).get("parsed", {}).get("ip_interfaces", []):
        addr = str(e.get("ip_address", ""))
        ip, _, prefix = addr.partition("/")
        add(e.get("interface", ""), ip, prefix)

    for e in cd.get("interfaces", {}).get("parsed", {}).get("ip_interfaces", []):
        add(e.get("intf", e.get("interface", "")),
            e.get("ipaddr", e.get("ip_address", "")), "")

    by_ip, by_intf = _interface_vrfs(device)
    for rec in seen.values():
        rec["vrf"] = by_ip.get(rec["ip"]) or by_intf.get(rec["interface"], "")
    return list(seen.values())


def _public_addresses(device):
    return [a for a in _device_addresses(device) if _is_public_ip(a["ip"])]


def _igp_interfaces(device):
    rd = device.get("collector_data", {}).get("routing_detail", {}).get("parsed", {})
    intfs = {str(o.get("interface", "")).lower() for o in rd.get("ospf_interfaces", [])}
    intfs |= {str(e.get("interface", "")).lower() for e in rd.get("eigrp_neighbors", [])}
    intfs.discard("")
    return intfs


def _short_intf(name):
    """Gi0/0 and GigabitEthernet0/0 compare equal on prefix letters + numbers."""
    m = re.match(r"^([A-Za-z]{2})[A-Za-z-]*\s*([\d/.:]+)$", str(name))
    return f"{m.group(1).lower()}{m.group(2)}" if m else str(name).lower()


def _static_default_out_non_igp(device):
    """Best-effort: a static default route leaving via a non-IGP interface,
    or pointing at a public next hop. Returns a reason string or ''."""
    routes = (device.get("collector_data", {}).get("l3_routing", {})
              .get("parsed", {}).get("routes", []))
    igp = {_short_intf(i) for i in _igp_interfaces(device)}
    for r in routes:
        network = str(r.get("network", ""))
        mask = str(r.get("prefix_length", r.get("mask", "")))
        if network != "0.0.0.0" or mask not in ("0", "/0", "0.0.0.0"):
            continue
        if not str(r.get("protocol", "")).upper().startswith("S"):
            continue
        nh_if = r.get("nexthop_if", "")
        nh_ip = r.get("nexthop_ip", "")
        if nh_if and _short_intf(nh_if) not in igp:
            return f"static default via {nh_if}"
        if nh_ip and _is_public_ip(nh_ip):
            return f"static default via {nh_ip}"
    return ""


def _edge_reasons(device):
    """Why a device counts as an internet edge device (empty = not edge)."""
    reasons = []
    rd = device.get("collector_data", {}).get("routing_detail", {}).get("parsed", {})
    public_asns = sorted({str(p.get("asn")) for p in rd.get("bgp_summary", [])
                          if _is_public_asn(p.get("asn"))})
    if public_asns:
        reasons.append(f"BGP to public AS {', '.join(public_asns)}")
    pub = _public_addresses(device)
    if pub:
        reasons.append("public address on " + ", ".join(
            sorted({a["interface"] for a in pub})))
    if _nat_configured(device):
        reasons.append("NAT configured")
    default = _static_default_out_non_igp(device)
    if default:
        reasons.append(default)
    return reasons


def _peer_vrf(bp):
    return bp.get("vrf") or "default"


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _is_permit_any(e):
    return (e.get("action", "").lower() == "permit"
            and e.get("protocol", "").lower() == "ip"
            and e.get("source", "").lower() == "any"
            and e.get("destination", "").lower() == "any")


def _analyze_edge(inventory_data):
    findings = []
    devices = inventory_data.get("devices", {})
    acl_usage = {}
    edge = OrderedDict()
    usage_unknown_hosts = []

    for hostname, device in sorted(devices.items()):
        cd = device.get("collector_data", {})

        reasons = _edge_reasons(device)
        if reasons:
            edge[hostname] = reasons

        # --- BGP peer state (all VRFs) ---
        rd_parsed = cd.get("routing_detail", {}).get("parsed", {})
        bgp_peers = rd_parsed.get("bgp_summary", [])

        for bp in bgp_peers:
            state = bp.get("state", "")
            if state and state != "Established":
                findings.append(make_finding(
                    hostname, CRITICAL, "BGP peer not Established",
                    (f"Neighbor {bp.get('neighbor', '?')} "
                     f"AS {bp.get('asn', '?')} (VRF {_peer_vrf(bp)}) state: {state}"),
                ))

        # --- Single-homed BGP (peer count spans every VRF) ---
        if len(bgp_peers) == 1:
            bp = bgp_peers[0]
            findings.append(make_finding(
                hostname, WARNING, "Single-homed BGP",
                (f"Only 1 BGP peer ({bp.get('neighbor', '?')} "
                 f"AS {bp.get('asn', '?')}, VRF {_peer_vrf(bp)}) "
                 f"across all VRFs -- no redundancy"),
                aggregate_key="Only 1 BGP peer across all VRFs -- no redundancy",
            ))

        # --- NAT pool utilization ---
        es_parsed = cd.get("edge_services", {}).get("parsed", {})
        nat_stats = es_parsed.get("nat_statistics", {}) or {}
        for pool in nat_stats.get("pools", []):
            util = pool.get("utilization_pct", 0)
            if isinstance(util, (int, float)) and util > 80:
                findings.append(make_finding(
                    hostname, WARNING, "NAT pool high utilization",
                    (f"Pool '{pool.get('name', '?')}' at {util}% "
                     f"({pool.get('allocated', '?')}/{pool.get('total_addresses', '?')})"),
                ))

        # --- ACL audit, by how each ACL is used ---
        acls = es_parsed.get("access_lists", [])
        usage = classify_acls([a.get("name", "") for a in acls],
                              _device_config(device),
                              es_parsed.get("ip_interfaces", []))
        acl_usage[hostname] = usage
        unknown_here = False
        for acl in acls:
            name = acl.get("name", "?")
            entries = acl.get("entries", [])
            cats = set(usage.get(name, [UNKNOWN]))
            if cats == {UNKNOWN}:
                unknown_here = True
                continue
            if UNREFERENCED in cats:
                findings.append(make_finding(
                    hostname, INFO, "Unreferenced ACL",
                    (f"ACL '{name}' ({len(entries)} rules) is not referenced "
                     f"anywhere in the running-config -- cleanup candidate"),
                    aggregate_key=(f"ACL '{name}' is unreferenced in the "
                                   f"running-config -- cleanup candidate"),
                ))
                continue
            if not entries:
                continue
            # Hit counters only mean something on interface filters.
            if cats & COUNTED and all(e.get("hit_count", 0) == 0 for e in entries):
                findings.append(make_finding(
                    hostname, INFO, "Dead ACL (all zero hits)",
                    f"ACL '{name}' has {len(entries)} rules, all with zero hits",
                    aggregate_key=f"ACL '{name}': every rule has zero hits",
                ))
            if cats & FILTERING and any(_is_permit_any(e) for e in entries):
                findings.append(make_finding(
                    hostname, WARNING, "ACL permit ip any any",
                    f"ACL '{name}' contains permit ip any any",
                ))
        if unknown_here:
            usage_unknown_hosts.append(hostname)

        # --- FHRP unexpected state ---
        findings.extend(fhrp_state_findings(hostname, device, make_finding, WARNING))

    if usage_unknown_hosts:
        findings.append(make_finding(
            "", INFO, "ACL usage unknown (config collector not enabled)",
            (f"Running-config was not collected on {len(usage_unknown_hosts)} "
             f"device(s), so ACL references (QoS, route-map, NAT, crypto) are "
             f"unknown. Dead-rule and permit-any checks ran only for ACLs seen "
             f"applied to an interface. Enable the config collector for a "
             f"full ACL audit."),
        ))

    overfire_check(findings, len(devices))
    return {"findings": findings, "acl_usage": acl_usage, "edge": edge}


# ---------------------------------------------------------------------------
# Row builders shared by xlsx and tabular output
# ---------------------------------------------------------------------------

def _summary_rows(analysis, inventory_data):
    devices = inventory_data.get("devices", {})
    bgp_peer_count = 0
    bgp_vrfs = set()
    nat_devices = 0
    nat_active = 0
    for device in devices.values():
        cd = device.get("collector_data", {})
        rd = cd.get("routing_detail", {}).get("parsed", {})
        es = cd.get("edge_services", {}).get("parsed", {})
        bgp = rd.get("bgp_summary", [])
        bgp_peer_count += len(bgp)
        bgp_vrfs |= {_peer_vrf(bp) for bp in bgp}
        if _nat_configured(device):
            nat_devices += 1
            nat_active += (es.get("nat_statistics") or {}).get("active_translations", 0)

    return [
        ["Total Devices", len(devices)],
        ["Edge Devices", len(analysis["edge"])],
        ["BGP Peers (all VRFs)", bgp_peer_count],
        ["BGP VRFs", len(bgp_vrfs)],
        ["Active NAT Translations", nat_active if nat_devices else NAT_NOT_CONFIGURED],
    ] + summary_count_rows(analysis["findings"])


_EDGE_HEADERS = ["Device", "Site/Location", "Edge Basis"]


def _edge_rows(analysis):
    return [[h, _derive_site(h), "; ".join(reasons)]
            for h, reasons in analysis["edge"].items()]


_BGP_HEADERS = ["Device", "Site/Location", "VRF", "Neighbor", "ASN", "State",
                "Prefixes Rcvd", "Uptime", "Address Family"]


def _bgp_rows(inventory_data):
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        rd = device.get("collector_data", {}).get("routing_detail", {}).get("parsed", {})
        site = _derive_site(hostname)
        for bp in rd.get("bgp_summary", []):
            rows.append([
                hostname, site, _peer_vrf(bp),
                bp.get("neighbor", ""),
                bp.get("asn", ""),
                bp.get("state", ""),
                bp.get("prefixes_received", ""),
                bp.get("up_down", ""),
                bp.get("address_family", ""),
            ])
    return rows


_NAT_HEADERS = ["Device", "Site/Location", "Inside Intfs", "Outside Intfs",
                "Active Translations", "Peak", "Pool Name",
                "Total Addrs", "Allocated", "Util %"]


def _nat_rows(inventory_data):
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        es = device.get("collector_data", {}).get("edge_services", {}).get("parsed", {})
        nat_stats = es.get("nat_statistics") or {}
        if not nat_stats or not _nat_configured(device):
            continue
        site = _derive_site(hostname)
        inside = ", ".join(nat_stats.get("inside_interfaces", []))
        outside = ", ".join(nat_stats.get("outside_interfaces", []))
        for pool in nat_stats.get("pools") or [{}]:
            rows.append([
                hostname, site, inside, outside,
                nat_stats.get("active_translations", ""),
                nat_stats.get("peak_translations", ""),
                pool.get("name", ""),
                pool.get("total_addresses", ""),
                pool.get("allocated", ""),
                pool.get("utilization_pct", ""),
            ])
    return rows


_ACL_HEADERS = ["Device", "Site/Location", "ACL Name", "Type", "ACL Usage",
                "Rule Count", "Zero-Hit Rules", "Has Permit-Any"]


def _acl_rows(analysis, inventory_data):
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        es = device.get("collector_data", {}).get("edge_services", {}).get("parsed", {})
        site = _derive_site(hostname)
        usage = analysis["acl_usage"].get(hostname, {})
        for acl in es.get("access_lists", []):
            entries = acl.get("entries", [])
            zero_hits = sum(1 for e in entries if e.get("hit_count", 0) == 0)
            has_permit_any = any(_is_permit_any(e) for e in entries)
            rows.append([
                hostname, site,
                acl.get("name", ""),
                acl.get("type", ""),
                ", ".join(usage.get(acl.get("name", ""), [UNKNOWN])),
                len(entries),
                zero_hits,
                "Yes" if has_permit_any else "No",
            ])
    return rows


_FHRP_HEADERS = FHRP_HEADERS


def _fhrp_rows(inventory_data):
    return fhrp_rows(inventory_data, _derive_site)


_PUBLIC_HEADERS = ["Device", "Site/Location", "Interface", "IP", "Prefix", "VRF"]


def _public_rows(inventory_data):
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        site = _derive_site(hostname)
        for a in _public_addresses(device):
            rows.append([hostname, site, a["interface"], a["ip"],
                         a["prefix"], a["vrf"] or "default"])
    return rows


def _write_simple_sheet(wb, title, table_name, headers, rows):
    ws = wb.create_sheet(title=title)
    _write_header_row(ws, headers)
    for i, row_data in enumerate(rows, 2):
        _write_row(ws, i, row_data)
    _finalize(ws, table_name, len(headers), len(rows) + 1)
    return ws


# ---------------------------------------------------------------------------
# XLSX sheet builders
# ---------------------------------------------------------------------------

def _build_summary_sheet(wb, analysis, inventory_data):
    _write_simple_sheet(wb, "Summary", "EdgeSummary", ["Metric", "Value"],
                        _summary_rows(analysis, inventory_data))


def _build_edge_devices_sheet(wb, analysis):
    _write_simple_sheet(wb, "Edge Devices", "EdgeDevices", _EDGE_HEADERS,
                        _edge_rows(analysis))


def _build_bgp_peers_sheet(wb, inventory_data):
    _write_simple_sheet(wb, "BGP Peers", "BGPPeers", _BGP_HEADERS,
                        _bgp_rows(inventory_data))


def _build_nat_overview_sheet(wb, inventory_data):
    _write_simple_sheet(wb, "NAT Overview", "NATOverview", _NAT_HEADERS,
                        _nat_rows(inventory_data))


def _build_acl_audit_sheet(wb, analysis, inventory_data):
    _write_simple_sheet(wb, "ACL Audit", "ACLAudit", _ACL_HEADERS,
                        _acl_rows(analysis, inventory_data))


def _build_fhrp_sheet(wb, inventory_data):
    _write_simple_sheet(wb, "FHRP Status", "FHRPStatus", _FHRP_HEADERS,
                        _fhrp_rows(inventory_data))


def _build_public_addresses_sheet(wb, inventory_data):
    _write_simple_sheet(wb, "Public Addresses", "PublicAddresses",
                        _PUBLIC_HEADERS, _public_rows(inventory_data))


def _build_edge_interfaces_sheet(wb, inventory_data):
    ws = wb.create_sheet(title="Edge Interfaces")
    headers = ["Device", "Site/Location", "Interface", "IP",
               "Description", "ACL In", "ACL Out", "Proxy ARP", "uRPF"]
    _write_header_row(ws, headers)
    row = 2
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        es = device.get("collector_data", {}).get("edge_services", {}).get("parsed", {})
        site = _derive_site(hostname)
        for iface in es.get("ip_interfaces", []):
            _write_row(ws, row, [
                hostname, site,
                iface.get("interface", ""),
                iface.get("ip_address", ""),
                "",
                iface.get("acl_in", ""),
                iface.get("acl_out", ""),
                "Yes" if iface.get("proxy_arp") else "No",
                "Yes" if iface.get("urpf") else "No",
            ])
            row += 1
    _finalize(ws, "EdgeInterfaces", len(headers), row - 1)


def _build_findings_sheet(wb, analysis):
    write_findings_sheets(wb, analysis["findings"], "EdgeFindings")


# ---------------------------------------------------------------------------
# Report class
# ---------------------------------------------------------------------------

class InternetEdgeReport(BaseReport):
    name = "internet_edge"
    label = "Internet Edge"
    description = "BGP peering, NAT overview, ACL audit, FHRP status, edge interface security"
    category = "Compliance & Config"
    required_collectors = ["routing_detail"]
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        if fmt != "xlsx":
            return self._generate_for_format(inventory_data, fmt)

        analysis = _analyze_edge(inventory_data)
        wb = Workbook()
        wb.remove(wb.active)

        _build_summary_sheet(wb, analysis, inventory_data)
        _build_edge_devices_sheet(wb, analysis)

        if _has_collector_data(inventory_data, "routing_detail"):
            _build_bgp_peers_sheet(wb, inventory_data)

        if _has_collector_data(inventory_data, "edge_services"):
            _build_nat_overview_sheet(wb, inventory_data)
            _build_acl_audit_sheet(wb, analysis, inventory_data)

        if _has_collector_data(inventory_data, "hsrp") or has_fhrp_data(inventory_data):
            _build_fhrp_sheet(wb, inventory_data)

        if _has_collector_data(inventory_data, "edge_services"):
            _build_edge_interfaces_sheet(wb, inventory_data)

        _build_public_addresses_sheet(wb, inventory_data)
        _build_findings_sheet(wb, analysis)

        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def generate_tabular_data(self, inventory_data):
        analysis = _analyze_edge(inventory_data)
        devices = inventory_data.get("devices", {})
        sheets = OrderedDict()

        sheets["Summary"] = (["Metric", "Value"],
                             _summary_rows(analysis, inventory_data))
        sheets["Edge Devices"] = (list(_EDGE_HEADERS), _edge_rows(analysis))

        if _has_collector_data(inventory_data, "routing_detail"):
            sheets["BGP Peers"] = (list(_BGP_HEADERS), _bgp_rows(inventory_data))

        if _has_collector_data(inventory_data, "edge_services"):
            sheets["NAT Overview"] = (list(_NAT_HEADERS), _nat_rows(inventory_data))
            sheets["ACL Audit"] = (list(_ACL_HEADERS),
                                   _acl_rows(analysis, inventory_data))

        if _has_collector_data(inventory_data, "hsrp") or has_fhrp_data(inventory_data):
            sheets["FHRP Status"] = (list(_FHRP_HEADERS), _fhrp_rows(inventory_data))

        # Edge Interfaces
        if _has_collector_data(inventory_data, "edge_services"):
            ei_headers = ["Device", "Site/Location", "Interface", "IP",
                          "ACL In", "ACL Out", "Proxy ARP", "uRPF"]
            ei_rows = []
            for hostname, device in sorted(devices.items()):
                es = device.get("collector_data", {}).get("edge_services", {}).get("parsed", {})
                site = _derive_site(hostname)
                for iface in es.get("ip_interfaces", []):
                    ei_rows.append([
                        hostname, site, iface.get("interface", ""),
                        iface.get("ip_address", ""),
                        iface.get("acl_in", ""), iface.get("acl_out", ""),
                        "Yes" if iface.get("proxy_arp") else "No",
                        "Yes" if iface.get("urpf") else "No",
                    ])
            sheets["Edge Interfaces"] = (ei_headers, ei_rows)

        sheets["Public Addresses"] = (list(_PUBLIC_HEADERS), _public_rows(inventory_data))

        findings_tabular_sheets(sheets, analysis["findings"])

        return sheets
