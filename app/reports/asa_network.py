"""
ASA report: Lifecycle, Zones and Reachability, Routing, Site-to-site VPN,
Remote Access VPN, VPN Sessions and Relationships sheets, and their checks.
"""
import ipaddress
import logging
import re
from collections import OrderedDict
from datetime import date

from . import asa_checks as checks

try:
    from app.collectors import asa_routing as rt
    from app.collectors import asa_vpn as vpn
    from app.collectors import asa_policy as pol
except ImportError:
    from collectors import asa_routing as rt
    from collectors import asa_vpn as vpn
    from collectors import asa_policy as pol

logger = logging.getLogger(__name__)
NA = "n/a"
LEAD = ["Hostname", "Context", "Site"]

WEAK_S2S = "Weak S2S crypto (DES/3DES/MD5/DH 1-2-5/IKEv1 aggressive)"
MARGINAL_S2S = "SHA1 or DH 14 only"
S2S_DOWN = "S2S tunnels configured but down"
RA_NO_MFA = "RA VPN without certificate or MFA"
SPLIT_TUNNEL = "RA split tunnel = tunnel all vs excluded"
ROUTING_NO_AUTH = "Routing protocol without authentication"
REDIST_NO_RM = "Redistribution without route-map"
HW_LDOS = "Hardware past LDoS"
HW_EOSWM = "Hardware past end of SW maintenance"
SW_EOS = "Software past end of support"


class NetView:
    """VPN and routing data for one unit context."""

    def __init__(self, unit, context, ctx):
        out = unit.outputs_for(context)
        self.out = out
        self.config = out.get("show running-config") or ""
        self.objects = pol.parse_objects(self.config)
        self.expander = pol.Expander(self.objects)
        self.acls = pol.parse_acl_config(self.config, self.objects)
        self.policies = vpn.parse_ike_policies(self.config)
        self.transforms = vpn.parse_transforms(self.config)
        self.maps = vpn.parse_crypto_maps(self.config)
        self.groups = vpn.parse_tunnel_groups(self.config)
        self.group_policies = vpn.parse_group_policies(self.config)
        self.pools = vpn.parse_pools(self.config)
        self.pool_usage = vpn.parse_pool_usage(out.get("show ip local pool"))
        detail = out.get("show vpn-sessiondb detail l2l") or out.get("show vpn-sessiondb l2l")
        self.l2l_collected = bool(detail) or "show vpn-sessiondb l2l" in out
        self.l2l = {s.get("Connection"): s for s in vpn.parse_sessions(detail)}
        self.ra_sessions = vpn.parse_sessions(out.get("show vpn-sessiondb anyconnect"))
        self.ra_collected = "show vpn-sessiondb anyconnect" in out
        self.nat = (pol.parse_nat_detail(out.get("show nat detail"))
                    or pol.parse_nat_config(self.config))
        self.routes = rt.parse_routes(out.get("show route"))
        self.routes_collected = bool(out.get("show route"))
        self.summary = rt.parse_route_summary(out.get("show route summary"))
        self.statics = rt.parse_static_routes(self.config)
        self.slas, self.tracks = rt.parse_sla(self.config)
        self.track_state = rt.parse_track_state(out.get("show track"))
        self.procs, self.intf_auth = rt.routing_config(self.config)
        self.interfaces = ctx.get("interfaces") or []
        self.aaa_groups = {g: p for g, p in re.findall(
            r"^aaa-server (\S+) protocol (\S+)", self.config, re.M)}


def views(unit):
    if unit.is_standby:
        return []
    if not hasattr(unit, "_net_views"):
        unit._net_views = [(name, NetView(unit, name, ctx)) for name, ctx in unit.contexts]
    return unit._net_views


def _acl_nets(v, acl, side):
    nets = []
    for e in v.acls.get(acl, []):
        if not e.get("action") or e["action"] != "permit":
            continue
        view = pol.LineView(e, v.expander)
        part = view.src if side == "src" else view.dst
        if part == pol.ANY_NETS:
            return pol.ANY_NETS
        nets += [n for n in part if n not in nets]
    return nets


def _overlaps(a, b):
    if a == pol.ANY_NETS or b == pol.ANY_NETS:
        return bool(a) and bool(b)
    return any(isinstance(x, ipaddress._BaseNetwork) and isinstance(y, ipaddress._BaseNetwork)
               and x.version == y.version and x.overlaps(y) for x in a for y in b)


def _nat_exempt(v, local, remote):
    for r in v.nat:
        if r["type"] not in ("twice NAT", "identity") or "inactive" in r["flags"]:
            continue
        src = v.expander.nets(r["real_src"]) if r["real_src"] in v.objects else []
        dst = v.expander.nets(r["real_dst"]) if r["real_dst"] in v.objects else []
        if _overlaps(src, local) and (not r["real_dst"] or _overlaps(dst, remote)):
            return True
    return False


# ---------------------------------------------------------------------------
# Site-to-site VPN
# ---------------------------------------------------------------------------

S2S_HEADERS = LEAD + [
    "Peer IP", "Tunnel-group", "Crypto Map", "Sequence", "Interface", "Peer Description",
    "IKE Version", "IKE Policy", "IPsec Transform / Proposal", "PFS Group",
    "SA Lifetime (s)", "SA Lifetime (KB)", "Auth Method", "Local Protected Networks",
    "Remote Protected Networks", "Status", "Uptime", "Bytes Tx", "Bytes Rx",
    "NAT Exemption Present", "Weak Crypto", "Weak Crypto Detail"]


def _ike_text(v, versions):
    parts = []
    for ver in versions:
        for p in v.policies.get(ver, []):
            parts.append(f"{ver} {p['priority']}: " + " ".join(
                x for x in (p["encryption"], p["hash"] or p["integrity"],
                            f"group {p['group']}" if p["group"] else "",
                            f"prf {p['prf']}" if p["prf"] else "",
                            f"life {p['lifetime']}" if p["lifetime"] else "") if x))
    return "; ".join(parts)


def s2s_entries(v):
    out = []
    for e in v.maps:
        if e["dynamic"]:
            continue
        local = _acl_nets(v, e["acl"], "src")
        remote = _acl_nets(v, e["acl"], "dst")
        versions = [x for x in ("ikev1", "ikev2") if e[x]]
        for peer in e["peers"] or [""]:
            group = v.groups.get(peer, {})
            session = v.l2l.get(peer)
            remark = next((x["remark"] for x in v.acls.get(e["acl"], [])
                           if x.get("remark")), "")
            out.append({"entry": e, "peer": peer, "group": group, "session": session,
                        "local": local, "remote": remote, "versions": versions,
                        "remark": remark, "weak": vpn.weak_reasons(v.policies, v.transforms, e),
                        "marginal": vpn.marginal_reasons(v.policies, v.transforms, e)})
    return out


def s2s_rows(unit):
    rows = []
    for name, v in views(unit):
        for t in s2s_entries(v):
            e, s = t["entry"], t["session"]
            transforms = "; ".join(
                f"{n} ({v.transforms.get(n, {}).get('encryption', '?')} "
                f"{v.transforms.get(n, {}).get('integrity', '')})".replace(" )", ")")
                for n in e["transforms"])
            status = NA if not v.l2l_collected else ("Up" if s else "Down")
            rows.append(unit.lead(name) + [
                t["peer"], t["group"].get("name", "") if t["group"] else "", e["map"], e["seq"],
                e["interface"], t["remark"], " + ".join(t["versions"]) or NA,
                _ike_text(v, t["versions"] or ["ikev1", "ikev2"]), transforms,
                e["pfs"], NA if e["lifetime_s"] is None else e["lifetime_s"],
                e["lifetime_kb"] or "", vpn.tunnel_auth(t["group"]) if t["group"] else "",
                pol.format_nets(t["local"]), pol.format_nets(t["remote"]), status,
                (s or {}).get("Duration", "") if s else "",
                vpn.session_bytes(s, "Bytes Tx") if s else "",
                vpn.session_bytes(s, "Bytes Rx") if s else "",
                "Yes" if _nat_exempt(v, t["local"], t["remote"]) else "No",
                "Yes" if t["weak"] else "No", "; ".join(t["weak"] + t["marginal"])])
    return rows


# ---------------------------------------------------------------------------
# Remote access VPN
# ---------------------------------------------------------------------------

RA_HEADERS = LEAD + [
    "Tunnel-group", "Group Alias / URL", "Authentication", "Authorization Server",
    "Accounting Server", "Default Group-policy", "Address Pool", "Pool Range", "Pool Size",
    "Pool In Use", "Pool Free", "Split Tunnel Policy", "Split Tunnel ACL",
    "Split Tunnel Networks", "DNS Servers", "Split DNS", "Protocols", "Simultaneous Logins",
    "Idle Timeout (min)", "HostScan", "DAP Records", "AnyConnect Packages",
    "Active Sessions", "Identity Certificate"]
SESSION_HEADERS = LEAD + ["Tunnel-group", "Group Policy", "Client Version", "Protocol",
                          "Assigned IP", "Duration", "Bytes Tx", "Bytes Rx", "Encryption"]


def _attr(lines, key):
    for s in lines:
        if s.startswith(key + " "):
            return s[len(key) + 1:].strip()
    return ""


def ra_profiles(v):
    out = []
    for g in v.groups.values():
        if g.get("type") != "remote-access":
            continue
        gen, web = g["general"], g["webvpn"]
        server = _attr(gen, "authentication-server-group").split()
        method = _attr(web, "authentication") or "aaa"
        protocol = v.aaa_groups.get(server[0], "") if server else ""
        if "saml" in method:
            auth = "SAML (MFA)"
        elif "certificate" in method and "aaa" in method:
            auth = f"AAA ({server[0] if server else 'LOCAL'}) + certificate"
        elif "certificate" in method:
            auth = "certificate"
        else:
            auth = f"AAA ({server[0] if server else 'LOCAL'}"
            auth += f", {protocol})" if protocol else ")"
        gp_name = _attr(gen, "default-group-policy") or "DfltGrpPolicy"
        gp = v.group_policies.get(gp_name, {})
        out.append({"group": g, "auth": auth, "method": method, "server": server,
                    "protocol": protocol, "gp_name": gp_name, "gp": gp,
                    "pool": _attr(gen, "address-pool")})
    return out


def ra_rows(unit, certs_by_tp):
    rows = []
    for name, v in views(unit):
        pkgs = vpn.webvpn_packages(v.config)
        posture = vpn.webvpn_posture(v.config)
        tp = next((re.match(r"ssl trust-point (\S+)", l).group(1)
                   for l in v.config.splitlines() if l.startswith("ssl trust-point ")), "")
        for p in ra_profiles(v):
            g, gp = p["group"], p["gp"]
            alias = ", ".join(x for x in (_attr(g["webvpn"], "group-alias"),
                                          _attr(g["webvpn"], "group-url")) if x)
            pool = v.pools.get(p["pool"], {})
            usage = v.pool_usage.get(pool.get("range", ""), {})
            split_acl = gp.get("split-tunnel-network-list", "")
            # Standard ACLs keep their one address as the destination.
            split_nets = _acl_nets(v, split_acl, "dst") if split_acl else []
            active = sum(1 for s in v.ra_sessions if s.get("Tunnel Group") == g["name"]) \
                if v.ra_collected else NA
            cert = certs_by_tp.get((unit.key, name, tp))
            rows.append(unit.lead(name) + [
                g["name"], alias, p["auth"],
                _attr(g["general"], "authorization-server-group"),
                _attr(g["general"], "accounting-server-group"), p["gp_name"], p["pool"],
                pool.get("range", ""), NA if not pool else pool.get("size"),
                usage.get("in_use", NA) if pool else NA, usage.get("free", NA) if pool else NA,
                gp.get("split-tunnel-policy", "") or "tunnelall (default)", split_acl,
                pol.format_nets(split_nets) if split_acl else "",
                gp.get("dns-server", ""), gp.get("split-dns", ""),
                gp.get("vpn-tunnel-protocol", ""), gp.get("vpn-simultaneous-logins", ""),
                gp.get("vpn-idle-timeout", ""), "Yes" if posture["hostscan"] else "No",
                ", ".join(posture["dap"]), ", ".join(pkgs), active,
                f"{tp} (expires {cert})" if tp and cert else tp])
    return rows


def session_rows(unit):
    rows = []
    for name, v in views(unit):
        for s in v.ra_sessions:
            rows.append(unit.lead(name) + [
                s.get("Tunnel Group", ""), s.get("Group Policy", ""),
                s.get("Client Ver", "") or NA, s.get("Protocol", ""), s.get("Assigned IP", ""),
                s.get("Duration", ""), vpn.session_bytes(s, "Bytes Tx"),
                vpn.session_bytes(s, "Bytes Rx"), s.get("Encryption", "")])
    return rows


# ---------------------------------------------------------------------------
# Routing and zones
# ---------------------------------------------------------------------------

ROUTE_SUMMARY_HEADERS = LEAD + [
    "Connected", "Static", "OSPF", "OSPF Intra-area", "OSPF Inter-area", "OSPF E1",
    "OSPF E2", "EIGRP", "BGP", "Total", "Default Route Next Hop", "Default Route Interface",
    "Floating Statics", "Tracked Statics"]
STATIC_HEADERS = LEAD + ["Interface", "Prefix", "Next Hop", "Distance", "Track ID",
                         "SLA Target", "Track State", "In RIB"]
NEIGHBOR_HEADERS = LEAD + [
    "Protocol", "Process / AS", "Neighbour IP", "Interface", "State", "Uptime",
    "Prefixes Received", "Prefixes Sent", "Area", "Interface Cost",
    "Authentication Configured", "Redistribution into Protocol"]
ZONE_HEADERS = LEAD + [
    "Nameif", "Security Level", "Connected Subnets", "Routed Subnets Behind It",
    "Route Count", "Default Route via This Interface", "Access-group In",
    "Access-group Out", "NAT Rules Referencing"]


def _sum_prefix(summary, prefix):
    values = [v for k, v in summary.items() if k.startswith(prefix) and isinstance(v, int)]
    return sum(values) if values else 0


def route_summary_rows(unit):
    rows = []
    for name, v in views(unit):
        if not v.routes_collected and len(v.summary) <= 1:
            rows.append(unit.lead(name) + [NA] * (len(ROUTE_SUMMARY_HEADERS) - 3))
            continue
        s, o = v.summary, v.summary.get("ospf_detail", {})
        default = next((r for r in v.routes if r["prefix"] is not None
                        and r["prefix"].prefixlen == 0 and not r["connected"]), None)
        rows.append(unit.lead(name) + [
            s.get("connected", 0), s.get("static", 0), _sum_prefix(s, "ospf"),
            o.get("Intra-area", 0), o.get("Inter-area", 0), o.get("External-1", 0),
            o.get("External-2", 0), _sum_prefix(s, "eigrp"), _sum_prefix(s, "bgp"),
            s.get("Total", len(v.routes)),
            default["next_hop"] if default else "", default["nameif"] if default else "",
            sum(1 for st in v.statics if st["distance"] > 1),
            sum(1 for st in v.statics if st["track"])])
    return rows


def static_rows(unit):
    rows = []
    for name, v in views(unit):
        rib = {(str(r["prefix"]), r["next_hop"]) for r in v.routes if r["code"].startswith("S")}
        for st in v.statics:
            sla = v.tracks.get(st["track"], "")
            rows.append(unit.lead(name) + [
                st["nameif"], str(st["prefix"]), st["next_hop"], st["distance"], st["track"],
                v.slas.get(sla, "") if sla else "",
                v.track_state.get(st["track"], NA) if st["track"] else "",
                NA if not v.routes_collected else
                ("Yes" if (str(st["prefix"]), st["next_hop"]) in rib else "No")])
    return rows


def neighbours(v):
    """[{protocol, process, address, nameif, state, uptime, rcvd, sent, area, cost,
    auth, redistribution}]."""
    out = []

    def redist(key):
        return ", ".join(f"{r['source']}" + (f" (route-map {r['route_map']})" if r["route_map"]
                                             else " (no route-map)")
                         for r in v.procs.get(key, {}).get("redistribute", []))

    ospf_if = rt.parse_ospf_interfaces(v.out.get("show ospf interface brief"))
    for n in rt.parse_ospf_neighbors(v.out.get("show ospf neighbor")):
        info = ospf_if.get(n["nameif"], {})
        key = f"ospf {info.get('process', '')}".strip()
        proc = v.procs.get(key) or next((p for k, p in v.procs.items()
                                         if k.startswith("ospf")), {})
        auth = (info.get("area") in proc.get("area_auth", set())
                or v.intf_auth.get(n["nameif"], {}).get("ospf", False))
        out.append({"protocol": "OSPF", "process": info.get("process", ""),
                    "address": n["address"], "nameif": n["nameif"], "state": n["state"],
                    "uptime": "", "rcvd": "", "sent": "", "area": info.get("area", ""),
                    "cost": info.get("cost", ""), "auth": auth,
                    "redistribution": redist(key if key in v.procs else next(
                        (k for k in v.procs if k.startswith("ospf")), ""))})
    for n in rt.parse_eigrp_neighbors(v.out.get("show eigrp neighbors")):
        key = f"eigrp {n['asn']}"
        out.append({"protocol": "EIGRP", "process": n["asn"], "address": n["address"],
                    "nameif": n["nameif"], "state": "Up", "uptime": n["uptime"], "rcvd": "",
                    "sent": "", "area": "", "cost": "",
                    "auth": v.intf_auth.get(n["nameif"], {}).get("eigrp", False),
                    "redistribution": redist(key)})
    local_as, bgp = rt.parse_bgp_summary(v.out.get("show bgp summary"))
    prefixes = rt.parse_bgp_neighbor_prefixes(v.out.get("show bgp neighbors"))
    key = f"bgp {local_as}"
    for n in bgp:
        sent, rcvd = prefixes.get(n["address"], (None, n["prefixes_received"]))
        out.append({"protocol": "BGP", "process": local_as, "address": n["address"],
                    "nameif": _nameif_for(v, n["address"]), "state": n["state"],
                    "uptime": n["uptime"], "rcvd": rcvd, "sent": sent, "area": "",
                    "cost": "",
                    "auth": n["address"] in v.procs.get(key, {}).get("bgp_password", set()),
                    "redistribution": redist(key)})
    return out


def _nameif_for(v, address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    for r in v.routes:
        if r["connected"] and r["prefix"] is not None and r["prefix"].prefixlen < 32 \
                and ip in r["prefix"]:
            return r["nameif"]
    return ""


def neighbour_rows(unit):
    rows = []
    for name, v in views(unit):
        for n in neighbours(v):
            rows.append(unit.lead(name) + [
                n["protocol"], n["process"], n["address"], n["nameif"], n["state"],
                n["uptime"], "" if n["rcvd"] is None else n["rcvd"],
                NA if n["sent"] is None else n["sent"], n["area"], n["cost"],
                "Yes" if n["auth"] else "No", n["redistribution"]])
    return rows


def zone_rows(unit):
    rows = []
    for name, v in views(unit):
        directions = pol.interface_directions(v.config)
        by_if = {}
        for acl, places in directions.items():
            for nif, d in places:
                by_if.setdefault((nif, d), []).append(acl)
        for i in v.interfaces:
            nif = i.get("nameif")
            if not nif:
                continue
            connected = []
            try:
                if i.get("ip") and i.get("mask"):
                    connected.append(ipaddress.ip_network(f"{i['ip']}/{i['mask']}",
                                                          strict=False))
            except ValueError:
                pass
            behind = [r for r in v.routes if r["nameif"] == nif and not r["connected"]
                      and r["prefix"] is not None]
            nets = list(ipaddress.collapse_addresses(
                [r["prefix"] for r in behind if r["prefix"].version == 4]))
            rows.append(unit.lead(name) + [
                nif, "" if i.get("security_level") is None else i["security_level"],
                "; ".join(map(str, connected)),
                pol.format_nets(nets) if v.routes_collected else NA,
                len(behind) if v.routes_collected else NA,
                ("Yes" if any(r["prefix"].prefixlen == 0 for r in behind) else "No")
                if v.routes_collected else NA,
                ", ".join(by_if.get((nif, "in"), [])), ", ".join(by_if.get((nif, "out"), [])),
                sum(1 for r in v.nat if nif in (r["real_if"], r["mapped_if"]))])
    return rows


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

LIFECYCLE_HEADERS = LEAD + [
    "Model", "Units of This Model", "ASA Version", "Versions of This Model in Use",
    "Hardware End of Sale", "Hardware End of SW Maintenance", "Hardware Last Date of Support",
    "EoX Bulletin", "Software Status", "Software Last Date of Support",
    "Recommended Release", "Months to LDoS"]


def eox_records(inventory_data):
    """(hardware {pid: record}, software {"version|ASA": record}) from the EOX
    report's cache and API lookup; empty when unavailable."""
    try:
        from .eox_lifecycle import EoxLifecycleReport
        return EoxLifecycleReport()._get_eox_data(inventory_data)
    except Exception as e:  # pragma: no cover - API or plugin trouble
        logger.warning("EOX lookup for the ASA report failed: %s", e)
        return {}, {}


def _model(unit):
    chassis = unit.parsed.get("chassis") or {}
    return chassis.get("pid") or (unit.parsed.get("version") or {}).get("model") or ""


def _date(text):
    try:
        return date.fromisoformat(text)
    except (TypeError, ValueError):
        return None


def _months(today, when):
    return (when.year - today.year) * 12 + (when.month - today.month)


def lifecycle(unit_list, hw, sw):
    """{unit key: {model, hw record, sw record, ...}}."""
    by_model = OrderedDict()
    for u in unit_list:
        by_model.setdefault(_model(u), []).append(u)
    out = {}
    for model, members in by_model.items():
        versions = sorted({(u.parsed.get("version") or {}).get("asa_version", "")
                           for u in members} - {""})
        for u in members:
            ver = (u.parsed.get("version") or {}).get("asa_version", "")
            out[u.key] = {"model": model, "count": len(members), "versions": versions,
                          "version": ver, "hw": hw.get(model), "sw": sw.get(f"{ver}|ASA")}
    return out


def lifecycle_rows(unit_list, life, today):
    rows = []
    for u in unit_list:
        info = life[u.key]
        h, s = info["hw"], info["sw"]
        ldos = _date((h or {}).get("last_date_of_support"))
        rows.append(u.lead() + [
            info["model"] or NA, info["count"], info["version"] or NA,
            ", ".join(info["versions"]),
            (h or {}).get("end_of_sale", "") if h else NA,
            (h or {}).get("end_of_sw_maintenance", "") if h else NA,
            (h or {}).get("last_date_of_support", "") if h else NA,
            " ".join(x for x in ((h or {}).get("bulletin_number", ""),
                                 (h or {}).get("bulletin_url", "")) if x) if h else NA,
            _sw_status(s, today), (s or {}).get("last_date_of_support", "") if s else NA,
            NA, _months(today, ldos) if ldos else (NA if not h else "")])
    return rows


def _sw_status(record, today):
    if not record:
        return NA
    ldos = _date(record.get("last_date_of_support"))
    eos = _date(record.get("end_of_sale"))
    if ldos and ldos < today:
        return "Past end of support"
    if eos and eos <= today:
        return "End of sale"
    return "Supported"


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

RELATION_HEADERS = LEAD + ["Interface A", "IP A", "Device B", "Context B", "Interface B",
                           "IP B", "Relationship", "Evidence"]


def _addresses(unit_list, inventory_data):
    """[(label, context, nameif, ip, network)] for every ASA interface and every
    other device's known interface addresses."""
    try:
        from app.identity import interface_addresses
    except ImportError:
        from identity import interface_addresses
    out = []
    for u in unit_list:
        if u.is_standby:
            continue
        for name, ctx in u.contexts:
            for i in ctx.get("interfaces") or []:
                if i.get("ip") and i.get("mask"):
                    try:
                        net = ipaddress.ip_network(f"{i['ip']}/{i['mask']}", strict=False)
                    except ValueError:
                        continue
                    out.append((u.hostname, name, i.get("nameif") or i["interface"],
                                i["ip"], net))
    asa_keys = {u.key for u in unit_list}
    for key, device in (inventory_data.get("devices") or {}).items():
        if key in asa_keys:
            continue
        for ip, intf in (interface_addresses(device) or {}).items():
            out.append((key, "", intf, ip, None))
    return out


def relationship_rows(unit_list, inventory_data, pair_map):
    rows = []
    addrs = _addresses(unit_list, inventory_data)
    by_ip = {}
    for a in addrs:
        by_ip.setdefault(a[3], a)
    for host, p in pair_map.items():
        if p.get("primary") and p.get("secondary"):
            fo = p["primary"].parsed.get("failover") or {}
            link = (fo.get("failover_link") or {}).get("interface", "")
            rows.append(p["primary"].lead() + [
                link, "", p["secondary"].key, "", link, "", "failover pair", "show failover"])
    seen = set()
    for a in addrs:
        if a[4] is None:
            continue
        for b in addrs:
            if b is a or b[0] == a[0]:
                continue
            try:
                inside = ipaddress.ip_address(b[3]) in a[4]
            except ValueError:
                continue
            key = tuple(sorted([(a[0], a[1], a[3]), (b[0], b[1], b[3])]))
            if inside and key not in seen and a[4].prefixlen < 32:
                seen.add(key)
                rows.append([a[0], a[1], _site(unit_list, a[0]), a[2], a[3], b[0], b[1],
                             b[2], b[3], "same subnet", f"{a[4]}"])
    for u in unit_list:
        for name, v in views(u):
            for n in neighbours(v):
                peer = by_ip.get(n["address"])
                rows.append(u.lead(name) + [
                    n["nameif"], "", peer[0] if peer else "", peer[1] if peer else "",
                    peer[2] if peer else "", n["address"],
                    f"{n['protocol']} neighbour", f"show {n['protocol'].lower()} neighbors"])
            for t in s2s_entries(v):
                if not t["peer"]:
                    continue
                peer = by_ip.get(t["peer"])
                rows.append(u.lead(name) + [
                    t["entry"]["interface"], "", peer[0] if peer else "",
                    peer[1] if peer else "", peer[2] if peer else "", t["peer"],
                    "S2S tunnel", f"crypto map {t['entry']['map']} {t['entry']['seq']}"])
    return rows


def _site(unit_list, hostname):
    return next((u.site for u in unit_list if u.hostname == hostname), "")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def findings(unit, life=None, today=None):
    out = []
    for name, v in views(unit):
        for t in s2s_entries(v):
            label = f"{t['peer'] or 'dynamic'} ({t['entry']['map']} {t['entry']['seq']})"
            if t["weak"]:
                out.append(checks.finding(unit, checks.HIGH, WEAK_S2S,
                                          f"{label}: {'; '.join(t['weak'])}.", obj=label,
                                          context=name))
            elif t["marginal"]:
                out.append(checks.finding(unit, checks.LOW, MARGINAL_S2S,
                                          f"{label}: {'; '.join(t['marginal'])}.", obj=label,
                                          context=name))
            if v.l2l_collected and t["peer"] and not t["session"]:
                out.append(checks.finding(unit, checks.LOW, S2S_DOWN,
                                          f"{label} has no active session.", obj=label,
                                          context=name))
        for p in ra_profiles(v):
            weak_auth = ("certificate" not in p["method"] and "saml" not in p["method"]
                         and p["protocol"] not in ("radius",))
            if weak_auth:
                out.append(checks.finding(
                    unit, checks.HIGH, RA_NO_MFA,
                    f"Tunnel-group {p['group']['name']} authenticates with {p['auth']} "
                    f"only.", obj=p["group"]["name"], context=name))
            policy_ = p["gp"].get("split-tunnel-policy", "") or "tunnelall"
            out.append(checks.finding(
                unit, checks.INFO_RATING, SPLIT_TUNNEL,
                f"Tunnel-group {p['group']['name']} ({p['gp_name']}): {policy_}.",
                obj=p["group"]["name"], context=name))
        for n in neighbours(v):
            if not n["auth"]:
                out.append(checks.finding(
                    unit, checks.MEDIUM, ROUTING_NO_AUTH,
                    f"{n['protocol']} {n['process']} neighbour {n['address']} on "
                    f"{n['nameif'] or 'n/a'} has no authentication configured.",
                    obj=f"{n['protocol']} {n['address']}", context=name))
        for key, proc in v.procs.items():
            for r in proc["redistribute"]:
                if not r["route_map"]:
                    out.append(checks.finding(
                        unit, checks.MEDIUM, REDIST_NO_RM,
                        f"router {key} redistributes {r['source']} without a route-map.",
                        obj=f"router {key}", context=name,
                        config_lines=[f"router {key}", f" redistribute {r['source']}"]))
    if life and unit.key in life and not unit.is_standby:
        today = today or unit.collected_at.date()
        info = life[unit.key]
        h, s = info["hw"] or {}, info["sw"] or {}
        ldos, eoswm = _date(h.get("last_date_of_support")), _date(h.get("end_of_sw_maintenance"))
        if ldos and ldos < today:
            out.append(checks.finding(unit, checks.HIGH, HW_LDOS,
                                      f"{info['model']} last date of support {ldos}.",
                                      obj=info["model"]))
        elif eoswm and eoswm < today:
            out.append(checks.finding(unit, checks.MEDIUM, HW_EOSWM,
                                      f"{info['model']} end of SW maintenance {eoswm}.",
                                      obj=info["model"]))
        sw_ldos = _date(s.get("last_date_of_support"))
        if sw_ldos and sw_ldos < today:
            out.append(checks.finding(unit, checks.HIGH, SW_EOS,
                                      f"ASA {info['version']} support ended {sw_ldos}.",
                                      obj=info["version"]))
    return out


def certificate_expiry(unit_list):
    """{(unit key, context, trustpoint): valid_to} for identity certificates."""
    out = {}
    for u in unit_list:
        for name, ctx in u.contexts:
            for c in ctx.get("certificates") or []:
                if c["type"] == "identity":
                    for tp in c.get("trustpoints") or []:
                        out[(u.key, name, tp)] = c.get("valid_to", "")
    return out
