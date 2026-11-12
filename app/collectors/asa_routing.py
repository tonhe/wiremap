"""
ASA routing: route table, route summary, static routes with tracking, and
OSPF / EIGRP / BGP neighbours with their authentication and redistribution.
"""
import ipaddress
import re
from collections import OrderedDict

from .asa_parsers import config_blocks

_ROUTE = re.compile(
    r"^(?P<code>[A-Za-z][A-Za-z0-9*]*(?: (?:E1|E2|N1|N2|IA|EX|L1|L2|ia))?\*?)\s+"
    r"(?P<net>\d+\.\d+\.\d+\.\d+) (?P<mask>\d+\.\d+\.\d+\.\d+)\s+(?P<rest>.*)$")
_VIA = re.compile(r"\[(\d+)/(\d+)\] via (\S+?),(?:\s*[\w:.]+,)?\s*(\S+)\s*$")


def _prefix(net, mask):
    try:
        return ipaddress.ip_network(f"{net}/{mask}", strict=False)
    except ValueError:
        return None


def parse_routes(text):
    """show route: [{code, prefix, distance, metric, next_hop, nameif, connected}]."""
    routes = []
    last = None
    for line in (text or "").splitlines():
        m = _ROUTE.match(line.strip()) if line and not line.startswith(" " * 8) else None
        if m:
            rest = m.group("rest")
            rec = {"code": m.group("code").replace("*", "").strip(),
                   "default_candidate": "*" in m.group("code"),
                   "prefix": _prefix(m.group("net"), m.group("mask")),
                   "distance": None, "metric": None, "next_hop": "", "nameif": "",
                   "connected": False}
            if c := re.search(r"is directly connected, (\S+)", rest):
                rec["connected"], rec["nameif"] = True, c.group(1)
            elif v := _VIA.search(rest):
                rec.update(distance=int(v.group(1)), metric=int(v.group(2)),
                           next_hop=v.group(3), nameif=v.group(4))
            if rec["prefix"] is not None:
                routes.append(rec)
                last = rec
            continue
        v = _VIA.search(line)
        if v and last is not None:
            routes.append(dict(last, distance=int(v.group(1)), metric=int(v.group(2)),
                               next_hop=v.group(3), nameif=v.group(4)))
    return routes


def gateway_of_last_resort(text):
    m = re.search(r"Gateway of last resort is (\S+) to network", text or "")
    return m.group(1) if m else None


def parse_route_summary(text):
    """show route summary: {source: count} plus OSPF intra/inter/E1/E2."""
    out = OrderedDict()
    ospf = {}
    for line in (text or "").splitlines():
        if m := re.match(r"^(connected|static|ospf \d+|eigrp \d+|bgp \d+|rip|isis|internal|"
                         r"Total)\s+(\d+)\s+(\d+)?", line, re.I):
            out[m.group(1)] = int(m.group(2)) + int(m.group(3) or 0)
        for key, val in re.findall(r"(Intra-area|Inter-area|External-1|External-2)"
                                   r":\s*(\d+)", line):
            if not line.strip().startswith("NSSA"):
                ospf[key] = ospf.get(key, 0) + int(val)
    out["ospf_detail"] = ospf
    return out


def parse_static_routes(config):
    """route lines: [{nameif, prefix, next_hop, distance, track, tunneled}]."""
    out = []
    for line in (config or "").splitlines():
        m = re.match(r"^route (\S+) (\S+) (\S+) (\S+)(.*)$", line)
        if not m:
            continue
        rest = m.group(5).split()
        distance = int(rest[0]) if rest and rest[0].isdigit() else 1
        track = rest[rest.index("track") + 1] if "track" in rest and \
            rest.index("track") + 1 < len(rest) else ""
        out.append({"nameif": m.group(1), "prefix": _prefix(m.group(2), m.group(3)),
                    "next_hop": m.group(4), "distance": distance, "track": track,
                    "tunneled": "tunneled" in rest, "text": line.strip()})
    return out


def parse_sla(config):
    """{sla id: target} from sla monitor blocks; {track id: sla id} from track lines."""
    slas, tracks = {}, {}
    for header, body in config_blocks(config, "sla monitor "):
        sid = header.split()[2] if len(header.split()) > 2 else ""
        for s in body:
            if m := re.match(r"type echo protocol ipIcmpEcho (\S+) interface (\S+)", s):
                slas[sid] = f"{m.group(1)} ({m.group(2)})"
    for line in (config or "").splitlines():
        if m := re.match(r"^track (\d+) rtr (\d+)", line):
            tracks[m.group(1)] = m.group(2)
    return slas, tracks


def parse_track_state(text):
    """show track: {track id: "Up"/"Down"}."""
    out = {}
    cur = None
    for line in (text or "").splitlines():
        if m := re.match(r"^Track (\d+)", line.strip()):
            cur = m.group(1)
        elif cur and (m := re.search(r"Reachability is (\w+)", line)):
            out[cur] = m.group(1)
    return out


def parse_ospf_neighbors(text):
    rows = []
    for line in (text or "").splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+"
                     r"(\S+)\s*$", line.strip())
        if m:
            rows.append({"router_id": m.group(1), "state": m.group(3).split("/")[0],
                         "address": m.group(5), "nameif": m.group(6)})
    return rows


def parse_ospf_interfaces(text):
    """show ospf interface brief: {nameif: {process, area, cost}}."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^(\S+)\s+(\d+)\s+(\S+)\s+\S+/\d+\s+(\d+)\s+", line.strip())
        if m and m.group(1) != "Interface":
            out[m.group(1)] = {"process": m.group(2), "area": m.group(3),
                               "cost": int(m.group(4))}
    return out


def parse_eigrp_neighbors(text):
    rows = []
    asn = ""
    for line in (text or "").splitlines():
        if m := re.search(r"for AS\((\d+)\)", line):
            asn = m.group(1)
            continue
        m = re.match(r"^\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\d+\s+(\S+)\s+", line.strip())
        if m:
            rows.append({"asn": asn, "address": m.group(1), "nameif": m.group(2),
                         "uptime": m.group(3)})
    return rows


def parse_bgp_summary(text):
    local = re.search(r"local AS number (\d+)", text or "")
    rows = []
    for line in (text or "").splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+4\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+"
                     r"(\S+)\s+(\S+)\s*$", line.strip())
        if m:
            state = m.group(4)
            rows.append({"address": m.group(1), "remote_as": m.group(2), "uptime": m.group(3),
                         "state": "Established" if state.isdigit() else state,
                         "prefixes_received": int(state) if state.isdigit() else None})
    return (local.group(1) if local else ""), rows


def parse_bgp_neighbor_prefixes(text):
    """show bgp neighbors: {address: (sent, received)}."""
    out = {}
    cur = None
    for line in (text or "").splitlines():
        if m := re.match(r"^BGP neighbor is (\S+),", line.strip()):
            cur = m.group(1)
        elif cur and (m := re.match(r"Prefixes Current:\s+(\d+)\s+(\d+)", line.strip())):
            out[cur] = (int(m.group(1)), int(m.group(2)))
    return out


def routing_config(config):
    """Per routing process: auth and redistribution, plus per-interface
    OSPF/EIGRP authentication and BGP neighbour passwords."""
    procs = {}
    for header, body in config_blocks(config, "router "):
        parts = header.split()
        if len(parts) < 2:
            continue
        key = " ".join(parts[1:3])
        p = procs.setdefault(key, {"redistribute": [], "area_auth": set(),
                                   "bgp_password": set(), "eigrp_auth": False})
        for s in body:
            if m := re.match(r"redistribute (\S+(?: \d+)?)(.*)$", s):
                rm = re.search(r"route-map (\S+)", m.group(2))
                p["redistribute"].append({"source": m.group(1), "route_map": rm.group(1)
                                          if rm else ""})
            elif m := re.match(r"area (\S+) authentication", s):
                p["area_auth"].add(m.group(1))
            elif m := re.match(r"neighbor (\S+) password", s):
                p["bgp_password"].add(m.group(1))
    intf_auth = {}
    for header, body in config_blocks(config, "interface "):
        nameif = next((s.split()[1] for s in body if s.startswith("nameif ")), "")
        text = "\n".join(body)
        intf_auth[nameif] = {
            "ospf": bool(re.search(r"ospf (message-digest-key|authentication)", text)),
            "eigrp": bool(re.search(r"authentication (mode|key) eigrp", text))}
    return procs, intf_auth
