"""
ASA security policy: objects, ACLs and NAT from running-config, show
access-list and show nat detail.

Pure functions over text. Objects and object-groups are expanded to address
networks and (protocol, port range) services so ACL lines can be compared:
a line is shadowed when an earlier line with the other action covers it,
redundant when an earlier line with the same action does.
"""
import ipaddress
import re
from collections import OrderedDict

ANY_PORTS = (0, 65535)
ANY_NETS = "any"
# Pairwise shadow analysis is quadratic; very large ACLs are left unchecked
# and say so rather than holding up the report.
SHADOW_CHECK_LIMIT = 3000

PORT_NAMES = {
    "echo": 7, "discard": 9, "daytime": 13, "chargen": 19, "ftp-data": 20, "ftp": 21,
    "ssh": 22, "telnet": 23, "smtp": 25, "time": 37, "nameserver": 42, "whois": 43,
    "tacacs": 49, "domain": 53, "bootps": 67, "bootpc": 68, "tftp": 69, "gopher": 70,
    "finger": 79, "www": 80, "http": 80, "kerberos": 88, "hostname": 101, "pop2": 109,
    "pop3": 110, "sunrpc": 111, "ident": 113, "nntp": 119, "ntp": 123,
    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ssn": 139, "imap4": 143,
    "snmp": 161, "snmptrap": 162, "xdmcp": 177, "bgp": 179, "irc": 194, "dnsix": 195,
    "ldap": 389, "mobile-ip": 434, "https": 443, "pim-auto-rp": 496, "isakmp": 500,
    "biff": 512, "exec": 512, "login": 513, "who": 513, "rsh": 514, "syslog": 514,
    "cmd": 514, "lpd": 515, "talk": 517, "rip": 520, "uucp": 540, "klogin": 543,
    "kshell": 544, "rtsp": 554, "ldaps": 636, "kerberos-adm": 749, "lotusnotes": 1352,
    "citrix-ica": 1494, "sqlnet": 1521, "radius": 1645, "radius-acct": 1646,
    "h323": 1720, "pptp": 1723, "nfs": 2049, "ctiqbe": 2748, "cifs": 3020,
    "sip": 5060, "secureid-udp": 5510, "aol": 5190, "pcanywhere-data": 5631,
    "pcanywhere-status": 5632,
}
_PORT_PROTOCOLS = ("tcp", "udp", "tcp-udp", "sctp")
_PROTO_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp",
                  "51": "ah", "58": "icmp6", "89": "ospf", "132": "sctp"}
_PRIVATE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def _port(token):
    if token is None:
        return None
    if token.isdigit():
        return int(token)
    return PORT_NAMES.get(token.lower())


def port_range(op, a, b=None):
    """(lo, hi) for an ASA port operator, or None when a name is unknown."""
    pa, pb = _port(a), _port(b)
    if pa is None or (op == "range" and pb is None):
        return None
    return {"eq": (pa, pa), "lt": (0, pa - 1), "gt": (pa + 1, 65535),
            "range": (pa, pb), "neq": None}.get(op)


def is_private(net):
    try:
        net = ipaddress.ip_network(net, strict=False)
    except (TypeError, ValueError):
        return False
    return any(net.version == p.version and net.subnet_of(p) for p in _PRIVATE)


def _net(addr, mask=None):
    try:
        if mask:
            return ipaddress.ip_network(f"{addr}/{mask}", strict=False)
        return ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return None


# --- objects ----------------------------------------------------------------

def parse_objects(config):
    """{name: {name, type, kind ("object"/"object-group"), members, description,
    protocol}} from running-config object and object-group blocks."""
    objects = OrderedDict()
    cur = None
    for line in (config or "").splitlines():
        if not line.strip() or line.startswith("!"):
            cur = None
            continue
        if not line[0].isspace():
            cur = None
            m = re.match(r"^(object|object-group) (network|service|protocol|icmp-type|user|"
                         r"security)\s+(\S+)(?:\s+(\S+))?", line)
            if m:
                cur = {"name": m.group(3), "type": m.group(2), "kind": m.group(1),
                       "members": [], "description": "", "protocol": m.group(4) or ""}
                objects[cur["name"]] = cur
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("description "):
            cur["description"] = s[len("description "):]
        elif s.startswith("nat "):
            cur["nat"] = s
        else:
            cur["members"].append(s)
    return objects


class Expander:
    """Expands objects and groups to networks and services, with a cycle guard."""

    def __init__(self, objects):
        self.objects = objects
        self._nets = {}
        self._svcs = {}

    def nets(self, name, seen=None):
        """[networks] or ANY_NETS; unresolvable members (fqdn, range parts that
        fail) are kept as text."""
        if name in self._nets:
            return self._nets[name]
        seen = (seen or set()) | {name}
        obj = self.objects.get(name)
        out = []
        if obj is None:
            out.append(f"unknown:{name}")
        for member in (obj or {}).get("members", []):
            t = member.split()
            if t[0] == "network-object":
                t = t[1:]
            if not t:
                continue
            if t[0] == "host" and len(t) > 1:
                out.append(_net(t[1]) or t[1])
            elif t[0] == "subnet" and len(t) > 2:
                out.append(_net(t[1], t[2]) or member)
            elif t[0] == "range" and len(t) > 2:
                try:
                    out += list(ipaddress.summarize_address_range(
                        ipaddress.ip_address(t[1]), ipaddress.ip_address(t[2])))
                except ValueError:
                    out.append(member)
            elif t[0] == "fqdn":
                out.append("fqdn:" + t[-1])
            elif t[0] in ("object", "group-object") and len(t) > 1:
                if t[1] in seen:
                    continue
                inner = self.nets(t[1], seen)
                if inner == ANY_NETS:
                    out = ANY_NETS
                    break
                out += inner
            elif len(t) == 2 and _net(t[0], t[1]):
                out.append(_net(t[0], t[1]))
            elif len(t) == 1 and _net(t[0]):
                out.append(_net(t[0]))
        if out != ANY_NETS and any(isinstance(n, ipaddress._BaseNetwork)
                                   and n.prefixlen == 0 for n in out):
            out = ANY_NETS
        self._nets[name] = out
        return out

    def services(self, name, seen=None, protocol=""):
        """[(proto, src_range, dst_range)]; ranges None when a name is unknown."""
        if name in self._svcs:
            return self._svcs[name]
        seen = (seen or set()) | {name}
        obj = self.objects.get(name) or {}
        proto = obj.get("protocol") or protocol
        out = []
        for member in obj.get("members", []):
            t = member.split()
            if t[0] == "group-object" and len(t) > 1 and t[1] not in seen:
                out += self.services(t[1], seen, proto)
            elif t[0] == "port-object":
                rng = port_range(t[1], *t[2:4]) if len(t) > 2 else None
                for p in _protos(proto or "tcp-udp"):
                    out.append((p, ANY_PORTS, rng))
            elif t[0] in ("service-object", "service"):
                out += _service_spec(t[1:], self)
            elif t[0] == "protocol-object" and len(t) > 1:
                out.append((_proto_name(t[1]), ANY_PORTS, ANY_PORTS))
            elif t[0] == "icmp-object" and len(t) > 1:
                out.append(("icmp", ANY_PORTS, ANY_PORTS))
        self._svcs[name] = out
        return out


def _proto_name(token):
    return _PROTO_NUMBERS.get(token, token)


def _protos(proto):
    return ["tcp", "udp"] if proto == "tcp-udp" else [proto]


def _service_spec(t, expander):
    """service-object / object service body: proto [source op p] [destination op p]."""
    if not t:
        return []
    if t[0] == "object" and len(t) > 1:
        return expander.services(t[1])
    proto = _proto_name(t[0])
    src, dst = ANY_PORTS, ANY_PORTS
    i = 1
    while i < len(t):
        side = None
        if t[i] in ("source", "destination"):
            side, i = t[i], i + 1
        if i < len(t) and t[i] in ("eq", "lt", "gt", "neq"):
            rng, i = port_range(t[i], t[i + 1] if i + 1 < len(t) else None), i + 2
        elif i < len(t) and t[i] == "range":
            rng = port_range("range", *t[i + 1:i + 3])
            i += 3
        else:
            i += 1
            continue
        if side == "source":
            src = rng
        else:
            dst = rng
    if proto not in _PORT_PROTOCOLS:
        return [(proto, ANY_PORTS, ANY_PORTS)]
    return [(p, src, dst) for p in _protos(proto)]


# --- ACLs -----------------------------------------------------------------------

_ADDR_ANY = ("any", "any4", "any6")


def _take_addr(t, i):
    """(text, kind, ref, index after) for an address at t[i]."""
    if i >= len(t):
        return "", "missing", None, i
    w = t[i]
    if w in _ADDR_ANY:
        return w, "any", None, i + 1
    if w in ("host", "object", "object-group", "interface") and i + 1 < len(t):
        return f"{w} {t[i + 1]}", w, t[i + 1], i + 2
    if i + 1 < len(t) and re.match(r"^\d+\.\d+\.\d+\.\d+$", w) and \
            re.match(r"^\d+\.\d+\.\d+\.\d+$", t[i + 1]):
        return f"{w} {t[i + 1]}", "net", None, i + 2
    if "/" in w or ":" in w:
        return w, "net", None, i + 1
    return w, "name", w, i + 1


def _take_port(t, i, objects):
    if i >= len(t):
        return "", None, i
    w = t[i]
    if w in ("eq", "lt", "gt", "neq") and i + 1 < len(t):
        return f"{w} {t[i + 1]}", ("op", w, t[i + 1]), i + 2
    if w == "range" and i + 2 < len(t):
        return f"range {t[i + 1]} {t[i + 2]}", ("op", "range", t[i + 1], t[i + 2]), i + 3
    if w == "object-group" and i + 1 < len(t) and \
            (objects.get(t[i + 1]) or {}).get("type") == "service":
        return f"object-group {t[i + 1]}", ("group", t[i + 1]), i + 2
    return "", None, i


def parse_acl_config(config, objects=None):
    """{acl: [line dicts]} from running-config access-list lines. Line numbers
    count remarks, as show access-list does."""
    objects = objects or {}
    acls = OrderedDict()
    for raw in (config or "").splitlines():
        m = re.match(r"^access-list (\S+) (.+)$", raw)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        lines = acls.setdefault(name, [])
        number = len(lines) + 1
        if rest.startswith("remark "):
            lines.append({"acl": name, "line": number, "remark": rest[7:], "text": raw})
            continue
        t = rest.split()
        entry = {"acl": name, "line": number, "remark": None, "text": raw, "type": t[0],
                 "action": "", "protocol": "", "service_ref": None, "src": "",
                 "src_kind": "", "src_ref": None, "src_port": "", "dst": "", "dst_kind": "",
                 "dst_ref": None, "dst_port": "", "log": False, "time_range": "",
                 "inactive": False, "_src_port": None, "_dst_port": None}
        if t[0] == "standard" and len(t) > 2:
            entry.update(action=t[1], protocol="ip", src="any", src_kind="any")
            entry["dst"], entry["dst_kind"], entry["dst_ref"], _ = _take_addr(t, 2)
            lines.append(entry)
            continue
        if t[0] != "extended" or len(t) < 3:
            lines.append(entry)
            continue
        entry["action"] = t[1]
        i = 2
        if t[i] in ("object", "object-group") and i + 1 < len(t):
            entry["protocol"], entry["service_ref"] = f"{t[i]} {t[i + 1]}", t[i + 1]
            i += 2
        else:
            entry["protocol"] = _proto_name(t[i])
            i += 1
        entry["src"], entry["src_kind"], entry["src_ref"], i = _take_addr(t, i)
        entry["src_port"], entry["_src_port"], i = _take_port(t, i, objects)
        entry["dst"], entry["dst_kind"], entry["dst_ref"], i = _take_addr(t, i)
        entry["dst_port"], entry["_dst_port"], i = _take_port(t, i, objects)
        while i < len(t):
            w = t[i]
            if w == "log":
                entry["log"] = True
            elif w == "time-range" and i + 1 < len(t):
                entry["time_range"] = t[i + 1]
                i += 1
            elif w == "inactive":
                entry["inactive"] = True
            elif not entry["dst_port"] and entry["protocol"] in ("icmp", "icmp6"):
                entry["dst_port"] = w  # icmp type
            i += 1
        lines.append(entry)
    return acls


_HIT_LINE = re.compile(r"^(\s*)access-list (\S+) line (\d+) (.*?)\(hitcnt=(\d+)\)"
                       r"(?:\s+\(inactive\))?\s*(0x[0-9a-fA-F]+)?")


def parse_acl_hits(text):
    """show access-list: {(acl, line): {hits, hash, elements}} and
    {acl: element count}."""
    lines, elements = {}, {}
    for raw in (text or "").splitlines():
        h = re.match(r"^access-list (\S+); (\d+) elements", raw)
        if h:
            elements[h.group(1)] = int(h.group(2))
            continue
        m = _HIT_LINE.match(raw)
        if not m:
            continue
        key = (m.group(2), int(m.group(3)))
        hits = int(m.group(5))
        rec = lines.setdefault(key, {"hits": None, "hash": "", "elements": 0,
                                     "child_hits": 0})
        if m.group(1):
            rec["elements"] += 1
            rec["child_hits"] += hits
        else:
            rec["hits"] = hits
            rec["hash"] = m.group(6) or ""
    for rec in lines.values():
        if rec["hits"] is None:
            rec["hits"] = rec["child_hits"]
        rec["elements"] = rec["elements"] or 1
    return lines, elements


def acl_bindings(config):
    """{acl: [where it is used]} from access-group, crypto map, class-map,
    group-policy and route-map references."""
    bound = {}

    def add(acl, where):
        bound.setdefault(acl, [])
        if where not in bound[acl]:
            bound[acl].append(where)

    block = ""
    for line in (config or "").splitlines():
        if line and not line[0].isspace():
            block = line.strip()
        s = line.strip()
        if m := re.match(r"^access-group (\S+) (in|out) interface (\S+)", s):
            add(m.group(1), f"{m.group(3)} {m.group(2)}")
        elif m := re.match(r"^access-group (\S+) global", s):
            add(m.group(1), "global")
        elif m := re.match(r"^crypto map (\S+) \d+ match address (\S+)", s):
            add(m.group(2), f"crypto map {m.group(1)}")
        elif (m := re.match(r"^match access-list (\S+)", s)) and block.startswith("class-map"):
            add(m.group(1), "class-map " + block.split()[1])
        elif m := re.match(r"^(?:split-tunnel-network-list|vpn-filter|ipv6-vpn-filter) value (\S+)", s):
            add(m.group(1), "group-policy " + (block.split()[1] if len(block.split()) > 1 else ""))
        elif (m := re.match(r"^match ip address (\S+)", s)) and block.startswith("route-map"):
            add(m.group(1), "route-map " + block.split()[1])
        elif m := re.match(r"^nat .* access-list (\S+)", s):
            add(m.group(1), "NAT")
    return bound


def interface_directions(config):
    """{(acl): [(nameif, direction)]} for interface-bound ACLs."""
    out = {}
    for line in (config or "").splitlines():
        if m := re.match(r"^access-group (\S+) (in|out) interface (\S+)", line):
            out.setdefault(m.group(1), []).append((m.group(3), m.group(2)))
    return out


class LineView:
    """An ACL line with expanded source, destination and service."""

    def __init__(self, entry, expander):
        self.e = entry
        self.src = _addr_nets(entry["src_kind"], entry["src"], entry["src_ref"], expander)
        self.dst = _addr_nets(entry["dst_kind"], entry["dst"], entry["dst_ref"], expander)
        self.svc = _line_services(entry, expander)

    def covers(self, other):
        return (_nets_cover(self.src, other.src) and _nets_cover(self.dst, other.dst)
                and _svcs_cover(self.svc, other.svc))

    def same(self, other):
        return self.covers(other) and other.covers(self)


def _addr_nets(kind, text, ref, expander):
    if kind == "any":
        return ANY_NETS
    if kind == "host":
        n = _net(ref)
        return [n] if n else [text]
    if kind == "net":
        parts = text.split()
        n = _net(*parts) if len(parts) == 2 else _net(parts[0])
        if n is not None and n.prefixlen == 0:
            return ANY_NETS
        return [n] if n else [text]
    if kind in ("object", "object-group"):
        return expander.nets(ref)
    return [text]


def _line_services(e, expander):
    proto = e["protocol"]
    if e["service_ref"]:
        return expander.services(e["service_ref"])
    if proto in ("ip", "ipv4"):
        return [("ip", ANY_PORTS, ANY_PORTS)]

    def rng(spec):
        if spec is None:
            return [ANY_PORTS]
        if spec[0] == "group":
            return [s[2] for s in expander.services(spec[1], protocol=proto)] or [None]
        return [port_range(spec[1], *spec[2:])]

    if proto not in _PORT_PROTOCOLS:
        return [(proto, ANY_PORTS, ANY_PORTS)]
    return [(p, s, d) for p in _protos(proto) for s in rng(e["_src_port"])
            for d in rng(e["_dst_port"])]


def _nets_cover(big, small):
    if big == ANY_NETS:
        return True
    if small == ANY_NETS:
        return False
    for n in small:
        if not isinstance(n, ipaddress._BaseNetwork):
            if n not in big:
                return False
            continue
        if not any(isinstance(b, ipaddress._BaseNetwork) and b.version == n.version
                   and n.subnet_of(b) for b in big):
            return False
    return True


def _range_cover(big, small):
    if big is None or small is None:
        return big == small and big is not None
    return big[0] <= small[0] and small[1] <= big[1]


def _svcs_cover(big, small):
    for p, s, d in small:
        if not any((bp == "ip" or bp == p) and (bp == "ip" or (
                _range_cover(bs, s) and _range_cover(bd, d))) for bp, bs, bd in big):
            return False
    return True


def shadow_flags(lines, expander):
    """{line number: ("shadowed"|"redundant", covering line number)} for one ACL."""
    entries = [e for e in lines if not e.get("remark") and e.get("action")
               and not e.get("inactive")]
    if len(entries) > SHADOW_CHECK_LIMIT:
        return None
    views = [LineView(e, expander) for e in entries]
    flags = {}
    for i, later in enumerate(views):
        for earlier in views[:i]:
            if earlier.covers(later):
                kind = ("redundant" if earlier.e["action"] == later.e["action"]
                        else "shadowed")
                flags[later.e["line"]] = (kind, earlier.e["line"])
                break
    return flags


def format_nets(nets, limit=20):
    if nets == ANY_NETS:
        return "any"
    shown = [str(n) for n in nets[:limit]]
    more = len(nets) - limit
    return "; ".join(shown) + (f"; +{more} more" if more > 0 else "")


def format_services(svcs, limit=20):
    out = []
    for p, s, d in svcs:
        if p == "ip":
            out.append("ip")
            continue
        text = p
        if s and s != ANY_PORTS:
            text += f" src {_fmt_range(s)}"
        if d is None or s is None:
            text += " (unknown port name)"
        elif d != ANY_PORTS:
            text += f" {_fmt_range(d)}"
        out.append(text)
    more = len(out) - limit
    return "; ".join(out[:limit]) + (f"; +{more} more" if more > 0 else "")


def _fmt_range(r):
    return str(r[0]) if r[0] == r[1] else f"{r[0]}-{r[1]}"


def object_references(config, objects):
    """{object name: [referencing places]}: ACLs, NAT, crypto, other groups."""
    refs = {name: [] for name in objects}

    def add(name, where):
        if where not in refs[name]:
            refs[name].append(where)

    own = None
    for line in (config or "").splitlines():
        if not line.strip():
            continue
        indented = line[0].isspace()
        s = line.strip()
        if not indented:
            head = s.split()
            own = head[2] if len(head) > 2 and head[0] in ("object", "object-group") else None
            block = head
        elif own in refs and s.startswith("nat "):
            # Auto NAT lives inside the object it translates.
            add(own, "NAT (object)")
        for name in set(s.split()) & refs.keys():
            if name == own:
                continue
            if s.startswith("access-list "):
                add(name, "ACL " + s.split()[1])
            elif s.startswith("nat "):
                add(name, "NAT")
            elif s.startswith("crypto "):
                add(name, "crypto")
            elif indented and own:
                add(name, f"{block[0]} {own}")
            else:
                add(name, s.split()[0])
    return refs


def object_signature(obj, expander):
    if obj["type"] == "network":
        nets = expander.nets(obj["name"])
        return ("network", "any" if nets == ANY_NETS else tuple(sorted(map(str, nets))))
    if obj["type"] == "service":
        return ("service", tuple(sorted(map(str, expander.services(obj["name"])))))
    return (obj["type"], tuple(sorted(obj["members"])))


# --- NAT ------------------------------------------------------------------------

_NAT_RULE = re.compile(r"^(\d+) \((\S+)\) to \((\S+)\) source (static|dynamic) (\S+) (\S+)(.*)$")


def parse_nat_detail(text):
    """show nat detail: one dict per rule, in section order."""
    rules = []
    section = None
    cur = None
    for raw in (text or "").splitlines():
        s = raw.strip()
        if m := re.search(r"\(Section (\d+)\)", s):
            section = int(m.group(1))
            cur = None
            continue
        if m := _NAT_RULE.match(s):
            rest = m.group(7)
            dest = re.search(r"destination (static|dynamic) (\S+) (\S+)", rest)
            svc = re.search(r"service (\S+) (\S+) (\S+)", rest)
            cur = {"section": section, "rule": int(m.group(1)),
                   "real_if": m.group(2), "mapped_if": m.group(3), "kind": m.group(4),
                   "real_src": m.group(5), "mapped_src": m.group(6),
                   "real_dst": dest.group(2) if dest else "",
                   "mapped_dst": dest.group(3) if dest else "",
                   "service": " ".join(svc.groups()) if svc else "",
                   "flags": [f for f in ("no-proxy-arp", "route-lookup", "unidirectional",
                                         "inactive") if re.search(rf"\b{f}\b", rest)],
                   "pat_pool": "pat-pool" in s,
                   "translate_hits": None, "untranslate_hits": None,
                   "src_origin": "", "src_translated": "", "dst_origin": "",
                   "dst_translated": "", "text": s}
            rules.append(cur)
            continue
        if cur is None:
            continue
        if m := re.search(r"translate_hits = (\d+), untranslate_hits = (\d+)", s):
            cur["translate_hits"], cur["untranslate_hits"] = int(m.group(1)), int(m.group(2))
        elif m := re.match(r"Source - Origin: (.+?), Translated: (.+)$", s):
            cur["src_origin"], cur["src_translated"] = m.group(1).strip(), m.group(2).strip()
        elif m := re.match(r"Destination - Origin: (.+?), Translated: (.+)$", s):
            cur["dst_origin"], cur["dst_translated"] = m.group(1).strip(), m.group(2).strip()
    for r in rules:
        r["type"] = nat_type(r)
        r["public"] = _any_public(r["src_translated"])
    return rules


def nat_type(rule):
    if rule["real_dst"]:
        return "twice NAT"
    if rule["kind"] == "static":
        same = rule["real_src"] == rule["mapped_src"] or (
            rule["src_origin"] and rule["src_origin"] == rule["src_translated"])
        return "identity" if same else "static"
    if rule["mapped_src"] == "interface" or rule["pat_pool"]:
        return "PAT"
    return "dynamic"


def _any_public(text):
    nets = [_net(t.strip()) for t in re.split(r"[,\s]+", text or "") if t.strip()]
    nets = [n for n in nets if n is not None]
    if not nets:
        return None
    return any(not is_private(n) for n in nets)


def rule_names(rule):
    return {rule[k] for k in ("real_src", "mapped_src", "real_dst", "mapped_dst") if rule[k]}
