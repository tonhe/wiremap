"""
Source-host access check -- is the wiremap host allowed to manage the network?

A vty access-class or SNMP community ACL that leaves out the host wiremap runs
on shows up as dozens of "connection refused" failures with no obvious cause.
The seed's running-config usually names the management ACL every other device
shares, so checking the source address against it once, right after the seed
is collected, explains the failures before they happen.

Only IPv4 is checked. Unknown constructs (object-groups, address groups,
unparsable entries) end the evaluation as "unknown", which never warns: a
false alarm here would send the operator chasing an ACL that is fine.
"""
import ipaddress
import re
import socket

try:
    from app.failures import failure_record, REFUSED
except ImportError:
    from failures import failure_record, REFUSED

PERMIT = "permit"
DENY = "deny"
UNKNOWN = "unknown"

VTY = "vty"
SNMP = "snmp"

_VTY_PORTS = {"22", "ssh", "23", "telnet"}
_SNMP_PORTS = {"161", "snmp"}
_PORT_OPS = {"eq", "neq", "lt", "gt", "range"}
_VTY_PROTOCOLS = {"ip", "tcp", "ipv4"}
_SNMP_PROTOCOLS = {"ip", "udp", "ipv4"}

_NAMED_HEADER_RE = re.compile(
    r"^ip\s+access-list\s+(?:(standard|extended)\s+)?(\S+)\s*$", re.I)
_NUMBERED_RE = re.compile(r"^access-list\s+(\d+)\s+(.*)$", re.I)
_SHOW_HEADER_RE = re.compile(
    r"^(?:(standard|extended)\s+)?ip\s+access\s+list\s+(\S+)", re.I)
_LINE_VTY_RE = re.compile(r"^line\s+vty\b", re.I)
_ACCESS_CLASS_RE = re.compile(r"^\s*access-class\s+(\S+)\s+in\b", re.I)
_SNMP_USE_ACL_RE = re.compile(r"\buse-(?:ipv4)?acl\s+(\S+)", re.I)
_MATCHES_RE = re.compile(r"\s*\(\d+\s+match(?:es)?\)\s*$", re.I)
_WILDCARD_BITS_RE = re.compile(r",\s*wildcard bits\s+", re.I)
_DOTTED_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def local_source_ip(dest, port=22):
    """The local address the OS would use to reach dest, or None.

    connect() on a UDP socket only picks a route and source address; no
    packet is sent.
    """
    if not dest:
        return None
    try:
        infos = socket.getaddrinfo(dest, port, 0, socket.SOCK_DGRAM)
    except (OSError, UnicodeError):
        return None
    for family, socktype, proto, _, addr in infos:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            sock.connect(addr)
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            if sock is not None:
                sock.close()
    return None


def _standard_number(number):
    n = int(number)
    return 1 <= n <= 99 or 1300 <= n <= 1999


def parse_acls(config):
    """{name: {"type": "standard"|"extended", "entries": [text, ...]}}.

    Reads named ACL blocks (IOS, NX-OS and EOS) and numbered access-list
    lines. An NX-OS or EOS "ip access-list NAME" without a type keyword is
    extended.
    """
    acls = {}
    current = None
    for raw in (config or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        indented = line[:1].isspace()
        if current is not None and indented:
            current["entries"].append(line.strip())
            continue
        current = None
        stripped = line.strip()
        m = _NAMED_HEADER_RE.match(stripped)
        if m:
            current = acls.setdefault(m.group(2), {
                "type": (m.group(1) or "extended").lower(), "entries": []})
            continue
        m = _NUMBERED_RE.match(stripped)
        if m:
            number, body = m.groups()
            acl = acls.setdefault(number, {
                "type": "standard" if _standard_number(number) else "extended",
                "entries": []})
            acl["entries"].append(body.strip())
    return acls


def parse_show_access_lists(output):
    """Same shape as parse_acls, from 'show access-lists' output.

    Used for ACLs the running-config did not carry. Hit counters and the
    "wildcard bits" spelling are normalised to config syntax.
    """
    acls = {}
    current = None
    for raw in (output or "").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        m = _SHOW_HEADER_RE.match(stripped)
        if m:
            kind = (m.group(1) or "extended").lower()
            current = acls.setdefault(m.group(2), {"type": kind, "entries": []})
            continue
        if current is None or not raw[:1].isspace():
            current = None
            continue
        entry = _MATCHES_RE.sub("", stripped)
        entry = _WILDCARD_BITS_RE.sub(" ", entry)
        current["entries"].append(entry)
    return acls


def vty_access_classes(config):
    """Inbound IPv4 access-class names applied to vty lines, in order."""
    names = []
    in_vty = False
    for raw in (config or "").splitlines():
        if not raw.strip():
            continue
        if not raw[:1].isspace():
            in_vty = bool(_LINE_VTY_RE.match(raw.strip()))
            continue
        if in_vty:
            m = _ACCESS_CLASS_RE.match(raw)
            if m and m.group(1) not in names:
                names.append(m.group(1))
    return names


def snmp_community_acls(config):
    """IPv4 ACL names on snmp-server community lines, in order."""
    names = []
    for raw in (config or "").splitlines():
        line = raw.strip()
        if not line.lower().startswith("snmp-server community "):
            continue
        m = _SNMP_USE_ACL_RE.search(line)
        if m:
            name = m.group(1)
        else:
            # snmp-server community <c> [view V] [RO|RW] [ipv6 N] [acl]
            tokens = line.split()[3:]
            name = None
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                low = tok.lower()
                if low in ("view", "ipv6", "group"):
                    i += 2
                    continue
                if low in ("ro", "rw"):
                    i += 1
                    continue
                name = tok
                i += 1
        if name and name not in names:
            names.append(name)
    return names


def _address(tokens, i, standard):
    """Parse an address spec at tokens[i]. Returns (network|None, next_i).

    network None means the spec could not be understood.
    """
    if i >= len(tokens):
        return None, i
    tok = tokens[i].lower()
    try:
        if tok == "any":
            return ipaddress.ip_network("0.0.0.0/0"), i + 1
        if tok == "host" and i + 1 < len(tokens):
            return ipaddress.ip_network(tokens[i + 1] + "/32"), i + 2
        if "/" in tok:
            return ipaddress.ip_network(tok, strict=False), i + 1
        if _DOTTED_RE.match(tok):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if _DOTTED_RE.match(nxt):
                return _Wildcard(tok, nxt), i + 2
            if standard:
                return ipaddress.ip_network(tok + "/32"), i + 1
    except ValueError:
        return None, i
    return None, i


class _Wildcard:
    """A base/wildcard pair that need not be a contiguous prefix."""

    def __init__(self, base, wildcard):
        self.base = int(ipaddress.IPv4Address(base))
        self.care = ~int(ipaddress.IPv4Address(wildcard)) & 0xFFFFFFFF

    def __contains__(self, addr):
        return (int(addr) & self.care) == (self.base & self.care)


def _skip_ports(tokens, i):
    """Step over a port qualifier; returns (ports or None, next_i)."""
    if i >= len(tokens) or tokens[i].lower() not in _PORT_OPS:
        return None, i
    op = tokens[i].lower()
    if op == "range":
        return [], i + 3
    ports = []
    j = i + 1
    while j < len(tokens) and tokens[j].lower() not in _PORT_OPS \
            and not _DOTTED_RE.match(tokens[j]) \
            and tokens[j].lower() not in ("any", "host", "log", "established") \
            and "/" not in tokens[j]:
        ports.append(tokens[j].lower())
        if op != "eq":
            j += 1
            break
        j += 1
    return (ports if op == "eq" else []), j


def match_entry(entry, acl_type, source_ip, service=VTY):
    """Evaluate one ACL entry for traffic from source_ip.

    Returns PERMIT or DENY when the entry matches, None when it does not,
    UNKNOWN when it cannot be judged. remark/statistics lines return None.
    """
    tokens = entry.split()
    if tokens and tokens[0].isdigit():
        tokens = tokens[1:]
    if not tokens:
        return None
    action = tokens[0].lower()
    if action not in (PERMIT, DENY):
        return None
    addr = ipaddress.IPv4Address(source_ip)

    if acl_type == "standard":
        net, _ = _address(tokens, 1, standard=True)
        if net is None:
            return UNKNOWN
        return action if addr in net else None

    if len(tokens) < 3:
        return UNKNOWN
    protocol = tokens[1].lower()
    if protocol in ("object-group", "addrgroup", "portgroup"):
        return UNKNOWN
    allowed = _VTY_PROTOCOLS if service == VTY else _SNMP_PROTOCOLS
    if not protocol.isdigit() and protocol not in allowed:
        return None
    if protocol.isdigit() and protocol not in ("0", "6", "17"):
        return None
    net, i = _address(tokens, 2, standard=False)
    if net is None:
        return UNKNOWN
    if addr not in net:
        return None
    src_ports, i = _skip_ports(tokens, i)
    if src_ports:
        # A source-port match on traffic to a vty is unusual; do not guess.
        return UNKNOWN
    dst, i = _address(tokens, i, standard=False)
    if dst is None:
        return UNKNOWN
    dst_ports, i = _skip_ports(tokens, i)
    if dst_ports:
        wanted = _VTY_PORTS if service == VTY else _SNMP_PORTS
        if not wanted.intersection(dst_ports):
            return None
    return action


def evaluate(acl, source_ip, service=VTY):
    """(PERMIT|DENY|UNKNOWN, entry text or None) for source_ip against acl."""
    for entry in acl.get("entries", []):
        result = match_entry(entry, acl.get("type", "extended"), source_ip,
                             service)
        if result is None:
            continue
        return result, entry
    return DENY, None


def check_source_access(config, source_ip, device, acl_output=""):
    """Warnings for each vty/SNMP ACL on device that denies source_ip.

    An ACL named but not defined anywhere is skipped: IOS treats an undefined
    access-class as permit-all.
    """
    try:
        if not source_ip or ipaddress.ip_address(source_ip).version != 4:
            return []
    except ValueError:
        return []
    acls = parse_show_access_lists(acl_output)
    acls.update(parse_acls(config))

    warnings = []
    checks = [(VTY, name) for name in vty_access_classes(config)]
    checks += [(SNMP, name) for name in snmp_community_acls(config)]
    for service, name in checks:
        acl = acls.get(name)
        if not acl:
            continue
        result, entry = evaluate(acl, source_ip, service)
        if result != DENY:
            continue
        if service == VTY:
            message = (f"This host ({source_ip}) is not permitted by vty "
                       f"access-class {name} on {device}; expect connection "
                       f"refused on devices sharing that ACL")
        else:
            message = (f"This host ({source_ip}) is not permitted by SNMP "
                       f"community ACL {name} on {device}; SNMP fallback will "
                       f"not answer on devices sharing that ACL")
        warnings.append({
            "kind": service,
            "acl": name,
            "device": device,
            "source_ip": source_ip,
            "matched_entry": entry or "implicit deny",
            "message": message,
        })
    return warnings


def refused_hint(failed, source_ip, threshold=3):
    """Console hint when several devices refused the connection, or None."""
    count = sum(1 for v in (failed or {}).values()
                if failure_record(v)["reason"] == REFUSED)
    if count < threshold:
        return None
    who = f"this host ({source_ip})" if source_ip else "this host"
    return (f"{count} devices refused the connection; check the vty "
            f"access-class ACLs permit {who}")
