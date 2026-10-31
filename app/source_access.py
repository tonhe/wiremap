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


def vty_blocks(config):
    """[(label, acl name or None)] for each 'line vty' block.

    'access-class NAME in vrf-also' counts; 'ipv6 access-class' does not,
    since only IPv4 sources are judged.
    """
    blocks = []
    current = None
    for raw in (config or "").splitlines():
        if not raw.strip():
            continue
        if not raw[:1].isspace():
            current = None
            stripped = raw.strip()
            if _LINE_VTY_RE.match(stripped):
                current = [stripped, None]
                blocks.append(current)
            continue
        if current is not None and current[1] is None:
            m = _ACCESS_CLASS_RE.match(raw)
            if m:
                current[1] = m.group(1)
    return [tuple(b) for b in blocks]


def _community_acl(tokens):
    """ACL named on one 'snmp-server community' line (tokens after the
    community string), or None."""
    name = None
    i = 0
    while i < len(tokens):
        low = tokens[i].lower()
        if low in ("use-acl", "use-ipv4acl") and i + 1 < len(tokens):
            return tokens[i + 1]
        if low in ("view", "ipv6", "group", "use-ipv6acl"):
            i += 2
            continue
        if low in ("ro", "rw"):
            i += 1
            continue
        name = tokens[i]
        i += 1
    return name


def _group_acl(tokens):
    """IPv4 ACL after 'access' on an 'snmp-server group' line, or None."""
    for i, tok in enumerate(tokens):
        if tok.lower() != "access":
            continue
        rest = tokens[i + 1:]
        if rest[:1] and rest[0].lower() == "ipv6":
            rest = rest[2:]
        return rest[0] if rest else None
    return None


def snmp_sources(config):
    """[(label, acl name or None)] for every community and v3 group.

    NX-OS puts a community's group and its ACL on separate lines; the group
    line alone does not mean the community is open.
    """
    sources = []
    community_acls = {}
    group_only = []
    for raw in (config or "").splitlines():
        line = raw.strip()
        tokens = line.split()
        low = line.lower()
        if low.startswith("snmp-server community ") and len(tokens) >= 3:
            community = tokens[2]
            acl = _community_acl(tokens[3:])
            if acl is None and "group" in (t.lower() for t in tokens[3:]):
                group_only.append(community)
                continue
            community_acls.setdefault(community, acl)
            if acl and community_acls[community] is None:
                community_acls[community] = acl
            sources.append(("community", acl))
        elif low.startswith("snmp-server group ") and len(tokens) >= 3:
            sources.append((f"group {tokens[2]}", _group_acl(tokens[3:])))
    for community in group_only:
        if community not in community_acls:
            sources.append(("community", None))
    return sources


def interface_access_groups(config):
    """[(interface, acl name)] for inbound IPv4 interface ACLs."""
    found = []
    interface = None
    for raw in (config or "").splitlines():
        if not raw.strip():
            continue
        if not raw[:1].isspace():
            stripped = raw.strip()
            interface = (stripped.split(None, 1)[1]
                         if stripped.lower().startswith("interface ")
                         and len(stripped.split()) > 1 else None)
            continue
        if interface is None:
            continue
        m = re.match(r"^\s*ip\s+access-group\s+(\S+)\s+in\b", raw, re.I)
        if m:
            found.append((interface, m.group(1)))
    return found


def acl_label(name):
    """'ACL 99' for a numbered ACL, the bare name for a named one."""
    return f"ACL {name}" if str(name).isdigit() else str(name)


def _judge(acls, name, source_ip, service):
    """(PERMIT|DENY|UNKNOWN, matched entry) for one ACL reference.

    No ACL, or an ACL named but not defined anywhere, permits: IOS treats
    an undefined access-class or community ACL as permit-all.
    """
    if not name:
        return PERMIT, None
    acl = acls.get(name)
    if not acl:
        return PERMIT, "not defined"
    return evaluate(acl, source_ip, service)


def _service_result(results, any_permit_wins):
    """Fold per-reference results into (permitted, deciding results)."""
    permits = [r for r in results if r[1] == PERMIT]
    denies = [r for r in results if r[1] == DENY]
    unknown = [r for r in results if r[1] == UNKNOWN]
    if any_permit_wins:
        if permits:
            return True, permits
        if unknown:
            return None, unknown
        return False, denies
    if not permits and not unknown:
        return False, denies
    if not denies and not unknown:
        return True, permits
    return None, unknown or denies


def _describe(results):
    parts = []
    for label, result, name, entry in results:
        what = acl_label(name) if name else "no ACL"
        if entry == "not defined":
            what += " (not defined, permits all)"
        elif entry:
            what += f" ({entry})"
        elif name and result == DENY:
            what += " (implicit deny)"
        parts.append(f"{label}: {result} by {what}")
    return "; ".join(parts)


def assess_source_access(config, source_ip, acl_output=""):
    """Per-service verdict for source_ip against the device's own config.

    Returns {"ssh": {...}, "snmp": {...}}; each holds "permitted" (True,
    False or None when it cannot be judged), "acl" (the deciding ACL name
    or None), "detail" and "matched_entry". SSH also lists inbound
    interface ACLs and whether each lets SSH from source_ip through; that
    is informational only, since which interface the traffic arrives on
    is not known. None when source_ip is not an IPv4 address.
    """
    try:
        if not source_ip or ipaddress.ip_address(source_ip).version != 4:
            return None
    except ValueError:
        return None
    acls = parse_show_access_lists(acl_output)
    acls.update(parse_acls(config))

    blocks = vty_blocks(config)
    if blocks:
        results = []
        for label, name in blocks:
            result, entry = _judge(acls, name, source_ip, VTY)
            results.append((label, result, name, entry))
        permitted, deciding = _service_result(results, any_permit_wins=False)
        names = [r[2] for r in deciding if r[2]]
        ssh = {
            "permitted": permitted,
            "acl": names[0] if names else None,
            "matched_entry": (deciding[0][3] if deciding else None),
            "detail": _describe(results),
        }
    else:
        ssh = {"permitted": True, "acl": None, "matched_entry": None,
               "detail": "no line vty block in config"}
    interface_acls = []
    for interface, name in interface_access_groups(config):
        acl = acls.get(name)
        if not acl:
            continue
        result, entry = evaluate(acl, source_ip, VTY)
        interface_acls.append({
            "interface": interface, "acl": name,
            "permitted": {PERMIT: True, DENY: False}.get(result),
            "matched_entry": entry or "implicit deny",
        })
    ssh["interface_acls"] = interface_acls

    sources = snmp_sources(config)
    if sources:
        results = []
        for label, name in sources:
            result, entry = _judge(acls, name, source_ip, SNMP)
            results.append((label, result, name, entry))
        permitted, deciding = _service_result(results, any_permit_wins=True)
        names = [r[2] for r in deciding if r[2]]
        snmp = {
            "permitted": permitted,
            "acl": names[0] if names else None,
            "matched_entry": (deciding[0][3] if deciding else None),
            "detail": _describe(results),
        }
    else:
        snmp = {"permitted": None, "acl": None, "matched_entry": None,
                "configured": False,
                "detail": "no SNMP community or group in config"}
    return {"ssh": ssh, "snmp": snmp}


_SERVICE_NAMES = {"ssh": "SSH", "snmp": "SNMP"}


def service_phrase(service, verdict):
    """'SSH permitted by VTY-IN', 'SNMP blocked by ACL 99', ..."""
    label = _SERVICE_NAMES[service]
    if verdict is None:
        return f"{label} not checked"
    if verdict.get("configured") is False:
        return f"{label} not configured"
    acl = verdict.get("acl")
    permitted = verdict.get("permitted")
    if permitted is True:
        if acl:
            return f"{label} permitted by {acl_label(acl)}"
        if service == "ssh":
            return f"{label} permitted (no vty access-class)"
        return f"{label} permitted (no ACL)"
    if permitted is False:
        return f"{label} blocked by {acl_label(acl)}" if acl \
            else f"{label} blocked"
    if acl:
        return f"{label} unknown ({acl_label(acl)} could not be evaluated)"
    return f"{label} unknown"


def access_warnings(assessment, source_ip, device, method=None):
    """Warning records for services that are blocked or cannot be judged.

    An unconfigured service never warns.
    """
    warnings = []
    if not assessment:
        return warnings
    nat_note = ""
    if method == SOURCE_LOCAL_SOCKET:
        nat_note = (" (address taken from the local socket; set Source IP "
                    "if devices see this host under a different address)")
    for service, kind in (("ssh", VTY), ("snmp", SNMP)):
        verdict = assessment.get(service) or {}
        permitted = verdict.get("permitted")
        if permitted is True or verdict.get("configured") is False:
            continue
        acl = verdict.get("acl")
        what = (f"vty access-class {acl}" if service == "ssh"
                else f"SNMP ACL {acl}") if acl else (
            "the vty access-class" if service == "ssh" else "the SNMP ACLs")
        if permitted is False:
            consequence = ("expect connection refused on devices sharing "
                           "that ACL" if service == "ssh" else
                           "SNMP fallback will not answer on devices "
                           "sharing that ACL")
            message = (f"This host ({source_ip}) is not permitted by {what} "
                       f"on {device}; {consequence}{nat_note}")
        else:
            message = (f"Could not tell whether this host ({source_ip}) is "
                       f"permitted by {what} on {device}: "
                       f"{verdict.get('detail')}")
        warnings.append({
            "kind": kind,
            "service": service,
            "permitted": permitted,
            "acl": acl,
            "device": device,
            "source_ip": source_ip,
            "matched_entry": verdict.get("matched_entry") or "implicit deny",
            "message": message,
        })
    return warnings


def check_source_access(config, source_ip, device, acl_output=""):
    """Warnings for each service on device that does not permit source_ip."""
    return access_warnings(
        assess_source_access(config, source_ip, acl_output=acl_output),
        source_ip, device)


# --- Source address -------------------------------------------------------

SOURCE_CONFIGURED = "configured"
SOURCE_SHOW_USERS = "seed-session (show users)"
SOURCE_TCP_BRIEF = "seed-session (show tcp brief)"
SOURCE_LOCAL_SOCKET = "local-socket (may be NATed/container address)"

_METHOD_LABELS = {
    SOURCE_CONFIGURED: "configured",
    SOURCE_SHOW_USERS: "learned from seed session",
    SOURCE_TCP_BRIEF: "learned from seed session",
    SOURCE_LOCAL_SOCKET: "local socket, may be a NAT or container address",
}

_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
_TCP_ADDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})[.:](\d+)$")
# Platforms whose 'show users' marks the caller's own session.
_SHOW_USERS_PLATFORMS = ("cisco_ios", "cisco_xe", "cisco_nxos")
_TCP_BRIEF_PLATFORMS = ("cisco_ios", "cisco_xe")


def clean_source_ip(value):
    """A stated source address as a string, '' when blank.

    Raises ValueError for anything that is not a single IPv4 address.
    """
    value = (value or "").strip()
    if not value:
        return ""
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError(f"Source IP must be an IPv4 address, not {value!r}")
    return str(addr)


def _ipv4(text):
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def parse_show_users(output, username=None):
    """The peer address of our own session in 'show users' output, or None.

    IOS and IOS-XE mark the caller's line with a leading '*'; NX-OS marks it
    with a trailing '*'. Without a marker, the last session line naming
    username is taken as the most recent.
    """
    marked = None
    by_user = None
    for raw in (output or "").splitlines():
        tokens = raw.split()
        if not tokens:
            continue
        addrs = [a for a in (_ipv4(m) for m in _IPV4_RE.findall(raw)) if a]
        is_ours = tokens[0].startswith("*") or tokens[-1] == "*"
        if is_ours:
            marked = addrs[-1] if addrs else None
            break
        if username and username in tokens and addrs:
            by_user = addrs[-1]
    return marked or by_user


def parse_tcp_brief(output, local_ip=None, port=22):
    """The foreign address of the established session to local port, or None.

    When local_ip is given only connections to that address count. Several
    different peers on the port leave the answer ambiguous, so None.
    """
    peers = []
    for raw in (output or "").splitlines():
        tokens = raw.split()
        if len(tokens) < 3:
            continue
        if not any(t.upper().startswith("ESTAB") for t in tokens):
            continue
        addrs = [_TCP_ADDR_RE.match(t) for t in tokens]
        addrs = [m for m in addrs if m]
        if len(addrs) < 2:
            continue
        local, foreign = addrs[0], addrs[1]
        if local.group(2) != str(port):
            continue
        if local_ip and local.group(1) != local_ip:
            continue
        peer = _ipv4(foreign.group(1))
        if peer and peer not in peers:
            peers.append(peer)
    return peers[0] if len(peers) == 1 else None


def learn_source_ip(conn, device_type, username=None, local_ip=None,
                    protocol="ssh"):
    """(address, method) of this host as the device sees it, or (None, None).

    Asks the device who is logged in. Runs on the live session before any
    collector, with plain send_command, so collected output is untouched.
    """
    platform = (device_type or "").lower()
    port = 23 if (protocol or "").lower() == "telnet" else 22

    def run(cmd):
        try:
            return conn.send_command(cmd, read_timeout=15)
        except Exception:
            return ""

    if platform.startswith(_SHOW_USERS_PLATFORMS):
        addr = parse_show_users(run("show users"), username=username)
        if addr:
            return addr, SOURCE_SHOW_USERS
    if platform.startswith(_TCP_BRIEF_PLATFORMS):
        addr = parse_tcp_brief(run("show tcp brief"), local_ip=local_ip,
                               port=port)
        if addr:
            return addr, SOURCE_TCP_BRIEF
    return None, None


def summary_line(source_ip, method, assessment):
    """'Scanning from 192.0.2.50 (learned from seed session) -- SSH
    permitted by VTY-IN, SNMP blocked by ACL 99'."""
    if not source_ip:
        return None
    label = _METHOD_LABELS.get(method, method or "unknown")
    line = f"Scanning from {source_ip} ({label})"
    if assessment:
        line += " — " + ", ".join(
            service_phrase(s, assessment.get(s)) for s in ("ssh", "snmp"))
    return line


def refused_hint(failed, source_ip, threshold=3):
    """Console hint when several devices refused the connection, or None."""
    count = sum(1 for v in (failed or {}).values()
                if failure_record(v)["reason"] == REFUSED)
    if count < threshold:
        return None
    who = f"this host ({source_ip})" if source_ip else "this host"
    return (f"{count} devices refused the connection; check the vty "
            f"access-class ACLs permit {who}")
