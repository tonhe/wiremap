"""
Targeted-scan host lists.

Operators bring inventory exports: pasted lines of `host [device_type]`, a
plain text file, or a CSV with a hostname and/or IP column. Hosts may be
IPv4 addresses or names; names are resolved here, before the scan starts, so
an unresolvable entry is reported up front instead of silently missing from
the results.
"""
import csv
import io
import re
import socket
from concurrent.futures import ThreadPoolExecutor, wait

# Lists larger than this are accepted but flagged; they are usually a whole
# CMDB export rather than the network gear the operator meant.
WARN_TARGET_COUNT = 5000

RESOLVE_WORKERS = 32
RESOLVE_TIMEOUT = 10.0

NAME_COLUMNS = ("hostname", "host", "name", "fqdn", "device", "device_name")
IP_COLUMNS = ("ip", "address", "ip_address", "mgmt_ip", "management_ip")
TYPE_COLUMNS = ("device_type", "type")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))*\.?$")


def is_ipv4(value):
    octets = value.split(".")
    if len(octets) != 4:
        return False
    return all(o.isdigit() and 0 <= int(o) <= 255 for o in octets)


def _classify(token, where):
    """Return (ip, hostname) for a host token; exactly one is set."""
    if is_ipv4(token):
        return token, None
    # Digits and dots only is a mistyped address, not a name.
    if re.fullmatch(r"[\d.]+", token):
        raise ValueError(f"{where}: invalid IP address '{token}'")
    if not _HOSTNAME_RE.match(token):
        raise ValueError(f"{where}: invalid host '{token}'")
    return None, token.rstrip(".")


def _check_type(device_type, valid_types, where):
    if device_type and device_type not in valid_types:
        raise ValueError(f"{where}: unknown device type '{device_type}'")
    return device_type or None


def parse_lines(text, valid_types):
    """Parse `host [device_type]` lines. Blank lines and # comments skipped."""
    entries = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        where = f"Line {lineno}"
        ip, hostname = _classify(parts[0], where)
        device_type = _check_type(parts[1] if len(parts) >= 2 else None,
                                  valid_types, where)
        entries.append({"ip": ip, "hostname": hostname,
                        "device_type": device_type})
    return entries


def _pick(header, candidates):
    for name in candidates:
        if name in header:
            return header.index(name)
    return None


def parse_csv(text, valid_types):
    """Parse CSV with a header naming a host and/or IP column."""
    rows = [r for r in csv.reader(io.StringIO(text))
            if r and any(c.strip() for c in r)
            and not r[0].strip().startswith("#")]
    if not rows:
        return []
    header = [h.strip().lower().replace(" ", "_") for h in rows[0]]
    name_col = _pick(header, NAME_COLUMNS)
    ip_col = _pick(header, IP_COLUMNS)
    type_col = _pick(header, TYPE_COLUMNS)
    if name_col is None and ip_col is None:
        raise ValueError(
            "CSV header needs a hostname/host/name/fqdn or ip/address/mgmt_ip column")

    def cell(row, col):
        if col is None or col >= len(row):
            return ""
        return row[col].strip()

    entries = []
    for rowno, row in enumerate(rows[1:], 2):
        where = f"CSV row {rowno}"
        name = cell(row, name_col)
        addr = cell(row, ip_col)
        if not name and not addr:
            continue
        if addr:
            ip, _ = _classify(addr, where)
            if ip is None:
                raise ValueError(f"{where}: invalid IP address '{addr}'")
            hostname = name.rstrip(".") or None
        else:
            ip, hostname = _classify(name, where)
        device_type = _check_type(cell(row, type_col), valid_types, where)
        entries.append({"ip": ip, "hostname": hostname,
                        "device_type": device_type})
    return entries


def _looks_like_csv(text):
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "," not in stripped:
            return False
        header = {h.strip().lower().replace(" ", "_") for h in stripped.split(",")}
        return bool(header & set(NAME_COLUMNS + IP_COLUMNS))
    return False


def parse_targets(text, valid_types, filename=None):
    """Parse pasted text or an uploaded file into host entries."""
    if not text:
        return []
    if (filename or "").lower().endswith(".csv") or _looks_like_csv(text):
        return parse_csv(text, valid_types)
    return parse_lines(text, valid_types)


def _system_nameservers(path="/etc/resolv.conf"):
    try:
        with open(path) as f:
            return [line.split()[1] for line in f
                    if line.startswith("nameserver") and len(line.split()) > 1]
    except OSError:
        return []


def _candidates(name, suffixes):
    """Names to try for one host-list entry. A bare name tries each suffix
    first; a dotted name is tried as given first."""
    with_suffix = [f"{name}.{s.strip('.')}" for s in suffixes if s.strip(".")]
    return with_suffix + [name] if "." not in name else [name] + with_suffix


def make_resolver(server=None, suffixes=None):
    """A getaddrinfo-shaped resolver for host-list names, and a description
    of it for the scan log.

    server is a DNS server address to query instead of the host's resolver,
    for customer zones the wiremap host cannot see; suffixes are search
    domains appended to bare names. Neither changes /etc/resolv.conf.
    """
    suffixes = [s for s in (suffixes or []) if s and s.strip(".")]
    if server:
        import dns.resolver

        dns_resolver = dns.resolver.Resolver(configure=False)
        dns_resolver.nameservers = [server]
        dns_resolver.lifetime = 5.0

        def lookup(name):
            answer = dns_resolver.resolve(name, "A")
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (r.address, 0))
                    for r in answer]
        description = f"DNS server {server}"
    else:
        def lookup(name):
            return socket.getaddrinfo(name, None, socket.AF_INET,
                                      socket.SOCK_STREAM)
        servers = _system_nameservers()
        description = ("the host's resolver"
                       + (f" ({', '.join(servers)})" if servers else ""))
    if suffixes:
        description += f", search {', '.join(suffixes)}"

    def resolver(name, *_args):
        last = None
        for candidate in _candidates(name, suffixes):
            try:
                return lookup(candidate)
            except Exception as e:
                last = e
        raise last
    return resolver, description


def _resolve_one(name, resolver):
    infos = resolver(name, None, socket.AF_INET, socket.SOCK_STREAM)
    for info in infos:
        addr = info[4][0]
        if is_ipv4(addr):
            return addr
    raise OSError("no IPv4 address")


def resolve_targets(entries, resolver=None, timeout=RESOLVE_TIMEOUT,
                    workers=RESOLVE_WORKERS):
    """Resolve names and dedupe by address.

    Returns (hosts, targets, unresolved):
      hosts      [(ip, device_type)] in input order, one per address
      targets    [{"input", "resolved_ip"}] for every name that resolved
      unresolved [{"input", "error"}]
    Two entries that land on the same address are collected once; a device
    type given on either is kept.
    """
    resolver = resolver or socket.getaddrinfo
    names = []
    for e in entries:
        if e["ip"] is None and e["hostname"] not in names:
            names.append(e["hostname"])

    resolved, errors = {}, {}
    if names:
        pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(names))))
        futures = {pool.submit(_resolve_one, n, resolver): n for n in names}
        done, pending = wait(futures, timeout=timeout)
        for fut in done:
            name = futures[fut]
            try:
                resolved[name] = fut.result()
            except Exception as e:
                errors[name] = str(e) or e.__class__.__name__
        for fut in pending:
            errors[futures[fut]] = "lookup timed out"
        # Lookups still running cannot be interrupted; don't wait for them.
        pool.shutdown(wait=False, cancel_futures=True)

    hosts, by_ip, targets, unresolved, seen_names = [], {}, [], [], set()
    for e in entries:
        name = e["hostname"]
        if e["ip"]:
            ip = e["ip"]
        elif name in resolved:
            ip = resolved[name]
        else:
            if name not in seen_names:
                unresolved.append({"input": name, "error": errors.get(name, "")})
                seen_names.add(name)
            continue
        if name and name not in seen_names:
            targets.append({"input": name, "resolved_ip": ip})
            seen_names.add(name)
        if ip in by_ip:
            idx = by_ip[ip]
            if hosts[idx][1] is None and e["device_type"]:
                hosts[idx] = (ip, e["device_type"])
            continue
        by_ip[ip] = len(hosts)
        hosts.append((ip, e["device_type"]))
    return hosts, targets, unresolved
