"""
ACL usage classification from a device's running-config.

Hit counters only move for ACLs that filter traffic on an interface (and,
on most platforms, line/management filters). An ACL used as a QoS class
matcher, route-map/distribute-list selector, NAT source list or crypto map
selector never accrues hits, so "all zero hits" says nothing about it.
Classifying by reference lets the edge report flag dead rules only where
the counter means something.
"""
import re
from collections import OrderedDict

INTERFACE = "Interface filter"
MANAGEMENT = "Management-plane filter"
QOS = "QoS classifier"
ROUTING = "Routing policy"
NAT = "NAT"
CRYPTO = "VPN selector"
OTHER = "Other reference"
UNREFERENCED = "Unreferenced"
UNKNOWN = "Unknown"

# Categories whose ACL hit counters are meaningful.
COUNTED = frozenset({INTERFACE})
# Categories where a permit ip any any is a filtering decision worth flagging.
# In a QoS matcher or NAT list it just means "match everything".
FILTERING = frozenset({INTERFACE, MANAGEMENT})

_ROUTING_SKIP = {"prefix-list", "prefix", "route-map", "gateway"}

_IFACE_FILTER_RE = re.compile(
    r"^\s*(?:ip|ipv6)\s+(?:port\s+)?(?:access-group|traffic-filter)\s+(\S+)\s+(in|out)\b")
_ACCESS_CLASS_RE = re.compile(
    r"^\s*(?:ip\s+|ipv6\s+)?access-class\s+(\S+)")
_HTTP_ACCESS_CLASS_RE = re.compile(
    r"^ip\s+http\s+access-class\s+(?:ipv4\s+)?(\S+)")
_NTP_ACL_RE = re.compile(
    r"^ntp\s+access-group\s+(?:ipv4\s+)?(?:peer|serve|serve-only|query-only)\s+(\S+)")
_SNMP_USE_ACL_RE = re.compile(r"\buse-(?:ipv4)?acl\s+(\S+)")
_QOS_RE = re.compile(r"^\s*match\s+access-group\s+(?:name\s+)?(\S+)")
_RMAP_MATCH_RE = re.compile(
    r"^\s*match\s+(?:ip|ipv6)\s+(?:address|next-hop|route-source)\s+(.+)$")
_DIST_LIST_RE = re.compile(r"\bdistribute-list\s+(\S+)")
_NAT_LIST_RE = re.compile(r"^\s*ip\s+nat\b.*?\blist\s+(\S+)")
_CRYPTO_MATCH_RE = re.compile(r"^\s*match\s+address\s+(\S+)")
_GENERIC_RE = re.compile(
    r"\b(?:access-group|access-class|boundary)\s+(?:name\s+)?(?:ipv4\s+)?(\S+)")


def _snmp_acls(line):
    """ACL names on an snmp-server community/group line."""
    names = []
    m = _SNMP_USE_ACL_RE.search(line)
    if m:
        names.append(m.group(1))
        return names
    tokens = line.split()
    if line.startswith("snmp-server community") and len(tokens) >= 4:
        # snmp-server community <string> [view V] [RO|RW] [ipv6 N] [acl]
        last = tokens[-1]
        if last.upper() not in ("RO", "RW") and tokens[-2] not in ("view", "ipv6", "group"):
            names.append(last)
    elif line.startswith("snmp-server group") and "access" in tokens:
        rest = tokens[tokens.index("access") + 1:]
        if rest[:1] == ["ipv6"]:
            rest = rest[2:]
        if rest:
            names.append(rest[0])
    return names


def parse_acl_references(config):
    """Return {acl_name: [(category, detail), ...]} from running-config text.

    detail is e.g. "GigabitEthernet0/0 in" for interface filters, or the
    enclosing block header otherwise.
    """
    refs = OrderedDict()

    def add(name, category, detail=""):
        refs.setdefault(name, [])
        if (category, detail) not in refs[name]:
            refs[name].append((category, detail))

    block = ""
    for raw_line in (config or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        indented = line[0] in " \t"
        if not indented:
            block = line.strip()
            stripped = block
        else:
            stripped = line.strip()

        # ACL definitions and their entries are not references.
        if block.startswith(("ip access-list", "ipv6 access-list",
                             "access-list", "mac access-list")):
            continue
        if not indented and stripped.startswith("access-list "):
            continue

        if block.startswith("interface ") and indented:
            m = _IFACE_FILTER_RE.match(stripped)
            if m:
                add(m.group(1), INTERFACE, f"{block.split(None, 1)[1]} {m.group(2)}")
                continue

        if block.startswith("line ") and indented:
            m = _ACCESS_CLASS_RE.match(stripped)
            if m:
                add(m.group(1), MANAGEMENT, block)
                continue

        if not indented:
            m = _HTTP_ACCESS_CLASS_RE.match(stripped) or _NTP_ACL_RE.match(stripped)
            if m:
                add(m.group(1), MANAGEMENT, stripped.split()[0])
                continue
            if stripped.startswith("snmp-server "):
                for name in _snmp_acls(stripped):
                    add(name, MANAGEMENT, "snmp-server")
                continue
            m = _NAT_LIST_RE.match(stripped)
            if m:
                add(m.group(1), NAT, "ip nat")
                continue

        if block.startswith("class-map") and indented:
            m = _QOS_RE.match(stripped)
            if m:
                add(m.group(1), QOS, block)
                continue

        if block.startswith(("crypto map", "crypto dynamic-map")) and indented:
            m = _CRYPTO_MATCH_RE.match(stripped)
            if m:
                add(m.group(1), CRYPTO, block)
                continue

        m = _RMAP_MATCH_RE.match(stripped)
        if m:
            tokens = m.group(1).split()
            if tokens and tokens[0] not in _ROUTING_SKIP:
                for name in tokens:
                    add(name, ROUTING, block)
            continue

        m = _DIST_LIST_RE.search(stripped)
        if m:
            if m.group(1) not in _ROUTING_SKIP:
                add(m.group(1), ROUTING, block)
            continue

        m = _GENERIC_RE.search(stripped)
        if m:
            add(m.group(1), OTHER, block)

    return refs


def classify_acls(acl_names, config, ip_interfaces=None):
    """Return {acl_name: [category, ...]} for each ACL in acl_names.

    config is the running-config text, or None/"" when the config collector
    did not run. Without it, ACLs seen applied in 'show ip interface' are
    still known interface filters; everything else is UNKNOWN rather than
    UNREFERENCED, since other references cannot be ruled out.
    """
    have_config = bool(config and config.strip())
    refs = parse_acl_references(config) if have_config else {}

    applied = set()
    for iface in ip_interfaces or []:
        for key in ("acl_in", "acl_out"):
            if iface.get(key):
                applied.add(iface[key])

    result = OrderedDict()
    for name in acl_names:
        cats = []
        for cat, _detail in refs.get(name, []):
            if cat not in cats:
                cats.append(cat)
        if name in applied and INTERFACE not in cats:
            cats.insert(0, INTERFACE)
        if not cats:
            cats = [UNREFERENCED] if have_config else [UNKNOWN]
        result[name] = cats
    return result
