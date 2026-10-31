"""PAN-OS output parsers.

ntc-templates covers most of the PAN-OS command set, but not `show routing
route` or `show lldp neighbors all` -- the two that matter most for as-built
documentation, since they carry the routing table and the neighbour links with
a port name at both ends.

Both parsers are deliberately tolerant: PAN-OS output varies by version and a
column that shifts should cost one field, not the whole table.
"""
import logging
import re

logger = logging.getLogger(__name__)

_VR_HEADER = re.compile(r"^VIRTUAL ROUTER:\s*(\S+)", re.I)
_PREFIX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

# show routing route flag letters -> protocol
_ROUTE_FLAGS = [
    ("C", "connected"),
    ("H", "host"),
    ("S", "static"),
    ("R", "rip"),
    ("Oi", "ospf"),
    ("Oo", "ospf"),
    ("O1", "ospf"),
    ("O2", "ospf"),
    ("O", "ospf"),
    ("B", "bgp"),
    ("M", "multicast"),
]


def _protocol_from_flags(flags: str) -> str:
    """Map the flags column to a protocol name. A is 'active', not a protocol."""
    tokens = flags.replace(",", " ").split()
    for token in tokens:
        for letter, protocol in _ROUTE_FLAGS:
            if token == letter:
                return protocol
    # Flags can also arrive concatenated, e.g. "AS" or "AC".
    compact = "".join(tokens)
    for letter, protocol in _ROUTE_FLAGS:
        if letter in compact:
            return protocol
    return ""


def parse_routes(output: str) -> list[dict]:
    """Parse `show routing route`.

        destination      nexthop      metric flags  age  interface    next-AS
        0.0.0.0/0        10.1.1.1     10     A S         ethernet1/1
        10.1.1.0/24      0.0.0.0      0      A C         ethernet1/1
    """
    routes = []
    if not output:
        return routes

    virtual_router = ""
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        vr = _VR_HEADER.match(stripped)
        if vr:
            virtual_router = vr.group(1)
            continue

        parts = stripped.split()
        # Every route line starts with a CIDR destination; headers and the
        # flags legend never do.
        if not parts or not _PREFIX.match(parts[0]):
            continue

        network, _, prefix_length = parts[0].partition("/")
        nexthop = parts[1] if len(parts) > 1 else ""
        metric = parts[2] if len(parts) > 2 else ""

        # Flags run from column 3 until the interface name. Interfaces are the
        # only remaining token containing a letter and not purely numeric.
        interface = ""
        flag_tokens = []
        for token in parts[3:]:
            if re.match(r"^(ethernet|ae|vlan|tunnel|loopback|management)", token, re.I):
                interface = token
                break
            flag_tokens.append(token)

        routes.append({
            "network": network,
            "prefix_length": prefix_length,
            "nexthop_ip": "" if nexthop in ("0.0.0.0", "") else nexthop,
            "nexthop_if": interface,
            "interface": interface,
            "protocol": _protocol_from_flags(" ".join(flag_tokens)),
            "metric": metric,
            "vrf": virtual_router,
        })

    return routes


def parse_lldp_neighbors(output: str) -> list[dict]:
    """Parse `show lldp neighbors all`.

    PAN-OS emits either a table or per-interface blocks depending on version,
    so both shapes are handled. The port name at each end is the point of
    collecting this at all, so a row without one is dropped.
    """
    if not output:
        return []

    neighbors = _parse_lldp_blocks(output)
    if neighbors:
        return neighbors
    return _parse_lldp_table(output)


def _clean(value: str) -> str:
    value = (value or "").strip()
    # PAN-OS annotates identifiers, e.g. "00:1b:17:aa:bb:cc  (MAC address)".
    value = re.sub(r"\s*\((?:MAC address|Interface name|Locally assigned)\)\s*$",
                   "", value, flags=re.I)
    return value.strip()


def _finish(current, neighbors):
    if current.get("local_intf") and (current.get("remote_device")
                                      or current.get("remote_intf")):
        neighbors.append({
            "local_intf": current.get("local_intf", ""),
            "remote_device": current.get("remote_device", ""),
            "remote_intf": current.get("remote_intf", ""),
            "remote_ip": current.get("remote_ip", ""),
            "remote_platform": current.get("remote_platform", ""),
            "remote_chassis_id": current.get("remote_chassis_id", ""),
            "remote_capabilities": current.get("remote_capabilities", ""),
            "protocols": ["LLDP"],
        })


_BLOCK_FIELDS = {
    "port id": "remote_intf",
    "port-id": "remote_intf",
    "system name": "remote_device",
    "system-name": "remote_device",
    "chassis id": "remote_chassis_id",
    "chassis-id": "remote_chassis_id",
    "system description": "remote_platform",
    "system-description": "remote_platform",
    "management address": "remote_ip",
    "system capabilities": "remote_capabilities",
}


def _parse_lldp_blocks(output: str) -> list[dict]:
    neighbors = []
    current = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        local = re.match(r"^(?:Local\s+)?Interface\s*:\s*(\S+)", stripped, re.I)
        if local:
            _finish(current, neighbors)
            current = {"local_intf": local.group(1)}
            continue

        if not current:
            continue

        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        field = _BLOCK_FIELDS.get(key.strip().lower())
        if field:
            current[field] = _clean(value)

    _finish(current, neighbors)
    return neighbors


def _parse_lldp_table(output: str) -> list[dict]:
    neighbors = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        lowered = stripped.lower()
        if "interface" in lowered and ("port" in lowered or "chassis" in lowered):
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue
        if not re.match(r"^(ethernet|ae|vlan|tunnel|loopback|management)",
                        parts[0], re.I):
            continue

        neighbors.append({
            "local_intf": parts[0],
            "remote_chassis_id": parts[1],
            "remote_intf": parts[2],
            "remote_device": parts[3] if len(parts) > 3 else "",
            "remote_ip": "",
            "remote_platform": "",
            "remote_capabilities": "",
            "protocols": ["LLDP"],
        })
    return neighbors
