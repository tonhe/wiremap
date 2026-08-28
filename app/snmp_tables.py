"""Standard-MIB table collection over SNMP.

For devices that never accept a CLI session -- Fireware ships with SSH
disabled, and unreachable APs are common -- SNMP is the only way to learn
anything. These are the IETF standard MIBs, so one implementation covers every
platform wiremap lists rather than needing a command set per vendor. That is
the whole point of SNMP, and it is why this module has no notion of device
type.

Output is shaped to match what the CLI collectors already produce, so every
existing report consumes SNMP-derived data without knowing where it came from.
"""
import logging

logger = logging.getLogger(__name__)

# IF-MIB
IF_COLUMNS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
}
IFX_COLUMNS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
}

# IP-MIB, ipAddrTable. Deprecated in favour of ipAddressTable but far more
# widely populated, and the addressing is the piece usually missing.
IP_ADDR_COLUMNS = {
    "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1",
    "ipAdEntIfIndex": "1.3.6.1.2.1.4.20.1.2",
    "ipAdEntNetMask": "1.3.6.1.2.1.4.20.1.3",
}

# IP-FORWARD-MIB, ipCidrRouteTable
ROUTE_COLUMNS = {
    "ipCidrRouteDest": "1.3.6.1.2.1.4.24.4.1.1",
    "ipCidrRouteMask": "1.3.6.1.2.1.4.24.4.1.2",
    "ipCidrRouteNextHop": "1.3.6.1.2.1.4.24.4.1.4",
    "ipCidrRouteIfIndex": "1.3.6.1.2.1.4.24.4.1.5",
    "ipCidrRouteType": "1.3.6.1.2.1.4.24.4.1.6",
    "ipCidrRouteProto": "1.3.6.1.2.1.4.24.4.1.7",
    "ipCidrRouteMetric1": "1.3.6.1.2.1.4.24.4.1.11",
}

# LLDP-MIB, lldpRemTable. Index is timeMark.localPortNum.remIndex, so the
# local port is recoverable from the index itself.
LLDP_COLUMNS = {
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
}
LLDP_LOC_PORT = {
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
    "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
}

# CISCO-CDP-MIB, cdpCacheTable. Index is ifIndex.deviceIndex.
CDP_COLUMNS = {
    "cdpCacheAddress": "1.3.6.1.4.1.9.9.23.1.2.1.1.4",
    "cdpCacheVersion": "1.3.6.1.4.1.9.9.23.1.2.1.1.5",
    "cdpCacheDeviceId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "cdpCacheDevicePort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
    "cdpCachePlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
}

# ARP: IP-MIB ipNetToMediaTable, indexed ifIndex.ipAddress
ARP_COLUMNS = {
    "ipNetToMediaPhysAddress": "1.3.6.1.2.1.4.22.1.2",
    "ipNetToMediaNetAddress": "1.3.6.1.2.1.4.22.1.3",
    "ipNetToMediaType": "1.3.6.1.2.1.4.22.1.4",
}

_IF_STATUS = {"1": "up", "2": "down", "3": "testing"}
_OPER_STATUS = {
    "1": "up", "2": "down", "3": "testing",
    "4": "unknown", "5": "dormant", "6": "notPresent",
    "7": "lowerLayerDown",
}
_ROUTE_PROTO = {
    "1": "other", "2": "local", "3": "netmgmt", "4": "icmp", "5": "egp",
    "6": "ggp", "7": "hello", "8": "rip", "9": "is-is", "10": "es-is",
    "11": "ciscoIgrp", "12": "bbnSpfIgp", "13": "ospf", "14": "bgp",
    "15": "idpr", "16": "ciscoEigrp",
}
# Physical and virtual interface types worth reporting. Everything else is
# internal plumbing that would bury the real ports.
_SKIP_IF_TYPES = {"24", "1"}  # softwareLoopback, other


def index_of(oid: str, column_oid: str) -> str:
    """Return the table index portion of a full OID."""
    prefix = column_oid.rstrip(".") + "."
    if oid.startswith(prefix):
        return oid[len(prefix):]
    return ""


def build_rows(walked: dict, columns: dict) -> dict:
    """Turn walked {oid: value} into {index: {column_name: value}}."""
    rows = {}
    for name, column_oid in columns.items():
        for oid, value in walked.items():
            idx = index_of(oid, column_oid)
            if not idx:
                continue
            rows.setdefault(idx, {})[name] = value
    return rows


def _walk_columns(walk, columns: dict) -> dict:
    """Walk every column in a table and collate by index."""
    walked = {}
    for column_oid in columns.values():
        try:
            walked.update(walk(column_oid) or {})
        except Exception as e:
            logger.debug(f"SNMP walk of {column_oid} failed: {type(e).__name__}: {e}")
    return build_rows(walked, columns)


def _speed(row) -> str:
    """Prefer ifHighSpeed (Mbps); ifSpeed saturates at 4.29 Gbps."""
    high = row.get("ifHighSpeed")
    if high and high not in ("0", ""):
        return f"{high} Mbps"
    raw = row.get("ifSpeed")
    if raw and raw.isdigit() and int(raw) > 0:
        return f"{int(raw) // 1_000_000} Mbps"
    return ""


def collect_interfaces(walk) -> list[dict]:
    """IF-MIB ifTable and ifXTable, shaped like the CLI interfaces collector."""
    rows = _walk_columns(walk, {**IF_COLUMNS, **IFX_COLUMNS})
    interfaces = []
    for index in sorted(rows, key=lambda i: int(i) if i.isdigit() else 0):
        row = rows[index]
        if row.get("ifType") in _SKIP_IF_TYPES:
            continue
        name = row.get("ifName") or row.get("ifDescr") or ""
        if not name:
            continue
        interfaces.append({
            "port": name,
            "interface": name,
            "name": row.get("ifAlias", ""),
            "description": row.get("ifAlias", ""),
            "status": _OPER_STATUS.get(row.get("ifOperStatus", ""), ""),
            "admin_status": _IF_STATUS.get(row.get("ifAdminStatus", ""), ""),
            "speed": _speed(row),
            "type": row.get("ifType", ""),
            "mac_address": row.get("ifPhysAddress", ""),
            "vlan": "",
            "duplex": "",
            "if_index": index,
        })
    return interfaces


def collect_ip_addresses(walk, if_names=None) -> list[dict]:
    """IP-MIB ipAddrTable, shaped like the CLI ip_interfaces output."""
    rows = _walk_columns(walk, IP_ADDR_COLUMNS)
    if_names = if_names or {}
    addresses = []
    for row in rows.values():
        addr = row.get("ipAdEntAddr")
        if not addr:
            continue
        if_index = row.get("ipAdEntIfIndex", "")
        addresses.append({
            "intf": if_names.get(if_index, if_index),
            "interface": if_names.get(if_index, if_index),
            "ipaddr": addr,
            "ip_address": addr,
            "mask": row.get("ipAdEntNetMask", ""),
            "prefix_length": _mask_to_prefix(row.get("ipAdEntNetMask", "")),
            "status": "up",
            "proto": "up",
        })
    return addresses


def _mask_to_prefix(mask: str) -> str:
    if not mask or mask.count(".") != 3:
        return ""
    try:
        return str(sum(bin(int(o)).count("1") for o in mask.split(".")))
    except ValueError:
        return ""


def collect_routes(walk, if_names=None) -> list[dict]:
    """IP-FORWARD-MIB ipCidrRouteTable, shaped like the CLI routes output."""
    rows = _walk_columns(walk, ROUTE_COLUMNS)
    if_names = if_names or {}
    routes = []
    for row in rows.values():
        dest = row.get("ipCidrRouteDest")
        if not dest:
            continue
        if_index = row.get("ipCidrRouteIfIndex", "")
        nexthop = row.get("ipCidrRouteNextHop", "")
        routes.append({
            "network": dest,
            "mask": row.get("ipCidrRouteMask", ""),
            "prefix_length": _mask_to_prefix(row.get("ipCidrRouteMask", "")),
            "nexthop_ip": "" if nexthop in ("0.0.0.0", "") else nexthop,
            "next_hop": "" if nexthop in ("0.0.0.0", "") else nexthop,
            "nexthop_if": if_names.get(if_index, if_index),
            "interface": if_names.get(if_index, if_index),
            "protocol": _ROUTE_PROTO.get(row.get("ipCidrRouteProto", ""), ""),
            "metric": row.get("ipCidrRouteMetric1", ""),
        })
    return routes


def collect_arp(walk, if_names=None) -> list[dict]:
    """IP-MIB ipNetToMediaTable, shaped like the CLI arp collector."""
    rows = _walk_columns(walk, ARP_COLUMNS)
    if_names = if_names or {}
    entries = []
    for index, row in rows.items():
        ip = row.get("ipNetToMediaNetAddress")
        if not ip:
            # The address is also the tail of the index: ifIndex.a.b.c.d
            parts = index.split(".")
            if len(parts) == 5:
                ip = ".".join(parts[1:])
        if not ip:
            continue
        if_index = index.split(".")[0]
        entries.append({
            "ip": ip,
            "ip_address": ip,
            "mac": row.get("ipNetToMediaPhysAddress", ""),
            "mac_address": row.get("ipNetToMediaPhysAddress", ""),
            "interface": if_names.get(if_index, if_index),
            "age": "",
        })
    return entries


def collect_lldp_neighbors(walk, if_names=None) -> list[dict]:
    """LLDP-MIB lldpRemTable, shaped like the CLI cdp_lldp collector.

    The local port is the second component of the row index, which is what
    makes a port name available at both ends of the link.
    """
    rows = _walk_columns(walk, LLDP_COLUMNS)
    local_ports = _walk_columns(walk, LLDP_LOC_PORT)
    if_names = if_names or {}

    neighbors = []
    for index, row in rows.items():
        parts = index.split(".")
        local_num = parts[1] if len(parts) >= 2 else ""
        local_row = local_ports.get(local_num, {})
        local_name = (local_row.get("lldpLocPortDesc")
                      or local_row.get("lldpLocPortId")
                      or if_names.get(local_num, local_num))

        remote_port = row.get("lldpRemPortDesc") or row.get("lldpRemPortId") or ""
        neighbors.append({
            "local_intf": local_name,
            "remote_device": row.get("lldpRemSysName", ""),
            "remote_intf": remote_port,
            "remote_platform": row.get("lldpRemSysDesc", ""),
            "remote_chassis_id": row.get("lldpRemChassisId", ""),
            "remote_ip": "",
            "remote_capabilities": "",
            "protocols": ["LLDP"],
            "source": "snmp",
        })
    return neighbors


def collect_cdp_neighbors(walk, if_names=None) -> list[dict]:
    """CISCO-CDP-MIB cdpCacheTable. Index is ifIndex.deviceIndex."""
    rows = _walk_columns(walk, CDP_COLUMNS)
    if_names = if_names or {}

    neighbors = []
    for index, row in rows.items():
        if_index = index.split(".")[0]
        device_id = row.get("cdpCacheDeviceId", "")
        if not device_id:
            continue
        neighbors.append({
            "local_intf": if_names.get(if_index, if_index),
            "remote_device": device_id,
            "remote_intf": row.get("cdpCacheDevicePort", ""),
            "remote_platform": row.get("cdpCachePlatform", ""),
            "remote_ip": _hex_to_ip(row.get("cdpCacheAddress", "")),
            "remote_capabilities": "",
            "protocols": ["CDP"],
            "source": "snmp",
        })
    return neighbors


def _hex_to_ip(value: str) -> str:
    """cdpCacheAddress is an octet string, often rendered as hex."""
    if not value:
        return ""
    text = value.strip()
    if text.count(".") == 3:
        return text
    cleaned = text.replace("0x", "").replace(":", "").replace(" ", "")
    if len(cleaned) == 8:
        try:
            return ".".join(str(int(cleaned[i:i + 2], 16)) for i in (0, 2, 4, 6))
        except ValueError:
            return ""
    return ""


def collect_all(walk) -> dict:
    """Collect every standard table, shaped as collector_data entries.

    The keys match the CLI collectors, so reports consume SNMP-derived data
    without knowing its origin.
    """
    interfaces = collect_interfaces(walk)
    if_names = {i["if_index"]: i["port"] for i in interfaces if i.get("if_index")}

    ip_addresses = collect_ip_addresses(walk, if_names)
    routes = collect_routes(walk, if_names)
    arp_entries = collect_arp(walk, if_names)
    neighbors = collect_lldp_neighbors(walk, if_names)
    if not neighbors:
        neighbors = collect_cdp_neighbors(walk, if_names)

    collected = {}
    if interfaces or ip_addresses:
        collected["interfaces"] = {
            "interfaces_status": interfaces,
            "interfaces_description": [],
            "ip_interfaces": ip_addresses,
            "ip_interfaces_full": [],
            "etherchannel": [],
            "collected_via": "snmp",
        }
    if routes:
        collected["l3_routing"] = {
            "routes": routes,
            "neighbors": [],
            "ip_protocols_raw": "",
            "collected_via": "snmp",
        }
    if arp_entries:
        collected["arp"] = {"entries": arp_entries, "collected_via": "snmp"}
    if neighbors:
        collected["cdp_lldp"] = {"neighbors": neighbors, "collected_via": "snmp"}

    return collected
