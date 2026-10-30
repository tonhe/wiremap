"""
CDP, LLDP, and L3 Routing Protocol Neighbor Parsers
Extract neighbor information from show command output
"""

import logging
import re
from typing import List, Dict, Optional

try:
    from app.identity import looks_like_mac, normalize_hostname, split_device_id
    from app.ifname import canonical_ifname
except ImportError:
    from identity import looks_like_mac, normalize_hostname, split_device_id
    from ifname import canonical_ifname

logger = logging.getLogger(__name__)


def parse_cdp_neighbors_detail(output: str) -> List[Dict[str, str]]:
    """
    Parse 'show cdp neighbors detail' output
    
    Returns list of neighbor dicts with keys:
    - remote_device: Neighbor hostname
    - remote_ip: Management IP address
    - remote_platform: Platform string
    - remote_capabilities: Device capabilities
    - local_intf: Local interface
    - remote_intf: Remote interface
    """
    neighbors = []
    current = {}
    in_mgmt = False

    for line in output.splitlines():
        line_stripped = line.strip()

        # New neighbor entry
        if line_stripped.startswith("Device ID:"):
            if current:
                neighbors.append(current)
                current = {}
            in_mgmt = False
            device_id = line_stripped.split("Device ID:")[1].strip()
            # NX-OS and MDS report NAME(SERIAL); keep the serial apart so the
            # name matches the device's own prompt.
            device_id, serial = split_device_id(device_id)
            # Sometimes includes domain, strip it
            current["remote_device"] = device_id.split('.')[0]
            if serial:
                current["remote_serial"] = serial

        # IOS lists "Management address(es):", NX-OS "Mgmt address(es):".
        elif line_stripped.lower().startswith(("management address",
                                               "mgmt address")):
            in_mgmt = True
        elif line_stripped.lower().startswith(("entry address", "interface",
                                               "platform:")):
            in_mgmt = False

        # IP address (multiple formats: "IP address:", "IPv4 Address:", etc.)
        if "IP address:" in line_stripped or "IPv4 Address:" in line_stripped:
            # Handle both "IP address: X.X.X.X" and "IPv4 Address: X.X.X.X"
            if "IPv4 Address:" in line_stripped:
                ip = line_stripped.split("IPv4 Address:")[1].strip()
            else:
                ip = line_stripped.split("IP address:")[1].strip()

            if ip and not ip.startswith("("):  # Skip "(not available)" or similar
                current["remote_ip"] = ip
                if in_mgmt:
                    current.setdefault("remote_mgmt_ip", ip)
        
        # Platform and capabilities
        elif line_stripped.startswith("Platform:"):
            parts = line_stripped.split(",")
            platform = parts[0].split("Platform:")[1].strip()
            current["remote_platform"] = platform
            
            # Capabilities might be on same line
            for part in parts:
                if "Capabilities:" in part:
                    caps = part.split("Capabilities:")[1].strip()
                    current["remote_capabilities"] = caps
        
        # Interface mapping
        elif line_stripped.startswith("Interface:"):
            # Format: "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet0/1"
            parts = line_stripped.split(",")
            local_intf = parts[0].split("Interface:")[1].strip()
            current["local_intf"] = local_intf
            
            if len(parts) > 1 and "Port ID" in parts[1]:
                remote_intf = parts[1].split(":")[-1].strip()
                current["remote_intf"] = remote_intf
    
    # Don't forget the last neighbor
    if current:
        neighbors.append(current)
    
    # Log what we extracted
    logger.info(f"Parsed {len(neighbors)} CDP neighbors")
    for i, n in enumerate(neighbors):
        logger.debug(f"  CDP Neighbor {i+1}: {n.get('remote_device', '?')} - IP: {n.get('remote_ip', 'MISSING')} - Platform: {n.get('remote_platform', '?')}")
    
    return neighbors


# Every field label `show lldp neighbors detail` prints on IOS, IOS-XE and
# NX-OS. System Description is free text spanning several lines, so it can
# only be ended by recognising the start of the next field.
_LLDP_FIELD_LABELS = (
    "Local Intf", "Local Port id", "Chassis id", "Port id",
    "Port Description", "System Name", "System Description",
    "Time remaining", "System Capabilities", "Enabled Capabilities",
    "Management Address", "Auto Negotiation", "Physical media",
    "Media Attachment Unit", "Vlan ID", "Peer Source MAC", "Total entries",
    "MED Information", "Unknown TLV", "Capability codes",
)

_LLDP_SEPARATOR = re.compile(r"^-{5,}$")
_LLDP_MGMT_IP = re.compile(r"^IP(?:v4)?:\s*(\S+)", re.I)

# Model strings found in LLDP system descriptions. LLDP has no platform TLV,
# so this is the only place a model can come from when the chassis id is a MAC.
_LLDP_MODEL_PATTERNS = (
    re.compile(r"running on an? Arista(?: Networks)? (\S+)", re.I),
    re.compile(r"Cisco IOS Software(?: \[[^\]]*\])?, ([A-Za-z]*\d[\w-]*) Software"),
    re.compile(r"\b(?i:cisco) ((?:WS-|AIR-|IE-)?[A-Za-z]+\d[\w-]*)"),
    re.compile(r"Juniper Networks, Inc\. (\S+)"),
    re.compile(r"Palo Alto Networks (PA-\S+)"),
)


def _lldp_label(line):
    for label in _LLDP_FIELD_LABELS:
        if line.startswith(label):
            return label
    return None


def _lldp_value(line):
    return line.split(":", 1)[1].strip() if ":" in line else ""


def _split_lldp_records(output):
    """Split detail output into one list of lines per neighbour.

    The ---- separator is authoritative where present. Within a chunk a
    second Chassis id or Local Intf still starts a new record, so output
    without separators (NX-OS) splits correctly too.
    """
    records = []
    current = []
    has_chassis = False
    for raw in output.splitlines():
        line = raw.strip()
        if _LLDP_SEPARATOR.match(line):
            if current:
                records.append(current)
            current, has_chassis = [], False
            continue
        starts_record = (
            line.startswith("Chassis id:")
            or (line.startswith("Local Intf:") and not
                line.startswith("Local Intf service"))
        )
        if starts_record and has_chassis:
            records.append(current)
            current, has_chassis = [], False
        if line.startswith("Chassis id:"):
            has_chassis = True
        current.append(line)
    if current:
        records.append(current)
    return records


def _platform_from_lldp_description(description):
    if not description:
        return ""
    for pattern in _LLDP_MODEL_PATTERNS:
        match = pattern.search(description)
        if match:
            model = match.group(1).rstrip(",;")
            if model and not looks_like_mac(model):
                return model
    return ""


def _parse_lldp_record(lines):
    fields = {}
    description = None
    in_description = False
    in_mgmt = False

    for line in lines:
        label = _lldp_label(line)
        if label:
            in_description = False
            in_mgmt = False
        elif in_description:
            if line:
                description.append(line)
            continue
        elif in_mgmt:
            match = _LLDP_MGMT_IP.match(line)
            if match and "remote_ip" not in fields:
                fields["remote_ip"] = match.group(1)
            continue
        else:
            continue

        value = _lldp_value(line)
        if label == "Local Intf":
            # IOS-XE 17.15 adds "Local Intf service instance: -", which is
            # not an interface.
            if line.startswith("Local Intf:") and value:
                fields["local_intf"] = value
        elif label == "Local Port id":
            if value:
                fields.setdefault("local_intf", value)
        elif label == "Chassis id":
            fields["chassis_id"] = value
        elif label == "Port id":
            fields["remote_intf"] = value
        elif label == "System Name":
            name, serial = split_device_id(value)
            # Strip domain if present
            fields["remote_device"] = name.split('.')[0] if name else name
            if serial:
                fields["remote_serial"] = serial
        elif label == "System Description":
            description = [value] if value else []
            in_description = True
        elif label == "System Capabilities":
            fields["remote_capabilities"] = value
        elif label == "Management Address":
            if line.startswith(("Management Addresses:", "Management Address:")):
                in_mgmt = True
                # NX-OS puts the address on the same line.
                if _is_ip(value) and "remote_ip" not in fields:
                    fields["remote_ip"] = value

    if description is not None:
        fields["system_description"] = " ".join(description)
    # LLDP only ever carries a management address, never a link address.
    if fields.get("remote_ip"):
        fields["remote_mgmt_ip"] = fields["remote_ip"]
    return fields


def parse_lldp_neighbors_detail(output: str) -> List[Dict[str, str]]:
    """
    Parse 'show lldp neighbors detail' output

    Returns list of neighbor dicts with keys:
    - remote_device: Neighbor hostname
    - remote_ip: Management IP address
    - remote_platform: Model taken from the system description, or ""
    - chassis_id: LLDP chassis id (usually a MAC)
    - remote_capabilities: System capabilities
    - local_intf: Local interface
    - remote_intf: Remote interface
    - system_description: System description string
    """
    neighbors = []
    for record in _split_lldp_records(output or ""):
        fields = _parse_lldp_record(record)
        if not any(fields.get(k) for k in ("chassis_id", "remote_device",
                                           "remote_intf")):
            continue
        fields["remote_platform"] = _platform_from_lldp_description(
            fields.get("system_description"))
        neighbors.append(fields)

    # Log what we extracted
    logger.info(f"Parsed {len(neighbors)} LLDP neighbors")
    for i, n in enumerate(neighbors):
        logger.debug(f"  LLDP Neighbor {i+1}: {n.get('remote_device', '?')} - IP: {n.get('remote_ip', 'MISSING')}")

    return neighbors


def parse_ospf_neighbors(output: str) -> List[Dict]:
    """
    Parse 'show ip ospf neighbor' / 'show ip ospf neighbors' output.
    Handles Cisco IOS, IOS-XE, NX-OS tabular format.

    Returns list of neighbor dicts (only FULL state neighbors).
    """
    neighbors = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('Neighbor') or line.startswith('OSPF') or line.startswith('Total'):
            continue
        # Tabular line: neighbor-id  pri  state  dead-time  address  interface
        # Point-to-point neighbours print as "FULL/  -"; rejoin the state so
        # the columns line up.
        line = re.sub(r'/\s+-(?=\s)', '/-', line)
        parts = line.split()
        if len(parts) < 6:
            continue
        # parts[0] = neighbor ID (router ID), parts[2] = state, parts[4] = address, parts[5] = interface
        state = parts[2].upper()
        if 'FULL' not in state and 'UP' not in state:
            continue
        neighbor_id = parts[0]
        address = parts[4]
        interface = parts[5]
        # Validate that address looks like an IP
        if not _is_ip(address):
            continue
        neighbors.append({
            'remote_ip': address,
            'remote_device': None,
            'local_intf': interface,
            'remote_intf': None,
            'remote_platform': None,
            'remote_capabilities': 'Router',
            'system_description': None,
            'protocol': 'OSPF',
            'state': state,
        })
        logger.debug(f"OSPF neighbor: {neighbor_id} via {address} on {interface}")
    logger.info(f"Parsed {len(neighbors)} OSPF neighbors")
    return neighbors


def parse_eigrp_neighbors(output: str) -> List[Dict]:
    """
    Parse 'show ip eigrp neighbors' output (Cisco IOS/IOS-XE/NX-OS).

    Returns list of neighbor dicts.
    """
    neighbors = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('H ') or line.startswith('EIGRP') or line.startswith('IP-EIGRP'):
            continue
        # Tabular line: H  address  interface  hold  uptime  srtt  rto  q  seq
        parts = line.split()
        if len(parts) < 3:
            continue
        # First column is H (index), second is address, third is interface
        try:
            int(parts[0])  # H column is a number
        except ValueError:
            continue
        address = parts[1]
        interface = parts[2]
        if not _is_ip(address):
            continue
        neighbors.append({
            'remote_ip': address,
            'remote_device': None,
            'local_intf': interface,
            'remote_intf': None,
            'remote_platform': None,
            'remote_capabilities': 'Router',
            'system_description': None,
            'protocol': 'EIGRP',
            'state': 'UP',
        })
        logger.debug(f"EIGRP neighbor: {address} on {interface}")
    logger.info(f"Parsed {len(neighbors)} EIGRP neighbors")
    return neighbors


def parse_bgp_neighbors(output: str) -> List[Dict]:
    """
    Parse 'show ip bgp neighbors' / 'show bgp ipv4 unicast neighbors' output.
    Handles Cisco IOS, IOS-XE, NX-OS, Arista multi-paragraph format.

    Returns list of neighbor dicts (only Established state).
    """
    neighbors = []
    current_ip = None
    current_state = None
    current_local_host = None

    for line in output.splitlines():
        line_stripped = line.strip()

        # "BGP neighbor is X.X.X.X"
        if line_stripped.startswith('BGP neighbor is '):
            # Save previous if established
            if current_ip and current_state and 'ESTABLISHED' in current_state.upper():
                neighbors.append({
                    'remote_ip': current_ip,
                    'remote_device': None,
                    'local_intf': current_local_host,
                    'remote_intf': None,
                    'remote_platform': None,
                    'remote_capabilities': 'Router',
                    'system_description': None,
                    'protocol': 'BGP',
                    'state': current_state,
                })
            current_ip = line_stripped.split('BGP neighbor is ')[1].split(',')[0].strip()
            current_state = None
            current_local_host = None

        elif line_stripped.startswith('BGP state =') or 'BGP state=' in line_stripped:
            state_part = line_stripped.replace('BGP state=', 'BGP state = ')
            current_state = state_part.split('BGP state =')[1].split(',')[0].strip()

        # "Local host: X.X.X.X, Local port: NNNNN"
        elif line_stripped.startswith('Local host:'):
            local_host = line_stripped.split('Local host:')[1].split(',')[0].strip()
            if _is_ip(local_host):
                current_local_host = local_host

    # Last neighbor
    if current_ip and current_state and 'ESTABLISHED' in current_state.upper():
        neighbors.append({
            'remote_ip': current_ip,
            'remote_device': None,
            'local_intf': current_local_host,
            'remote_intf': None,
            'remote_platform': None,
            'remote_capabilities': 'Router',
            'system_description': None,
            'protocol': 'BGP',
            'state': current_state,
        })

    logger.info(f"Parsed {len(neighbors)} BGP neighbors")
    return neighbors


def parse_isis_neighbors(output: str) -> List[Dict]:
    """
    Parse 'show isis neighbors' / 'show isis adjacency' output.
    Handles Cisco IOS tabular format.

    Returns list of neighbor dicts (only UP state).
    """
    neighbors = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('System') or line.startswith('IS-IS') or line.startswith('Tag'):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        # IOS: system-id  interface  snpa  state  holdtime  type  protocol
        # Check that state field (index 3) is UP
        state = parts[3].upper() if len(parts) > 3 else ''
        if 'UP' not in state:
            continue
        system_id = parts[0]
        interface = parts[1] if len(parts) > 1 else None
        neighbors.append({
            'remote_ip': None,           # IS-IS uses system IDs, not IPs
            'remote_device': system_id,  # Use system ID as device identifier
            'local_intf': interface,
            'remote_intf': None,
            'remote_platform': None,
            'remote_capabilities': 'Router',
            'system_description': None,
            'protocol': 'IS-IS',
            'state': state,
        })
        logger.debug(f"IS-IS neighbor: {system_id} on {interface}")
    logger.info(f"Parsed {len(neighbors)} IS-IS neighbors")
    return neighbors


def parse_l3_neighbors(output: str, protocol: str) -> List[Dict]:
    """Dispatch to the correct L3 parser based on protocol name."""
    protocol = protocol.lower()
    if protocol == 'ospf':
        return parse_ospf_neighbors(output)
    elif protocol == 'eigrp':
        return parse_eigrp_neighbors(output)
    elif protocol == 'bgp':
        return parse_bgp_neighbors(output)
    elif protocol == 'isis':
        return parse_isis_neighbors(output)
    return []


_NX_FLAGS = frozenset(('*', '+', '#', 'CP', 'PS', 'RO', 'D'))


def parse_arp_table(output: str) -> List[Dict]:
    """
    Parse ARP table output into a list of host entries.

    Handles:
    - Cisco IOS/XE/Arista: 'show ip arp'
      Internet  10.1.1.100  15  0050.56aa.bb01  ARPA  GigabitEthernet0/1
    - Cisco NX-OS: 'show ip arp'
      10.1.1.100  00:00:15  0050.56aa.bb01  Ethernet1/1
      * 10.1.1.101  00:00:20  0050.56aa.bb02  Ethernet1/1  (flagged entry)
    - Juniper JunOS: 'show arp'
      00:50:56:aa:bb:cc  10.1.1.100  10.1.1.100  ge-0/0/1.0  none

    Returns list of dicts with keys: ip, mac, interface, age
    """
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip header/summary lines
        if line.startswith(('Protocol', 'MAC', 'Destination', 'Address',
                             'IP', 'Total', 'ARP', 'Flags')):
            continue

        parts = line.split()

        # Cisco IOS/XE/Arista tabular format:
        # Internet  <ip>  <age>  <mac>  ARPA  <interface>
        # An unresolved entry has no MAC and usually no interface:
        # Internet  <ip>  0  Incomplete  ARPA
        if len(parts) >= 4 and parts[0] == 'Internet':
            ip = parts[1]
            age = parts[2] if parts[2] != '-' else '0'
            mac_raw = parts[3]
            interface = parts[5] if len(parts) > 5 else ''
            if _is_ip(ip):
                entries.append(_arp_entry(ip, mac_raw, age, interface))
            continue

        # Juniper format: <mac>  <ip>  <name>  <interface>  <flags>
        if len(parts) >= 4 and ':' in parts[0] and _is_ip(parts[1]):
            entries.append({
                'ip': parts[1],
                'mac': parts[0],
                'age': '?',
                'interface': parts[3],
            })
            continue

        # NX-OS format: [optional_flag]  <ip>  <age>  <mac>  <interface>
        # Flags: * + # CP PS RO D  (see 'show ip arp' legend)
        idx = 1 if parts[0] in _NX_FLAGS else 0
        if len(parts) >= idx + 3 and _is_ip(parts[idx]):
            ip = parts[idx]
            age = parts[idx + 1]
            mac_raw = parts[idx + 2]
            interface = parts[idx + 3] if len(parts) > idx + 3 else ''
            entries.append(_arp_entry(ip, mac_raw, age, interface))

    logger.info(f"Parsed {len(entries)} ARP entries")
    return entries


def _arp_entry(ip, mac_raw, age, interface):
    # "Incomplete" is ARP state, not a MAC. Left in the mac field it gets
    # joined against MAC tables and printed as an address.
    if mac_raw.lower() == 'incomplete':
        return {'ip': ip, 'mac': '', 'age': age, 'interface': interface,
                'incomplete': True}
    return {'ip': ip, 'mac': _normalize_mac(mac_raw), 'age': age,
            'interface': interface, 'incomplete': False}


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to xx:xx:xx:xx:xx:xx. Handles Cisco dotted notation."""
    if '.' in mac:
        raw = mac.replace('.', '')
        if len(raw) == 12:
            return ':'.join(raw[i:i+2] for i in range(0, 12, 2))
    return mac


def _is_ip(s: str) -> bool:
    """Return True if s looks like an IPv4 address."""
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def merge_neighbor_info(cdp_neighbors: List[Dict], lldp_neighbors: List[Dict],
                        l3_neighbors: Optional[List[Dict]] = None) -> List[Dict]:
    """
    Merge CDP, LLDP, and optional L3 routing protocol neighbor information.
    Prioritize CDP for platform info, but use LLDP if CDP is missing.
    L3 neighbors are deduplicated against L2 entries by IP address.

    One record per link, not per neighbour: two cables to the same switch are
    two records. A CDP and an LLDP sighting of the same link become one record
    with protocols ["CDP", "LLDP"].

    Returns: Deduplicated list of neighbors with best available info
    """
    merged = {}

    def add_protocol(entry, protocol):
        entry['protocols'] = sorted(set(entry.get('protocols', [])) | {protocol})

    # Process CDP neighbors first (usually more detailed platform info)
    for neighbor in cdp_neighbors:
        key = neighbor_link_key(neighbor)
        if not key[1]:
            continue
        if key in merged:
            add_protocol(merged[key], 'CDP')
            continue
        entry = dict(neighbor)
        entry['protocols'] = ['CDP']
        merged[key] = entry

    # Add or merge LLDP neighbors
    for neighbor in lldp_neighbors:
        key = neighbor_link_key(neighbor)
        if not key[1]:
            continue

        existing = merged.get(key)
        if existing is None:
            # LLDP port ids are not always interface names (some peers send a
            # port description). Same local port to the same neighbour is
            # still the same link, so attach to a CDP record there.
            for other_key, entry in merged.items():
                if (other_key[:2] == key[:2]
                        and entry.get('protocols') == ['CDP']):
                    existing = entry
                    break

        if existing is not None:
            for field in ('remote_ip', 'remote_intf', 'local_intf',
                          'remote_platform', 'remote_capabilities',
                          'chassis_id'):
                if not existing.get(field) and neighbor.get(field):
                    existing[field] = neighbor[field]
            if neighbor.get('system_description'):
                existing['system_description'] = neighbor['system_description']
            add_protocol(existing, 'LLDP')
        else:
            entry = dict(neighbor)
            entry['protocols'] = ['LLDP']
            merged[key] = entry

    # Merge L3 neighbors
    if l3_neighbors:
        for neighbor in l3_neighbors:
            protocol = neighbor.get('protocol', 'L3')
            neighbor_ip = neighbor.get('remote_ip')
            neighbor_device = neighbor.get('remote_device')

            # Match against an existing entry by IP, preferring the link the
            # adjacency actually runs over when there are parallel links.
            candidates = [e for e in merged.values()
                          if neighbor_ip and e.get('remote_ip') == neighbor_ip]
            local = canonical_ifname(neighbor.get('local_intf'))
            matched = next((e for e in candidates
                            if local and canonical_ifname(e.get('local_intf')) == local),
                           candidates[0] if candidates else None)

            if matched is not None:
                add_protocol(matched, protocol)
                logger.debug(f"L3 {protocol} neighbor {neighbor_ip} merged with existing entry")
            else:
                # L3-only neighbor — add as new entry
                if not (neighbor_ip or neighbor_device):
                    continue
                entry = dict(neighbor)
                entry['protocols'] = [protocol]
                merged[('l3', neighbor_ip or neighbor_device, protocol)] = entry
                logger.debug(f"L3-only {protocol} neighbor added: {neighbor_ip or neighbor_device}")

    result = list(merged.values())
    logger.info(f"Merged to {len(result)} unique neighbors")
    return result


def neighbor_link_key(neighbor):
    """Identity of one link: (local port, neighbour, neighbour port).

    Interface names are canonicalised so CDP's GigabitEthernet1/0/1 and
    LLDP's Gi1/0/1 agree; the neighbour name drops domain and NX-OS serial
    suffix for the same reason.
    """
    remote = normalize_hostname(neighbor.get('remote_device')) \
        or (neighbor.get('remote_ip') or '')
    return (canonical_ifname(neighbor.get('local_intf')), remote,
            canonical_ifname(neighbor.get('remote_intf')))
