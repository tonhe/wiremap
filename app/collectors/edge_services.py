"""
Edge services collector.
Gathers ACL and IP interface data (applied ACLs, proxy-arp, uRPF,
directed-broadcast) from network devices.
"""
import re

from .base import BaseCollector

_COMMANDS = {
    "cisco_ios": ["show access-lists", "show ip interface"],
    "cisco_xe": ["show access-lists", "show ip interface"],
    "cisco_nxos": ["show access-lists", "show ip interface"],
}
_DEFAULT_COMMANDS = ["show access-lists", "show ip interface"]


def _parse_access_lists(output: str) -> list[dict]:
    """Parse 'show access-lists' output into structured ACL data."""
    acls = []
    current_acl = None

    for line in output.splitlines():
        # Match ACL header: "Extended IP access list NAME" or "Standard IP access list NAME"
        header = re.match(
            r"^(Extended|Standard)\s+IP\s+access\s+list\s+(\S+)", line
        )
        if header:
            current_acl = {
                "name": header.group(2),
                "type": header.group(1),
                "entries": [],
            }
            acls.append(current_acl)
            continue

        if current_acl is None:
            continue

        stripped = line.strip()
        if not stripped:
            continue

        if current_acl["type"] == "Extended":
            # Extended: "10 permit tcp any host 10.0.0.1 eq 443 (1234 matches)"
            m = re.match(
                r"(\d+)\s+(permit|deny)\s+(\S+)\s+(.*?)(?:\s+\((\d+)\s+match(?:es)?\))?$",
                stripped,
            )
            if m:
                seq, action, protocol, remainder, hits = m.groups()
                # Split remainder into source and destination
                # For extended ACLs the remainder has source then destination tokens
                parts = remainder.split()
                src_parts = []
                dst_parts = []
                in_dst = False
                i = 0
                while i < len(parts):
                    token = parts[i]
                    if not in_dst:
                        src_parts.append(token)
                        # "any" or "host x.x.x.x" or "x.x.x.x wildcard" completes source
                        if token == "any":
                            in_dst = True
                        elif token == "host":
                            if i + 1 < len(parts):
                                src_parts.append(parts[i + 1])
                                i += 1
                            in_dst = True
                        elif re.match(r"\d+\.\d+\.\d+\.\d+", token):
                            # Next token could be wildcard or it could be destination
                            if i + 1 < len(parts) and re.match(
                                r"\d+\.\d+\.\d+\.\d+", parts[i + 1]
                            ):
                                src_parts.append(parts[i + 1])
                                i += 1
                            in_dst = True
                    else:
                        dst_parts.append(token)
                    i += 1

                current_acl["entries"].append({
                    "action": action,
                    "protocol": protocol,
                    "source": " ".join(src_parts),
                    "destination": " ".join(dst_parts),
                    "hit_count": int(hits) if hits else 0,
                })
        else:
            # Standard: "10 permit 10.0.0.0, wildcard bits 0.0.0.255 (100 matches)"
            m = re.match(
                r"(\d+)\s+(permit|deny)\s+(.*?)(?:\s+\((\d+)\s+match(?:es)?\))?$",
                stripped,
            )
            if m:
                seq, action, source_raw, hits = m.groups()
                # Clean up source: "10.0.0.0, wildcard bits 0.0.0.255"
                source = source_raw.strip()
                current_acl["entries"].append({
                    "action": action,
                    "protocol": "ip",
                    "source": source,
                    "destination": "",
                    "hit_count": int(hits) if hits else 0,
                })

    return acls


def _parse_ip_interfaces(output: str) -> list[dict]:
    """Parse 'show ip interface' output into per-interface records."""
    interfaces = []
    current = None

    for line in output.splitlines():
        # Interface header line (not indented)
        iface_match = re.match(r"^(\S+)\s+is\s+", line)
        if iface_match:
            current = {
                "interface": iface_match.group(1),
                "ip_address": "",
                "acl_in": "",
                "acl_out": "",
                "proxy_arp": False,
                "urpf": False,
                "directed_broadcast": False,
            }
            interfaces.append(current)
            continue

        if current is None:
            continue

        stripped = line.strip()

        # IP address
        ip_match = re.match(r"Internet address is (\S+)", stripped)
        if ip_match:
            current["ip_address"] = ip_match.group(1)
            continue

        # Inbound ACL
        acl_in = re.match(
            r"Inbound\s+access list is (.+)", stripped
        )
        if acl_in:
            val = acl_in.group(1).strip()
            current["acl_in"] = "" if val == "not set" else val
            continue

        # Outbound ACL
        acl_out = re.match(
            r"Outgoing\s+access list is (.+)", stripped
        )
        if acl_out:
            val = acl_out.group(1).strip()
            current["acl_out"] = "" if val == "not set" else val
            continue

        # Proxy ARP
        if re.match(r"Proxy ARP is (enabled|disabled)", stripped):
            current["proxy_arp"] = "enabled" in stripped
            continue

        # uRPF
        if re.search(r"IP verify source reachable-via", stripped):
            current["urpf"] = True
            continue
        if re.match(r"Unicast RPF", stripped):
            current["urpf"] = True
            continue

        # Directed broadcast
        if re.match(r"IP directed.broadcast forwarding is (enabled|disabled)", stripped):
            current["directed_broadcast"] = "enabled" in stripped
            continue

    return interfaces


class EdgeServicesCollector(BaseCollector):
    name = "edge_services"
    label = "Edge Services"
    description = "Collect ACLs and IP interface security data from devices"
    enabled_by_default = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, _DEFAULT_COMMANDS))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        acl_cmd = "show access-lists"
        iface_cmd = "show ip interface"

        acl_output = raw_outputs.get(acl_cmd, "")
        iface_output = raw_outputs.get(iface_cmd, "")

        access_lists = _parse_access_lists(acl_output) if acl_output else []
        ip_interfaces = _parse_ip_interfaces(iface_output) if iface_output else []

        return {
            "access_lists": access_lists,
            "ip_interfaces": ip_interfaces,
        }
