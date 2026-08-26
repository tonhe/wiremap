"""The neighbour sources discovery can crawl from."""
from .base import NeighborSource


class CdpLldpSource(NeighborSource):
    name = "cdp_lldp"
    label = "CDP / LLDP"
    description = "Directly connected neighbours advertised by CDP or LLDP"
    collector = "cdp_lldp"

    def extract(self, device):
        refs = []
        for n in self.parsed_for(device).get("neighbors", []):
            ref = dict(n)
            ref["source"] = self.name
            refs.append(ref)
        return refs


class RoutingAdjacencySource(NeighborSource):
    name = "routing_adjacency"
    label = "Routing Adjacencies"
    description = "OSPF, EIGRP, BGP and IS-IS peers"
    collector = "l3_routing"

    def extract(self, device):
        refs = []
        for n in self.parsed_for(device).get("neighbors", []):
            ip = n.get("remote_ip")
            if not ip:
                continue
            ref = dict(n)
            ref["source"] = self.name
            # A routing peer is a router by definition, even when the
            # protocol output says nothing about capabilities.
            ref.setdefault("remote_capabilities", "Router")
            if not ref.get("remote_capabilities"):
                ref["remote_capabilities"] = "Router"
            refs.append(ref)
        return refs


class NextHopSource(NeighborSource):
    name = "next_hop"
    label = "Route Next-Hops"
    description = "Gateways named by the routing table"
    collector = "l3_routing"
    # Off unless asked for: a full routing table names far more gateways than
    # a site actually owns, and each one costs a login attempt.
    enabled_by_default = False

    def extract(self, device):
        seen = set()
        refs = []
        for route in self.parsed_for(device).get("routes", []):
            ip = route.get("nexthop_ip") or route.get("next_hop")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            refs.append({
                "remote_ip": ip,
                "remote_device": None,
                "remote_platform": None,
                "remote_capabilities": "Router",
                "remote_intf": route.get("nexthop_if") or route.get("interface"),
                "source": self.name,
            })
        return refs


class HsrpVrrpSource(NeighborSource):
    name = "hsrp_vrrp"
    label = "HSRP / VRRP Peers"
    description = "First-hop redundancy group members"
    collector = "hsrp"

    _PEER_FIELDS = ("active_ip", "standby_ip", "peer_ip", "active", "standby")

    def extract(self, device):
        seen = set()
        refs = []
        for entry in self.parsed_for(device).get("entries", []):
            for field in self._PEER_FIELDS:
                ip = entry.get(field)
                if not ip or ip in seen:
                    continue
                # "local" and similar markers appear where an address would be.
                if not str(ip)[0].isdigit():
                    continue
                seen.add(ip)
                refs.append({
                    "remote_ip": ip,
                    "remote_device": None,
                    "remote_platform": None,
                    "remote_capabilities": "Router",
                    "remote_intf": entry.get("interface"),
                    "source": self.name,
                })
        return refs
