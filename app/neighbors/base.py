"""Base class for neighbour sources.

Discovery used to read CDP/LLDP alone, so anything reachable only via a
routing adjacency or a next-hop was invisible. A source turns one collector's
parsed output into candidate neighbours; the engine merges them.
"""
from abc import ABC, abstractmethod


class NeighborSource(ABC):
    name: str = ""
    label: str = ""
    description: str = ""
    collector: str = ""
    enabled_by_default: bool = True

    def parsed_for(self, device: dict) -> dict:
        """Return this source's collector output, or {} if unusable."""
        parsed = (device.get("collector_data", {})
                  .get(self.collector, {})
                  .get("parsed", {}))
        if not parsed or parsed.get("collector_failed") or parsed.get("not_applicable"):
            return {}
        return parsed

    @abstractmethod
    def extract(self, device: dict) -> list[dict]:
        """Return neighbour dicts.

        Each carries remote_ip and, where the protocol knows it, remote_device,
        remote_platform, remote_capabilities and remote_intf -- plus source,
        naming which sighting produced it.
        """
