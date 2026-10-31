"""Neighbour source registry.

Mirrors the collector registry: sources are declared once here and the
discovery engine asks for all of them rather than reading CDP directly.
"""
from .base import NeighborSource

try:
    from app.parsers import neighbor_link_key
except ImportError:
    from parsers import neighbor_link_key
from .scope import CrawlScope
from .sources import (
    CdpLldpSource,
    HsrpVrrpSource,
    NextHopSource,
    RoutingAdjacencySource,
)

_REGISTRY = {
    s.name: s for s in (
        CdpLldpSource(),
        RoutingAdjacencySource(),
        NextHopSource(),
        HsrpVrrpSource(),
    )
}


def get_registry() -> dict:
    return dict(_REGISTRY)


def default_enabled() -> set:
    return {n for n, s in _REGISTRY.items() if s.enabled_by_default}


def extract_all(device: dict, enabled=None) -> list[dict]:
    """Collect neighbours from every enabled source, merged by address.

    The same peer is routinely seen twice -- CDP knows its hostname, OSPF only
    its address. Merging keeps the richest view of each and records every
    sighting in seen_via.
    """
    if enabled is None:
        enabled = default_enabled()

    # Parallel links to one peer share an address but are separate links,
    # each with its own far-end port worth recording. Within a source,
    # sightings are keyed per link; another source's sighting of the same
    # address (OSPF knows only the address) folds into the first link.
    merged = {}
    by_ip = {}
    unaddressed = []
    for name, source in _REGISTRY.items():
        if name not in enabled:
            continue
        for ref in source.extract(device):
            ip = ref.get("remote_ip")
            if not ip:
                # Keep it: a named CDP neighbour without an address is still
                # evidence, even though it can never be crawled.
                ref.setdefault("seen_via", [ref.get("source")])
                unaddressed.append(ref)
                continue
            key = (name,) + neighbor_link_key(ref)
            existing = merged.get(key)
            if existing is None:
                first = by_ip.get(ip)
                if first is not None and first.get("source") != name:
                    existing = first
            if existing is None:
                ref["seen_via"] = [ref.get("source")]
                merged[key] = ref
                by_ip.setdefault(ip, ref)
                continue
            if ref.get("source") not in existing.setdefault("seen_via", []):
                existing["seen_via"].append(ref.get("source"))
            for field in ("remote_device", "remote_platform",
                          "remote_capabilities", "remote_intf"):
                if not existing.get(field) and ref.get(field):
                    existing[field] = ref[field]

    return list(merged.values()) + unaddressed


__all__ = ["NeighborSource", "CrawlScope", "get_registry",
           "default_enabled", "extract_all"]
