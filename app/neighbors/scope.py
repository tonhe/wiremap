"""Bounds on what discovery is allowed to crawl.

Crawling routing next-hops on a network with an internet edge will otherwise
walk straight out into transit and ISP space. Private address space is the
default boundary; an explicit allow list replaces it rather than extending it,
so an operator who names a range gets exactly that range.
"""
import ipaddress
import logging

logger = logging.getLogger(__name__)

_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _parse_cidrs(values, label):
    networks = []
    for value in values or []:
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError as e:
            raise ValueError(f"invalid {label} CIDR {value!r}: {e}") from e
    return networks


class CrawlScope:
    def __init__(self, allow_cidrs=None, deny_cidrs=None,
                 rfc1918_only=True, max_devices=None):
        self.allow = _parse_cidrs(allow_cidrs, "allow")
        self.deny = _parse_cidrs(deny_cidrs, "deny")
        self.rfc1918_only = rfc1918_only
        self.max_devices = max_devices

    def allows(self, ip) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return False

        # Never crawl addresses that cannot identify a manageable device.
        if (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified or addr.is_reserved):
            return False
        if str(addr) == "255.255.255.255":
            return False

        if any(addr in net for net in self.deny):
            return False

        if self.allow:
            return any(addr in net for net in self.allow)

        if self.rfc1918_only:
            return any(addr in net for net in _PRIVATE)

        return True

    def under_ceiling(self, current_count: int) -> bool:
        if not self.max_devices:
            return True
        return current_count < self.max_devices
