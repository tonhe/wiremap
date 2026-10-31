"""Which non-CDP/LLDP neighbour addresses are worth a login attempt.

Routing adjacencies, next-hops and FHRP peers name addresses, not devices.
Many of those addresses are firewall interfaces on /29 and /30 transits,
provider PE addresses or eBGP peers -- each one costs an SSH timeout plus a
telnet attempt and yields nothing. CDP/LLDP is the only source that proves a
neighbour is network gear we can log into, so every other source has to earn
its login:

- the address is also CDP/LLDP-visible somewhere in this scan, or
- an ARP table already collected maps it to a network-vendor MAC, or
- the operator turned on expand_non_cdp_neighbors.

BGP peers and OSPF neighbours on multi-access segments are the worst
offenders (provider edges, firewall transits), so a vendor MAC is not enough
for them: they need CDP/LLDP visibility or the explicit setting.
"""

# Well-known OUI prefixes for network vendors. Deliberately compact and
# non-exhaustive: each vendor owns hundreds of blocks. A miss only means an
# address is reported as not attempted rather than crawled; the operator can
# widen the crawl with expand_non_cdp_neighbors.
NETWORK_VENDOR_OUIS = {
    "cisco": (
        "00:00:0c", "00:01:42", "00:01:64", "00:01:96", "00:02:b9",
        "00:03:6b", "00:04:9a", "00:05:9a", "00:06:d7", "00:07:0e",
        "00:08:a3", "00:0b:be", "00:0d:bc", "00:0e:d7", "00:12:80",
        "00:13:5f", "00:14:1b", "00:15:62", "00:16:9c", "00:17:5a",
        "00:18:73", "00:19:aa", "00:1a:a1", "00:1b:54", "00:1c:58",
        "00:1d:a1", "00:1e:13", "00:1f:6c", "00:21:a0", "00:22:55",
        "00:23:eb", "00:24:97", "00:25:b4", "00:26:cb", "00:27:0d",
        "00:2a:6a", "00:3a:98", "00:42:68", "00:5f:86", "00:62:ec",
        "00:81:c4", "00:87:31", "00:a2:89", "00:be:75", "00:c8:8b",
        "00:cc:fc", "00:de:fb", "00:e0:1e", "00:eb:d5", "04:62:73",
        "2c:31:24", "38:ed:18", "3c:0e:23", "40:55:39", "50:3d:e5",
        "58:97:bd", "5c:50:15", "64:f6:9d", "68:bd:ab", "70:db:98",
        "74:a0:2f", "78:da:6e", "7c:ad:74", "84:b8:02", "88:5a:92",
        "8c:60:4f", "94:d4:69", "a0:3d:6f", "a4:6c:2a", "b0:aa:77",
        "bc:16:65", "c0:62:6b", "c4:72:95", "cc:46:d6", "d4:6d:50",
        "e0:89:9d", "e8:65:49", "f0:29:29", "f4:cf:e2", "f8:72:ea",
        # Meraki
        "00:18:0a", "0c:8d:db", "88:15:44", "ac:17:c8", "e0:55:3d",
    ),
    "arista": (
        "00:1c:73", "28:99:3a", "44:4c:a8", "74:83:ef", "98:5d:82",
        "c0:d6:82", "fc:bd:67",
    ),
    "juniper": (
        "00:05:85", "00:10:db", "00:12:1e", "00:14:f6", "00:17:cb",
        "00:19:e2", "00:1d:b5", "00:1f:12", "00:21:59", "00:22:83",
        "00:23:9c", "00:24:dc", "00:26:88", "28:8a:1c", "2c:6b:f5",
        "3c:61:04", "40:b4:f0", "54:e0:32", "5c:5e:ab", "64:87:88",
        "78:19:f7", "80:71:1f", "84:18:88", "88:e0:f3", "9c:cc:83",
        "a8:d0:e5", "b0:c6:9a", "cc:e1:7f", "ec:3e:f7", "f0:1c:2d",
        "f4:cc:55",
    ),
    "hpe_aruba": (
        "00:0b:86", "00:1a:1e", "00:24:6c", "04:bd:88", "08:2e:5f",
        "18:64:72", "20:4c:03", "24:de:c6", "40:e3:d6", "6c:f3:7f",
        "70:3a:0e", "84:d4:7e", "94:57:a5", "94:b4:0f", "9c:1c:12",
        "9c:8c:d8", "ac:a3:1e", "d8:c7:c8", "ec:eb:b8", "f0:5c:19",
    ),
    "extreme": (
        "00:01:30", "00:04:96", "00:e0:2b", "5c:0e:8b", "b8:50:01",
        "00:1b:4f",
    ),
    "fortinet": (
        "00:09:0f", "04:d5:90", "08:5b:0e", "70:4c:a5", "90:6c:ac",
        "94:ff:3c", "e8:1c:ba",
    ),
    "paloalto": (
        "00:1b:17", "08:30:6b", "08:66:1f", "24:0b:0a", "58:49:3b",
        "7c:89:c1", "b4:0c:25", "d4:1d:71", "e4:a7:49",
    ),
}

_OUI_TO_VENDOR = {
    prefix: vendor
    for vendor, prefixes in NETWORK_VENDOR_OUIS.items()
    for prefix in prefixes
}

# Reasons recorded in scan_summary["not_attempted"].
REASON_BGP = "bgp_peer_not_cdp_lldp_visible"
REASON_OSPF_MULTIACCESS = "ospf_multiaccess_not_cdp_lldp_visible"
REASON_NO_ARP = "no_arp_entry"
REASON_NON_VENDOR_MAC = "non_network_vendor_mac"


def _oui(mac):
    if not mac:
        return None
    hexdigits = "".join(c for c in str(mac).lower() if c in "0123456789abcdef")
    if len(hexdigits) != 12:
        return None
    return ":".join(hexdigits[i:i + 2] for i in (0, 2, 4))


def vendor_for_mac(mac):
    """Network vendor owning this MAC's OUI, or None."""
    return _OUI_TO_VENDOR.get(_oui(mac))


def is_cdp_lldp(ref):
    return "cdp_lldp" in (ref.get("seen_via") or [ref.get("source")])


def _ospf_is_multiaccess(state):
    # IOS prints "FULL/DR", "FULL/BDR", "FULL/DROTHER" on broadcast segments
    # and "FULL/-" on point-to-point links.
    state = str(state or "").upper().replace(" ", "")
    if "/" not in state:
        return False
    role = state.split("/", 1)[1]
    return role not in ("", "-")


def kind_of(ref):
    """bgp, ospf_multiaccess, or other (vendor MAC is enough)."""
    protocol = str(ref.get("protocol") or "").upper()
    if protocol == "BGP":
        return "bgp"
    if protocol == "OSPF" and _ospf_is_multiaccess(ref.get("state")):
        return "ospf_multiaccess"
    return "other"


def decide(ref, cdp_visible, mac=None, expand=False):
    """Return (allowed, reason). reason is None when allowed."""
    if cdp_visible or expand:
        return True, None
    kind = kind_of(ref)
    if kind == "bgp":
        return False, REASON_BGP
    if kind == "ospf_multiaccess":
        return False, REASON_OSPF_MULTIACCESS
    if not mac:
        return False, REASON_NO_ARP
    if vendor_for_mac(mac):
        return True, None
    return False, REASON_NON_VENDOR_MAC


def arp_map(devices):
    """IP -> MAC from every ARP table already collected."""
    result = {}
    for dev in (devices or {}).values():
        parsed = (dev.get("collector_data", {}).get("arp", {})
                  .get("parsed", {})) or {}
        for entry in parsed.get("entries") or []:
            ip = entry.get("ip")
            mac = entry.get("mac")
            if ip and mac and not entry.get("incomplete"):
                result.setdefault(ip, mac)
    return result


def discovered_via_label(ref):
    """How a neighbour sighting names its source in discovered_via."""
    source = ref.get("source") or "cdp_lldp"
    if source == "cdp_lldp":
        protocols = {str(p).upper() for p in ref.get("protocols") or []}
        if "CDP" in protocols or not protocols:
            return "cdp"
        return "lldp"
    return {
        "routing_adjacency": "routing",
        "next_hop": "next_hop",
        "hsrp_vrrp": "hsrp_vrrp",
        "arp": "arp",
    }.get(source, source)
