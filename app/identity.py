"""Device identity helpers.

Devices arrive from several sources under inconsistent names: CDP reports
SW1(FOC1234ABCD), the device itself reports SW1, and DNS reports
SW1.example.local. Keying the inventory on the raw string turns one chassis
into three devices.
"""
import ipaddress
import re

try:
    from app.ifname import canonical_ifname
except ImportError:
    from ifname import canonical_ifname

# NX-OS CDP reports device IDs as hostname(serial), and the domain may follow
# the parentheses rather than precede them -- MDS-A(JPG00000000).example.com.
# Anchoring this to end-of-string left the suffix attached in that form, so the
# sighting never grouped with the login record and survived merge as a shadow.
_SERIAL_SUFFIX = re.compile(r"\([^)]*\)")
_MAC_PATTERNS = [
    re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.I),
    re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I),
    re.compile(r"^([0-9a-f]{2}-){5}[0-9a-f]{2}$", re.I),
    re.compile(r"^[0-9a-f]{12}$", re.I),
]


def normalize_hostname(name) -> str:
    if not name:
        return ""
    result = str(name).strip()
    result = _SERIAL_SUFFIX.sub("", result).strip()
    result = result.split(".")[0]
    return result.casefold()


# Only a parenthesised token that looks like a chassis serial is split off a
# stored name. normalize_hostname drops any parentheses for matching, but a
# name like EDGE(BACKUP) is a real hostname and must be kept as reported.
_DEVICE_ID_SERIAL = re.compile(r"\((?=[A-Z0-9]*\d)([A-Z0-9]{8,14})\)")


def split_device_id(device_id):
    """Split a CDP Device ID of the form NAME(SERIAL) into (name, serial).

    NX-OS, MDS and some hosts advertise their serial in the Device ID, and
    the domain may follow it (NAME(SERIAL).example.com). Storing that raw
    string as the hostname lists the chassis twice once it is logged into
    under its bare name. Returns (device_id, None) when no serial is present.
    """
    if not device_id:
        return device_id, None
    text = str(device_id).strip()
    match = _DEVICE_ID_SERIAL.search(text)
    if not match:
        return text, None
    name = (text[:match.start()] + text[match.end():]).strip()
    if not name:
        return text, None
    return name, match.group(1)


def device_key(hostname, serial=None) -> str:
    if serial and str(serial).strip():
        return f"serial:{str(serial).strip()}"
    return f"host:{normalize_hostname(hostname)}"


# Server NICs advertise themselves over LLDP using the adapter's product
# description as the system name, so they arrive looking like devices with no
# management address and nothing to log into.
_HOST_NIC_PATTERNS = [
    re.compile(r"\badapt(?:er|r)\b", re.I),
    re.compile(r"fw_version:", re.I),
    re.compile(r"netxtreme", re.I),
    re.compile(r"\bocp3\b", re.I),
    re.compile(r"connectx", re.I),
    re.compile(r"\bbcm\d{4,}", re.I),
    re.compile(r"converged network", re.I),
]


def looks_like_host_nic(*values) -> bool:
    """True if a neighbour is a server network adapter rather than a device.

    These cannot be logged into and have no management address, so counting
    them as network devices inflates coverage.
    """
    for value in values:
        if not value:
            continue
        text = str(value)
        if any(p.search(text) for p in _HOST_NIC_PATTERNS):
            return True
    return False


# PAN-OS prompts carry the login user and the HA role: admin@fw01(active).
# The role is the only way to tell which half of a pair carries traffic, so it
# is kept rather than discarded with the rest of the decoration.
_HA_STATES = {"active", "passive", "active-primary", "active-secondary",
              "suspended", "non-functional", "initial", "tentative"}
_PROMPT_USER = re.compile(r"^[^@\s]+@")
_PROMPT_PAREN = re.compile(r"\(([^)]*)\)\s*$")


def parse_device_prompt(prompt) -> dict:
    """Split a device prompt into a hostname and, where present, an HA state."""
    if not prompt:
        return {"hostname": "", "ha_state": None}

    text = str(prompt).strip().rstrip("#>$").strip()
    text = _PROMPT_USER.sub("", text)

    ha_state = None
    match = _PROMPT_PAREN.search(text)
    if match:
        inner = match.group(1).strip().lower()
        if inner in _HA_STATES:
            ha_state = inner
        # A config-mode prompt is decoration either way -- drop it.
        text = text[:match.start()].strip()

    return {"hostname": text, "ha_state": ha_state}


def looks_like_mac(value) -> bool:
    """True if value is a bare MAC address.

    LLDP frequently reports a chassis MAC where a platform string belongs.
    Writing that through produces rows like Platform=009a.d2d4.9700.
    """
    if not value:
        return False
    candidate = str(value).strip()
    return any(p.match(candidate) for p in _MAC_PATTERNS)


def collected_serial(device) -> str:
    """The serial a record can be trusted to hold for conflict checks.

    A neighbour-only record may carry the serial from a CDP Device ID. NX-OS
    can advertise the chassis serial while show version reports the
    supervisor's, so two different serials on records sharing a name do not
    prove two chassis unless both were collected.
    """
    serial = (device.get("serial") or "").strip()
    if (serial and not device.get("login_succeeded")
            and serial == (device.get("cdp_serial") or "").strip()):
        return ""
    return serial


_LOOPBACK_RE = re.compile(r"^(?:loopback|lo)\s*(\d+)", re.I)


def _ipv4(value):
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    text = str(value or "").split("/")[0].strip()
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def interface_addresses(device) -> dict:
    """Map each IPv4 address the device reported on an interface to it."""
    parsed = ((device.get("collector_data") or {})
              .get("interfaces", {}).get("parsed") or {})
    addresses = {}
    for entry in parsed.get("ip_interfaces") or []:
        addr = _ipv4(entry.get("ip_address") or entry.get("ipaddr"))
        if addr is None:
            continue
        ifname = entry.get("interface") or entry.get("intf") or ""
        addresses.setdefault(str(addr), ifname)
    return addresses


def resolve_mgmt_ip(device):
    """Pick a logged-in device's management address. Returns (ip, source).

    Taking whichever address the device happened to be reached on made twin
    routers disagree: one listed under a circuit address, the other under an
    interface. The rule is fixed so the answer does not depend on crawl
    order:

    1. an address a neighbour saw advertised as the management address,
       provided the device owns it and it is not simply the address of the
       link that neighbour sits on;
    2. the lowest-numbered Loopback's address;
    3. the address the device was logged into.

    Ties go to the numerically lowest address.
    """
    reached = device.get("reached_ip") or device.get("mgmt_ip")
    owned = interface_addresses(device)

    advertised = set()
    for entry in device.get("evidence") or []:
        if not isinstance(entry, dict):
            continue
        addr = _ipv4(entry.get("mgmt_address"))
        if addr is None or str(addr) not in owned:
            continue
        link_port = entry.get("remote_port") or ""
        if link_port and (canonical_ifname(owned[str(addr)])
                          == canonical_ifname(link_port)):
            continue
        advertised.add(addr)
    if advertised:
        return str(min(advertised)), "advertised"

    loopbacks = []
    for addr, ifname in owned.items():
        match = _LOOPBACK_RE.match(str(ifname).strip())
        if match:
            loopbacks.append((int(match.group(1)), ipaddress.IPv4Address(addr)))
    if loopbacks:
        return str(min(loopbacks)[1]), "loopback"

    return reached, "reached"
