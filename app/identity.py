"""Device identity helpers.

Devices arrive from several sources under inconsistent names: CDP reports
SW1(FOC1234ABCD), the device itself reports SW1, and DNS reports
SW1.example.local. Keying the inventory on the raw string turns one chassis
into three devices.
"""
import re

# NX-OS CDP reports device IDs as hostname(serial), and the domain may follow
# the parentheses rather than precede them -- DCN5K-5A(SSI16421TNJ).trmc.us.
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
