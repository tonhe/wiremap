"""Device identity helpers.

Devices arrive from several sources under inconsistent names: CDP reports
SW1(FOC1234ABCD), the device itself reports SW1, and DNS reports
SW1.example.local. Keying the inventory on the raw string turns one chassis
into three devices.
"""
import re

_SERIAL_SUFFIX = re.compile(r"\([^)]*\)\s*$")
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


def looks_like_mac(value) -> bool:
    """True if value is a bare MAC address.

    LLDP frequently reports a chassis MAC where a platform string belongs.
    Writing that through produces rows like Platform=009a.d2d4.9700.
    """
    if not value:
        return False
    candidate = str(value).strip()
    return any(p.match(candidate) for p in _MAC_PATTERNS)
