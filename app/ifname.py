"""Interface-name canonicalisation.

The same port shows up as Gi1/0/1 in `show interfaces status`,
GigabitEthernet1/0/1 in CDP and Gi1/0/1 again in LLDP. Anything that joins
interface data from two commands must compare canonical names, or the join
silently never matches.
"""
import re

_CANONICAL = {
    "GigabitEthernet": ("gi", "gig", "gige", "gigabitethernet"),
    "TenGigabitEthernet": ("te", "ten", "tengig", "tengige",
                           "tengigabitethernet"),
    "TwentyFiveGigE": ("twe", "twentyfivegige", "twentyfivegigabitethernet"),
    "TwoGigabitEthernet": ("tw", "two", "twogigabitethernet"),
    "FiveGigabitEthernet": ("fi", "five", "fivegigabitethernet"),
    "FortyGigabitEthernet": ("fo", "fortygige", "fortygigabitethernet"),
    "FiftyGigE": ("fif", "fiftygige", "fiftygigabitethernet"),
    "HundredGigE": ("hu", "hundredgige", "hundredgigabitethernet"),
    "FourHundredGigE": ("fourhundredgige", "fourhundredgigabitethernet"),
    "FastEthernet": ("fa", "fastethernet"),
    "Ethernet": ("e", "et", "eth", "ethernet"),
    "AppGigabitEthernet": ("ap", "appgigabitethernet"),
    "Port-channel": ("po", "port-channel", "portchannel"),
    "Bundle-Ether": ("be", "bundle-ether"),
    "Vlan": ("vl", "vlan"),
    "Loopback": ("lo", "loopback"),
    "Tunnel": ("tu", "tunnel"),
    "Serial": ("se", "serial"),
    "Management": ("ma", "management"),
    "MgmtEth": ("mgmteth",),
    "mgmt": ("mgmt",),
    "BDI": ("bdi",),
    "nve": ("nve",),
    "Dialer": ("di", "dialer"),
}

_ALIASES = {alias: canon for canon, aliases in _CANONICAL.items()
            for alias in aliases}

# Letters (and hyphens inside the type name, as in Port-channel) followed by
# the slot/port numbering. A trailing hyphen is not part of the type: that is
# Juniper's ge-0/0/0 style, which is left alone.
_SPLIT = re.compile(r"^([A-Za-z]+(?:-[A-Za-z]+)*)(\d.*)$")


def canonical_ifname(name):
    """Return one canonical spelling for an interface name.

    Known Cisco/Arista/NX-OS types are expanded to their long form
    (Te1/1/1 -> TenGigabitEthernet1/1/1, Eth1/1 -> Ethernet1/1,
    Po10 -> Port-channel10). Anything unrecognised is returned lowercased
    with whitespace removed, so comparisons stay case-insensitive.
    """
    if not name:
        return ""
    text = re.sub(r"\s+", "", str(name))
    if not text:
        return ""
    match = _SPLIT.match(text)
    if match:
        canon = _ALIASES.get(match.group(1).lower())
        if canon:
            return canon + match.group(2)
    return text.lower()
