"""Decide whether a logged-in device is a router with no switching plane.

An ASR1000 or ISR4000 runs IOS-XE and is cisco_xe exactly like a Catalyst
9300, so platform gating sends it switchport, VLAN, VTP, STP and MAC-table
commands that it rejects. The model number is what tells them apart.
"""
import re

# IOS / IOS-XE "show version":
#   cisco ASR1001-X (1RU) processor with 3730415K/6147K bytes of memory.
#   cisco C9300-48P (X86) processor with 1419044K/6147K bytes of memory.
#   Cisco CISCO2911/K9 (revision 1.0) with 479232K/45056K bytes of memory.
_PROCESSOR_RE = re.compile(
    r"^cisco\s+(?P<model>\S+)\s+\([^)]*\)\s+(?:processor|with)",
    re.I | re.M,
)

_ROUTER_MODEL_RE = re.compile(
    r"^(?:"
    r"ASR-?\d"                       # ASR 900 / 1000
    r"|ISR-?\d"                      # ISR 4000 / ISR1100
    r"|CSR1000V"
    r"|C8000V"
    r"|C8[2-5]00"                    # Catalyst 8200 / 8300 / 8500 edge
    r"|C11\d\d"                      # ISR 1100 (C1111, C1121, C1161)
    r"|CISCO(?:18|19|28|29|38|39)\d\d"  # ISR G1 / G2
    r")",
    re.I,
)

# ISR 1100 models with an integrated LAN switch (C1111-8P, C1121X-8P,
# C1161-8PLTEP) do have switchports.
_INTEGRATED_SWITCH_RE = re.compile(r"^C11\d\dX?-\d+P", re.I)


def model_from_show_version(text):
    if not text:
        return ""
    m = _PROCESSOR_RE.search(text)
    return m.group("model") if m else ""


def _clean_model(model):
    model = (model or "").strip()
    # CDP platform strings arrive as "cisco ASR1001-X"
    if model.lower().startswith("cisco "):
        model = model[6:].strip()
    return model


def is_router_model(model):
    model = _clean_model(model)
    if not model or _INTEGRATED_SWITCH_RE.match(model):
        return False
    return bool(_ROUTER_MODEL_RE.match(model))


# Analog voice gateways (VG202/204/224, VG310/320/350, VG400/450) run IOS and
# advertise themselves as routers, but they have neither a switching plane
# nor a routing table worth collecting.
_VOICE_GATEWAY_RE = re.compile(r"^VG[234]\d\d", re.I)

_SWITCH_MODEL_RE = re.compile(
    r"^(?:"
    r"WS-C"                          # Catalyst 2960 / 3560 / 3750 / 3850 ...
    r"|C9[2-6]\d\d"                  # Catalyst 9200 - 9600
    r"|C[1-3]\d00-\d"                # Catalyst 1000 / 1200 / 1300 / 2960-L
    r"|IE-?\d"                       # Industrial Ethernet
    r"|N\dK"                         # Nexus N3K / N5K / N7K / N9K
    r"|NEXUS"
    r"|DS-C9"                        # MDS
    r")",
    re.I,
)


def is_voice_gateway_model(model):
    return bool(_VOICE_GATEWAY_RE.match(_clean_model(model)))


def is_switch_model(model):
    model = _clean_model(model)
    if not model:
        return False
    if _INTEGRATED_SWITCH_RE.match(model):
        return False
    return bool(_SWITCH_MODEL_RE.match(model))


def category_for_model(model):
    """Device category implied by a hardware model, or None if unknown.

    A neighbour's CDP capabilities decide the category before login, and an
    ISR4351 doing CUBE advertises Switch alongside Router. The model is
    what the device actually is.
    """
    model = _clean_model(model)
    if not model:
        return None
    if is_voice_gateway_model(model):
        return "voice-gateway"
    if is_router_model(model):
        return "router"
    if is_switch_model(model):
        return "switch"
    return None


def _first_model(show_version, model, platform):
    for candidate in (model_from_show_version(show_version), model, platform):
        candidate = _clean_model(candidate)
        if candidate:
            return candidate
    return ""


def is_switchless_router(show_version="", model="", platform="", category=""):
    """True when switching commands should not be sent to this device.

    The model from show version wins; failing that, a model or platform
    recorded from a neighbour sighting; failing that, a CDP/LLDP category of
    plain "router" (routing capability without switch/bridge). When nothing
    is known the answer is False: running the commands and letting error
    detection discard rejections is safer than missing a switch's data.
    """
    candidate = _first_model(show_version, model, platform)
    if candidate:
        return is_router_model(candidate) or is_voice_gateway_model(candidate)
    return category in ("router", "voice-gateway")


def skips_routing(show_version="", model="", platform="", category=""):
    """True when routing collectors should not be sent to this device."""
    candidate = _first_model(show_version, model, platform)
    if candidate:
        return is_voice_gateway_model(candidate)
    return category == "voice-gateway"


# Ordered: IOS-XE show version also carries a "Cisco IOS Software" line.
_OS_FAMILIES = (
    (re.compile(r"Adaptive Security Appliance Software", re.I), "cisco_asa"),
    (re.compile(r"Cisco IOS[ -]XE Software|\bIOS-XE\b", re.I), "cisco_xe"),
    (re.compile(r"Cisco IOS XR Software", re.I), None),
    (re.compile(r"Cisco Nexus Operating System|\bNX-OS\b", re.I), "cisco_nxos"),
    (re.compile(r"Cisco IOS Software|IOS \(tm\)", re.I), "cisco_ios"),
)

# Types whose commands differ only by which Cisco OS answers. The netmiko
# cisco_ios driver logs into all of them, so whichever a neighbour guessed
# is no evidence of what the device runs.
CISCO_FAMILY_TYPES = frozenset({"cisco_ios", "cisco_xe", "cisco_nxos"})


def device_type_from_show_version(show_version, current=None):
    """The device type show version proves, else current.

    Two identical routers were recorded as cisco_ios and cisco_xe because each
    kept whatever its first neighbour's platform string suggested. Only the
    Cisco IOS family is refined; any other type was chosen for a reason this
    output cannot overrule.
    """
    if current and current not in CISCO_FAMILY_TYPES:
        return current
    if not show_version:
        return current
    for pattern, device_type in _OS_FAMILIES:
        if pattern.search(show_version):
            return device_type or current
    return current
