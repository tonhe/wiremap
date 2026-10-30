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


def is_switchless_router(show_version="", model="", platform="", category=""):
    """True when switching commands should not be sent to this device.

    The model from show version wins; failing that, a model or platform
    recorded from a neighbour sighting; failing that, a CDP/LLDP category of
    plain "router" (routing capability without switch/bridge). When nothing
    is known the answer is False: running the commands and letting error
    detection discard rejections is safer than missing a switch's data.
    """
    for candidate in (model_from_show_version(show_version), model, platform):
        candidate = _clean_model(candidate)
        if candidate:
            return is_router_model(candidate)
    return category == "router"
