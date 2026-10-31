"""
Redundancy and stack-ring collector.

show redundancy covers dual supervisors and StackWise Virtual/SVL pairs;
stack-ports and stack-ring speed cover StackWise rings. Stack membership and
virtual-pair detail stay in device_inventory; this collector records the
health of the redundancy itself.
"""
import re

from .base import BaseCollector

_REDUNDANCY = "show redundancy"
_NXOS_REDUNDANCY = "show system redundancy status"
_STACK_PORTS = "show switch stack-ports"
_STACK_RING = "show switch stack-ring speed"

_COMMANDS = {
    "cisco_ios": [_REDUNDANCY, _STACK_PORTS, _STACK_RING],
    "cisco_xe": [_REDUNDANCY, _STACK_PORTS, _STACK_RING],
    "cisco_nxos": [_NXOS_REDUNDANCY],
}

_KV_RE = re.compile(r"^\s*(?P<key>[A-Za-z][\w ()/-]*?)\s*[=:]\s*(?P<val>.*?)\s*$")

_IOS_KEYS = {
    "hardware mode": "hardware_mode",
    "configured redundancy mode": "configured_mode",
    "operating redundancy mode": "operating_mode",
    "communications": "communications",
    "switchovers system experienced": "switchovers",
    "standby failures": "standby_failures",
    "last switchover reason": "last_switchover_reason",
    "available system uptime": "system_uptime",
}


def parse_redundancy(text):
    """Parse IOS/IOS-XE show redundancy into a flat dict.

    active_state and peer_state come from the Current and Peer Processor
    blocks ("Current Software state = STANDBY HOT").
    """
    result = {}
    if not text or not text.strip():
        return result
    block = ""
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("current processor information"):
            block = "active"
            continue
        if low.startswith("peer processor information"):
            block = "peer"
            continue
        if low.startswith("peer (slot"):
            # "Peer (slot: Unknown) : Empty" on a single supervisor
            block = "peer"
            result.setdefault("peer_state", line.split(":")[-1].strip())
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower()
        val = m.group("val")
        if key in _IOS_KEYS:
            result[_IOS_KEYS[key]] = val
        elif key == "current software state" and block:
            result[f"{block}_state"] = val
        elif key in ("active location", "standby location") and block:
            result[f"{block}_location"] = val
    return result


def parse_nxos_redundancy(text):
    result = {}
    if not text or not text.strip():
        return result
    block = ""
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("this supervisor"):
            block = "active"
            continue
        if low.startswith("other supervisor"):
            block = "peer"
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower()
        val = m.group("val")
        if key == "administrative":
            result["configured_mode"] = val
        elif key == "operational":
            result["operating_mode"] = val
        elif key == "redundancy state" and block:
            result[f"{block}_state"] = val
    return result


_STACK_PORT_ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s*$")


def parse_stack_ports(text):
    members = []
    if not text:
        return members
    for line in text.splitlines():
        m = _STACK_PORT_ROW.match(line)
        if m:
            members.append({"switch": m.group(1), "port1": m.group(2),
                            "port2": m.group(3)})
    return members


def parse_stack_ring(text):
    result = {}
    if not text:
        return result
    for line in text.splitlines():
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower()
        if key == "stack ring speed":
            result["speed"] = m.group("val")
        elif key == "stack ring configuration":
            result["configuration"] = m.group("val")
        elif key == "stack ring protocol":
            result["protocol"] = m.group("val")
    return result


class RedundancyCollector(BaseCollector):
    name = "redundancy"
    label = "Redundancy & Stack Ring"
    description = "Collect supervisor/SVL redundancy state and stack ring health"
    enabled_by_default = True
    # Routers have no stack ring; they still answer show redundancy.
    switching_commands = frozenset({_STACK_PORTS, _STACK_RING})

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, []))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if not raw_outputs:
            return {"not_applicable": True,
                    "reason": f"redundancy: no commands for {device_type}"}
        if device_type == "cisco_nxos":
            redundancy = parse_nxos_redundancy(raw_outputs.get(_NXOS_REDUNDANCY, ""))
        else:
            redundancy = parse_redundancy(raw_outputs.get(_REDUNDANCY, ""))
        return {
            "redundancy": redundancy,
            "stack_ports": parse_stack_ports(raw_outputs.get(_STACK_PORTS, "")),
            "stack_ring": parse_stack_ring(raw_outputs.get(_STACK_RING, "")),
        }
