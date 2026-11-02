"""
QoS collector: attached policy-map counters, classic Catalyst MLS QoS trust,
queueing and DSCP counters, auto-QoS, class-map and policy-map definitions,
and per-port hardware queue counters on Catalyst 9000.

The configuration says what QoS was meant to do; the counters say whether it
is doing it. Commands a platform does not have are recorded as not
applicable, like every other collector.

Which commands run depends on the platform family, worked out from the model
in show version. A device whose model is not recognised gets the common MQC
commands plus the classic MLS ones, and whichever are rejected are n/a.

Catalyst 9000 hardware queue counters are one command per port, so they are
only run on trunks and on ports with a phone, voice gateway, AP, router or
switch neighbour, capped at QUEUE_STATS_CAP per device.
"""
import hashlib
import re

from .base import BaseCollector
from .errors import send_failure_output

try:
    from app.device_role import is_router_model, is_voice_gateway_model, category_for_model
    from app.ifname import canonical_ifname
except ImportError:
    from device_role import is_router_model, is_voice_gateway_model, category_for_model
    from ifname import canonical_ifname

POLICY_MAP_INTERFACE = "show policy-map interface"
CLASS_MAP = "show class-map"
POLICY_MAP = "show policy-map"
AUTO_QOS = "show auto qos"

MLS_QOS = "show mls qos"
MLS_INTERFACE = "show mls qos interface"
MLS_QUEUEING = "show mls qos interface queueing"
MLS_STATISTICS = "show mls qos interface statistics"
MLS_QUEUE_SET = "show mls qos queue-set"
MLS_DSCP_MAP = "show mls qos maps dscp-output-q"
MLS_COS_MAP = "show mls qos maps cos-output-q"

FED_POLICY_SUMMARY = "show platform software fed switch active qos policy summary"
FED_QUEUE_STATS = "show platform hardware fed switch {switch} qos queue stats interface {intf}"
QFP_QOS_GLOBAL = "show platform hardware qfp active feature qos config global"
CAT4K_QOS = "show qos"
CAT4K_QOS_INTERFACE = "show qos interface"

NXOS_COMMANDS = ["show policy-map interface", "show queuing interface",
                 "show class-map type qos", "show policy-map type qos"]
EOS_COMMANDS = ["show qos interfaces", "show policy-map interface"]

COMMON = [POLICY_MAP_INTERFACE, CLASS_MAP, POLICY_MAP, AUTO_QOS]
CLASSIC = [MLS_QOS, MLS_INTERFACE, MLS_QUEUEING, MLS_STATISTICS,
           MLS_QUEUE_SET, MLS_DSCP_MAP, MLS_COS_MAP]

# Platform families
FAMILY_CLASSIC = "classic"            # 2960/3560/3750: mls qos, srr queues
FAMILY_CAT9K = "cat9k"                # C9200-C9600: MQC, fed queue counters
FAMILY_MQC_SWITCH = "mqc-switch"      # 3650/3850: MQC, trusts by default
FAMILY_CAT4500 = "cat4500"            # 4500-X / Sup7-8: MQC, show qos
FAMILY_ROUTER_QFP = "router-qfp"      # ASR1000, ISR4000, C8000
FAMILY_ROUTER = "router"              # ISR G2, voice gateways
FAMILY_NXOS = "nxos"
FAMILY_EOS = "eos"
FAMILY_UNKNOWN = "unknown"

# Families where ports trust DSCP unless a policy says otherwise.
TRUSTS_BY_DEFAULT = frozenset({FAMILY_CAT9K, FAMILY_MQC_SWITCH, FAMILY_CAT4500})
SWITCH_FAMILIES = frozenset({FAMILY_CLASSIC, FAMILY_CAT9K, FAMILY_MQC_SWITCH,
                             FAMILY_CAT4500})

QUEUE_STATS_CAP = 24
READ_TIMEOUT = 180

_CAT9K_RE = re.compile(r"^C9[2-6]\d\d", re.I)
_MQC_SWITCH_RE = re.compile(r"^WS-C3[68]50", re.I)
_CAT4500_RE = re.compile(r"^WS-C45\d\dX|^WS-C4500X", re.I)
_QFP_RE = re.compile(r"^(?:ASR1|ISR4|C8[2-5]00|C8000V|CSR1000V)", re.I)


def platform_family(device_type, model="", router=False):
    """QoS platform family for a device type and hardware model."""
    if device_type == "cisco_nxos":
        return FAMILY_NXOS
    if device_type == "arista_eos":
        return FAMILY_EOS
    model = (model or "").strip()
    if model.lower().startswith("cisco "):
        model = model[6:].strip()
    if _CAT9K_RE.match(model):
        return FAMILY_CAT9K
    if _MQC_SWITCH_RE.match(model):
        return FAMILY_MQC_SWITCH
    if _CAT4500_RE.match(model):
        return FAMILY_CAT4500
    if _QFP_RE.match(model):
        return FAMILY_ROUTER_QFP
    if router or is_router_model(model) or is_voice_gateway_model(model):
        return FAMILY_ROUTER
    if model.upper().startswith(("WS-C", "IE-")):
        return FAMILY_CLASSIC
    return FAMILY_UNKNOWN


def commands_for(device_type, family):
    """Fixed commands for a family; per-port queue counters come later."""
    if family == FAMILY_NXOS:
        return list(NXOS_COMMANDS)
    if family == FAMILY_EOS:
        return list(EOS_COMMANDS)
    if device_type not in ("cisco_ios", "cisco_xe"):
        return []
    if family == FAMILY_CLASSIC or family == FAMILY_UNKNOWN:
        return COMMON + CLASSIC
    if family == FAMILY_CAT9K:
        return COMMON + [FED_POLICY_SUMMARY]
    if family == FAMILY_CAT4500:
        return COMMON + [CAT4K_QOS, CAT4K_QOS_INTERFACE]
    if family == FAMILY_ROUTER_QFP:
        return COMMON + [QFP_QOS_GLOBAL]
    return list(COMMON)


# ---------------------------------------------------------------------------
# show policy-map interface
# ---------------------------------------------------------------------------

_IFACE_LINE_RE = re.compile(r"^\s{0,2}([A-Za-z][\w./:-]*\d(?:\.\d+)?)\s*$")
_CONTROL_PLANE_RE = re.compile(r"^\s{0,2}Control Plane\s*$", re.I)
_SERVICE_POLICY_RE = re.compile(
    r"^Service-policy\s*(?:\([\w-]+\)\s*)?(input|output)?\s*:\s*(\S+)", re.I)
_CLASS_LINE_RE = re.compile(r"^Class-map:\s*(\S+)(?:\s*\((match-\w+)\))?", re.I)
_PACKETS_RE = re.compile(r"^(\d+) packets(?:, (\d+) bytes)?")
_OFFERED_RE = re.compile(
    r"(?:minute|second) offered rate (\d+) bps(?:, drop rate (\d+) bps)?")
_PRIORITY_PCT_RE = re.compile(r"Priority:\s*(\d+)\s*%\s*(?:\((\d+) kbps\))?", re.I)
_PRIORITY_KBPS_RE = re.compile(r"Priority:\s*(\d+) kbps", re.I)
_PRIORITY_LEVEL_RE = re.compile(r"priority level:?\s*(\d+)", re.I)
_BW_EXCEED_RE = re.compile(r"b/w exceed drops:\s*(\d+)")
_QUEUE_STATS_RE = re.compile(
    r"\(queue depth/total drops/no-buffer drops(?:/flowdrops)?\)\s*(\d+)/(\d+)/(\d+)")
_TOTAL_DROPS_RE = re.compile(r"\(total drops\)\s*(\d+)")
_PKTS_OUTPUT_RE = re.compile(r"\(pkts output/bytes output\)\s*(\d+)/(\d+)")
_BYTES_OUTPUT_RE = re.compile(r"\(bytes output\)\s*(\d+)")
_POLICE_CIR_RE = re.compile(r"\bcir\s+(\d+)\s*(bps|%)?", re.I)
_POLICE_EXCEEDED_RE = re.compile(r"^exceeded\s+(\d+)\s+(?:bytes|packets)", re.I)
_BANDWIDTH_RE = re.compile(
    r"^bandwidth\s+(remaining\s+)?(?:ratio\s+)?(\d+)\s*\(?\s*(%|kbps)?", re.I)
_SHAPE_RE = re.compile(r"^shape\s*\((?:average|peak)\)\s*cir\s+(\d+)", re.I)
_QUEUE_LIMIT_RE = re.compile(r"^queue[- ]limit\s+(\d+)", re.I)
_SET_LINE_RE = re.compile(
    r"^(ip dscp|ip precedence|dscp|cos|precedence|qos-group|discard-class)\s+(\S+)",
    re.I)


def _new_policy(interface, direction, name, parent=None, parent_class=None):
    return {"interface": interface, "direction": direction, "policy_name": name,
            "parent_policy": parent, "parent_class": parent_class,
            "classes": [], "priority_queue": {}}


def _new_class(name, match_type):
    return {"class_name": name, "match_type": match_type or "", "match": [],
            "set": [], "packets": None, "bytes": None,
            "offered_rate_bps": None, "drop_rate_bps": None,
            "drops": None, "queue_depth": None, "pkts_output": None,
            "is_priority": False, "priority_level": None,
            "priority_percent": None, "priority_kbps": None,
            "priority_drops": None, "police_cir_bps": None,
            "police_cir_percent": None, "police_exceeded": None,
            "bandwidth": "", "shape_bps": None, "queue_limit": None}


def _add_drops(cls, value):
    cls["drops"] = (cls["drops"] or 0) + value


def class_actions(cls):
    """Readable action list for a parsed class."""
    actions = []
    for item in cls.get("set") or []:
        actions.append(f"set {item}")
    if cls.get("is_priority"):
        if cls.get("priority_percent") is not None:
            actions.append(f"priority {cls['priority_percent']}%")
        elif cls.get("priority_kbps") is not None:
            actions.append(f"priority {cls['priority_kbps']} kbps")
        elif cls.get("priority_level") is not None:
            actions.append(f"priority level {cls['priority_level']}")
        else:
            actions.append("priority")
    if cls.get("police_cir_bps") is not None:
        actions.append(f"police cir {cls['police_cir_bps']} bps")
    elif cls.get("police_cir_percent") is not None:
        actions.append(f"police cir {cls['police_cir_percent']}%")
    if cls.get("bandwidth"):
        actions.append(f"bandwidth {cls['bandwidth']}")
    if cls.get("shape_bps") is not None:
        actions.append(f"shape {cls['shape_bps']} bps")
    return actions


def parse_policy_map_interface(text):
    """One record per attached policy-map instance.

    A child policy nested under a parent class is its own record, with
    parent_policy and parent_class set. Class-map indentation decides which
    policy a class belongs to: a class indented no deeper than the child's
    Service-policy line is back in the parent.
    """
    policies = []
    if not text or not text.strip():
        return policies
    interface = None
    stack = []          # [policy, service-policy indent]
    cls = None
    seen_match = False
    in_set = None       # indent of the QoS Set line while inside it
    in_police = False
    for raw in text.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if _CONTROL_PLANE_RE.match(raw):
            interface, stack, cls = "Control Plane", [], None
            continue
        m = _IFACE_LINE_RE.match(raw)
        if m and not _SERVICE_POLICY_RE.match(line):
            interface, stack, cls = canonical_ifname(m.group(1)), [], None
            continue

        m = _SERVICE_POLICY_RE.match(line)
        if m and interface:
            direction = (m.group(1) or "").lower()
            if direction:
                policy = _new_policy(interface, direction, m.group(2))
                stack = [[policy, indent]]
            else:
                while len(stack) > 1 and indent <= stack[-1][1]:
                    stack.pop()
                parent = stack[-1][0] if stack else None
                policy = _new_policy(
                    interface, parent["direction"] if parent else "",
                    m.group(2),
                    parent=parent["policy_name"] if parent else None,
                    parent_class=cls["class_name"] if cls else None)
                stack.append([policy, indent])
            policies.append(policy)
            cls, in_set, in_police = None, None, False
            continue
        if not stack:
            continue

        m = _CLASS_LINE_RE.match(line)
        if m:
            while len(stack) > 1 and indent <= stack[-1][1]:
                stack.pop()
            cls = _new_class(m.group(1), m.group(2))
            stack[-1][0]["classes"].append(cls)
            seen_match, in_set, in_police = False, None, False
            continue

        if line.lower().startswith("queue stats for all priority classes"):
            cls = None
            continue

        if cls is None:
            # Policy-level priority queue stats (Catalyst 9000).
            pq = stack[-1][0]["priority_queue"]
            m = _PRIORITY_LEVEL_RE.search(line)
            if m:
                pq["level"] = int(m.group(1))
            m = _TOTAL_DROPS_RE.search(line)
            if m:
                pq["drops"] = int(m.group(1))
            m = _BYTES_OUTPUT_RE.search(line)
            if m:
                pq["bytes_output"] = int(m.group(1))
            continue

        if in_set is not None:
            if indent > in_set:
                m = _SET_LINE_RE.match(line)
                if m:
                    cls["set"].append(f"{m.group(1).lower()} {m.group(2)}")
                continue
            in_set = None

        if line.startswith("Match:"):
            seen_match = True
            match = " ".join(line[len("Match:"):].split())
            if match:
                cls["match"].append(match)
            continue
        m = _PACKETS_RE.match(line)
        if m:
            if not seen_match and cls["packets"] is None:
                cls["packets"] = int(m.group(1))
                if m.group(2):
                    cls["bytes"] = int(m.group(2))
            continue
        m = _OFFERED_RE.search(line)
        if m:
            cls["offered_rate_bps"] = int(m.group(1))
            if m.group(2):
                cls["drop_rate_bps"] = int(m.group(2))
            continue
        if line.lower().startswith("qos set"):
            in_set = indent
            continue
        if line.lower().startswith("police"):
            in_police = True
            m = _POLICE_CIR_RE.search(line)
            if m:
                _set_police(cls, m)
            continue
        if line.lower().startswith("priority"):
            cls["is_priority"] = True
            m = _PRIORITY_PCT_RE.search(line)
            if m:
                cls["priority_percent"] = int(m.group(1))
                if m.group(2):
                    cls["priority_kbps"] = int(m.group(2))
            else:
                m = _PRIORITY_KBPS_RE.search(line)
                if m:
                    cls["priority_kbps"] = int(m.group(1))
            m = _PRIORITY_LEVEL_RE.search(line)
            if m:
                cls["priority_level"] = int(m.group(1))
            m = _BW_EXCEED_RE.search(line)
            if m:
                cls["priority_drops"] = int(m.group(1))
            continue
        m = _QUEUE_STATS_RE.search(line)
        if m:
            cls["queue_depth"] = int(m.group(1))
            _add_drops(cls, int(m.group(2)))
            continue
        m = _TOTAL_DROPS_RE.search(line)
        if m:
            _add_drops(cls, int(m.group(1)))
            continue
        m = _PKTS_OUTPUT_RE.search(line)
        if m:
            cls["pkts_output"] = int(m.group(1))
            continue
        m = _BANDWIDTH_RE.match(line)
        if m:
            unit = m.group(3) or ("%" if "(%)" in line else "")
            prefix = "remaining " if m.group(1) else ""
            cls["bandwidth"] = f"{prefix}{m.group(2)}{unit if unit == '%' else ' ' + unit}".strip()
            continue
        m = _SHAPE_RE.match(line)
        if m:
            cls["shape_bps"] = int(m.group(1))
            continue
        m = _QUEUE_LIMIT_RE.match(line)
        if m:
            cls["queue_limit"] = int(m.group(1))
            continue
        if in_police:
            m = _POLICE_CIR_RE.match(line)
            if m and cls["police_cir_bps"] is None and cls["police_cir_percent"] is None:
                _set_police(cls, m)
                continue
            m = _POLICE_EXCEEDED_RE.match(line)
            if m:
                cls["police_exceeded"] = int(m.group(1))
    for policy in policies:
        for c in policy["classes"]:
            c["action"] = class_actions(c)
    return policies


def _set_police(cls, m):
    if m.group(2) == "%":
        cls["police_cir_percent"] = int(m.group(1))
    else:
        cls["police_cir_bps"] = int(m.group(1))


# ---------------------------------------------------------------------------
# show policy-map / show class-map (definitions)
# ---------------------------------------------------------------------------

_POLICY_DEF_RE = re.compile(r"^\s*Policy Map\s+(?:type\s+\S+\s+)?(\S+)", re.I)
_CLASS_DEF_RE = re.compile(r"^\s*Class\s+(\S+)", re.I)
_CLASS_MAP_DEF_RE = re.compile(
    r"^\s*Class Map\s+(?:type\s+\S+\s+)?(?:(match-any|match-all)\s+)?(\S+)", re.I)
_ACL_REF_RE = re.compile(r"access-group\s+(?:name\s+)?(\S+)", re.I)


def body_hash(lines):
    """Short stable hash of a normalised definition body."""
    text = "\n".join(" ".join(str(l).split()) for l in lines)
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def parse_policy_maps(text):
    """Policy-map definitions as the device parsed them."""
    policies = []
    current = None
    cls = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _POLICY_DEF_RE.match(raw)
        if m:
            current = {"name": m.group(1), "classes": []}
            policies.append(current)
            cls = None
            continue
        if current is None:
            continue
        m = _CLASS_DEF_RE.match(raw)
        if m and not line.lower().startswith("class-map"):
            cls = {"name": m.group(1), "actions": []}
            current["classes"].append(cls)
            continue
        if cls is not None:
            cls["actions"].append(" ".join(line.split()))
    for p in policies:
        body = []
        for c in p["classes"]:
            body.append(f"class {c['name']}")
            body.extend(c["actions"])
        p["hash"] = body_hash(body)
    return policies


def parse_class_maps(text):
    """Class-map definitions: match type, match lines and ACLs referenced."""
    classes = []
    current = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _CLASS_MAP_DEF_RE.match(raw)
        if m:
            name = re.sub(r"\(id\s*\d+\)$", "", m.group(2)).strip()
            current = {"name": name, "match_type": (m.group(1) or "").lower(),
                       "match": [], "acls": []}
            classes.append(current)
            continue
        if current is None:
            continue
        if line.lower().startswith("match "):
            match = " ".join(line[len("match "):].split())
            current["match"].append(match)
            m = _ACL_REF_RE.search(match)
            if m:
                current["acls"].append(m.group(1))
    for c in classes:
        c["hash"] = body_hash([c["match_type"]] + c["match"])
    return classes


# ---------------------------------------------------------------------------
# Classic Catalyst MLS QoS
# ---------------------------------------------------------------------------

_MLS_IFACE_RE = re.compile(r"^([A-Za-z][\w./-]*\d)\s*(?:\(.*\))?\s*$")

# IOS defaults for the 2960/3560/3750 family. Auto-QoS and manual tuning
# both change these.
DEFAULT_QUEUE_SET = {
    "buffers": [25, 25, 25, 25],
    "threshold1": [100, 100, 100, 100],
    "threshold2": [100, 100, 100, 100],
    "reserved": [50, 50, 50, 50],
    "maximum": [400, 400, 400, 400],
}


def _default_dscp_queue(dscp):
    if dscp < 16:
        return "02-01"
    if dscp < 32:
        return "03-01"
    if dscp < 40:
        return "04-01"
    if dscp < 48:
        return "01-01"
    return "04-01"


DEFAULT_DSCP_OUTPUT_Q = {str(d): _default_dscp_queue(d) for d in range(64)}
DEFAULT_COS_OUTPUT_Q = {"0": "2-1", "1": "2-1", "2": "3-1", "3": "3-1",
                        "4": "4-1", "5": "1-1", "6": "4-1", "7": "4-1"}


def parse_mls_qos(text):
    """Global state: QoS enabled and DSCP rewrite. None when not reported."""
    result = {"mls_qos_enabled": None, "dscp_rewrite": None}
    for line in (text or "").splitlines():
        low = line.strip().lower()
        if low.startswith("qos is "):
            result["mls_qos_enabled"] = "enabled" in low and "disabled" not in low
        elif "dscp rewrite is" in low:
            result["dscp_rewrite"] = low.endswith("enabled")
    return result


def _blocks(text):
    """(interface, lines) for outputs that start each port with its name."""
    name, lines = None, []
    for raw in (text or "").splitlines():
        m = _MLS_IFACE_RE.match(raw)
        if m and not raw.startswith(" "):
            if name:
                yield name, lines
            name, lines = canonical_ifname(m.group(1)), []
            continue
        if name:
            lines.append(raw)
    if name:
        yield name, lines


def parse_mls_interface(text):
    """Per-port trust state, trust device and attached policies."""
    result = {}
    for name, lines in _blocks(text):
        entry = {}
        for raw in lines:
            if ":" not in raw:
                continue
            key, val = (p.strip() for p in raw.split(":", 1))
            key = key.lower()
            if key == "trust state":
                entry["trust_state"] = val
            elif key == "trust mode":
                entry["trust_mode"] = val
            elif key == "trust device":
                entry["trust_device"] = val
            elif key == "attached policy-map for ingress":
                entry["ingress_policy"] = val
            elif key == "attached policy-map for egress":
                entry["egress_policy"] = val
        if entry:
            result[name] = entry
    return result


def parse_mls_queueing(text):
    """Per-port egress expedite queue and queue-set."""
    result = {}
    for name, lines in _blocks(text):
        entry = {}
        for raw in lines:
            low = raw.strip().lower()
            if low.startswith("egress priority queue"):
                entry["expedite_queue"] = low.rstrip().endswith("enabled")
            elif "mapped to qset" in low:
                m = re.search(r"qset\s*:\s*(\d+)", low)
                if m:
                    entry["queue_set"] = int(m.group(1))
            elif low.startswith("shaped queue weights"):
                entry["shaped_weights"] = raw.split(":", 1)[-1].strip()
            elif low.startswith("shared queue weights"):
                entry["shared_weights"] = raw.split(":", 1)[-1].strip()
        if entry:
            result[name] = entry
    return result


_RANGE_ROW_RE = re.compile(r"^\s*(\d+)\s*-\s*(\d+)\s*:\s*([\d\s]+)$")
_QUEUE_ROW_RE = re.compile(r"^\s*queue\s*(\d+)\s*:\s*([\d\s]+)$", re.I)
_POLICER_RE = re.compile(r"Inprofile:\s*(\d+)\s*OutofProfile:\s*(\d+)", re.I)


def parse_mls_statistics(text):
    """Per-port DSCP/CoS counters and per-queue enqueued/dropped packets.

    The statistics output numbers egress queues 0-3; they are queues 1-4 in
    the srr-queue configuration and the output-queue maps, so they are
    stored 1-based here to line up with both.
    """
    result = {}
    for name, lines in _blocks(text):
        entry = {"dscp_in": {}, "dscp_out": {}, "cos_in": {}, "cos_out": {},
                 "enqueued": {}, "dropped": {}}
        section = None
        for raw in lines:
            low = raw.strip().lower()
            if low.startswith("dscp: incoming"):
                section = "dscp_in"
                continue
            if low.startswith("dscp: outgoing"):
                section = "dscp_out"
                continue
            if low.startswith("cos: incoming"):
                section = "cos_in"
                continue
            if low.startswith("cos: outgoing"):
                section = "cos_out"
                continue
            if low.startswith("output queues enqueued"):
                section = "enqueued"
                continue
            if low.startswith("output queues dropped"):
                section = "dropped"
                continue
            m = _POLICER_RE.search(raw)
            if m:
                entry["policer_in_profile"] = int(m.group(1))
                entry["policer_out_of_profile"] = int(m.group(2))
                continue
            if section in ("enqueued", "dropped"):
                m = _QUEUE_ROW_RE.match(raw)
                if m:
                    total = sum(int(v) for v in m.group(2).split())
                    entry[section][str(int(m.group(1)) + 1)] = total
                continue
            if section:
                m = _RANGE_ROW_RE.match(raw)
                if m:
                    start = int(m.group(1))
                    for offset, val in enumerate(m.group(3).split()):
                        if int(val):
                            entry[section][str(start + offset)] = int(val)
        result[name] = entry
    return result


def parse_queue_sets(text):
    """Queue-set buffer and threshold tables, keyed by queue-set number."""
    sets = {}
    current = None
    for raw in (text or "").splitlines():
        m = re.match(r"^\s*Queueset:\s*(\d+)", raw, re.I)
        if m:
            current = sets.setdefault(m.group(1), {})
            continue
        if current is None or ":" not in raw:
            continue
        key, val = raw.split(":", 1)
        key = key.strip().lower()
        if key in DEFAULT_QUEUE_SET:
            nums = [int(v) for v in val.split() if v.isdigit()]
            if nums:
                current[key] = nums
    return sets


def queue_sets_tuned(sets):
    """True when any queue-set differs from the IOS default, None if unknown."""
    if not sets:
        return None
    for table in sets.values():
        for key, default in DEFAULT_QUEUE_SET.items():
            if key in table and table[key] != default:
                return True
    return False


_DSCP_MAP_ROW_RE = re.compile(r"^\s*(\d)\s*:\s*((?:\d+-\d+\s*)+)$")


def parse_dscp_output_q(text):
    """DSCP -> 'queue-threshold' as shown, e.g. {'46': '01-01'}."""
    result = {}
    for raw in (text or "").splitlines():
        m = _DSCP_MAP_ROW_RE.match(raw)
        if not m:
            continue
        tens = int(m.group(1))
        for units, token in enumerate(m.group(2).split()):
            dscp = tens * 10 + units
            if dscp < 64:
                result[str(dscp)] = token
    return result


def parse_cos_output_q(text):
    """CoS -> 'queue-threshold' as shown, e.g. {'5': '1-1'}."""
    cos_values, queues = [], []
    for raw in (text or "").splitlines():
        low = raw.strip().lower()
        if low.startswith("cos:"):
            cos_values = [v for v in low.split(":", 1)[1].split() if v.isdigit()]
        elif low.startswith("queue-threshold:"):
            queues = low.split(":", 1)[1].split()
    return dict(zip(cos_values, queues))


def map_queue(token):
    """Queue number from a map token such as '01-01' or '1-1'."""
    try:
        return int(str(token).split("-")[0])
    except (ValueError, IndexError):
        return None


def parse_auto_qos(text):
    """Auto-QoS macros: global lines and per-interface lines."""
    result = {"global": [], "interfaces": {}}
    current = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        m = _MLS_IFACE_RE.match(raw)
        if m and not low.startswith("auto"):
            current = canonical_ifname(m.group(1))
            continue
        if low.startswith("auto qos") or low.startswith("auto-qos"):
            macro = " ".join(line.split())
            if current:
                result["interfaces"].setdefault(current, []).append(macro)
            else:
                result["global"].append(macro)
    return result


# ---------------------------------------------------------------------------
# Catalyst 9000 hardware queue counters
# ---------------------------------------------------------------------------

_FED_CMD_RE = re.compile(
    r"^show platform hardware fed switch (\S+) qos queue stats interface (\S+)$")
_FED_ROW_RE = re.compile(r"^\s*(\d{1,2})\s+(\d+(?:\s+\d+){3,})\s*$")


def parse_fed_queue_stats(text):
    """Per-queue enqueued and dropped bytes from one port's fed output.

    Enqueue rows are Q, Buffers, TH0, TH1, TH2, Qpolicer; drop rows are Q,
    TH0, TH1, TH2, SBufDrop, QebDrop, QpolicerDrop. Queue ids stay 0-based,
    as the device numbers them.
    """
    queues = {}
    section = None
    for raw in (text or "").splitlines():
        low = raw.lower()
        if "enqueue" in low and "counters" in low:
            section = "enqueue"
            continue
        if "drop" in low and "counters" in low:
            section = "drop"
            continue
        if not section:
            continue
        m = _FED_ROW_RE.match(raw)
        if not m:
            continue
        qid = int(m.group(1))
        vals = [int(v) for v in m.group(2).split()]
        q = queues.setdefault(qid, {"queue_id": qid, "enqueued": 0, "dropped": 0})
        if section == "enqueue":
            q["enqueued"] += sum(vals[1:4])
        else:
            q["dropped"] += sum(vals)
    return [queues[k] for k in sorted(queues)]


# ---------------------------------------------------------------------------
# Joining with the rest of the device's data
# ---------------------------------------------------------------------------

_SEP_PHONE_RE = re.compile(r"^SEP[0-9A-F]{12}$", re.I)
_AP_PLATFORM_RE = re.compile(r"\bAIR-|\bC91\d\d|\bCW91\d\d|access point", re.I)


def neighbor_class(neighbor):
    """phone / ap / vg / router / switch / firewall / other for a neighbour."""
    platform = neighbor.get("remote_platform") or ""
    name = neighbor.get("remote_device") or ""
    caps = str(neighbor.get("remote_capabilities") or "")
    caps_up = {c.strip().upper() for c in re.split(r"[\s,]+", caps) if c.strip()}
    if _SEP_PHONE_RE.match(name.split(".")[0]) or "phone" in platform.lower() \
            or "PHONE" in caps_up:
        return "phone"
    if any(k in platform.lower() for k in ("palo alto", "asa", "firepower",
                                           "fortigate")):
        return "firewall"
    by_model = category_for_model(platform)
    if by_model == "voice-gateway":
        return "vg"
    if by_model in ("router", "switch"):
        return by_model
    if _AP_PLATFORM_RE.search(platform) or caps_up & {"WLAN", "W", "AP"}:
        return "ap"
    if caps_up & {"SWITCH", "S", "BRIDGE", "B"}:
        return "switch"
    if caps_up & {"ROUTER", "R"}:
        return "router"
    return "other"


UPLINK_CLASSES = frozenset({"switch", "router", "firewall"})
VOICE_CLASSES = frozenset({"phone", "vg", "ap"})


def _cd_parsed(context, name):
    cd = (context or {}).get("collector_data") or {}
    return (cd.get(name) or {}).get("parsed") or {}


def port_context(context):
    """Neighbours, trunks, voice VLANs and STP root ports by canonical name."""
    neighbors = {}
    for n in _cd_parsed(context, "cdp_lldp").get("neighbors", []) or []:
        local = canonical_ifname(n.get("local_intf"))
        if local and local not in neighbors:
            neighbors[local] = {"neighbor": n.get("remote_device") or "",
                                "neighbor_platform": n.get("remote_platform") or "",
                                "neighbor_class": neighbor_class(n)}
    trunks, voice_vlans = set(), {}
    for sp in _cd_parsed(context, "switchport").get("switchports", []) or []:
        name = canonical_ifname(sp.get("interface"))
        if not name:
            continue
        if "trunk" in str(sp.get("operational_mode") or "").lower():
            trunks.add(name)
        vv = str(sp.get("voice_vlan") or "").strip()
        if vv and vv.lower() != "none":
            voice_vlans[name] = vv
    root_ports = {canonical_ifname(r.get("port"))
                  for r in _cd_parsed(context, "stp_detail").get("stp_root_summary", []) or []
                  if r.get("port")}
    return {"neighbors": neighbors, "trunks": trunks, "voice_vlans": voice_vlans,
            "root_ports": root_ports}


def stack_member_count(context):
    inv = _cd_parsed(context, "device_inventory")
    return len(inv.get("stack_members") or [])


def select_queue_ports(context, cap=QUEUE_STATS_CAP):
    """Ports worth per-port queue counters: uplinks first, then voice ports.

    Returns (selected, eligible_count). Port-channels are skipped; their
    members show up individually through CDP.
    """
    ports = port_context(context)
    ranked = {}
    for name, n in ports["neighbors"].items():
        rank = 0 if n["neighbor_class"] in UPLINK_CLASSES else (
            1 if n["neighbor_class"] in VOICE_CLASSES else None)
        if rank is not None:
            ranked[name] = rank
    for name in ports["trunks"]:
        ranked.setdefault(name, 0)
    eligible = sorted((n for n in ranked if not n.lower().startswith("port-channel")),
                      key=lambda n: (ranked[n], n))
    return eligible[:cap], len(eligible)


def fed_switch_keyword(interface, stacked):
    """'switch N' for a stack member's port, 'switch active' otherwise."""
    if stacked:
        m = re.search(r"(\d+)/", interface)
        if m:
            return m.group(1)
    return "active"


def _queuing_classes(policy):
    """Classes that get a hardware queue, in the order they get one."""
    return [c for c in policy.get("classes", [])
            if c.get("is_priority") or c.get("bandwidth") or c.get("shape_bps")
            or c.get("queue_limit") is not None
            or c.get("class_name") == "class-default"]


def join_device(parsed, context, family):
    """Add neighbour, trunk, uplink and queue-priority detail to parsed data."""
    ports = port_context(context)
    policies = parsed.get("policies", [])
    mls_if = parsed.pop("_mls_interface", {})
    queueing = parsed.pop("_mls_queueing", {})
    stats = parsed.pop("_mls_statistics", {})
    fed = parsed.pop("_fed_queues", {})
    auto = parsed.get("auto_qos", {}).get("interfaces", {})

    top = {}
    for p in policies:
        if p.get("parent_policy") or p["interface"] == "Control Plane":
            continue
        top.setdefault((p["interface"], p["direction"]), p)

    names = (set(mls_if) | set(queueing) | set(stats) | set(auto) | set(fed)
             | {i for i, _ in top} | set(ports["neighbors"]) | set(ports["voice_vlans"]))
    interfaces = []
    for name in sorted(names):
        if name == "Control Plane":
            continue
        mls = mls_if.get(name, {})
        q = queueing.get(name, {})
        nb = ports["neighbors"].get(name, {})
        ingress = (top.get((name, "input")) or {}).get("policy_name") or mls.get("ingress_policy") or ""
        egress = (top.get((name, "output")) or {}).get("policy_name") or mls.get("egress_policy") or ""
        nclass = nb.get("neighbor_class") or "none"
        interfaces.append({
            "interface": name,
            "trust_state": mls.get("trust_state", ""),
            "trust_mode": mls.get("trust_mode", ""),
            "trust_device": mls.get("trust_device", ""),
            "auto_qos_macro": "; ".join(auto.get(name, [])),
            "queue_set": q.get("queue_set"),
            "expedite_queue": q.get("expedite_queue"),
            "ingress_policy": ingress,
            "egress_policy": egress,
            "neighbor": nb.get("neighbor", ""),
            "neighbor_platform": nb.get("neighbor_platform", ""),
            "neighbor_class": nclass,
            "voice_vlan": ports["voice_vlans"].get(name, ""),
            "is_trunk": name in ports["trunks"],
            "is_uplink": (nclass in UPLINK_CLASSES or name in ports["root_ports"]
                          or (name in ports["trunks"] and nclass not in VOICE_CLASSES
                              and nclass != "none")),
        })

    queues, dscp = [], []
    for name, entry in sorted(stats.items()):
        expedite = (queueing.get(name) or {}).get("expedite_queue")
        for qid in sorted(set(entry["enqueued"]) | set(entry["dropped"]), key=int):
            queues.append({"interface": name, "queue_id": int(qid),
                           "enqueued": entry["enqueued"].get(qid, 0),
                           "dropped": entry["dropped"].get(qid, 0),
                           "is_priority": bool(expedite) and qid == "1",
                           "unit": "packets", "source": "mls"})
        for direction in ("in", "out"):
            if entry[f"dscp_{direction}"] or entry[f"cos_{direction}"]:
                dscp.append({"interface": name, "direction": direction,
                             "dscp": entry[f"dscp_{direction}"],
                             "cos": entry[f"cos_{direction}"]})
    for name, rows in sorted(fed.items()):
        egress = top.get((name, "output"))
        prio_ids = set()
        if egress:
            for idx, c in enumerate(_queuing_classes(egress)):
                if c.get("is_priority"):
                    prio_ids.add(idx)
        for row in rows:
            queues.append({"interface": name, "queue_id": row["queue_id"],
                           "enqueued": row["enqueued"], "dropped": row["dropped"],
                           "is_priority": row["queue_id"] in prio_ids,
                           "unit": "bytes", "source": "fed"})

    parsed["interfaces"] = interfaces
    parsed["queues"] = queues
    parsed["dscp_counters"] = dscp
    glob = parsed.setdefault("qos_global", {})
    glob["platform_family"] = family
    glob["auto_qos_applied"] = bool(auto or parsed.get("auto_qos", {}).get("global"))
    return parsed


class QosCollector(BaseCollector):
    name = "qos"
    label = "QoS"
    description = ("Collect QoS policy counters, trust, queueing and DSCP "
                   "counters, and class/policy definitions")
    enabled_by_default = True
    optional = True
    needs_custom_collect = True
    needs_device_context = True
    unsupported_platforms = frozenset({"cisco_wlc", "vyos", "watchguard_fireware",
                                       "paloalto_panos"})

    def get_commands(self, device_type: str) -> list[str]:
        return commands_for(device_type, platform_family(device_type))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if not raw_outputs:
            return {"not_applicable": True,
                    "reason": f"qos: no commands for {device_type}"}
        get = raw_outputs.get
        mls = parse_mls_qos(get(MLS_QOS, ""))
        sets = parse_queue_sets(get(MLS_QUEUE_SET, ""))
        fed = {}
        for cmd, out in raw_outputs.items():
            m = _FED_CMD_RE.match(cmd)
            if m and out:
                fed[canonical_ifname(m.group(2))] = parse_fed_queue_stats(out)
        return {
            "qos_global": {
                "platform_family": FAMILY_UNKNOWN,
                "mls_qos_enabled": mls["mls_qos_enabled"],
                "dscp_rewrite": mls["dscp_rewrite"],
                "queue_set_tuned": queue_sets_tuned(sets),
            },
            "policies": parse_policy_map_interface(get(POLICY_MAP_INTERFACE, "")),
            "policy_definitions": parse_policy_maps(
                get(POLICY_MAP, "") or get("show policy-map type qos", "")),
            "class_definitions": parse_class_maps(
                get(CLASS_MAP, "") or get("show class-map type qos", "")),
            "auto_qos": parse_auto_qos(get(AUTO_QOS, "")),
            "queue_sets": sets,
            "maps": {"dscp_output_q": parse_dscp_output_q(get(MLS_DSCP_MAP, "")),
                     "cos_output_q": parse_cos_output_q(get(MLS_COS_MAP, ""))},
            "_mls_interface": parse_mls_interface(get(MLS_INTERFACE, "")),
            "_mls_queueing": parse_mls_queueing(get(MLS_QUEUEING, "")),
            "_mls_statistics": parse_mls_statistics(get(MLS_STATISTICS, "")),
            "_fed_queues": fed,
        }

    def collect(self, connection, device_type: str, context=None) -> dict:
        if device_type in self.unsupported_platforms:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"qos does not apply to {device_type}"}}
        context = context or {}
        family = platform_family(device_type, context.get("model", ""),
                                 context.get("router", False))
        cmds = commands_for(device_type, family)
        if not cmds:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"no commands defined for {device_type}"}}
        selection = None
        if family == FAMILY_CAT9K:
            selected, eligible = select_queue_ports(context)
            stacked = stack_member_count(context) > 1
            cmds = cmds + [FED_QUEUE_STATS.format(
                switch=fed_switch_keyword(p, stacked), intf=p) for p in selected]
            selection = {"selected": selected, "eligible": eligible,
                         "cap": QUEUE_STATS_CAP, "capped": eligible > len(selected)}

        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd, read_timeout=READ_TIMEOUT)
            except Exception as e:
                raw_outputs[cmd] = send_failure_output(e)

        parsed = self.parse_collected(raw_outputs, device_type)
        if not parsed.get("not_applicable") and not parsed.get("collector_failed"):
            parsed = join_device(parsed, context, family)
            if selection is not None:
                parsed["queue_stats_ports"] = selection
        else:
            for key in ("_mls_interface", "_mls_queueing", "_mls_statistics", "_fed_queues"):
                parsed.pop(key, None)
        return {"raw": raw_outputs, "parsed": parsed}
