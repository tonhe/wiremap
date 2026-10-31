"""
Environment collector: power supplies, fans, temperature and PoE budget.

Raw output is the priority. The parse is a cheap line classifier that pulls
a component, a name and a status out of the common Catalyst, ISR/ASR and
Nexus layouts, enough to flag a failed PSU or fan without a per-model
parser.
"""
import re

from .base import BaseCollector

_ENV_ALL = "show environment all"
_ENV = "show environment"
_POWER_INLINE = "show power inline"

_COMMANDS = {
    "cisco_ios": [_ENV_ALL, _POWER_INLINE],
    "cisco_xe": [_ENV_ALL, _POWER_INLINE],
    "cisco_nxos": [_ENV],
}

# Statuses that mean the component is healthy, absent by design, or faulted.
_OK = {"ok", "normal", "good", "green", "on", "powered-on", "active"}
_ABSENT = {"not present", "absent", "not installed", "empty"}
_FAULT = {"fail", "failed", "failure", "faulty", "bad", "not ok", "critical",
          "major", "minor", "warning", "shutdown", "no input power",
          "not responding", "red", "yellow", "powered-off", "off",
          "fan-fail", "alarm"}
_STATUS_WORDS = _OK | _ABSENT | _FAULT

# "Switch 1 FAN 1 is OK", "FAN PS-1 is NOT PRESENT", "TEMPERATURE is OK"
_IS_RE = re.compile(r"^(?P<name>.*?)\s+is\s+(?P<status>[A-Za-z][A-Za-z -]*?)\s*\.?$")
# "Temperature State: GREEN"
_TEMP_STATE_RE = re.compile(r"^(?:(?P<who>.*?)\s+)?Temperature State\s*:\s*(?P<status>\w+)",
                            re.I)
# Catalyst PSU table: "1A  PWR-C1-715WAC  DCB0000X0AA OK  Good  Good  715"
_CAT_PSU_RE = re.compile(
    r"^(?P<sw>\d+[A-Z]?)\s+(?:(?P<absent>Not Present)|(?P<pid>\S+)\s+(?P<serial>\S+)?\s*"
    r"(?P<status>OK|Bad|Faulty|No Input Power|Not Responding|Disabled|Off)\b)",
    re.I)
_CAT_PSU_HEADER = re.compile(r"^SW\s+PID\s+Serial#", re.I)


def _status_kind(status):
    s = status.strip().lower()
    if s in _OK:
        return "ok"
    if s in _ABSENT:
        return "absent"
    if s in _FAULT or s.startswith("fail") or s.startswith("not ok"):
        return "fault"
    return ""


def _component_for(name, section=""):
    n = name.lower()
    if "fan" in n:
        return "fan"
    if re.search(r"temp|inlet|outlet|hotspot|celsius", n):
        return "temperature"
    if re.search(r"\bps\b|ps-?\d|pwr|power|psu|\bpem|v(?:in|out)|i(?:in|out)", n):
        return "power"
    return section or "sensor"


def _section_for(line):
    s = line.strip().rstrip(":").lower()
    if s in ("power supply", "power supplies", "power"):
        return "power"
    if s in ("fan", "fans", "fan status"):
        return "fan"
    if s in ("temperature", "temperatures"):
        return "temperature"
    return None


def parse_environment(text):
    """Return a list of {component, name, status, reading, state} rows.

    state is ok, absent or fault. Lines that carry no recognisable status
    are skipped; the raw output keeps everything.
    """
    items = []
    if not text or not text.strip():
        return items
    section = ""
    in_cat_psu = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= set("-* "):
            continue
        sec = _section_for(stripped)
        if sec:
            section = sec
            in_cat_psu = False
            continue
        if _CAT_PSU_HEADER.match(stripped):
            in_cat_psu = True
            continue
        if in_cat_psu:
            m = _CAT_PSU_RE.match(stripped)
            if m:
                status = "Not Present" if m.group("absent") else m.group("status")
                items.append({"component": "power",
                              "name": f"PS {m.group('sw')} {m.group('pid') or ''}".strip(),
                              "status": status, "reading": "",
                              "state": _status_kind(status)})
                continue
            in_cat_psu = False

        m = _TEMP_STATE_RE.match(stripped)
        if m:
            status = m.group("status")
            items.append({"component": "temperature",
                          "name": (m.group("who") or "System").strip(),
                          "status": status, "reading": "",
                          "state": _status_kind(status)})
            continue

        m = _IS_RE.match(stripped)
        if m and _status_kind(m.group("status")):
            name = m.group("name").rstrip(":").strip()
            if re.search(r"fan|temp|power|ps\b|ps-|pwr|supply|rps", name, re.I):
                items.append({"component": _component_for(name, section),
                              "name": name, "status": m.group("status").strip(),
                              "reading": "",
                              "state": _status_kind(m.group("status"))})
                continue

        # Column layouts (ISR/ASR sensor table, Nexus PSU/fan/temp tables):
        # fields are separated by two or more spaces.
        tokens = re.split(r"\s{2,}", stripped)
        if len(tokens) < 3:
            continue
        for idx in range(1, len(tokens)):
            kind = _status_kind(tokens[idx])
            if not kind:
                continue
            name = " ".join(tokens[:min(idx, 2)])
            if re.match(r"^(slot|module|fan|power|sensor)\b", tokens[0], re.I) \
                    and not re.search(r"\d", tokens[0]):
                break  # a header row that happens to contain "Status"
            reading = tokens[idx + 1] if idx + 1 < len(tokens) else ""
            if reading.startswith("("):
                reading = ""
            items.append({"component": _component_for(" ".join(tokens[:idx]), section),
                          "name": name, "status": tokens[idx],
                          "reading": reading, "state": kind})
            break
    return items


_BUDGET_RE = re.compile(
    r"Available\s*:\s*([\d.]+)\s*\(w\)\s*Used\s*:\s*([\d.]+)\s*\(w\)\s*"
    r"Remaining\s*:\s*(-?[\d.]+)", re.I)
_MODULE_BUDGET_RE = re.compile(r"^\s*(\d+)\s+([\d.]+)\s+([\d.]+)\s+(-?[\d.]+)\s*$")
_POE_PORT_RE = re.compile(
    r"^(?P<intf>[A-Za-z][\w/.-]*\d)\s+(?P<admin>auto|static|off|never|consumer)\s+"
    r"(?P<oper>on|off|faulty|power-deny|err-disable|errdisable|\S+)", re.I)


def parse_power_inline(text):
    """PoE budget per module and port counts by operational state."""
    result = {"budgets": [], "ports_by_state": {}, "problem_ports": []}
    if not text or not text.strip():
        return result
    m = _BUDGET_RE.search(text)
    if m:
        result["budgets"].append({"module": "", "available_w": float(m.group(1)),
                                  "used_w": float(m.group(2)),
                                  "remaining_w": float(m.group(3))})
    for line in text.splitlines():
        mm = _MODULE_BUDGET_RE.match(line)
        if mm:
            result["budgets"].append({"module": mm.group(1),
                                      "available_w": float(mm.group(2)),
                                      "used_w": float(mm.group(3)),
                                      "remaining_w": float(mm.group(4))})
            continue
        pm = _POE_PORT_RE.match(line.strip())
        if pm:
            oper = pm.group("oper").lower()
            result["ports_by_state"][oper] = result["ports_by_state"].get(oper, 0) + 1
            if oper in ("faulty", "power-deny", "err-disable", "errdisable"):
                result["problem_ports"].append({"interface": pm.group("intf"),
                                                "oper": oper})
    return result


class EnvironmentCollector(BaseCollector):
    name = "environment"
    label = "Environment & PoE"
    description = "Collect power supply, fan, temperature and PoE budget state"
    enabled_by_default = True
    # A router has no PoE budget to report.
    switching_commands = frozenset({_POWER_INLINE})

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, []))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if not raw_outputs:
            return {"not_applicable": True,
                    "reason": f"environment: no commands for {device_type}"}
        env_text = raw_outputs.get(_ENV_ALL) or raw_outputs.get(_ENV) or ""
        items = parse_environment(env_text)
        return {
            "items": items,
            "faults": [i for i in items if i["state"] == "fault"],
            "power_inline": parse_power_inline(raw_outputs.get(_POWER_INLINE, "")),
        }
