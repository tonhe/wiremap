"""
Interface counters collector: errors, CRC, drops and last input/output from
the full show interfaces output.

The output runs to thousands of lines on a large stack, so it is sent with
a longer read timeout than the batch path's 30 seconds.
"""
import re

from .base import BaseCollector
from .errors import send_failure_output

_IOS = "show interfaces"
_NXOS = "show interface"

_COMMANDS = {
    "cisco_ios": [_IOS],
    "cisco_xe": [_IOS],
    "cisco_nxos": [_NXOS],
}

READ_TIMEOUT = 180

_HEADER_RE = re.compile(
    r"^(?P<intf>[A-Za-z][\w/.:-]*\d)\s+is\s+(?P<status>administratively down|up|down|"
    r"deleted|disabled|err-disabled|testing|dormant)(?:\s*\([^)]*\))?"
    r"(?:,\s*line protocol is\s+(?P<proto>\w+))?", re.I)

_INT_FIELDS = {
    "input_packets": [r"(\d+) packets input", r"(\d+) input packets"],
    "output_packets": [r"(\d+) packets output", r"(\d+) output packets"],
    "input_errors": [r"(\d+) input errors?"],
    "crc": [r"(\d+) CRC"],
    "frame": [r"(\d+) frame"],
    "runts": [r"(\d+) runts"],
    "giants": [r"(\d+) giants"],
    "output_errors": [r"(\d+) output errors?"],
    "collisions": [r"(\d+) collisions?"],
    "interface_resets": [r"(\d+) interface resets"],
    "output_drops": [r"Total output drops:\s*(\d+)", r"(\d+) output discard"],
    "input_drops": [r"Input queue:\s*\d+/\d+/(\d+)/\d+", r"(\d+) input discard"],
}
_INT_RES = {k: [re.compile(p) for p in pats] for k, pats in _INT_FIELDS.items()}


def _block_value(block, regexes):
    for rx in regexes:
        m = rx.search(block)
        if m:
            return int(m.group(1))
    return None


def parse_interfaces(text):
    """One row per interface; counters missing from the output are None."""
    rows = []
    if not text or not text.strip():
        return rows
    current = None
    lines = []

    def flush():
        if current is None:
            return
        block = "\n".join(lines)
        row = dict(current)
        for key, regexes in _INT_RES.items():
            row[key] = _block_value(block, regexes)
        m = re.search(r"Description:\s*(.+)", block)
        row["description"] = m.group(1).strip() if m else ""
        m = re.search(r"Last input ([^,]+), output ([^,]+),", block)
        row["last_input"] = m.group(1).strip() if m else ""
        row["last_output"] = m.group(2).strip() if m else ""
        m = re.search(r'Last clearing of "show interface" counters\s+(\S+)', block)
        row["counters_cleared"] = m.group(1) if m else ""
        m = re.search(r"Last link flapped\s+(\S+)", block)
        row["last_flap"] = m.group(1) if m else ""
        # The first rate line is the load-interval one (5 minute by default).
        m = re.search(r"input rate (\d+) bits/sec", block)
        row["input_rate_bps"] = int(m.group(1)) if m else None
        m = re.search(r"output rate (\d+) bits/sec", block)
        row["output_rate_bps"] = int(m.group(1)) if m else None
        m = re.search(r"Queueing strategy:\s*(.+)", block)
        row["queueing_strategy"] = m.group(1).strip() if m else ""
        rows.append(row)

    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if m and not line.startswith(" "):
            flush()
            current = {"interface": m.group("intf"),
                       "status": m.group("status").lower(),
                       "protocol": (m.group("proto") or "").lower()}
            lines = []
            continue
        if current is not None:
            lines.append(line)
    flush()
    return rows


class InterfaceCountersCollector(BaseCollector):
    name = "interface_counters"
    label = "Interface Counters"
    description = "Collect per-interface errors, CRC, drops and last input/output"
    enabled_by_default = True
    needs_custom_collect = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, []))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if not raw_outputs:
            return {"not_applicable": True,
                    "reason": f"interface_counters: no commands for {device_type}"}
        text = raw_outputs.get(_IOS) or raw_outputs.get(_NXOS) or ""
        return {"interfaces": parse_interfaces(text)}

    def collect(self, connection, device_type: str) -> dict:
        cmds = self.get_commands(device_type)
        if not cmds:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"no commands defined for {device_type}"}}
        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd, read_timeout=READ_TIMEOUT)
            except Exception as e:
                raw_outputs[cmd] = send_failure_output(e)
        return {"raw": raw_outputs,
                "parsed": self.parse_collected(raw_outputs, device_type)}
