"""
CPU and memory collector.

The CPU utilisation line gives the 5 second / 1 minute / 5 minute load;
cpu history is kept raw for the 72-hour graph. The sorted memory table runs
to hundreds of process rows, so only the pool header and the top rows are
stored.
"""
import re

from .base import BaseCollector
from .errors import send_failure_output, is_error_output

_CPU = "show processes cpu | include CPU utilization"
_CPU_HISTORY = "show processes cpu history"
_MEMORY = "show processes memory sorted"
_NXOS_RESOURCES = "show system resources"

_COMMANDS = {
    "cisco_ios": [_CPU, _CPU_HISTORY, _MEMORY],
    "cisco_xe": [_CPU, _CPU_HISTORY, _MEMORY],
    "cisco_nxos": [_NXOS_RESOURCES, _CPU_HISTORY],
}

TOP_PROCESSES = 10


def trim_memory_sorted(text, top=TOP_PROCESSES):
    """Keep the pool lines, the column header and the first top process rows."""
    if not text or is_error_output(text):
        return text
    kept = []
    rows = 0
    in_table = False
    for line in text.splitlines():
        if not in_table:
            kept.append(line)
            if re.match(r"^\s*PID\s+TTY\s+", line):
                in_table = True
            continue
        if re.match(r"^\s*\d+\s+\d+\s+\d+", line):
            rows += 1
            if rows > top:
                break
        kept.append(line)
    return "\n".join(kept)


def parse_cpu(text):
    result = {}
    m = re.search(r"five seconds:\s*(\d+)%(?:/(\d+)%)?;\s*one minute:\s*(\d+)%;\s*"
                  r"five minutes:\s*(\d+)%", text or "", re.I)
    if m:
        result = {"cpu_5s": int(m.group(1)),
                  "cpu_5s_interrupt": int(m.group(2)) if m.group(2) else None,
                  "cpu_1m": int(m.group(3)), "cpu_5m": int(m.group(4))}
    return result


def parse_memory(text):
    """Processor pool totals, and the top processes by holding."""
    result = {"pools": [], "top_processes": []}
    if not text:
        return result
    for m in re.finditer(r"^\s*(\S+(?: \S+)?) Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)",
                         text, re.M):
        total = int(m.group(2))
        used = int(m.group(3))
        result["pools"].append({"pool": m.group(1), "total": total, "used": used,
                                "free": int(m.group(4)),
                                "used_pct": round(100 * used / total, 1) if total else None})
    for m in re.finditer(r"^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+(\d+)\s+\d+\s+\d+\s+(.+?)\s*$",
                         text, re.M):
        result["top_processes"].append({"pid": m.group(1), "holding": int(m.group(2)),
                                        "process": m.group(3)})
    return result


def parse_nxos_resources(text):
    cpu = {}
    memory = {"pools": [], "top_processes": []}
    if not text:
        return cpu, memory
    m = re.search(r"CPU states\s*:\s*([\d.]+)% user,\s*([\d.]+)% kernel,\s*([\d.]+)% idle",
                  text, re.I)
    if m:
        cpu["cpu_now"] = round(100 - float(m.group(3)), 1)
    m = re.search(r"Load average:\s*1 minute:\s*([\d.]+)\s+5 minutes:\s*([\d.]+)", text, re.I)
    if m:
        cpu["load_1m"] = float(m.group(1))
        cpu["load_5m"] = float(m.group(2))
    m = re.search(r"Memory usage:\s*(\d+)K total,\s*(\d+)K used,\s*(\d+)K free", text, re.I)
    if m:
        total = int(m.group(1)) * 1024
        used = int(m.group(2)) * 1024
        memory["pools"].append({"pool": "System", "total": total, "used": used,
                                "free": int(m.group(3)) * 1024,
                                "used_pct": round(100 * used / total, 1) if total else None})
    return cpu, memory


class CpuMemoryCollector(BaseCollector):
    name = "cpu_memory"
    label = "CPU & Memory"
    description = "Collect CPU utilisation, CPU history and top memory consumers"
    enabled_by_default = True
    needs_custom_collect = True

    def get_commands(self, device_type: str) -> list[str]:
        return list(_COMMANDS.get(device_type, []))

    def parse(self, raw_outputs: dict[str, str], device_type: str) -> dict:
        if not raw_outputs:
            return {"not_applicable": True,
                    "reason": f"cpu_memory: no commands for {device_type}"}
        if device_type == "cisco_nxos":
            cpu, memory = parse_nxos_resources(raw_outputs.get(_NXOS_RESOURCES, ""))
        else:
            cpu = parse_cpu(raw_outputs.get(_CPU, ""))
            memory = parse_memory(raw_outputs.get(_MEMORY, ""))
        return {"cpu": cpu, "memory": memory}

    def collect(self, connection, device_type: str) -> dict:
        cmds = self.get_commands(device_type)
        if not cmds:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"no commands defined for {device_type}"}}
        raw_outputs = {}
        for cmd in cmds:
            try:
                raw_outputs[cmd] = connection.send_command(cmd, read_timeout=60)
            except Exception as e:
                raw_outputs[cmd] = send_failure_output(e)
        if _MEMORY in raw_outputs:
            raw_outputs[_MEMORY] = trim_memory_sorted(raw_outputs[_MEMORY])
        return {"raw": raw_outputs,
                "parsed": self.parse_collected(raw_outputs, device_type)}
