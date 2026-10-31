import pytest

from app.collectors.cpu_memory import (
    CpuMemoryCollector, parse_cpu, parse_memory, parse_nxos_resources,
    trim_memory_sorted, TOP_PROCESSES,
)

CPU_LINE = "CPU utilization for five seconds: 12%/3%; one minute: 9%; five minutes: 85%\n"

MEMORY_HEADER = """\
Processor Pool Total:  865281348 Used:  805231436 Free:   60049912
 lsmpi_io Pool Total:    6295128 Used:    6294296 Free:        832

 PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process
"""


def _memory_sorted(rows=40):
    lines = [MEMORY_HEADER.rstrip("\n")]
    for i in range(rows):
        holding = 900000000 - i * 1000
        lines.append(f"{i:4d}   0  {holding + 5000:9d}  {5000:9d}  {holding:9d}"
                     f"          0          0 Process {i}")
    return "\n".join(lines) + "\n"


CPU_HISTORY = """\
    111112222211111
    5    0    5    0
100
 90
 80
 70
 60                 *
   0....5....1....1....2....2....3....3....4....4....5....5....6
             0    5    0    5    0    5    0    5    0    5    0
               CPU% per second (last 60 seconds)
"""

NXOS_RESOURCES = """\
Load average:   1 minute: 0.50   5 minutes: 0.42   15 minutes: 0.40
Processes   :   812 total, 1 running
CPU states  :   3.50% user,   2.00% kernel,   94.50% idle
Memory usage:   16400000K total,   15580000K used,   820000K free
Current memory status: OK
"""


@pytest.fixture
def collector():
    return CpuMemoryCollector()


def test_commands(collector):
    assert collector.get_commands("cisco_ios") == [
        "show processes cpu | include CPU utilization",
        "show processes cpu history",
        "show processes memory sorted",
    ]
    assert collector.get_commands("cisco_nxos") == ["show system resources",
                                                    "show processes cpu history"]
    assert collector.get_commands("cisco_wlc") == []


def test_parse_cpu():
    assert parse_cpu(CPU_LINE) == {"cpu_5s": 12, "cpu_5s_interrupt": 3,
                                   "cpu_1m": 9, "cpu_5m": 85}
    assert parse_cpu("") == {}


def test_parse_memory_pools_and_top():
    mem = parse_memory(_memory_sorted(5))
    assert mem["pools"][0]["pool"] == "Processor"
    assert mem["pools"][0]["used_pct"] == 93.1
    assert mem["pools"][1]["pool"] == "lsmpi_io"
    assert mem["top_processes"][0] == {"pid": "0", "holding": 900000000,
                                       "process": "Process 0"}
    assert len(mem["top_processes"]) == 5


def test_trim_keeps_header_and_top_rows():
    trimmed = trim_memory_sorted(_memory_sorted(40))
    assert "Processor Pool Total" in trimmed
    assert "PID TTY" in trimmed
    assert f"Process {TOP_PROCESSES - 1}" in trimmed
    assert f"Process {TOP_PROCESSES}\n" not in trimmed + "\n"
    assert len(parse_memory(trimmed)["top_processes"]) == TOP_PROCESSES


def test_trim_leaves_errors_alone():
    err = "% Invalid input detected at '^' marker."
    assert trim_memory_sorted(err) == err


def test_parse_nxos_resources():
    cpu, mem = parse_nxos_resources(NXOS_RESOURCES)
    assert cpu == {"cpu_now": 5.5, "load_1m": 0.5, "load_5m": 0.42}
    assert mem["pools"][0]["pool"] == "System"
    assert mem["pools"][0]["used_pct"] == 95.0


class _Conn:
    def __init__(self, outputs):
        self.outputs = outputs
        self.kwargs = {}

    def send_command(self, cmd, **kwargs):
        self.kwargs[cmd] = kwargs
        return self.outputs.get(cmd, "")


def test_collect_trims_memory_and_keeps_history(collector):
    conn = _Conn({"show processes cpu | include CPU utilization": CPU_LINE,
                  "show processes cpu history": CPU_HISTORY,
                  "show processes memory sorted": _memory_sorted(40)})
    result = collector.collect(conn, "cisco_xe")
    assert result["raw"]["show processes cpu history"] == CPU_HISTORY
    assert result["raw"]["show processes memory sorted"].count("Process ") == TOP_PROCESSES
    assert result["parsed"]["cpu"]["cpu_5m"] == 85
    assert all(k.get("read_timeout", 0) >= 30 for k in conn.kwargs.values())


def test_collect_nxos(collector):
    conn = _Conn({"show system resources": NXOS_RESOURCES,
                  "show processes cpu history": CPU_HISTORY})
    parsed = collector.collect(conn, "cisco_nxos")["parsed"]
    assert parsed["cpu"]["cpu_now"] == 5.5
    assert parsed["memory"]["pools"][0]["used_pct"] == 95.0
