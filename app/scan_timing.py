"""
Per-device timing for a scan -- where did the time go?

A 40-minute run over 300 devices is usually a handful of slow chassis or one
collector whose command takes a minute on every box. Each collected device
gets a record of how long login took (and how long it waited on the login
rate limit), each command and collector, and the whole visit; the summary
names the slowest devices and the collectors that cost the most overall.
"""


def collector_ms(collector_commands, command_ms):
    """{collector: ms} for batch collectors from per-command times.

    Commands are sent once per device even when two collectors want them, so
    a shared command counts towards each collector that uses it.
    """
    out = {}
    for name, cmds in collector_commands.items():
        out[name] = sum(command_ms.get(c, 0) for c in dict.fromkeys(cmds))
    return out


def summarize(timing, top=5):
    """Slowest devices and costliest collectors from a timing map.

    timing is {hostname: record} as stored in scan_summary["timing"].
    """
    devices = sorted(
        ({"hostname": name,
          "ip": rec.get("ip"),
          "total_ms": rec.get("total_ms", 0),
          "connect_ms": rec.get("connect_ms", 0),
          "login_wait_ms": rec.get("login_wait_ms", 0)}
         for name, rec in (timing or {}).items()),
        key=lambda d: -d["total_ms"])
    totals = {}
    for name, rec in (timing or {}).items():
        for cname, ms in (rec.get("collectors_ms") or {}).items():
            entry = totals.setdefault(cname, {"collector": cname,
                                              "total_ms": 0, "max_ms": 0,
                                              "max_device": None,
                                              "devices": 0})
            entry["total_ms"] += ms
            entry["devices"] += 1
            if ms > entry["max_ms"]:
                entry["max_ms"] = ms
                entry["max_device"] = name
    collectors = sorted(totals.values(), key=lambda c: -c["total_ms"])
    return {"devices": devices[:top], "collectors": collectors[:top]}
