"""
Parsers for Cisco ASA and ASAv command output.

Pure functions over text, so the asa collector and the reports can re-parse a
saved scan without a device. Every parser tolerates empty or partial output
and returns None (not collected / not reported) rather than raising. Output
from ASA, ASAv and ASA code on Firepower hardware differs mainly in show
version, which says which of the three it is.
"""
import re
from datetime import datetime, timezone

# --- shared helpers --------------------------------------------------------

_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
# "10:15:22 UTC Oct 1 2026", "10:15:22.123 UTC Fri Nov 7 2026"
_ASA_TIME = re.compile(
    r"(?P<time>\d{1,2}:\d{2}:\d{2})(?:\.\d+)?\s+(?P<tz>[A-Za-z]{2,5})\s+"
    r"(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?(?P<mon>" + _MONTHS + r")\s+"
    r"(?P<day>\d{1,2})\s+(?P<year>\d{4})")


def asa_time(text):
    """ISO 8601 UTC for an ASA timestamp in UTC/GMT, else None.

    Other zone abbreviations are ambiguous (CST is three different zones), so
    a time in one is not converted; the caller keeps the device's text.
    """
    m = _ASA_TIME.search(text or "")
    if not m or m.group("tz").upper() not in ("UTC", "GMT"):
        return None
    try:
        dt = datetime.strptime(
            f"{m.group('time')} {m.group('mon')} {m.group('day')} {m.group('year')}",
            "%H:%M:%S %b %d %Y")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _int(text):
    try:
        return int(str(text).replace(",", ""))
    except (TypeError, ValueError):
        return None


def _lines(text):
    return (text or "").splitlines()


def mask_to_prefix(mask):
    try:
        return sum(bin(int(o)).count("1") for o in str(mask).split("."))
    except ValueError:
        return None


# --- Block 0 / 1: platform --------------------------------------------------

def parse_clock(text):
    text = (text or "").strip()
    if not text:
        return None
    return {"text": text.splitlines()[0].strip(), "utc": asa_time(text)}


def parse_mode(text):
    m = re.search(r"Security context mode:\s*(\w+)", text or "", re.I)
    return m.group(1).lower() if m else None


_LICENCE_LINE = re.compile(r"^(?P<name>[A-Za-z0-9][\w /&.-]*?)\s*:\s*(?P<value>.+?)"
                           r"(?:\s{2,}(?P<term>perpetual|\d+ days))?\s*$", re.I)


def parse_version(text):
    """show version: software, hardware, uptime, licence features."""
    if not (text or "").strip():
        return None
    out = {"asa_version": "", "ssp_version": "", "asdm_version": "", "boot_image": "",
           "uptime": "", "failover_uptime": "", "model": "", "model_id": "", "ram_mb": None,
           "serial": "", "licence_tier": "", "licence_mode": "", "features": {},
           "last_reload_reason": "", "last_modified": "", "platform_type": "Physical"}
    in_features = False
    for line in _lines(text):
        s = line.strip()
        if m := re.match(r"Cisco Adaptive Security Appliance Software Version (\S+)", s):
            out["asa_version"] = m.group(1)
        elif m := re.match(r"SSP Operating System Version (\S+)", s):
            out["ssp_version"] = m.group(1)
        elif m := re.match(r"(?:Device Manager|ASDM) Version (\S+)", s):
            out["asdm_version"] = m.group(1)
        elif m := re.match(r'System image file is "([^"]+)"', s):
            out["boot_image"] = m.group(1)
        elif m := re.match(r"failover cluster up (.+)$", s):
            out["failover_uptime"] = m.group(1).strip()
        elif (m := re.match(r"\S+ up (.+)$", s)) and not out["uptime"] \
                and not s.lower().startswith("failover"):
            out["uptime"] = m.group(1).strip()
        elif m := re.match(r"Hardware:\s*([^,]+)(?:,\s*(\d+)\s*MB RAM)?", s):
            out["model"] = m.group(1).strip()
            out["ram_mb"] = _int(m.group(2))
        elif m := re.match(r"Model Id:\s*(\S+)", s):
            out["model_id"] = m.group(1)
        elif m := re.match(r"Serial Number:\s*(\S+)", s):
            out["serial"] = m.group(1)
        elif m := re.match(r"This platform has an? (.+?) license\.?$", s, re.I):
            out["licence_tier"] = m.group(1).strip()
        elif m := re.match(r"License mode:\s*(.+)$", s, re.I):
            out["licence_mode"] = m.group(1).strip()
        elif m := re.match(r"(?:Last )?[Rr]eload reason:\s*(.+)$", s):
            out["last_reload_reason"] = m.group(1).strip()
        elif m := re.match(r"Configuration last modified by .+? at (.+)$", s):
            out["last_modified"] = m.group(1).strip()
        elif re.match(r"Licensed features for this platform:", s, re.I):
            in_features = True
            continue
        elif in_features:
            if not s:
                # A blank line ends the table, not the one after its heading.
                if out["features"]:
                    in_features = False
                continue
            fm = _LICENCE_LINE.match(s)
            if fm:
                out["features"][fm.group("name").strip()] = fm.group("value").strip()
            else:
                in_features = False
    if not out["licence_mode"]:
        out["licence_mode"] = ("Smart" if re.search(r"Smart Licensing", text, re.I)
                               else "PAK" if re.search(r"Activation Key", text, re.I) else "")
    model = out["model"]
    if model.upper().startswith("ASAV"):
        out["platform_type"] = "ASAv"
    elif out["ssp_version"] or re.match(r"(FPR|Firepower)", model, re.I):
        out["platform_type"] = "Firepower running ASA"
    return out


def parse_inventory(text):
    """show inventory: [{name, descr, pid, vid, sn}]."""
    items = []
    current = None
    for line in _lines(text):
        if m := re.match(r'\s*Name:\s*"?([^",]*)"?\s*,\s*DESCR:\s*"?([^"]*)"?', line):
            current = {"name": m.group(1).strip(), "descr": m.group(2).strip(),
                       "pid": "", "vid": "", "sn": ""}
            items.append(current)
        elif current and (m := re.match(
                r"\s*PID:\s*([^,]*?)\s*,\s*VID:\s*([^,]*?)\s*,\s*SN:\s*(\S*)", line)):
            current.update(pid=m.group(1).strip(), vid=m.group(2).strip(),
                           sn=m.group(3).strip())
    return items


def chassis(inventory):
    """The chassis entry of show inventory, else the first entry, else {}."""
    for item in inventory or []:
        if "chassis" in item["name"].lower() or "chassis" in item["descr"].lower():
            return item
    return (inventory or [{}])[0]


def parse_cpu(text):
    m = re.search(r"5 seconds\s*=\s*(\d+)%;\s*1 minute:\s*(\d+)%;\s*5 minutes:\s*(\d+)%",
                  text or "")
    if not m:
        return None
    return {"5s": int(m.group(1)), "1m": int(m.group(2)), "5m": int(m.group(3))}


def parse_memory(text):
    free = re.search(r"Free memory:\s*(\d+) bytes", text or "")
    used = re.search(r"Used memory:\s*(\d+) bytes", text or "")
    total = re.search(r"Total memory:\s*(\d+) bytes", text or "")
    if not (free and used):
        return None
    free_b, used_b = int(free.group(1)), int(used.group(1))
    total_b = int(total.group(1)) if total else free_b + used_b
    return {"total": total_b, "used": used_b, "free": free_b,
            "used_pct": round(100 * used_b / total_b, 1) if total_b else None}


def parse_disk(text):
    m = re.search(r"(\d+) bytes total \((\d+) bytes free", text or "")
    if not m:
        return None
    total, free = int(m.group(1)), int(m.group(2))
    return {"total": total, "free": free,
            "used_pct": round(100 * (total - free) / total, 1) if total else None}


def parse_bootvar(text):
    m = re.search(r"BOOT variable\s*=\s*(.*)$", text or "", re.M)
    if not m:
        return None
    return m.group(1).strip()


_PROC = re.compile(r"(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%\s+(\S.*)$")


def parse_processes(text, top=5):
    rows = []
    for line in _lines(text):
        m = _PROC.search(line)
        if m:
            rows.append({"process": m.group(4).strip(), "5s": float(m.group(1)),
                         "1m": float(m.group(2)), "5m": float(m.group(3))})
    rows.sort(key=lambda r: (-r["1m"], -r["5s"], r["process"]))
    return rows[:top]


def parse_blocks(text):
    """Block sizes whose low watermark reached 0 (pool exhausted at least once)."""
    zero = []
    for line in _lines(text):
        m = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if m and int(m.group(3)) == 0:
            zero.append(int(m.group(1)))
    return zero


def parse_asp_drop(text, top=10):
    rows = []
    for line in _lines(text):
        m = re.match(r"\s+(\S.*?\(\S+\))\s+(\d+)\s*$", line)
        if m:
            rows.append({"reason": m.group(1).strip(), "count": int(m.group(2))})
    rows.sort(key=lambda r: -r["count"])
    return rows[:top]


def parse_in_use(text):
    """show conn count / show xlate count: '120 in use, 4500 most used'."""
    m = re.search(r"(\d+) in use,\s*(\d+) most used", text or "")
    if not m:
        return None
    return {"in_use": int(m.group(1)), "peak": int(m.group(2))}


def parse_resource_usage(text):
    rows = []
    for line in _lines(text):
        m = re.match(r"\s*(\S.*?)\s{2,}(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s*$", line)
        if not m or m.group(1).lower() == "resource":
            continue
        rows.append({"resource": m.group(1).strip(), "current": int(m.group(2)),
                     "peak": int(m.group(3)), "limit": _int(m.group(4)),
                     "denied": int(m.group(5)), "context": m.group(6)})
    return rows


def resource(rows, name, context=None):
    for r in rows or []:
        if r["resource"].lower() == name.lower() and (context is None
                                                     or r["context"] == context):
            return r
    return None


def parse_crashinfo(text):
    text = text or ""
    present = bool(re.search(r"Traceback|Thread Name", text))
    thread = re.search(r"Thread Name:\s*(.+)$", text, re.M)
    when = asa_time(text) if present else None
    return {"present": present, "thread": thread.group(1).strip() if thread else "",
            "time": when}


def parse_ntp_status(text):
    m = re.search(r"Clock is (synchronized|unsynchronized),\s*stratum (\d+)", text or "")
    if not m:
        return None
    return {"synced": m.group(1) == "synchronized", "stratum": int(m.group(2))}


def parse_critical_logs(text, last=5):
    lines = [l.strip() for l in _lines(text) if re.search(r"%ASA-[1-3]-", l)]
    return {"count": len(lines), "last": lines[-last:]}


def parse_threat_top(text, top=5):
    lines = [l.strip() for l in _lines(text) if l.strip()]
    if not lines or any(re.search(r"not enabled|disabled", l, re.I) for l in lines[:2]):
        return []
    return [l for l in lines if re.search(r"\d", l)][:top]


def _hex(text):
    return re.sub(r"[^0-9a-f]", "", (text or "").lower())


def parse_checksum(text):
    m = re.search(r"Cryptochecksum:?\s*([0-9a-fA-F ]+)", text or "")
    return _hex(m.group(1)) if m else None


def config_saved(running_checksum_text, startup_checksum_text):
    run = parse_checksum(running_checksum_text)
    start = parse_checksum(startup_checksum_text)
    if not run or not start:
        return None
    return run == start


def parse_contexts(text):
    """show context: [{name, admin, class, interfaces, url}]."""
    out = []
    for line in _lines(text):
        m = re.match(r"^([* ])(\S+)\s+(\S+)\s+(.*?)\s+(Routed|Transparent)\s+(\S+)\s*$",
                     line)
        if not m or m.group(2).lower() == "context":
            continue
        out.append({"name": m.group(2), "admin": m.group(1) == "*",
                    "class": m.group(3), "interfaces": m.group(4).strip().rstrip(","),
                    "mode": m.group(5), "url": m.group(6)})
    return out


def parse_license_status(text):
    """show license all / status (Smart): registration and authorisation."""
    text = text or ""
    reg = re.search(r"Registration:\s*\n\s*Status:\s*(.+)$", text, re.M)
    auth = re.search(r"License Authorization:\s*\n\s*Status:\s*(.+)$", text, re.M)
    tier = re.search(r"(?:Feature tier|Tier)\s*:\s*(.+)$", text, re.M | re.I)
    throughput = re.search(r"Throughput level\s*:?\s*(\S+)", text, re.I)
    if not (reg or auth or tier or throughput):
        return None
    return {"registration": reg.group(1).strip() if reg else "",
            "authorization": auth.group(1).strip() if auth else "",
            "tier": tier.group(1).strip() if tier else "",
            "throughput": throughput.group(1).strip() if throughput else ""}


# --- Block 2: failover -------------------------------------------------------

_FO_INTF = re.compile(r"Interface\s+(\S+)\s+\(([^)]*)\):\s*(.+?)\s*(?:\(([^)]*)\))?\s*$")


def parse_failover(text):
    """show failover. None when not collected; {"enabled": False} when off."""
    text = text or ""
    if not text.strip():
        return None
    out = {"enabled": bool(re.search(r"^\s*Failover On", text, re.M)),
           "unit": "", "failover_link": None, "stateful_link": None,
           "poll": {}, "monitored": None, "monitored_max": None,
           "version": {}, "serial": {}, "last_failover": "",
           "this_host": None, "other_host": None}
    if m := re.search(r"Failover unit (Primary|Secondary)", text):
        out["unit"] = m.group(1).lower()
    if m := re.search(r"Failover LAN Interface:\s*(\S+)\s+(\S+)\s+\((\w[\w ]*)\)", text):
        out["failover_link"] = {"name": m.group(1), "interface": m.group(2),
                                "state": m.group(3)}
    if m := re.search(r"Unit Poll frequency (\d+) (\w+), holdtime (\d+) (\w+)", text):
        out["poll"]["unit"] = f"{m.group(1)} {m.group(2)}"
        out["poll"]["unit_hold"] = f"{m.group(3)} {m.group(4)}"
    if m := re.search(r"Interface Poll frequency (\d+) (\w+), holdtime (\d+) (\w+)", text):
        out["poll"]["interface"] = f"{m.group(1)} {m.group(2)}"
        out["poll"]["interface_hold"] = f"{m.group(3)} {m.group(4)}"
    if m := re.search(r"Monitored Interfaces (\d+) of (\d+)", text):
        out["monitored"], out["monitored_max"] = int(m.group(1)), int(m.group(2))
    if m := re.search(r"Version:\s*Ours (\S+),\s*Mate (\S+)", text):
        out["version"] = {"ours": m.group(1), "mate": m.group(2)}
    if m := re.search(r"Serial Number:\s*Ours (\S+),\s*Mate (\S+)", text):
        out["serial"] = {"ours": m.group(1), "mate": m.group(2)}
    if m := re.search(r"Last Failover at:\s*(.+)$", text, re.M):
        out["last_failover"] = m.group(1).strip()
    host = None
    in_stateful = False
    for line in _lines(text):
        s = line.strip()
        if m := re.match(r"(This|Other) host:\s*(Primary|Secondary)\s*-\s*(.+)$", s):
            host = {"failover_role": m.group(2).lower(), "state": m.group(3).strip(),
                    "interfaces": []}
            out["this_host" if m.group(1) == "This" else "other_host"] = host
            continue
        if s.startswith("Stateful Failover"):
            in_stateful, host = True, None
            continue
        if in_stateful and (m := re.match(r"Link\s*:\s*(\S+)\s+(\S+)\s+\((\w[\w ]*)\)", s)):
            out["stateful_link"] = {"name": m.group(1), "interface": m.group(2),
                                    "state": m.group(3)}
            continue
        if host is not None and (m := _FO_INTF.match(s)):
            host["interfaces"].append({"nameif": m.group(1), "ip": m.group(2),
                                       "status": m.group(3).strip(),
                                       "monitor": (m.group(4) or "").strip()})
    return out


def parse_failover_history(text):
    """show failover history, oldest first: [{time, from, to, reason}]."""
    entries = []
    when = None
    for line in _lines(text):
        s = line.strip()
        if not s or s.startswith("=") or s.startswith("From State"):
            continue
        if _ASA_TIME.match(s):
            when = s
            continue
        parts = re.split(r"\s{2,}", s)
        if when and len(parts) >= 2:
            entries.append({"time": when, "from": parts[0], "to": parts[1],
                            "reason": " ".join(parts[2:])})
            when = None
    return entries


def parse_monitor_interface(text):
    """show monitor-interface, this host only: {nameif: status text}."""
    out = {}
    this = False
    for line in _lines(text):
        s = line.strip()
        if s.startswith("This host"):
            this = True
            continue
        if s.startswith("Other host"):
            this = False
            continue
        if this and (m := _FO_INTF.match(s)):
            out[m.group(1)] = f"{m.group(3).strip()} ({m.group(4) or ''})".replace(" ()", "")
    return out


def is_monitored(status):
    text = (status or "").lower()
    if "not-monitored" in text:
        return False
    return "monitored" in text or "waiting" in text


# --- Running-config sections ---------------------------------------------------

def config_blocks(config, keyword):
    """[(header line, [indented body lines])] for top-level lines starting with
    keyword."""
    blocks = []
    current = None
    for line in _lines(config):
        if not line.strip() or line.startswith("!"):
            current = None
            continue
        if not line[0].isspace():
            current = None
            if line.startswith(keyword):
                current = (line.rstrip(), [])
                blocks.append(current)
        elif current is not None:
            current[1].append(line.strip())
    return blocks


def config_lines(config, prefix):
    return [l.rstrip() for l in _lines(config) if l.startswith(prefix)]


def firewall_mode(config):
    if config is None:
        return None
    return "Transparent" if re.search(r"^firewall transparent", config, re.M) else "Routed"


def parse_config_interfaces(config):
    """interface blocks: {interface: {nameif, security_level, ip, mask, standby_ip,
    vlan, description, channel_group, management_only, shutdown}}."""
    out = {}
    for header, body in config_blocks(config, "interface "):
        name = header.split(None, 1)[1].strip()
        rec = {"nameif": "", "security_level": None, "ip": "", "mask": "", "standby_ip": "",
               "vlan": None, "description": "", "channel_group": None,
               "management_only": False, "shutdown": False}
        for s in body:
            if m := re.match(r"nameif (\S+)", s):
                rec["nameif"] = m.group(1)
            elif m := re.match(r"security-level (\d+)", s):
                rec["security_level"] = int(m.group(1))
            elif m := re.match(r"ip address (\S+) (\S+)(?: standby (\S+))?", s):
                rec["ip"], rec["mask"] = m.group(1), m.group(2)
                rec["standby_ip"] = m.group(3) or ""
            elif m := re.match(r"vlan (\d+)", s):
                rec["vlan"] = int(m.group(1))
            elif m := re.match(r"description (.+)", s):
                rec["description"] = m.group(1).strip()
            elif m := re.match(r"channel-group (\d+)", s):
                rec["channel_group"] = int(m.group(1))
            elif s == "management-only":
                rec["management_only"] = True
            elif s == "shutdown":
                rec["shutdown"] = True
        out[name] = rec
    return out


def same_security(config):
    if config is None:
        return None
    return {"inter": bool(re.search(r"^same-security-traffic permit inter-interface",
                                    config, re.M)),
            "intra": bool(re.search(r"^same-security-traffic permit intra-interface",
                                    config, re.M))}


# --- Block 4: interfaces --------------------------------------------------------

_INTF_HEAD = re.compile(r'^Interface (\S+) "([^"]*)", is (.+?), line protocol is (\S+)')


def parse_show_interface(text):
    """show interface (ASA): [{interface, nameif, admin, line, ...counters}]."""
    rows = []
    rec = None
    for line in _lines(text):
        if m := _INTF_HEAD.match(line):
            status = m.group(3)
            rec = {"interface": m.group(1), "nameif": m.group(2),
                   "admin": "down" if "administratively" in status else "up",
                   "line": m.group(4).rstrip(","), "speed": "", "duplex": "", "mtu": None,
                   "description": "", "ip": "", "mask": "", "vlan": None,
                   "management_only": False, "input_packets": None,
                   "output_packets": None, "input_errors": None, "crc": None,
                   "overruns": None, "underruns": None, "output_errors": None,
                   "output_drops": None, "in_rate_bps": None, "out_rate_bps": None,
                   "members": []}
            rows.append(rec)
            continue
        if rec is None:
            continue
        s = line.strip()
        if m := re.search(r"(?:Auto-)?Duplex\(?([\w-]+)\)?,\s*(?:Auto-)?Speed\(?([^)]+)\)?", s):
            rec["duplex"], rec["speed"] = m.group(1), m.group(2).strip()
        elif m := re.match(r"(Full|Half)-[Dd]uplex,\s*(\S+ \S+)", s):
            rec["duplex"], rec["speed"] = m.group(1), m.group(2)
        if m := re.search(r"MTU (\d+)", s):
            rec["mtu"] = int(m.group(1))
        if m := re.match(r"Description:\s*(.+)$", s):
            rec["description"] = m.group(1).strip()
        elif m := re.match(r"IP address (\S+), subnet mask (\S+)", s):
            rec["ip"], rec["mask"] = m.group(1), m.group(2)
        elif m := re.match(r"VLAN identifier (\d+)", s):
            rec["vlan"] = int(m.group(1))
        elif s.startswith("Management-only interface"):
            rec["management_only"] = True
        elif m := re.match(r"(\d+) packets input", s):
            if rec["input_packets"] is None:
                rec["input_packets"] = int(m.group(1))
        elif m := re.match(r"(\d+) packets output", s):
            if rec["output_packets"] is None:
                rec["output_packets"] = int(m.group(1))
            if um := re.search(r"(\d+) underruns", s):
                rec["underruns"] = int(um.group(1))
        elif m := re.match(r"(\d+) input errors,\s*(\d+) CRC,\s*\d+ frame,\s*(\d+) overrun", s):
            rec["input_errors"], rec["crc"] = int(m.group(1)), int(m.group(2))
            rec["overruns"] = int(m.group(3))
        elif m := re.match(r"(\d+) output errors", s):
            rec["output_errors"] = int(m.group(1))
        elif m := re.match(r"(\d+) packets dropped", s):
            rec["output_drops"] = int(m.group(1))
        elif m := re.match(r"5 minute input rate \d+ pkts/sec,\s*(\d+) bytes/sec", s):
            rec["in_rate_bps"] = int(m.group(1)) * 8
        elif m := re.match(r"5 minute output rate \d+ pkts/sec,\s*(\d+) bytes/sec", s):
            rec["out_rate_bps"] = int(m.group(1)) * 8
        elif m := re.match(r"Members\s+(.+)$", s):
            rec["members"] = re.findall(r"(\S+?)\(", m.group(1))
    return rows


def parse_nameif(text):
    """show nameif: {interface: (nameif, security level)}."""
    out = {}
    for line in _lines(text):
        m = re.match(r"^(\S+)\s+(\S+)\s+(\d+)\s*$", line)
        if m and m.group(1) != "Interface":
            out[m.group(1)] = (m.group(2), int(m.group(3)))
    return out


def parse_ip_brief(text):
    """show interface ip brief: [{interface, ip, status, protocol}]."""
    rows = []
    for line in _lines(text):
        m = re.match(r"^(\S+)\s+(\S+)\s+(YES|NO)\s+(\S+)\s+(.+?)\s+(up|down)\s*$", line)
        if m:
            rows.append({"interface": m.group(1), "ip": m.group(2),
                         "status": m.group(5).strip(), "protocol": m.group(6)})
    return rows


# --- Block 9: certificates ------------------------------------------------------

def _cert_time(text):
    iso = asa_time(text)
    if iso:
        return iso
    return (text or "").strip()


def parse_certificates(text):
    """show crypto ca certificates: one dict per certificate."""
    certs = []
    cur = None
    section = None
    for line in _lines(text):
        s = line.strip()
        if s in ("Certificate", "CA Certificate", "Router Self-Signed Certificate"):
            cur = {"type": "ca" if s.startswith("CA") else "identity",
                   "status": "", "serial": "", "usage": "", "key_type": "", "key_size": None,
                   "sig_alg": "", "issuer": {}, "subject": {}, "valid_from": "",
                   "valid_to": "", "trustpoints": []}
            certs.append(cur)
            section = None
            continue
        if cur is None or not s:
            continue
        if m := re.match(r"Status:\s*(.+)$", s):
            cur["status"] = m.group(1)
        elif m := re.match(r"Certificate Serial Number:\s*(\S+)", s):
            cur["serial"] = m.group(1)
        elif m := re.match(r"Certificate Usage:\s*(.+)$", s):
            cur["usage"] = m.group(1)
        elif m := re.match(r"Public Key Type:\s*(\S+)(?:\s*\((\d+) bits\))?", s):
            cur["key_type"], cur["key_size"] = m.group(1), _int(m.group(2))
        elif m := re.match(r"Signature Algorithm:\s*(.+)$", s):
            cur["sig_alg"] = m.group(1)
        elif s.startswith("Issuer Name"):
            section = "issuer"
        elif s.startswith("Subject Name"):
            section = "subject"
        elif s.startswith("Validity Date"):
            section = "validity"
        elif m := re.match(r"start\s+date:\s*(.+)$", s):
            cur["valid_from"] = _cert_time(m.group(1))
        elif m := re.match(r"end\s+date:\s*(.+)$", s):
            cur["valid_to"] = _cert_time(m.group(1))
        elif m := re.match(r"Associated Trustpoints?:\s*(.+)$", s):
            cur["trustpoints"] = m.group(1).split()
            section = None
        elif section in ("issuer", "subject") and (m := re.match(r"(\w+)=(.+)$", s)):
            cur[section].setdefault(m.group(1).lower(), m.group(2).strip())
        elif s.startswith(("Storage", "CRL Distribution", "Public Key", "Certificate")):
            section = None
    for c in certs:
        c["subject_cn"] = c["subject"].get("cn", "")
        c["issuer_cn"] = c["issuer"].get("cn", "")
        c["self_signed"] = bool(c["subject"]) and c["subject"] == c["issuer"]
    return certs


def trustpoint_users(config):
    """{trustpoint: [where it is used]} from running-config."""
    used = {}

    def add(tp, where):
        used.setdefault(tp, [])
        if where not in used[tp]:
            used[tp].append(where)

    for line in _lines(config):
        s = line.strip()
        if m := re.match(r"ssl trust-point (\S+)(?: (\S+))?", s):
            add(m.group(1), f"ssl {m.group(2)}" if m.group(2) else "ssl (all interfaces)")
    for header, body in config_blocks(config, "tunnel-group "):
        name = header.split()[1]
        for s in body:
            if m := re.match(r"(?:ikev1 )?trust-point (\S+)", s):
                add(m.group(1), f"tunnel-group {name}")
            elif m := re.match(r"ikev2 local-authentication certificate (\S+)", s):
                add(m.group(1), f"tunnel-group {name}")
    for line in _lines(config):
        if m := re.match(r"crypto map (\S+) \d+ set trustpoint (\S+)", line):
            add(m.group(2), f"crypto map {m.group(1)}")
    return used


# --- Block 10: management plane ----------------------------------------------------

_ACCESS = re.compile(r"^(ssh|telnet|http) (\S+) (\S+) (\S+)\s*$")


def parse_management(config):
    """Management-plane settings from running-config (and its sections)."""
    if config is None:
        return None
    m = {"ssh": [], "telnet": [], "http": [], "http_server": False, "ssh_version": "",
         "ssh_ciphers": "", "ssh_kex": "", "icmp": [], "aaa_auth": {}, "aaa_cmd_authz": False,
         "aaa_accounting": [], "aaa_server_groups": {}, "aaa_servers": [],
         "local_users": [], "password_policy": {}, "max_fail": None, "snmp": {
             "communities": 0, "hosts": [], "users": [], "groups": []},
         "syslog_hosts": [], "logging": {}, "flow_export": [], "ntp_servers": [],
         "ntp_authenticate": False, "dns_servers": [], "domain_name": "", "banners": [],
         "management_access": "", "call_home": False, "smart_licensing": False,
         "enable_password": None}
    for line in _lines(config):
        s = line.rstrip()
        st = s.strip()
        if a := _ACCESS.match(s):
            if re.match(r"^[\d.]+$|^any", a.group(2)) and re.match(r"^[\d.]+$", a.group(3)):
                m[a.group(1)].append({"net": a.group(2), "mask": a.group(3),
                                      "nameif": a.group(4)})
                continue
        if mm := re.match(r"^http server enable", s):
            m["http_server"] = True
        elif mm := re.match(r"^ssh version (\d)", s):
            m["ssh_version"] = mm.group(1)
        elif mm := re.match(r"^ssh cipher encryption (.+)$", s):
            m["ssh_ciphers"] = mm.group(1).strip()
        elif mm := re.match(r"^ssh key-exchange group (.+)$", s):
            m["ssh_kex"] = mm.group(1).strip()
        elif mm := re.match(r"^icmp (permit|deny) (.+)$", s):
            parts = mm.group(2).split()
            m["icmp"].append({"action": mm.group(1), "from": " ".join(parts[:-1]),
                              "nameif": parts[-1]})
        elif mm := re.match(r"^aaa authentication (ssh|http|telnet|serial|enable) console (.+)$", s):
            m["aaa_auth"][mm.group(1)] = mm.group(2).strip()
        elif re.match(r"^aaa authorization command ", s):
            m["aaa_cmd_authz"] = True
        elif mm := re.match(r"^aaa accounting (.+)$", s):
            m["aaa_accounting"].append(mm.group(1).strip())
        elif mm := re.match(r"^aaa-server (\S+) protocol (\S+)", s):
            m["aaa_server_groups"][mm.group(1)] = mm.group(2)
        elif mm := re.match(r"^aaa-server (\S+) \((\S+)\) host (\S+)", s):
            m["aaa_servers"].append({"group": mm.group(1), "nameif": mm.group(2),
                                     "host": mm.group(3)})
        elif mm := re.match(r"^aaa local authentication attempts max-fail (\d+)", s):
            m["max_fail"] = int(mm.group(1))
        elif mm := re.match(r"^username (\S+) .*?privilege (\d+)", s):
            m["local_users"].append({"username": mm.group(1), "privilege": int(mm.group(2))})
        elif mm := re.match(r"^username (\S+) (?:password|nopassword)", s):
            m["local_users"].append({"username": mm.group(1), "privilege": 2})
        elif mm := re.match(r"^password-policy (\S+) (\S+)", s):
            m["password_policy"][mm.group(1)] = mm.group(2)
        elif re.match(r"^snmp-server community ", s):
            m["snmp"]["communities"] += 1
        elif mm := re.match(r"^snmp-server host (\S+) (\S+)(.*)$", s):
            rest = mm.group(3)
            ver = re.search(r"version (\S+)", rest)
            kind = "poll" if " poll" in rest else "trap" if " trap" in rest else "poll+trap"
            m["snmp"]["hosts"].append({"nameif": mm.group(1), "host": mm.group(2),
                                       "version": ver.group(1) if ver else "1",
                                       "kind": kind})
        elif mm := re.match(r"^snmp-server user (\S+) (\S+) v3(.*)$", s):
            rest = mm.group(3)
            auth = re.search(r"auth (md5|sha\S*)", rest)
            priv = re.search(r"priv (\S+)(?: (128|192|256))?", rest)
            m["snmp"]["users"].append({
                "user": mm.group(1), "group": mm.group(2),
                "auth": auth.group(1) if auth else "",
                "priv": " ".join(x for x in (priv.group(1), priv.group(2) or "") if x)
                if priv else ""})
        elif mm := re.match(r"^snmp-server group (\S+) v3 (\S+)", s):
            m["snmp"]["groups"].append({"group": mm.group(1), "level": mm.group(2)})
        elif mm := re.match(r"^logging host (\S+) (\S+)(?: (\d+)/(\d+))?", s):
            m["syslog_hosts"].append({"nameif": mm.group(1), "host": mm.group(2),
                                      "protocol": {"6": "tcp", "17": "udp"}.get(
                                          mm.group(3) or "17", mm.group(3)),
                                      "port": int(mm.group(4)) if mm.group(4) else 514})
        elif s == "logging enable":
            m["logging"]["enabled"] = True
        elif s == "logging timestamp":
            m["logging"]["timestamp"] = True
        elif mm := re.match(r"^logging (buffered|trap|console|monitor|history|asdm) (\S+)$", s):
            m["logging"][mm.group(1)] = mm.group(2)
        elif mm := re.match(r"^flow-export destination (\S+) (\S+) (\d+)", s):
            m["flow_export"].append({"nameif": mm.group(1), "host": mm.group(2),
                                     "port": int(mm.group(3))})
        elif mm := re.match(r"^ntp server (\S+)(.*)$", s):
            m["ntp_servers"].append({"host": mm.group(1),
                                     "key": bool(re.search(r"\bkey\b", mm.group(2)))})
        elif s == "ntp authenticate":
            m["ntp_authenticate"] = True
        elif mm := re.match(r"^\s*name-server (.+)$", s):
            m["dns_servers"] += [t for t in mm.group(1).split() if re.match(r"[\d.:]+$", t)]
        elif mm := re.match(r"^\s*domain-name (\S+)", s):
            m["domain_name"] = m["domain_name"] or mm.group(1)
        elif mm := re.match(r"^banner (\S+) ", s):
            if mm.group(1) not in m["banners"]:
                m["banners"].append(mm.group(1))
        elif mm := re.match(r"^management-access (\S+)", s):
            m["management_access"] = mm.group(1)
        elif s == "call-home" or s.startswith("call-home "):
            m["call_home"] = True
        elif s.startswith("license smart"):
            m["smart_licensing"] = True
        elif mm := re.match(r"^enable password (\S+)", s):
            m["enable_password"] = mm.group(1)
    return m


# ASA's encrypted form of an empty enable password. Well known, not a secret.
BLANK_ENABLE_HASH = "8Ry2YjIyt7RRXU24"


def enable_password_set(mgmt):
    if mgmt is None:
        return None
    value = mgmt.get("enable_password")
    return bool(value) and value != BLANK_ENABLE_HASH


def parse_aaa_server_status(text):
    """show aaa-server: [{group, protocol, host, status}]."""
    rows = []
    cur = None
    for line in _lines(text):
        s = line.strip()
        if m := re.match(r"Server Group:\s*(\S+)", s):
            cur = {"group": m.group(1), "protocol": "", "host": "", "status": ""}
            rows.append(cur)
        elif cur and (m := re.match(r"Server Protocol:\s*(\S+)", s)):
            cur["protocol"] = m.group(1)
        elif cur and (m := re.match(r"Server (?:Address|Name):\s*(\S+)", s)):
            if cur["host"]:
                cur = dict(cur, host="", status="")
                rows.append(cur)
            cur["host"] = m.group(1)
        elif cur and (m := re.match(r"Server status:\s*(\w+)", s)):
            cur["status"] = m.group(1).upper()
    return rows


# --- counts used on the Devices sheet ---------------------------------------------

def acl_elements(text):
    if not (text or "").strip():
        return None
    return sum(int(n) for n in re.findall(r";\s*(\d+) elements", text))


def nat_rule_count(text):
    if not (text or "").strip():
        return None
    return len(re.findall(r"^\s*\d+ \(\S+\) to \(\S+\)", text, re.M))


def s2s_configured(config):
    if config is None:
        return None
    return len({(m.group(1), m.group(2)) for m in re.finditer(
        r"^crypto map (\S+) (\d+) set peer ", config, re.M)})


def l2l_sessions(text):
    if text is None:
        return None
    return len(re.findall(r"^Connection\s*:", text, re.M))


def parse_vpn_summary(text):
    """show vpn-sessiondb summary: {anyconnect: {active, cumulative, peak},
    site_to_site: {...}, capacity, load_pct}."""
    if not (text or "").strip():
        return None
    out = {"capacity": None, "load_pct": None}
    for line in _lines(text):
        m = re.match(r"^(\S.*?)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+)", line)
        if m and not line.startswith(" "):
            key = m.group(1).strip().lower()
            out[key] = {"active": int(m.group(2)), "cumulative": int(m.group(3)),
                        "peak": int(m.group(4))}
        elif m := re.match(r"Device Total VPN Capacity\s*:\s*(\d+)", line):
            out["capacity"] = int(m.group(1))
        elif m := re.match(r"Device Load\s*:\s*(\d+)%", line):
            out["load_pct"] = int(m.group(1))
    return out
