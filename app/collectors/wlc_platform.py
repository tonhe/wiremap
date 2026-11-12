"""
Parsers for AireOS controller platform output: system, licence, HA,
interfaces, ports, neighbours, time and health.

Pure functions over the raw text of one command, so the report can re-parse
a saved scan without a controller. Every parser returns None when the
output is empty or is a CLI error (the report shows n/a), and otherwise a
dict or list that may be empty (collected, nothing in it). None of them
raise on odd output; a field the code did not print comes back None or "".
"""
import re

from . import wlc_text as t

try:
    from app.collectors.errors import error_reason
except ImportError:
    from collectors.errors import error_reason


# --- shared helpers --------------------------------------------------------

def _usable(text):
    return bool((text or "").strip()) and not error_reason(text)


def _snake(label):
    s = re.sub(r"[^0-9a-z]+", "_", str(label or "").lower())
    return s.strip("_")


def _blank(value):
    """'' for the placeholders AireOS prints instead of an empty value."""
    v = (value or "").strip()
    if v.lower() in ("unconfigured", "not configured", "n/a", "none", "<none>", "0.0.0.0",
                     "::", "::/128", "::/0"):
        return ""
    return v


def _pairs(text):
    """{label: value} from dotted lines and from 'Label = value' lines, which
    show redundancy summary uses."""
    out = dict(t.dotted(text))
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([A-Za-z][^=]*?)\s+=\s+(.*?)\s*$", line)
        if m and m.group(1) not in out:
            out[m.group(1)] = m.group(2)
    return out


def _clean(value):
    # Values like "Present, OK" or ": 1033670656 bytes" (memory statistics
    # puts a colon after the dots).
    return re.sub(r"^:\s*", "", (value or "").strip())


# --- show sysinfo ------------------------------------------------------------

def parse_sysinfo(text):
    if not _usable(text):
        return None
    info = {k: _clean(v) for k, v in t.dotted(text).items()}

    def get(*labels):
        return t.lookup(info, *labels) or ""

    uptime = get("System Up Time")
    country = get("Configured Country")
    supplies = []
    for label, value in t.dotted_all(text):
        m = re.match(r"Power Supply\s*(\d+)$", label, re.I)
        if m:
            supplies.append(f"{m.group(1)}: {value}")
    return {
        "system_name": get("System Name"),
        "version": get("Product Version"),
        "field_recovery": get("Field Recovery Image Version"),
        "emergency_image": get("Emergency Image Version"),
        "uptime": uptime,
        "uptime_days": _days(uptime),
        "last_reset": get("Last Reset"),
        "max_aps": t.to_int(get("Maximum number of APs supported")),
        "location": get("System Location"),
        "contact": get("System Contact"),
        "ip": get("IP Address"),
        "redundancy_mode": get("Redundancy Mode"),
        "country": country.split()[0] if country else "",
        "temperature_c": t.to_int(get("Internal Temperature")),
        "temp_alarm_limits": get("Internal Temp Alarm Limits"),
        "fan_status": get("Fan Status"),
        "power_supplies": supplies,
        "clients": t.to_int(get("Number of Active Clients")),
        "wlans": t.to_int(get("Number of WLANs")),
        "cpu_current": t.to_int(get("CPU Current Usage")),
        "memory_current": t.to_int(get("Memory Current Usage")),
        "burned_in_mac": t.norm_mac(get("Burned-in MAC Address")),
        "licensing_type": get("Licensing Type"),
    }


def _days(uptime):
    m = re.search(r"(\d+)\s*day", uptime or "", re.I)
    if m:
        return int(m.group(1))
    # Under a day AireOS still prints "0 days", but keep 0 for "3 hrs ..." too.
    return 0 if re.search(r"\d+\s*(hr|hour|min)", uptime or "", re.I) else None


# --- show inventory ----------------------------------------------------------

def parse_inventory(text):
    """Chassis model/serial plus every NAME/PID entry. Some code also prints
    the burned-in MAC, power supplies and AP maximum here as dotted lines."""
    if not _usable(text):
        return None
    entries, current = [], None
    for line in text.splitlines():
        m = re.match(r'\s*NAME:\s*"?([^",]*?)"?\s*,\s*DESCR:\s*"?([^"]*)"?', line, re.I)
        if m:
            current = {"name": m.group(1).strip(), "descr": m.group(2).strip(),
                       "pid": "", "vid": "", "sn": ""}
            entries.append(current)
            continue
        m = re.match(r"\s*PID:\s*([^,]*?)\s*,\s*VID:\s*([^,]*?)\s*,\s*SN:\s*(\S*)", line, re.I)
        if m:
            if current is None:
                current = {"name": "", "descr": "", "pid": "", "vid": "", "sn": ""}
                entries.append(current)
            current.update(pid=m.group(1).strip(), vid=m.group(2).strip(), sn=m.group(3).strip())
            current = None
    chassis = next((e for e in entries if "chassis" in e["name"].lower()),
                   entries[0] if entries else {})
    info = t.dotted(text)
    supplies = [f"{m.group(1)}: {v}" for k, v in t.dotted_all(text)
                if (m := re.match(r"Power Supply\s*(\d+)$", k, re.I))]
    return {
        "model": chassis.get("pid", ""),
        "serial": chassis.get("sn", ""),
        "description": chassis.get("descr", ""),
        "burned_in_mac": t.norm_mac(t.lookup(info, "Burned-in MAC Address")),
        "max_aps": t.to_int(t.lookup(info, "Maximum number of APs supported")),
        "power_supplies": supplies,
        "entries": entries,
    }


# --- show boot ---------------------------------------------------------------

def parse_boot(text):
    if not _usable(text):
        return None
    out = {"primary": "", "backup": "", "default": "", "active": ""}
    for label, value in t.dotted_all(text):
        which = label.split()[0].lower()
        if which not in ("primary", "backup"):
            continue
        image = value.split()[0] if value.split() else ""
        out[which] = image
        if "(default)" in value.lower():
            out["default"] = image
        if "(active)" in value.lower():
            out["active"] = image
    return out


# --- licences ----------------------------------------------------------------

_AP_FEATURE = re.compile(r"\b(base[-_ ])?ap[-_ ]?count\b|\bap[-_ ]adder\b|\bap\s+count\b", re.I)


def parse_license(summary_text, capacity_text, all_text):
    """{licensed_aps, type, in_use}.

    Order of trust: the capacity table (Max / Current count), then dotted
    "Licensed AP count"-style lines, then the CLM feature blocks of show
    license summary/all ("Feature: ap_count ... License Count: 50/0/0"),
    summing every ap-count feature that is active, since a 5508 carries a
    base count plus adder licences.
    """
    texts = [x for x in (summary_text, capacity_text, all_text) if _usable(x)]
    if not texts:
        return None
    joined = "\n".join(texts)
    out = {"licensed_aps": None, "type": None, "in_use": None}

    for row in (t.table(capacity_text) if _usable(capacity_text) else []):
        feature = " ".join(str(v) for v in list(row.values())[:1])
        if _AP_FEATURE.search(feature):
            out["licensed_aps"] = t.to_int(t.lookup(row, "Max Count", "Maximum Count", "Max"))
            out["in_use"] = t.to_int(t.lookup(row, "Current Count", "Current", "In Use",
                                              "Used Count"))
            break

    if out["licensed_aps"] is None:
        for label, value in t.dotted_all(joined):
            if re.search(r"licensed\s+ap|ap[-_ ]?count|max(imum)?\s+.*aps?\s+licen", label, re.I):
                out["licensed_aps"] = t.to_int(value)
                if out["licensed_aps"] is not None:
                    break
    if out["in_use"] is None:
        for label, value in t.dotted_all(joined):
            if re.search(r"(aps?|count)\b.*\b(in use|used|current)|current.*ap", label, re.I):
                out["in_use"] = t.to_int(value)
                if out["in_use"] is not None:
                    break

    blocks = _active_ap_blocks(joined)
    if out["licensed_aps"] is None and blocks:
        out["licensed_aps"] = sum(count for count, _ in blocks)
    if out["licensed_aps"] is None:
        m = re.search(r"\bap[-_ ]count\s*[:=]?\s*(\d+)", joined, re.I)
        if m:
            out["licensed_aps"] = int(m.group(1))

    lowered = joined.lower()
    if re.search(r"smart licen[sc]ing\s+(is\s+)?enabled|smart licen[sc]ing\s*\.+\s*enabled|"
                 r"smart account", lowered):
        out["type"] = "Smart"
    elif re.search(r"\brtu\b|right to use", lowered):
        out["type"] = "RTU"
    elif blocks and all(kind == "evaluation" for _, kind in blocks):
        out["type"] = "Evaluation"
    elif re.search(r"feature\s*:", lowered):
        out["type"] = "Permanent"
    return out


def _active_ap_blocks(text):
    """[(count, licence type)] for active ap-count feature blocks. Blocks are
    "Feature: <name>" followed by indented "License ..." lines."""
    out = []
    blocks = re.split(r"(?=^\s*(?:Index\s+\d+|StoreIndex:\s*\d+)?\s*Feature(?: name)?\s*:)",
                      text, flags=re.M | re.I)
    for block in blocks:
        m = re.search(r"Feature(?: name)?\s*:\s*(\S+)", block, re.I)
        if not m or not _AP_FEATURE.search(m.group(1).replace("_", "-")):
            continue
        state = re.search(r"License State\s*:\s*(.+)", block, re.I)
        if state and not re.search(r"\bactive", state.group(1), re.I):
            continue
        count = re.search(r"License Count\s*:\s*(\d+)", block, re.I)
        kind = re.search(r"License Type\s*:\s*(\S+)", block, re.I)
        if count:
            out.append((int(count.group(1)), kind.group(1).lower() if kind else ""))
    return out


# --- show cpu / show memory statistics -------------------------------------

def parse_cpu(text):
    """current_pct from "Current CPU(s) load"; per-core figures are
    user%/system% pairs, so a core's load is their sum and avg_pct is the
    mean over cores. current_pct falls back to avg_pct when absent."""
    if not _usable(text):
        return None
    m = re.search(r"Current CPU(?:\(s\))?\s+load\s*[:.]*\s*(\d+)\s*%", text, re.I)
    cores = []
    m2 = re.search(r"Individual CPU load\s*[:.]*\s*(.+)", text, re.I)
    if m2:
        for pair in re.finditer(r"(\d+)%\s*(?:/\s*(\d+)%)?", m2.group(1)):
            cores.append(int(pair.group(1)) + int(pair.group(2) or 0))
    avg = round(sum(cores) / len(cores)) if cores else None
    current = int(m.group(1)) if m else avg
    if current is None:
        info = t.dotted(text)
        current = t.to_int(t.lookup(info, "CPU Current Usage", "Current CPU Usage"))
    return {"current_pct": current, "avg_pct": avg, "cores": cores}


_UNITS_KB = {"b": 1 / 1024, "bytes": 1 / 1024, "kb": 1, "k": 1, "mb": 1024, "gb": 1024 * 1024}


def _kb(value):
    m = re.search(r"(\d[\d,]*)\s*([a-zA-Z]+)?", value or "")
    if not m:
        return None
    n = int(m.group(1).replace(",", ""))
    unit = (m.group(2) or "bytes").lower()
    return int(n * _UNITS_KB.get(unit, 1 / 1024))


def parse_memory(text):
    """Totals in kB whatever unit the code prints (8.x prints bytes, some
    builds kB). Free is derived from total - used when not printed."""
    if not _usable(text):
        return None
    info = {k: _clean(v) for k, v in t.dotted(text).items()}
    total = _kb(t.lookup(info, "Total System Memory", "Total Memory"))
    free = _kb(t.lookup(info, "Free System Memory", "Free Memory"))
    used = _kb(t.lookup(info, "Used System Memory", "Used Memory"))
    if total is None:
        # One-line form: "Total System Memory: 3851260 kB, Free System Memory: ..."
        m = re.search(r"Total System Memory[.:\s]*([\d,]+\s*\w*)", text, re.I)
        total = _kb(m.group(1)) if m else None
    if free is None:
        m = re.search(r"Free System Memory[.:\s]*([\d,]+\s*\w*)", text, re.I)
        free = _kb(m.group(1)) if m else None
    if free is None and total is not None and used is not None:
        free = total - used
    pct = round(100 * free / total, 1) if total and free is not None else None
    return {"total_kb": total, "free_kb": free, "free_pct": pct}


# --- redundancy (HA SSO) -----------------------------------------------------

def parse_redundancy_summary(text):
    """Named fields plus every 'Label = value' line as a snake_case key."""
    if not _usable(text):
        return None
    raw = _pairs(text)
    out = {_snake(k): v.strip() for k, v in raw.items()}
    mode_text = t.lookup(raw, "Redundancy Mode") or ""
    if re.search(r"disabled", mode_text, re.I):
        mode = "Disabled"
    elif re.search(r"sso", mode_text, re.I):
        mode = "SSO"
    else:
        mode = mode_text.split()[0].title() if mode_text else ""
    unit_text = t.lookup(raw, "Unit") or ""
    out.update({
        "mode": mode,
        "mode_text": mode_text,
        "local_state": t.lookup(raw, "Local State") or "",
        "peer_state": t.lookup(raw, "Peer State") or "",
        "unit": unit_text.split()[0].title() if unit_text else "",
        "ha_sku": bool(re.search(r"ha\s*-?sku", unit_text, re.I)),
        "unit_id": t.norm_mac(t.lookup(raw, "Unit ID")) or (t.lookup(raw, "Unit ID") or ""),
        "redundancy_state": t.lookup(raw, "Redundancy State") or "",
        "mobility_mac": t.norm_mac(t.lookup(raw, "Mobility MAC")),
        "bulk_sync_status": t.lookup(raw, "BulkSync Status", "Bulk Sync Status") or "",
        "local_rmi": t.lookup(raw, "Local RMI", "Local Redundancy Management IP") or "",
        "peer_rmi": t.lookup(raw, "Peer RMI", "Peer Redundancy Management IP") or "",
        "peer_latency_us": t.to_int(t.lookup(
            raw, "Average Redundancy Peer Reachability Latency")),
        "gateway_latency_us": t.to_int(t.lookup(
            raw, "Average Management Gateway Reachability Latency")),
    })
    return out


def parse_redundancy_detail(text):
    if not _usable(text):
        return None
    raw = _pairs(text)
    port_state = ""
    for label, value in raw.items():
        if re.search(r"redundancy port", label, re.I) and re.search(r"state|status", label, re.I):
            port_state = value
            break
    return {
        "redundancy_mgmt_ip": _blank(t.lookup(raw, "Redundancy Management IP Address",
                                              "Redundancy Management IP")),
        "peer_redundancy_mgmt_ip": _blank(t.lookup(raw, "Peer Redundancy Management IP Address",
                                                   "Peer Redundancy Management IP")),
        "redundancy_port_ip": _blank(t.lookup(raw, "Redundancy Port IP Address",
                                              "Redundancy Port IP")),
        "peer_redundancy_port_ip": _blank(t.lookup(raw, "Peer Redundancy Port IP Address",
                                                   "Peer Redundancy Port IP")),
        "peer_service_port_ip": _blank(t.lookup(raw, "Peer Service Port IP Address",
                                                "Peer Service Port IP")),
        "redundancy_port_state": port_state,
    }


def parse_redundancy_statistics(text):
    if not _usable(text):
        return None
    raw = _pairs(text)
    out = {_snake(k): v.strip() for k, v in raw.items()}
    switchovers = None
    for label, value in raw.items():
        if re.search(r"(number of|total)\s+switchovers?|switchover count", label, re.I):
            switchovers = t.to_int(value)
            break
    out.update({
        "last_switchover_time": _blank(t.lookup(raw, "Last Switchover Time",
                                                "Last Switchover Timestamp")),
        "last_switchover_reason": _blank(t.lookup(raw, "Last Switchover Reason")),
        "switchovers": switchovers,
    })
    return out


def _to_ms(value):
    n = t.to_float(value)
    if n is None:
        return None
    v = (value or "").lower()
    if re.search(r"\bsec|\bs\b", v) and "milli" not in v and "ms" not in v.split():
        return int(n * 1000)
    return int(n)


def _to_s(value):
    n = t.to_float(value)
    if n is None:
        return None
    v = (value or "").lower()
    if "milli" in v or "ms" in v.split():
        return round(n / 1000, 3)
    return int(n) if n == int(n) else n


def parse_redundancy_timers(text):
    """Every dotted timer as snake_case text, plus keepalive_ms and
    peer_search_s converted from whatever unit is printed (default unit:
    milliseconds for keepalive, seconds for peer search)."""
    if not _usable(text):
        return None
    raw = _pairs(text)
    out = {_snake(k): v.strip() for k, v in raw.items()}
    keepalive = next((v for k, v in raw.items()
                      if re.search(r"keep\s*-?alive\s+(timeout|timer|interval)", k, re.I)), None)
    search = next((v for k, v in raw.items() if re.search(r"peer search", k, re.I)), None)
    retries = next((v for k, v in raw.items()
                    if re.search(r"keep\s*-?alive\s+retr", k, re.I)), None)
    out.update({"keepalive_ms": _to_ms(keepalive), "peer_search_s": _to_s(search),
                "keepalive_retries": t.to_int(retries)})
    return out


_IP = r"\d{1,3}(?:\.\d{1,3}){3}"


def parse_peer_route(text):
    if not _usable(text):
        return None
    out = []
    for line in text.splitlines():
        m = re.match(rf"^\s*({_IP})\s+({_IP})\s+({_IP})\s*$", line)
        if m:
            out.append({"network": m.group(1), "mask": m.group(2), "gateway": m.group(3)})
    return out


# --- interfaces ------------------------------------------------------------

def parse_interface_summary(text):
    if not _usable(text):
        return None
    out = []
    for row in t.table(text):
        name = t.lookup(row, "Interface Name")
        if not name:
            continue
        out.append({
            "name": name,
            "port": t.lookup(row, "Port") or "",
            "vlan": t.lookup(row, "Vlan Id", "VLAN Id", "VLAN") or "",
            "ip": t.lookup(row, "IP Address") or "",
            "type": (t.lookup(row, "Type") or "").title(),
            "ap_manager": t.enabled(t.lookup(row, "Ap Mgr", "AP Mgr")) is True,
            "guest": t.enabled(t.lookup(row, "Guest")) is True,
        })
    return out


def _port_name(value):
    # "LAG (13)" -> "LAG"; "1" stays "1".
    v = _blank(value)
    return "LAG" if v.upper().startswith("LAG") else v


def parse_interface_detail(text):
    """show interface detailed <name>. 8.5 prints "Physical Port", 8.10
    "Primary Physical Port" plus "Active Physical Port"."""
    if not _usable(text):
        return None
    info = t.dotted(text)

    def get(*labels):
        return t.lookup(info, *labels) or ""

    qvlan = t.to_int(get("Quarantine-vlan", "Quarantine Vlan"))
    quarantine = (qvlan or 0) > 0 or t.enabled(get("Quarantine")) is True
    ipv6 = ""
    for label, value in t.dotted_all(text):
        if re.match(r"(Primary )?IPv6 Address$", label, re.I) and _blank(value):
            ipv6 = value
            break
    port = _port_name(get("Primary Physical Port", "Physical Port"))
    return {
        "name": get("Interface Name"),
        "mac": t.norm_mac(get("MAC Address")),
        "ip": _blank(get("IP Address")),
        "mask": _blank(get("IP Netmask")),
        "gateway": _blank(get("IP Gateway")),
        "vlan": get("VLAN", "VLAN Identifier"),
        "port": port,
        "backup_port": _port_name(get("Backup Physical Port")),
        "active_port": _port_name(get("Active Physical Port")) or port,
        "dhcp_primary": _blank(get("Primary DHCP Server")),
        "dhcp_secondary": _blank(get("Secondary DHCP Server")),
        "dhcp_proxy": get("DHCP Proxy Mode"),
        "acl": _blank(get("IPv4 ACL", "ACL")),
        "ipv6": ipv6,
        "nas_id": _blank(get("NAS-Identifier", "NAS Identifier")),
        "guest_lan": t.enabled(get("Guest Interface")) is True,
        "quarantine": quarantine,
        "quarantine_vlan": qvlan or 0,
        "ap_manager": t.enabled(get("AP Manager")) is True,
        "interface_group": _blank(get("Interface Group", "Interface Group Name")),
    }


def parse_interface_groups(text):
    """show interface group summary: one row per group with member counts.

    The summary does not name the member interfaces; that needs the run
    config, see interface_group_members.
    """
    if not _usable(text):
        return None
    out = []
    for row in t.table(text):
        name = t.lookup(row, "Interface Group Name", "Group Name")
        if not name:
            continue
        out.append({
            "name": name,
            "interface_count": t.to_int(t.lookup(row, "Total Interfaces")),
            "wlan_count": t.to_int(t.lookup(row, "Total WLANs")),
            "ap_group_count": t.to_int(t.lookup(row, "Total AP Groups")),
            "quarantine": t.enabled(t.lookup(row, "Quarantine Interface", "Quarantine")) is True,
        })
    return out


def interface_group_members(run_config):
    """{group: [interface names]} from 'config interface group interface add'."""
    out = {}
    for m in re.finditer(r"^\s*config\s+interface\s+group\s+interface\s+add\s+(\S+)\s+(\S+)",
                         run_config or "", re.I | re.M):
        out.setdefault(m.group(1), [])
        if m.group(2) not in out[m.group(1)]:
            out[m.group(1)].append(m.group(2))
    return out


# --- ports -----------------------------------------------------------------

def _two_line_table(text):
    """Rows of a table whose header spans two lines above the dash rule,
    keyed by both header words joined ("Physical Status"). t.table keys by
    the lower line only, which repeats "Mode" and "Status"."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if i < 1 or not re.match(r"^\s*-{2,}(\s+-{2,})+\s*$", line):
            continue
        spans = [(m.start(), m.end()) for m in re.finditer(r"-+", line)]
        names = [""] * len(spans)
        for header in lines[max(0, i - 2):i]:
            for w in re.finditer(r"\S+", header):
                idx = max((k for k, (s, _) in enumerate(spans) if s <= w.start() + 1),
                          default=0)
                names[idx] = (names[idx] + " " + w.group()).strip()
        rows = []
        for row in lines[i + 1:]:
            if not row.strip():
                break
            cells = t._split_row(row, spans)
            rows.append(dict(zip(names, cells)))
        return rows
    return []


def parse_port_summary(text):
    if not _usable(text):
        return None
    out = []
    for row in _two_line_table(text):
        port = t.to_int(t.lookup(row, "Pr", "Port"))
        if port is None:
            continue
        status = t.lookup(row, "Physical Status") or ""
        speed = re.match(r"\s*(\d+)\s*(\w+)?", status)
        out.append({
            "port": port,
            "type": t.lookup(row, "Type") or "",
            "stp": t.lookup(row, "STP Stat") or "",
            "admin": t.lookup(row, "Admin Mode") or "",
            "phys_mode": t.lookup(row, "Physical Mode") or "",
            "phys_status": status,
            "speed_mbps": int(speed.group(1)) if speed else None,
            "duplex": (speed.group(2) or "") if speed else "",
            "link": t.lookup(row, "Link Status") or "",
            "link_trap": t.lookup(row, "Link Trap") or "",
            "poe": t.lookup(row, "POE") or "",
            "media": t.lookup(row, "SFPType", "SFP Type") or "",
        })
    return out


def parse_lag(text):
    if not _usable(text):
        return None
    m = re.search(r"LAG\s+(?:is\s+|Mode\W*)?(enabled|disabled)", text, re.I)
    return {"enabled": m.group(1).lower() == "enabled" if m else None}


# Receive-side counters whose sum is the input error count when the code
# does not print a total; FASTPATH's "with MAC Errors" total is these.
_RX_ERRORS = ("jabbers received", "fragments/undersize received", "alignment errors",
              "fcs errors", "overruns")
_TX_ERRORS = ("fcs errors", "oversized", "underrun errors", "excessive collision frames",
              "late collisions")


def parse_port_stats(text):
    """show stats port detailed <n>.

    Counters are read in order; everything after the first transmit counter
    is the transmit side, since labels like "FCS Errors" repeat in both.
    input_errors is "Total Packets Received with MAC Errors" when printed,
    else the sum of the receive error counters; output_errors is "Total
    Transmit Errors" when printed, else the sum of the transmit ones.
    """
    if not _usable(text):
        return None
    rx, tx, counters = {}, {}, {}
    side = rx
    for label, value in t.dotted_all(text):
        n = t.to_int(value)
        if n is None:
            continue
        key = label.strip().lower()
        if side is rx and re.search(r"transmit|tx\b", key):
            side = tx
        side.setdefault(key, n)
        counters.setdefault(("rx_" if side is rx else "tx_") + _snake(label), n)

    def total(side, names):
        found = [v for k, v in side.items() if any(k.startswith(n) for n in names)]
        return sum(found) if found else None

    input_errors = next((v for k, v in rx.items() if "with mac errors" in k), None)
    if input_errors is None:
        input_errors = total(rx, _RX_ERRORS)
    output_errors = next((v for k, v in tx.items() if k.startswith("total transmit errors")),
                         None)
    if output_errors is None:
        output_errors = total(tx, _TX_ERRORS)
    return {
        "input_errors": input_errors,
        "output_errors": output_errors,
        "input_drops": next((v for k, v in rx.items() if "discard" in k), None),
        "output_drops": next((v for k, v in tx.items() if "discard" in k), None),
        "crc": rx.get("fcs errors"),
        "counters": counters,
    }


# --- CDP -------------------------------------------------------------------

def parse_cdp_neighbors(text):
    if not _usable(text):
        return None
    out = []
    for block in re.split(r"(?=^\s*Device ID\s*:)", text, flags=re.M):
        m = re.search(r"Device ID\s*:\s*(\S+)", block)
        if not m:
            continue
        ip = re.search(r"IP(?:v4)? address\s*:\s*(" + _IP + ")", block, re.I)
        plat = re.search(r"Platform\s*:\s*(.*?)\s*,\s*Capabilities\s*:\s*(.*)", block, re.I)
        intf = re.search(r"Interface\s*:\s*(.*?)\s*,\s*Port ID \(outgoing port\)\s*:\s*(.+)",
                         block, re.I)
        version = re.search(r"Version\s*:\s*\n\s*(\S.*)", block)
        out.append({
            "local_port": intf.group(1).strip() if intf else "",
            "device_id": m.group(1),
            "ip": ip.group(1) if ip else "",
            "platform": plat.group(1).strip() if plat else "",
            "remote_port": intf.group(2).strip() if intf else "",
            "capabilities": plat.group(2).strip() if plat else "",
            "version": version.group(1).strip() if version else "",
        })
    return out


# --- time and NTP ----------------------------------------------------------

def _ntp_status(value):
    v = (value or "").strip().lower()
    if not v:
        return None
    if v.startswith(("not", "un")) or "fail" in v:
        return False
    if "sync" in v:
        return True
    return None


def parse_time(text):
    """show time. 8.3+ prints an NTP table with Status; 8.0-8.2 the same
    table without Status; older code dotted "NTP Server 1" lines. The NTP
    table's dash rule is one long run, so rows are read by pattern."""
    if not _usable(text):
        return None
    info = t.dotted(text)
    servers = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s*(.*?)\s*$", line)
        if not m or m.group(3).isdigit():
            continue
        rest = [p for p in re.split(r"\s{2,}", m.group(4)) if p]
        status = ""
        if rest and not rest[0].upper().startswith("AUTH"):
            status = rest[0]
        servers.append({"index": int(m.group(1)), "server": m.group(3), "status": status,
                        "key_index": int(m.group(2))})
    if not servers:
        for label, value in t.dotted_all(text):
            m = re.match(r"NTP Server\s*(\d+)$", label, re.I)
            if m and _blank(value):
                servers.append({"index": int(m.group(1)), "server": value, "status": "",
                                "key_index": None})
    states = [_ntp_status(s["status"]) for s in servers if s["status"]]
    known = [s for s in states if s is not None]
    return {
        "time": t.lookup(info, "Time") or "",
        "timezone": t.lookup(info, "Timezone location") or t.lookup(info, "Timezone delta") or "",
        "timezone_delta": t.lookup(info, "Timezone delta") or "",
        "ntp_servers": servers,
        "ntp_synced": any(known) if known else None,
        "ntp_version": t.to_int(t.lookup(info, "NTP Version")),
        "polling_interval": t.to_int(t.lookup(info, "NTP Polling Interval")),
    }


# --- crash data --------------------------------------------------------------

def parse_coredumps(text):
    """present is True when a dump file is named or said to be in flash."""
    if not _usable(text):
        return None
    files = []
    for label, value in t.dotted_all(text):
        if re.search(r"file\s*name", label, re.I) and not re.search(r"ftp", label, re.I) \
                and _blank(value):
            files.append(value)
    for m in re.finditer(r"Core\s*Dump\s+File\s+Name\s*:\s*(\S+)", text, re.I):
        if m.group(1) not in files:
            files.append(m.group(1))
    saved = re.search(r"core\s*dump file is saved|core\s*dump.*present in flash", text, re.I)
    none = re.search(r"\bno\s+core\s*dump", text, re.I)
    enabled = re.search(r"Core\s*Dump is (enabled|disabled)", text, re.I)
    return {
        "present": bool(files or saved) and not (none and not files),
        "files": files,
        "enabled": enabled.group(1).lower() == "enabled" if enabled else None,
    }


def parse_ap_crash_files(text):
    """File names listed under "Local Core Files:" / "AP Crash Files:" /
    "Local Crash Files:"; the trailing "(size)" is dropped."""
    if not _usable(text):
        return None
    out, listing = [], False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r".*(core|crash)\s+files\s*:\s*$", s, re.I):
            listing = True
            continue
        if not s or not listing:
            continue
        if re.match(r"(no |the number|the size)", s, re.I) or len(s.split()) > 2:
            continue
        name = re.sub(r"\s*\(\d+\)\s*$", "", s)
        if name and name not in out:
            out.append(name)
    return out


# --- management-plane settings ---------------------------------------------

_SECTION_KEYS = {"strong password check features": "strong_password",
                 "mgmt user": "mgmt_user", "snmpv3 user": "snmpv3_user"}


def parse_switchconfig(text):
    """Every dotted setting as {snake_case: text}. Indented settings under a
    "Heading:" line get the heading as a prefix, because the Mgmt User and
    SNMPv3 User sections repeat the same labels."""
    if not _usable(text):
        return None
    out, section = {}, ""
    for line in text.splitlines():
        heading = re.match(r"^\s*([A-Za-z][\w .]*?)\s*:\s*$", line)
        if heading:
            name = heading.group(1).strip().lower()
            section = _SECTION_KEYS.get(name, _snake(name))
            continue
        m = re.match(r"^(\s*)(\S[^\n]*?)\s*\.{3,}\s*(.*?)\s*$", line)
        if not m:
            continue
        if not m.group(1):
            section = ""
        key = _snake(m.group(2))
        if section:
            key = f"{section}_{key}"
        out.setdefault(key, m.group(3))
    return out


def parse_stats_switch(text):
    if not _usable(text):
        return None
    info = t.dotted(text)
    return {
        "rx_packets": t.to_int(t.lookup(info, "Packets Received Without Error")),
        "rx_errors": t.to_int(t.lookup(info, "Packets Received With Error")),
        "tx_packets": t.to_int(t.lookup(info, "Packets Transmitted Without Error")),
        "tx_errors": t.to_int(t.lookup(info, "Transmit Packet Errors",
                                       "Packets Transmitted With Error")),
        "since_cleared": t.lookup(info, "Time Since Counters Last Cleared") or "",
    }


def _first(info, pattern):
    return next((v for k, v in info.items() if re.search(pattern, k, re.I)), None)


def parse_serial(text):
    if not _usable(text):
        return None
    info = t.dotted(text)
    return {"console_timeout_min": t.to_int(_first(info, r"timeout")),
            "baud_rate": t.to_int(_first(info, r"baud"))}


def parse_sessions(text):
    if not _usable(text):
        return None
    info = t.dotted(text)
    return {"cli_timeout_min": t.to_int(_first(info, r"(login|session)\s+timeout")),
            "max_sessions": t.to_int(_first(info, r"maximum number"))}


def parse_loginsession(text):
    """Number of logged-in sessions; user names are not kept."""
    if not _usable(text):
        return None
    return {"count": len(t.table(text))}
