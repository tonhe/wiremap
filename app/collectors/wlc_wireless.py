"""
Parsers for the wireless side of AireOS controller output: WLANs, AP groups,
global RF, RF profiles, radios, access points, AP joins, and the client and
exclusion lists.

Pure functions over the raw text of one command, so the report can re-parse
a saved scan without a controller. Every parser returns None when the output
is empty or is a CLI error (the report shows n/a), and otherwise a dict or
list that may be empty. None of them raise on odd output; a field the code
did not print comes back None.

Client output arrives already scrubbed (MACs are xx:xx:xx:xx:xx:xx, user
names <REDACTED>), and the client parsers return counts and attributes only,
never an identifier.
"""
import re

from . import wlc_text as t

try:
    from app.collectors.errors import error_reason
except ImportError:
    from collectors.errors import error_reason


# --- shared helpers --------------------------------------------------------

_DOT_LINE = re.compile(r"^\s*(\S.*?)\s*\.{3,}\s*(.*?)\s*$")
# Placeholders AireOS prints where a value is unset.
_UNSET = {"", "none", "<none>", "not configured", "unconfigured", "n/a", "na",
          "not applicable", "not available", "0.0.0.0"}
# 5 GHz channels that need DFS (UNII-2 and UNII-2e).
_DFS = set(range(52, 65, 4)) | set(range(100, 145, 4))


def _usable(text):
    return bool((text or "").strip()) and not error_reason(text)


def _norm(label):
    # Labels carry stray colons ("802.11 Authentication:"), leading "- "
    # (join stats) and doubled spaces ("S/W  Version").
    label = re.sub(r"^[-\s]+", "", label or "")
    label = label.rstrip(": ").strip()
    return re.sub(r"\s+", " ", label).lower()


def _kv(text):
    """{normalised label: value}, first occurrence wins."""
    out = {}
    for label, value in t.dotted_all(text):
        key = _norm(label)
        if key and key not in out:
            out[key] = value
    return out


def _get(kv, *labels):
    for label in labels:
        value = kv.get(_norm(label))
        if value is not None:
            return value
    return None


def _prefixed(kv, prefix):
    """Value of the first label starting with prefix; AireOS truncates long
    labels ("Global client minimum exception lev")."""
    prefix = _norm(prefix)
    for key, value in kv.items():
        if key.startswith(prefix):
            return value
    return None


def _strip_band(kv):
    """Drop the band prefix ("802.11a ", "802.11b/g ") from every label."""
    out = {}
    for key, value in kv.items():
        key = re.sub(r"^802\.11[a-z/]*\s+", "", key)
        if key not in out:
            out[key] = value
    return out


def _val(value):
    if value is None:
        return None
    value = value.strip()
    return None if value.lower() in _UNSET else value


def _bool(value):
    v = (value or "").strip().lower()
    if v.startswith("admin_"):
        v = v[6:]
    return t.enabled(v)


def _title(value):
    v = _val(value)
    if v is None:
        return None
    v = re.sub(r"^admin_", "", v, flags=re.I)
    return v[:1].upper() + v[1:].lower()


def _lower(value):
    v = _val(value)
    return v.lower() if v is not None else None


def _indent(line):
    return len(line) - len(line.lstrip())


def _under(text, header):
    """Lines indented beneath the first line matching header (a regex for the
    whole stripped line), blank lines kept."""
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        if re.fullmatch(header, line.strip(), re.I):
            base = _indent(line)
            out = []
            for nxt in lines[i + 1:]:
                if nxt.strip() and _indent(nxt) <= base:
                    break
                out.append(nxt)
            return "\n".join(out)
    return ""


def _number_list(text, label):
    """Integers in a dotted list value, including the wrapped continuation
    lines AireOS prints under it ("......... 104,108,112")."""
    lines = (text or "").splitlines()
    want = _norm(label)
    for i, line in enumerate(lines):
        m = _DOT_LINE.match(line)
        if not m or _norm(m.group(1)) != want:
            continue
        parts = [m.group(2)]
        for nxt in lines[i + 1:]:
            c = re.fullmatch(r"\s*(?:\.{3,}\s*)?([\d,\s]+?),?\s*", nxt)
            if not c or not c.group(1).strip():
                break
            parts.append(c.group(1))
        return [int(n) for n in re.findall(r"\d+", ",".join(parts))]
    return []


def _seconds(value):
    """'600 seconds', '1 Hour(s)', '10 minutes' -> seconds."""
    v = (value or "").lower()
    n = t.to_int(v)
    if n is None:
        return None
    if "hour" in v:
        return n * 3600
    if "min" in v:
        return n * 60
    return n


def _timeout(value):
    # 0 means no timeout, as in the AireOS config commands.
    v = (value or "").lower()
    if not v.strip():
        return None
    if re.search(r"infinit|disable", v):
        return 0
    return _seconds(v)


def uptime_seconds(value):
    """'41 days, 03 h 10 m 05 s' or '2 days 3 hrs 4 mins 5 secs' -> seconds."""
    total, found = 0, False
    for n, unit in re.findall(r"(\d+)\s*([a-z]+)", (value or "").lower()):
        mult = {"d": 86400, "h": 3600, "m": 60, "s": 1}.get(unit[0])
        if mult:
            total += int(n) * mult
            found = True
    return total if found else None


def _controller(value):
    """'lab-wlc-01 (192.0.2.40)' -> {'name', 'ip'}; None when unset."""
    v = _val(value)
    if not v:
        return None
    m = re.match(r"^(\S+)?\s*\(?\s*(\d{1,3}(?:\.\d{1,3}){3})?\s*\)?\s*$", v)
    if m and m.group(1) and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", m.group(1)):
        return {"name": None, "ip": m.group(1)}
    if m:
        return {"name": m.group(1), "ip": m.group(2)}
    return {"name": v.split()[0], "ip": None}


def _band(value):
    v = (value or "").lower().replace(" ", "")
    if not v:
        return None
    if "2.4" in v or re.search(r"802\.11b|802\.11g", v):
        return "2.4"
    if "6ghz" in v:
        return "6"
    if "5ghz" in v or "802.11a" in v or v == "5":
        return "5"
    return None


def _rate_lists(text):
    """Operational rates from '802.11a 6M Rate.... Mandatory' lines."""
    seen = {}
    for label, value in t.dotted_all(text):
        m = re.search(r"(\d+(?:\.\d+)?)\s*M\s+Rate$", label.strip(), re.I)
        if m and m.group(1) not in seen:
            seen[m.group(1)] = value.strip().lower()
    order = sorted(seen, key=float)
    return {
        "mandatory_rates": [r for r in order if seen[r].startswith("mandatory")],
        "supported_rates": [r for r in order if seen[r].startswith("supported")],
        "disabled_rates": [r for r in order if seen[r].startswith("disabled")],
    }


def _rows(text, *required):
    """Rows of every table whose header has all the required columns."""
    out = []
    for rows in t.tables(text):
        if rows and all(t.lookup(rows[0], c) is not None for c in required):
            out.extend(rows)
    return out


def _speed_mbps(value):
    v = (value or "").lower()
    n = t.to_float(v)
    if n is None:
        return None
    return int(n * 1000) if re.search(r"\d\s*g", v) else int(n)


# --- WLANs ------------------------------------------------------------------

def parse_wlan_summary(text):
    """show wlan summary -> [{id, profile, ssid, status, interface}]."""
    if not _usable(text):
        return None
    out = []
    for row in _rows(text, "WLAN ID") or _rows(text, "WLAN Id"):
        wid = t.to_int(t.lookup(row, "WLAN ID", "WLAN Id"))
        if wid is None:
            continue
        names = t.lookup(row, "WLAN Profile Name / SSID", "Profile Name / SSID") or ""
        profile, _, ssid = names.partition(" / ")
        out.append({
            "id": wid,
            "profile": profile.strip(),
            "ssid": (ssid or profile).strip(),
            "status": _title(t.lookup(row, "Status")),
            "interface": _val(t.lookup(row, "Interface Name", "Interface")),
        })
    return out


_AKM = {
    "802.1x": "802.1X", "psk": "PSK", "cckm": "CCKM", "ft-1x(802.11r)": "FT-802.1X",
    "ft-psk(802.11r)": "FT-PSK", "pmf-1x(802.11w)": "PMF-802.1X",
    "pmf-psk(802.11w)": "PMF-PSK", "sae": "SAE", "ft-sae": "FT-SAE", "owe": "OWE",
    "osen-1x": "OSEN", "suiteb-1x": "SUITEB", "suiteb192-1x": "SUITEB192",
    "802.1x-sha256": "802.1X-SHA256", "psk-sha256": "PSK-SHA256",
}
_CIPHERS = [("tkip cipher", "TKIP"), ("aes cipher", "AES"), ("ccmp256 cipher", "CCMP256"),
            ("gcmp128 cipher", "GCMP"), ("gcmp256 cipher", "GCMP256")]
_SERVER = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?:\s+(\d+))?")


def _servers(text, label):
    out, global_ = [], False
    for name, value in t.dotted_all(_under(text, r"Radius Servers") or text):
        if _norm(name) != label:
            continue
        m = _SERVER.search(value)
        if m:
            out.append(f"{m.group(1)}:{m.group(2)}" if m.group(2) else m.group(1))
        elif "global" in value.lower():
            global_ = True
    return out, global_


def _anchors(text):
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        if re.fullmatch(r"Mobility Anchor List", line.strip(), re.I):
            found = t.tables("\n".join(lines[i + 1:]))
            if not found or not found[0] or t.lookup(found[0][0], "IP Address") is None:
                return []
            return [{"ip": t.lookup(r, "IP Address"), "status": _val(t.lookup(r, "Status"))}
                    for r in found[0] if t.lookup(r, "IP Address")]
    return []


def parse_wlan(text):
    """show wlan <id>."""
    if not _usable(text):
        return None
    akm_text = _under(text, r"Auth Key Management")
    # The AKM block repeats labels used elsewhere ("802.1x" vs the legacy
    # "802.1X" line), so the rest is read without it.
    rest = text.replace(akm_text, "") if akm_text.strip() else text
    kv = _kv(rest)
    akm_kv = _kv(akm_text)
    if not _get(kv, "WLAN Identifier", "Profile Name"):
        return None

    akm = [_AKM.get(k, k.upper()) for k, v in akm_kv.items() if _bool(v)]
    encryption = []
    for label, value in t.dotted_all(text):
        for key, name in _CIPHERS:
            if _norm(label) == key and _bool(value) and name not in encryption:
                encryption.append(name)

    wpa_master = next((v for k, v in kv.items() if k.startswith("wi-fi protected access")), None)
    if _bool(wpa_master):
        parts = [n for n, lbl in (("WPA", "WPA (SSN IE)"), ("WPA2", "WPA2 (RSN IE)"),
                                  ("WPA3", "WPA3 (WPA3 IE)")) if _bool(_get(kv, lbl))]
        l2 = "+".join(parts) or "WPA"
    elif _bool(_get(kv, "Static WEP Keys")):
        l2 = "Static WEP"
    elif _bool(_get(kv, "802.1X")):
        # Legacy 802.1X without WPA is dynamic WEP.
        l2 = "WEP"
    else:
        l2 = "None"
    if l2 == "None":
        akm, encryption = [], []
    elif "WEP" in l2:
        akm, encryption = [], ["WEP"]

    if _bool(_get(kv, "Web Based Authentication")):
        l3 = "web auth"
    elif _bool(_get(kv, "Web-Passthrough", "Web Passthrough")):
        l3 = "web passthrough"
    elif _bool(_get(kv, "Conditional Web Redirect")):
        l3 = "conditional"
    elif _bool(_get(kv, "Splash-Page Web Redirect")):
        l3 = "splash"
    else:
        l3 = "none"

    ft_mode = _lower(_get(kv, "FT Support"))
    exclusion_flag = _get(kv, "Exclusionlist", "Client Exclusion")
    exclusion_timeout = _get(kv, "Exclusionlist Timeout")
    if exclusion_flag is not None:
        exclusion = _bool(exclusion_flag)
    elif exclusion_timeout is not None:
        exclusion = "disable" not in exclusion_timeout.lower()
    else:
        exclusion = None
    auth, auth_global = _servers(text, "authentication")
    acct, acct_global = _servers(text, "accounting")
    qos = _val(_get(kv, "Quality of Service"))

    return {
        "id": t.to_int(_get(kv, "WLAN Identifier")),
        "profile": _val(_get(kv, "Profile Name")),
        "ssid": _val(_get(kv, "Network Name (SSID)", "SSID")),
        "status": _title(_get(kv, "Status")),
        "broadcast_ssid": _bool(_get(kv, "Broadcast SSID")),
        "radio_policy": _val(_get(kv, "Radio Policy")),
        "interface": _val(_get(kv, "Interface")),
        "interface_group": _val(_get(kv, "Interface Group Name", "Interface Group")),
        "dot11_auth": _val(_get(kv, "802.11 Authentication")),
        "l2_security": l2,
        "encryption": encryption,
        "akm": akm,
        # Whether a shared key (PSK or SAE passphrase) is in use; the key
        # itself is never read.
        "psk_set": any("PSK" in a or "SAE" in a for a in akm),
        "pmf": _lower(_get(kv, "PMF")),
        "ft": ft_mode in ("enabled", "adaptive") or any(a.startswith("FT-") for a in akm),
        "ft_mode": ft_mode,
        "ft_over_ds": _bool(_get(kv, "FT Over-The-DS mode", "FT Over-The-DS")),
        "dot11k": _bool(_get(kv, "802.11k Neighbor List")),
        "dot11v": _bool(_get(kv, "802.11v BSS Transition Service")),
        "l3_security": l3,
        "web_auth_type": _val(_get(kv, "Web Authentication Type", "Webauth Type",
                                   "WebAuth Type")),
        "mac_filtering": _bool(_get(kv, "MAC Filtering")),
        "auth_servers": auth,
        "auth_global": auth_global,
        "acct_servers": acct,
        "acct_global": acct_global,
        "aaa_override": _bool(_get(kv, "AAA Policy Override")),
        "session_timeout_s": _timeout(_get(kv, "Session Timeout")),
        "idle_timeout_s": _timeout(_get(kv, "User Idle Timeout")),
        "exclusion": exclusion,
        "exclusion_timeout_s": _timeout(exclusion_timeout) if exclusion else None,
        "max_clients": t.to_int(_get(kv, "Maximum number of Associated Clients",
                                     "Maximum Clients Allowed")),
        "p2p_blocking": _lower(_get(kv, "Peer-to-Peer Blocking Action")),
        "dhcp_required": _bool(_get(kv, "DHCP Address Assignment Required")),
        "qos_profile": qos.split()[0].capitalize() if qos else None,
        "wmm": _title(_get(kv, "WMM")),
        "avc": _bool(_get(kv, "AVC Visibility", "AVC Visibilty")),
        "avc_profile": _val(_get(kv, "AVC Profile Name")),
        "netflow_monitor": _val(_get(kv, "Flow Monitor Name", "NetFlow Monitor")),
        "mobility_anchors": _anchors(text),
        "flex_local_switching": _bool(_get(kv, "FlexConnect Local Switching")),
        "flex_local_auth": _bool(_get(kv, "FlexConnect Local Authentication")),
        "mdns_snooping": _bool(_get(kv, "mDNS Status")),
        "mdns_profile": _val(_get(kv, "mDNS Profile Name")),
        "multicast_vlan": _val(_get(kv, "Multicast Interface", "Multicast Vlan Interface",
                                    "Multicast VLAN")),
        "dtim_a": t.to_int(_get(kv, "DTIM period for 802.11a radio")),
        "dtim_b": t.to_int(_get(kv, "DTIM period for 802.11b radio")),
        "band_select": _bool(_get(kv, "Band Select")),
        "load_balancing": _bool(_get(kv, "Load Balancing")),
        "clients": t.to_int(_get(kv, "Number of Active Clients")),
    }


def parse_apgroups(text, wlans=None):
    """show wlan apgroups. wlans (parse_wlan_summary rows) fills in SSIDs,
    which the group's WLAN table does not print."""
    if not _usable(text):
        return None
    ssids = {w["id"]: w["ssid"] for w in (wlans or [])}
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines)
              if (m := _DOT_LINE.match(line)) and _norm(m.group(1)) == "site name"]
    out = []
    for n, start in enumerate(starts):
        block = "\n".join(lines[start:starts[n + 1] if n + 1 < len(starts) else None])
        kv = _kv(block)
        group_wlans = []
        for row in _rows(block, "WLAN ID"):
            wid = t.to_int(t.lookup(row, "WLAN ID"))
            if wid is None:
                continue
            group_wlans.append({
                "id": wid,
                "ssid": ssids.get(wid),
                "interface": _val(t.lookup(row, "Interface")),
                "radio_policy": _val(t.lookup(row, "Radio Policy")),
            })
        out.append({
            "name": _val(_get(kv, "Site Name")),
            "description": _val(_get(kv, "Site Description")),
            "rf_profile_a": _val(_get(kv, "5 GHz band")),
            "rf_profile_b": _val(_get(kv, "2.4 GHz band")),
            "wlans": group_wlans,
            "aps": [t.lookup(r, "AP Name") for r in _rows(block, "AP Name")
                    if t.lookup(r, "AP Name")],
        })
    return out


# --- RF global -------------------------------------------------------------

def parse_band(text):
    """show 802.11a / show 802.11b."""
    if not _usable(text):
        return None
    kv = _kv(text)
    network = next((v for k, v in kv.items() if re.fullmatch(r"802\.11[ab](/g)? network", k)),
                   None)
    out = {
        "network_enabled": _bool(network),
        "g_enabled": _bool(_get(kv, "11gSupport", "802.11g Support")),
        "n_enabled": _bool(_get(kv, "11nSupport", "802.11n Support")),
        "ac_enabled": _bool(_get(kv, "802.11ac", "11acSupport", "802.11ac Support")),
        "ax_enabled": _bool(_get(kv, "802.11ax", "11axSupport", "802.11ax Support")),
        "beacon_interval": t.to_int(_get(kv, "Beacon Interval")),
        "dtim": t.to_int(_get(kv, "DTIM Period", "DTIM")),
        "fragmentation": t.to_int(_get(kv, "Fragmentation Threshold")),
        "default_channel": t.to_int(_get(kv, "Default Channel")),
        "dtpc": _bool(_get(kv, "DTPC Status")),
        "short_preamble": _bool(_get(kv, "Short Preamble mandatory")),
        "rssi_low_check": _bool(_get(kv, "RSSI Low Check")),
        "rssi_threshold": t.to_int(_get(kv, "RSSI Threshold")),
    }
    out.update(_rate_lists(text))
    return out


def parse_channel(text):
    """show advanced 802.11a|b channel."""
    if not _usable(text):
        return None
    kv = _kv(text)
    width = next((v for k, v in kv.items() if "channel width" in k), None)
    sensitivity = _val(_get(kv, "DCA Sensitivity Level"))
    channels = _number_list(text, "Allowed Channel List")
    return {
        "dca_mode": _lower(_get(kv, "Channel Assignment Mode")),
        "interval_s": _seconds(_get(kv, "Channel Update Interval")),
        "anchor_hour": t.to_int(_get(kv, "Anchor time (Hour of the day)")),
        "sensitivity": sensitivity.split()[0].lower() if sensitivity else None,
        "sensitivity_db": t.to_int(re.sub(r"^[^(]*", "", sensitivity or "")),
        "width": _val(width),
        "width_mhz": t.to_int(width),
        "leader": _controller(_get(kv, "Channel Assignment Leader")),
        "edrrm": _bool(_get(kv, "CleanAir Event-driven RRM option")),
        "channels": channels,
        "unused_channels": _number_list(text, "Unused Channel List"),
        "dfs_channels_in_list": [c for c in channels if c in _DFS],
    }


def parse_txpower(text):
    """show advanced 802.11a|b txpower."""
    if not _usable(text):
        return None
    kv = _kv(text)
    return {
        "tpc_mode": _lower(_get(kv, "Transmit Power Assignment Mode", "Power Assignment Mode")),
        "tpc_version": _val(_get(kv, "TPC Mode")),
        "interval_s": _seconds(_get(kv, "Transmit Power Update Interval",
                                    "Power Update Interval")),
        "threshold_dbm": t.to_int(_get(kv, "Transmit Power Threshold", "Power Threshold")),
        "neighbor_count": t.to_int(_get(kv, "Transmit Power Neighbor Count",
                                        "Power Neighbor Count")),
        "min_dbm": t.to_int(_get(kv, "Min Transmit Power")),
        "max_dbm": t.to_int(_get(kv, "Max Transmit Power")),
        "leader": _controller(_get(kv, "Transmit Power Assignment Leader",
                                   "Power Assignment Leader")),
    }


def parse_coverage(text):
    """show advanced 802.11a|b coverage."""
    if not _usable(text):
        return None
    kv = _strip_band(_kv(text))
    return {
        "enabled": _bool(_get(kv, "Coverage Hole Detection Mode")),
        "voice_packet_count": t.to_int(_get(kv, "Coverage Voice Packet Count")),
        "voice_packet_pct": t.to_int(_get(kv, "Coverage Voice Packet Percentage")),
        "voice_rssi_dbm": t.to_int(_get(kv, "Coverage Voice RSSI Threshold")),
        "data_packet_count": t.to_int(_get(kv, "Coverage Data Packet Count")),
        "data_packet_pct": t.to_int(_get(kv, "Coverage Data Packet Percentage")),
        "data_rssi_dbm": t.to_int(_get(kv, "Coverage Data RSSI Threshold")),
        "exception_level_pct": t.to_int(_prefixed(kv, "Global coverage exception")),
        "min_clients": t.to_int(_prefixed(kv, "Global client minimum exception")),
    }


def parse_group(text):
    """show advanced 802.11a|b group. The RF group name itself is in show
    network summary (RF-Network Name); it is read here only if printed."""
    if not _usable(text):
        return None
    kv = _strip_band(_kv(text))
    members = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _DOT_LINE.match(line)
        if not m or not re.search(r"group member$", _norm(m.group(1))):
            continue
        values = [m.group(2)]
        for nxt in lines[i + 1:]:
            if _DOT_LINE.match(nxt) or not nxt.strip():
                break
            values.append(nxt.strip())
        members = [c for c in (_controller(v) for v in values) if c]
        break
    return {
        "group_name": _val(_get(kv, "RF Group Name", "RF-Network Name")),
        "mode": _lower(_get(kv, "Group Mode")),
        "interval_s": _seconds(_get(kv, "Group Update Interval")),
        "leader": _controller(_get(kv, "Group Leader")),
        "members": members,
    }


def parse_monitor(text):
    """show advanced 802.11a|b monitor."""
    if not _usable(text):
        return None
    kv = _strip_band(_kv(text))
    return {
        "enabled": _bool(_get(kv, "Monitor Mode")),
        "channels": _val(_get(kv, "Monitor Channels")),
        "neighbor_discover_type": _val(_get(kv, "RRM Neighbor Discover Type")),
        "coverage_interval_s": _seconds(_get(kv, "AP Coverage Interval")),
        "load_interval_s": _seconds(_get(kv, "AP Load Interval")),
        "monitor_interval_s": _seconds(_get(kv, "AP Monitor Measurement Interval")),
        "report_interval_s": _seconds(_get(kv, "AP Report Measurement Interval")),
    }


def parse_profile_global(text):
    """show advanced 802.11a|b profile global."""
    if not _usable(text):
        return None
    kv = _strip_band(_kv(text))
    return {
        "interference_pct": t.to_int(_get(kv, "Global Interference threshold")),
        "noise_dbm": t.to_int(_get(kv, "Global noise threshold")),
        "utilization_pct": t.to_int(_get(kv, "Global RF utilization threshold")),
        "throughput_bps": t.to_int(_get(kv, "Global throughput threshold")),
        "clients": t.to_int(_get(kv, "Global clients threshold")),
    }


def parse_cleanair(text):
    """show 802.11a|b cleanair config."""
    if not _usable(text):
        return None
    kv = _kv(text)
    return {
        "enabled": _bool(_get(kv, "Clean Air Solution", "CleanAir Solution")),
        "aq_reporting": _bool(_get(kv, "Air Quality Reporting")),
        "edrrm": _bool(_get(kv, "CleanAir ED-RRM State")),
        "edrrm_sensitivity": _lower(_get(kv, "CleanAir ED-RRM Sensitivity")),
        "persistent_devices": _bool(_get(kv, "CleanAir Persistent Devices state")),
    }


def parse_fra(text):
    """show advanced fra."""
    if not _usable(text):
        return None
    kv = _kv(text)
    sensitivity = _val(_get(kv, "FRA Sensitivity"))
    return {
        "enabled": _bool(_get(kv, "FRA State")),
        "sensitivity": sensitivity.split()[0].lower() if sensitivity else None,
        "interval_s": _seconds(_get(kv, "FRA Interval")),
        "priority": _lower(_get(kv, "Service Priority")),
        "client_aware": _bool(_get(kv, "Client Aware FRA")),
    }


def parse_dot11h(text):
    """show 802.11h."""
    if not _usable(text):
        return None
    kv = _kv(text)
    return {
        "power_constraint": t.to_int(_get(kv, "Power Constraint")),
        "channel_switch": _bool(_get(kv, "Channel Switch")),
        "channel_switch_mode": t.to_int(_get(kv, "Channel Switch Mode")),
        "smart_dfs": _bool(_get(kv, "Smart DFS")),
    }


# --- RF profiles -------------------------------------------------------------

def parse_rf_profile_summary(text):
    if not _usable(text):
        return None
    out = []
    for row in _rows(text, "RF Profile Name") or _rows(text, "Profile Name"):
        name = t.lookup(row, "RF Profile Name", "Profile Name")
        if not name:
            continue
        out.append({
            "name": name,
            "band": _band(t.lookup(row, "Band")),
            "description": _val(t.lookup(row, "Description")),
            "applied": _bool(t.lookup(row, "Applied")),
        })
    return out


def parse_rf_profile(text, name=None):
    """show rf-profile details <name>. The name is passed in when the output
    does not print it."""
    if not _usable(text):
        return None
    kv = _kv(text)
    if not kv:
        return None
    lb = _kv(_under(text, r"Load Balancing"))
    cov = _kv(_under(text, r"Coverage Data"))
    trap = _kv(_under(text, r"Trap Threshold"))
    width = _val(_get(kv, "DCA Bandwidth", "DCA Channel Width"))
    out = {
        "name": _val(_get(kv, "RF Profile Name", "Profile Name")) or name,
        "description": _val(_get(kv, "Description")),
        "band": _band(_get(kv, "Radio policy")),
        "ap_group": _val(_get(kv, "AP Group Name")),
        "tpc_min": t.to_int(_get(kv, "Min Transmit Power")),
        "tpc_max": t.to_int(_get(kv, "Max Transmit Power")),
        "tpc_threshold": t.to_int(_get(kv, "Transmit Power Threshold v1",
                                       "Transmit Power Threshold")),
        "tpc_threshold_v2": t.to_int(_get(kv, "Transmit Power Threshold v2")),
        "max_clients": t.to_int(_get(kv, "Max Clients")),
        "channels": _number_list(text, "DCA Channel List"),
        "width": width,
        "width_mhz": t.to_int(width),
        "load_balancing": {"window": t.to_int(_get(lb, "Window")),
                           "denial": t.to_int(_get(lb, "Denial"))},
        "coverage": {
            "data_rssi_dbm": t.to_int(_get(cov, "Data") or _get(kv, "Coverage Data RSSI Threshold")),
            "voice_rssi_dbm": t.to_int(_get(cov, "Voice")
                                       or _get(kv, "Coverage Voice RSSI Threshold")),
            "min_clients": t.to_int(_get(cov, "Minimum Client Level")),
            "exception_pct": t.to_int(_get(cov, "Exception Level")),
        },
        "trap_thresholds": {
            "clients": t.to_int(_get(trap, "Clients")),
            "interference_pct": t.to_int(_get(trap, "Interference")),
            "noise_dbm": t.to_int(_get(trap, "Noise")),
            "utilization_pct": t.to_int(_get(trap, "Utilization")),
        },
        "client_aware_fra": _bool(_get(kv, "Client Aware FRA")),
        "rx_sop": _val(_get(kv, "Rx SOP Threshold")),
    }
    out.update(_rate_lists(text))
    return out


# --- radios ----------------------------------------------------------------

def _channel_field(value):
    """'(36,40)*' -> (36, 40, True): primary channel, width, RRM-assigned."""
    nums = [int(n) for n in re.findall(r"\d+", value or "")]
    if not nums:
        return None, None, False
    return nums[0], 20 * len(nums), "*" in (value or "")


def _power_field(value):
    """'*1/6 (17 dBm)' -> (1, 6, 17)."""
    v = value or ""
    m = re.search(r"(\d+)\s*/\s*(\d+)", v)
    level, levels = (int(m.group(1)), int(m.group(2))) if m else (t.to_int(v), None)
    d = re.search(r"(-?\d+)\s*dBm", v, re.I)
    return level, levels, int(d.group(1)) if d else None


def parse_radio_summary(text):
    """show advanced 802.11a|b summary -> one row per radio."""
    if not _usable(text):
        return None
    out = []
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if not name:
            continue
        channel, width, rrm = _channel_field(t.lookup(row, "Channel"))
        level, levels, dbm = _power_field(t.lookup(row, "TxPower", "Tx Power"))
        out.append({
            "ap_name": name,
            "mac": t.norm_mac(t.lookup(row, "MAC Address", "Radio MAC")) or None,
            "slot": t.to_int(t.lookup(row, "Slot")),
            "admin": _title(t.lookup(row, "Admin")),
            "oper": _title(t.lookup(row, "Oper")),
            "channel": channel,
            "width": width,
            "channel_rrm": rrm,
            "tx_power_level": level,
            "tx_power_levels": levels,
            "tx_power_dbm": dbm,
        })
    return out


# --- access points -----------------------------------------------------------

def parse_ap_summary(text):
    if not _usable(text):
        return None
    out = []
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if not name:
            continue
        out.append({
            "name": name,
            "slots": t.to_int(t.lookup(row, "Slots")),
            "model": _val(t.lookup(row, "AP Model")),
            "ethernet_mac": t.norm_mac(t.lookup(row, "Ethernet MAC")) or None,
            "location": _val(t.lookup(row, "Location")),
            "country": _val(t.lookup(row, "Country")),
            "ip": _val(t.lookup(row, "IP Address")),
            "clients": t.to_int(t.lookup(row, "Clients")),
        })
    return out


_INV_NAME = re.compile(r'NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"', re.I)
_INV_PID = re.compile(r"PID:\s*([^,]*?)\s*,\s*VID:\s*([^,]*?)\s*,\s*SN:\s*(\S*)", re.I)


def parse_ap_inventory(text):
    """show ap inventory all -> {ap name: {name, descr, pid, vid, sn}}; the
    first entry per AP (the AP itself, before any module)."""
    if not _usable(text):
        return None
    out, ap, entry = {}, None, None
    for line in text.splitlines():
        m = re.match(r"^\s*Inventory for\s+(\S+)", line, re.I)
        if m:
            ap, entry = m.group(1), None
            continue
        if ap is None or ap in out and out[ap].get("pid"):
            continue
        m = _INV_NAME.search(line)
        if m:
            entry = {"name": m.group(1).strip(), "descr": m.group(2).strip(),
                     "pid": None, "vid": None, "sn": None}
            out[ap] = entry
            continue
        m = _INV_PID.search(line)
        if m:
            entry = out.setdefault(ap, {"name": None, "descr": None})
            entry.update({"pid": _val(m.group(1)), "vid": _val(m.group(2)),
                          "sn": _val(m.group(3))})
    return out


def parse_ap_cdp(text):
    """show ap cdp neighbors all -> [{ap_name, ap_ip, neighbor, neighbor_ip, port}]."""
    if not _usable(text):
        return None
    out = []
    for row in _rows(text, "AP Name"):
        if not t.lookup(row, "AP Name"):
            continue
        out.append({
            "ap_name": t.lookup(row, "AP Name"),
            "ap_ip": _val(t.lookup(row, "AP IP", "AP IP Address")),
            "neighbor": _val(t.lookup(row, "Neighbor Name", "Neighbor")),
            "neighbor_ip": _val(t.lookup(row, "Neighbor IP", "Neighbor IP Address")),
            "port": _val(t.lookup(row, "Neighbor Port", "Port")),
        })
    return out


def parse_ap_image(text):
    if not _usable(text):
        return None
    out = {}
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if name:
            out[name] = {
                "primary": _val(t.lookup(row, "Primary Image")),
                "backup": _val(t.lookup(row, "Backup Image")),
                "predownload_status": _val(t.lookup(row, "Predownload Status")),
            }
    return out


def parse_ap_uptime(text):
    if not _usable(text):
        return None
    out = {}
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if not name:
            continue
        up = _val(t.lookup(row, "AP Up Time", "Up Time"))
        join = _val(t.lookup(row, "Association Up Time", "LWAPP Up Time", "Join Up Time"))
        out[name] = {
            "ethernet_mac": t.norm_mac(t.lookup(row, "Ethernet MAC")) or None,
            "uptime": up,
            "uptime_s": uptime_seconds(up),
            "join_uptime": join,
            "join_uptime_s": uptime_seconds(join),
        }
    return out


def parse_join_summary(text):
    """show ap join stats summary all, printed with or without a dash rule."""
    if not _usable(text):
        return None
    out = []
    rows = _rows(text, "AP Name")
    if rows:
        for row in rows:
            base = t.norm_mac(t.lookup(row, "Base Mac", "Base MAC", "Radio MAC"))
            if not base:
                continue
            out.append({
                "base_mac": base,
                "ethernet_mac": t.norm_mac(t.lookup(row, "AP EthernetMac", "Ethernet MAC"))
                or None,
                "name": _val(t.lookup(row, "AP Name")),
                "ip": _val(t.lookup(row, "IP Address")),
                "status": _val(t.lookup(row, "Status")),
            })
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not t.norm_mac(parts[0]) or not t.norm_mac(parts[1]):
            continue
        out.append({
            "base_mac": t.norm_mac(parts[0]),
            "ethernet_mac": t.norm_mac(parts[1]),
            "name": _val(parts[2]),
            "ip": _val(parts[3]),
            "status": " ".join(parts[4:]),
        })
    return out


def parse_join_detail(text):
    """show ap join stats detailed <mac>."""
    if not _usable(text):
        return None
    kv = _kv(text)
    if not kv:
        return None

    def get(*labels):
        return _val(_get(kv, *labels))

    unsuccessful = get("Time at last unsuccessful join attempt")
    success = get("Time at last successful join attempt")
    tail = re.search(r"Ethernet Mac\s*:\s*(\S+)\s+Ip Address\s*:\s*(\S+)", text, re.I)
    return {
        "last_join_attempt": unsuccessful or success,
        "last_success": success,
        "last_failure": unsuccessful,
        "last_error_type": get("Type of error that occurred last"),
        "last_error": get("Reason for error that occurred last"),
        "last_error_time": get("Time at which the last join error occurred"),
        "attempts": t.to_int(get("Join requests received")),
        "failures": t.to_int(get("Unsuccessful join request processing")),
        "discovery_requests": t.to_int(get("Discovery requests received")),
        "failure_reason": (get("Reason for last unsuccessful join attempt")
                           or get("Reason for last unsuccessful configuration attempt")
                           or get("Reason for last unsuccessful discovery attempt")),
        "disconnect_reason": get("Last AP disconnect reason"),
        "ethernet_mac": t.norm_mac(tail.group(1)) or None if tail else None,
        "ip": _val(tail.group(2)) if tail else None,
    }


def _power(value):
    v = (value or "").lower()
    if not v.strip():
        return None
    if "injector" in v:
        return "injector"
    if "low" in v:
        return "PoE low power"
    if "medium" in v:
        return "PoE medium power"
    if "full" in v:
        return "PoE full"
    return value.strip()


def _ctrl_pair(kv, which):
    name = _val(_get(kv, f"{which} Cisco Switch Name"))
    ip = _val(_get(kv, f"{which} Cisco Switch IP Address"))
    if not name and not ip:
        return None
    return {"name": name, "ip": ip}


def parse_ap_config_general(text):
    """show ap config general <ap>."""
    if not _usable(text):
        return None
    kv = _kv(text)
    name = _val(_get(kv, "Cisco AP Name"))
    if not name:
        return None
    country = _val(_get(kv, "AP Country code", "Country code"))
    ip_mode = _val(_get(kv, "IP Address Configuration"))
    if ip_mode:
        ip_mode = "DHCP" if "dhcp" in ip_mode.lower() else "Static"
    return {
        "name": name,
        "base_mac": t.norm_mac(_get(kv, "Base Radio MAC", "Radio MAC", "Cisco Radio MAC"))
        or None,
        "ethernet_mac": t.norm_mac(_get(kv, "MAC Address")) or None,
        "model": _val(_get(kv, "AP Model")),
        "serial": _val(_get(kv, "AP Serial Number")),
        "ip": _val(_get(kv, "IP Address")),
        "mask": _val(_get(kv, "IP NetMask", "IP Netmask")),
        "gateway": _val(_get(kv, "Gateway IP Addr", "Gateway IP Address")),
        "ip_mode": ip_mode,
        "mode": _val(_get(kv, "AP Mode")),
        "submode": _val(_get(kv, "AP SubMode")),
        "ap_group": _val(_get(kv, "Cisco AP Group Name", "AP Group Name")),
        "flex_group": _val(_get(kv, "FlexConnect Group Name", "Flexconnect Group",
                                "FlexConnect Group")),
        "location": _val(_get(kv, "Cisco AP Location")),
        "primary_controller": _ctrl_pair(kv, "Primary"),
        "secondary_controller": _ctrl_pair(kv, "Secondary"),
        "tertiary_controller": _ctrl_pair(kv, "Tertiary"),
        "sw_version": _val(_get(kv, "S/W Version", "IOS Version")),
        "boot_version": _val(_get(kv, "Boot Version")),
        "uptime": _val(_get(kv, "AP Up Time")),
        "uptime_s": uptime_seconds(_get(kv, "AP Up Time")),
        "join_uptime": _val(_get(kv, "AP LWAPP Up Time", "AP CAPWAP Up Time")),
        "join_date": _val(_get(kv, "Join Date and Time")),
        "last_reboot_reason": _val(_get(kv, "Last Reboot Reason", "AP Last Reboot Reason",
                                        "Last AP Reboot Reason", "Reboot Reason")),
        "last_disconnect_reason": _val(_get(kv, "Last AP Disconnect Reason",
                                            "AP Last Disconnect Reason",
                                            "Last Disconnect Reason")),
        "power": _power(_get(kv, "Power Type/Mode")),
        "power_raw": _val(_get(kv, "Power Type/Mode")),
        "admin_state": _title(_get(kv, "Administrative State")),
        "oper_state": _title(_get(kv, "Operation State")),
        "country": country.split()[0] if country else None,
        "led_state": _bool(_get(kv, "LED State")),
        "tcp_mss": t.to_int(_get(kv, "AP TCP MSS Size")),
    }


def _radio_band(radio_type):
    v = (radio_type or "").lower()
    if not v:
        return None
    if "2.4" in v or re.search(r"80211(b|g|bg)\b", v):
        return "2.4"
    if re.search(r"-6\b|6ghz", v):
        return "6"
    if re.search(r"-5\b|5ghz|80211a", v):
        return "5"
    return None


def parse_ap_radio_config(text, band=None):
    """show ap config 802.11a|b <ap> -> one dict per 'Attributes for Slot'
    block (an XOR AP in dual-5 GHz mode prints two)."""
    if not _usable(text):
        return None
    lines = text.splitlines()
    starts = [(i, int(m.group(1))) for i, line in enumerate(lines)
              if (m := re.match(r"^\s*Attributes for Slot\s+(\d+)", line, re.I))]
    out = []
    for n, (start, slot) in enumerate(starts):
        block = "\n".join(lines[start + 1:starts[n + 1][0] if n + 1 < len(starts) else None])
        kv = _kv(block)
        radio_type = _val(_get(kv, "Radio Type"))
        level = t.to_int(_get(kv, "Current Tx Power Level"))
        dbm = t.to_int(_get(kv, f"Tx Power Level {level}")) if level else None
        out.append({
            "slot": slot,
            "radio_type": radio_type,
            "band": _radio_band(radio_type) or band,
            "admin": _title(_get(kv, "Administrative State")),
            "oper": _title(_get(kv, "Operation State")),
            "channel": t.to_int(_get(kv, "Current Channel")),
            "width": t.to_int(_get(kv, "Channel Width")),
            "tx_power_level": level,
            "tx_power_dbm": dbm,
            "tx_power_assigned_by": _val(_get(kv, "Tx Power Assigned By")),
            # Load and interference come from show ap auto-rf on most code;
            # read here only when the radio config prints them.
            "utilization": t.to_int(_get(kv, "Channel Utilization")),
            "noise": t.to_int(_get(kv, "Noise Level")),
            "interference": t.to_int(_get(kv, "Interference Level")),
            "clients": t.to_int(_get(kv, "Number of Clients", "Client Count")),
            "coverage_status": _val(_get(kv, "Coverage Profile", "Coverage Status")),
            "cleanair_capable": _bool(_get(kv, "CleanAir Capable")),
            "cleanair_enabled": _bool(_get(kv, "CleanAir Management Admin State")),
        })
    return out


def parse_link_encryption(text):
    """show ap link-encryption all -> {ap name: DTLS data encryption on}."""
    if not _usable(text):
        return None
    out = {}
    lines = text.splitlines()
    rule = next((i for i, line in enumerate(lines) if re.fullmatch(r"[-\s]+", line)
                 and "-" in line), None)
    if rule is None:
        return out
    for line in lines[rule + 1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        state = parts[1].lower()
        if state.startswith("en"):
            out[parts[0]] = True
        elif state.startswith("dis"):
            out[parts[0]] = False
    return out


def parse_ap_ethernet(text):
    """show ap stats ethernet summary -> {ap name: {interface, status,
    speed_mbps, duplex}}; the first interface that is up is the uplink."""
    if not _usable(text):
        return None
    out = {}
    name = None
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name") or name
        if not name:
            continue
        status = _val(t.lookup(row, "Status"))
        speed = t.lookup(row, "Speed") or ""
        duplex = _lower(t.lookup(row, "Duplex"))
        if duplex is None:
            d = re.search(r"\b(full|half)\b", speed, re.I)
            duplex = d.group(1).lower() if d else None
        entry = {
            "interface": _val(t.lookup(row, "Ethernet Interface Name", "Ethernet Name",
                                       "Interface")),
            "status": status,
            "speed_mbps": _speed_mbps(speed),
            "duplex": duplex,
        }
        current = out.get(name)
        if current is None or (not _bool(current["status"]) and _bool(status)):
            out[name] = entry
    return out


def parse_tcp_mss(text):
    """show ap tcp-mss-adjust all -> {ap name: {enabled, mss}}."""
    if not _usable(text):
        return None
    out = {}
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if name:
            out[name] = {"enabled": _bool(t.lookup(row, "TCP State", "State")),
                         "mss": t.to_int(t.lookup(row, "MSS Size", "MSS"))}
    return out


def parse_retransmit(text):
    """show ap retransmit all -> {ap name: {interval, count}}."""
    if not _usable(text):
        return None
    out = {}
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if name:
            out[name] = {"interval": t.to_int(t.lookup(row, "Retransmit Interval")),
                         "count": t.to_int(t.lookup(row, "Retransmit count"))}
    return out


def parse_ap_max_count(text):
    if not _usable(text):
        return None
    m = re.search(r"max(?:imum)?\s+number\s+of\s+AP'?s?\s+supported\D*(\d+)", text, re.I)
    if m:
        return int(m.group(1))
    for _, value in t.dotted_all(text):
        n = t.to_int(value)
        if n is not None:
            return n
    return None


def parse_air_quality(text, slot=None):
    """show 802.11a|b cleanair air-quality summary -> {(ap name, slot):
    {channel, avg, min, interferers}}. The summary has no slot column on
    most code, so the caller passes the band's usual slot."""
    if not _usable(text):
        return None
    out = {}
    for row in _rows(text, "AP Name"):
        name = t.lookup(row, "AP Name")
        if not name:
            continue
        row_slot = t.to_int(t.lookup(row, "Slot", "Slot#"))
        out[(name, row_slot if row_slot is not None else slot)] = {
            "channel": t.to_int(t.lookup(row, "Channel")),
            "avg": t.to_int(t.lookup(row, "Avg AQ", "AQ")),
            "min": t.to_int(t.lookup(row, "Min AQ")),
            "interferers": t.to_int(t.lookup(row, "Interferers")),
        }
    return out


# --- clients -----------------------------------------------------------------

def _protocol(value):
    """'802.11ac(5 GHz)' -> ('ac', '5'); band from the letter when the GHz
    tag is missing (older code)."""
    v = (value or "").strip()
    if not v or v.lower() in ("n/a", "802.3"):
        return ("wired" if v == "802.3" else None), None
    m = re.match(r"802\.11\s*([a-z]+)\s*(?:\(\s*([\d.]+)\s*GHz\s*\))?", v, re.I)
    if not m:
        return v, None
    proto, ghz = m.group(1).lower(), m.group(2)
    if ghz:
        band = ghz
    elif proto in ("a", "ac"):
        band = "5"
    elif proto in ("b", "g"):
        band = "2.4"
    else:
        band = None
    return proto, band


def parse_client_summary(text):
    """show client summary (scrubbed) -> client attributes, never a MAC."""
    if not _usable(text):
        return None
    out = []
    for row in _rows(text, "AP Name"):
        proto, band = _protocol(t.lookup(row, "Protocol"))
        out.append({
            "ap": _val(t.lookup(row, "AP Name")),
            "slot": t.to_int(t.lookup(row, "Slot")),
            "status": _val(t.lookup(row, "Status")),
            "wlan": t.to_int(t.lookup(row, "WLAN", "WLAN Id")),
            "auth": _bool(t.lookup(row, "Auth")),
            "protocol": proto,
            "band": band,
            "wired": _bool(t.lookup(row, "Wired")),
        })
    return out


def client_counts(rows):
    """{total, 2.4, 5, 6, by_wlan: {wlan: n}, groups: [{wlan, band,
    protocol, count}]}."""
    rows = rows or []
    out = {"total": len(rows), "2.4": 0, "5": 0, "6": 0, "by_wlan": {}, "groups": []}
    groups = {}
    for r in rows:
        if r.get("band") in ("2.4", "5", "6"):
            out[r["band"]] += 1
        out["by_wlan"][r.get("wlan")] = out["by_wlan"].get(r.get("wlan"), 0) + 1
        key = (r.get("wlan"), r.get("band"), r.get("protocol"))
        groups[key] = groups.get(key, 0) + 1
    out["groups"] = [{"wlan": w, "band": b, "protocol": p, "count": n}
                     for (w, b, p), n in sorted(groups.items(), key=lambda kv: str(kv[0]))]
    return out


def parse_exclusionlist(text):
    """show exclusionlist -> {count, reasons: {reason: n}}; MACs dropped."""
    if not _usable(text):
        return None
    reasons = {}
    count = 0
    for row in _rows(text, "Exclusion Reason"):
        reason = _val(t.lookup(row, "Exclusion Reason")) or "unknown"
        reasons[reason] = reasons.get(reason, 0) + 1
        count += 1
    return {"count": count, "reasons": reasons}
