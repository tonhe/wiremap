"""
Parsers for the AireOS service commands: AAA, ACLs, WIPS and rogues,
mobility, FlexConnect groups, QoS, AVC and NetFlow, mDNS, NMSP, multicast,
the management plane (network summary, SNMP, logging) and certificates.

Pure functions over the text the wlc collector stored, so the report can
re-read a saved scan without a controller. That text is already redacted:
secrets read <REDACTED>, SNMP community names are masked to <REDACTED> and
local net user names are pseudonyms (user-<hex>); parsers pass those through
unchanged. Every parser returns None for empty or error output and never
raises on partial output.

Rogue tables list MAC addresses of devices that are not ours, so the rogue
parsers return counts only.
"""
import re

from . import wlc_text as t
from .errors import error_reason

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MONTHS = {m: i for i, m in enumerate(
    "jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}


# --- shared helpers --------------------------------------------------------

def _empty(text):
    return not (text or "").strip() or error_reason(text) is not None


def _snake(label):
    return re.sub(r"[^a-z0-9]+", "_", str(label).lower()).strip("_")


def _col(row, *needles):
    """Value of the first column whose header contains a needle, in needle
    order. Headers drift between releases ('Tout', 'Timeout', 'MgmtTout'),
    so exact names are too brittle."""
    for needle in needles:
        for key, value in (row or {}).items():
            if needle.lower() in key.lower():
                return value
    return None


def _is_ip(value):
    v = str(value or "").strip()
    return bool(_IPV4.match(v)) or (":" in v and re.match(r"^[0-9a-f:]+$", v, re.I) is not None
                                    and v.count(":") >= 2)


def _chunks(text, heading):
    """[(heading line, text under it)] split at lines matching heading;
    whatever precedes the first heading comes back under ''."""
    out = [("", [])]
    for line in (text or "").splitlines():
        if re.match(heading, line, re.I):
            out.append((line.strip(), []))
        else:
            out[-1][1].append(line)
    return [(h, "\n".join(lines)) for h, lines in out]


def _ruled(text):
    """Some service tables (AVC, NetFlow) rule their header with '=' runs;
    turn those into dash runs so wlc_text.tables reads them."""
    return "\n".join(line.replace("=", "-") if re.match(r"^\s*=+(\s+=+)*\s*$", line) else line
                     for line in (text or "").splitlines())


def _counters(text):
    """{snake label: int} for every dotted line with a number."""
    out = {}
    for label, value in t.dotted_all(text):
        n = t.to_int(value)
        key = _snake(label)
        if n is not None and key not in out:
            out[key] = n
    return out


def _mac_rows(text):
    """Lines that start with a MAC: the rows of rogue and AP lists, which
    some releases print without a dash rule."""
    return [line for line in (text or "").splitlines()
            if line.split() and t.norm_mac(line.split()[0]) and t.macs_in(line.split()[0])]


# --- AAA: RADIUS and TACACS+ ---------------------------------------------------

_USE = {"authentication": "auth", "accounting": "acct", "authorization": "athr"}


def _server_tables(text):
    """[(use, rows)] for the 'Authentication / Accounting / Authorization
    Servers' sections of show radius summary and show tacacs summary."""
    out = []
    for heading, chunk in _chunks(text, r"^\s*(Authentication|Accounting|Authorization)\s+Servers"):
        if not heading:
            continue
        rows = t.table(chunk)
        out.append((_USE[heading.split()[0].lower()], rows))
    return out


def _server_type(value):
    # Type column: N = network user, M = management, NM = both.
    v = (value or "").upper()
    return "N" in v, "M" in v


def parse_radius_summary(text):
    """show radius summary.

    Keywrap is printed once for the controller, not per server, so every
    server carries the global value. Retransmit count is not in this
    output (it lives in the run-config), so retransmit is None.
    """
    if _empty(text):
        return None
    values = t.dotted(text)
    keywrap = t.enabled(t.lookup(values, "Keywrap", "Key Wrap"))
    servers = []
    for use, rows in _server_tables(text):
        for row in rows:
            index = t.to_int(_col(row, "Idx", "Index"))
            ip = _col(row, "Server Address", "Address")
            if index is None or not ip:
                continue
            type_cell = _col(row, "Type")
            if type_cell is None:
                network_user, management = None, None
            else:
                network_user, management = _server_type(type_cell)
            ipsec_cell = _col(row, "IPSec")
            servers.append({
                "use": use,
                "index": index,
                "ip": ip,
                "port": t.to_int(t.lookup(row, "Port")),
                "admin": "Enabled" if t.enabled(_col(row, "State")) else "Disabled",
                "network_user": network_user,
                "management": management,
                "timeout_s": t.to_int(t.lookup(row, "Tout", "Timeout")),
                "mgmt_timeout_s": t.to_int(_col(row, "MgmtTout")),
                "retransmit": None,
                "keywrap": bool(keywrap),
                "rfc3576": t.enabled(_col(row, "RFC3576", "RFC 3576")) is True,
                "ipsec": t.enabled(ipsec_cell) if ipsec_cell is not None else None,
                "active": "*" in (_col(row, "Idx", "Index") or ""),
            })
    return {
        "servers": servers,
        "keywrap": keywrap,
        "fallback_mode": t.lookup(values, "Test Mode", "Fallback Test Mode", "Fallback Mode"),
        "aggressive_failover": t.enabled(t.lookup(values, "Aggressive Failover")),
        "mac_delimiter": t.lookup(values, "MAC Delimiter for Authentication Messages",
                                  "MAC Delimiter"),
        "mac_delimiter_acct": t.lookup(values, "MAC Delimiter for Accounting Messages"),
        "auth_called_station_id": t.lookup(values, "Auth Call Station Id Type",
                                           "Call Station Id Type"),
        "framed_mtu": t.to_int(t.lookup(values, "RADIUS Authentication Framed-MTU")),
        "settings": values,
    }


def _stat_blocks(text):
    """[(dotted pairs)] split at each 'Server Index' line."""
    blocks = []
    for label, value in t.dotted_all(text):
        if label.lower() == "server index":
            blocks.append([])
        if blocks:
            blocks[-1].append((label, value))
    return blocks


def _sum(*values):
    found = [v for v in values if v is not None]
    return sum(found) if found else None


def _server_stats(text):
    out = {}
    for block in _stat_blocks(text):
        values = dict(reversed(block))
        index = t.to_int(t.lookup(values, "Server Index"))
        if index is None:
            continue
        first = t.to_int(t.lookup(values, "First Requests"))
        accept = t.to_int(t.lookup(values, "Accept Responses"))
        responses = t.to_int(t.lookup(values, "Accounting Responses"))
        entry = {
            "server": t.lookup(values, "Server Address"),
            "round_trip_ms": t.to_int(t.lookup(values, "Msg Round Trip Time")),
            "requests": first,
            "retransmissions": t.to_int(t.lookup(values, "Retry Requests")),
            "accepts": accept if accept is not None else responses,
            "rejects": t.to_int(t.lookup(values, "Reject Responses")),
            "challenges": t.to_int(t.lookup(values, "Challenge Responses")),
            "errors": t.to_int(t.lookup(values, "Error Responses")),
            "timeouts": t.to_int(t.lookup(values, "Timeout Requests")),
            "malformed": t.to_int(t.lookup(values, "Malformed Msgs")),
            "bad_authenticators": t.to_int(t.lookup(values, "Bad Authenticator Msgs")),
            "pending": t.to_int(t.lookup(values, "Pending Requests")),
            "dropped": _sum(t.to_int(t.lookup(values, "Unknowntype Msgs")),
                            t.to_int(t.lookup(values, "Other Drops"))),
            "last_error": t.lookup(values, "Last Error", "Last Error Reason"),
        }
        out[index] = entry
    return out


def parse_radius_stats(text):
    """show radius auth statistics / show radius acct statistics.

    requests counts first attempts only; retransmissions are the retries.
    Accounting has no accept/reject, so accepts carries Accounting
    Responses there and rejects is None. AireOS prints no last-error field
    on 8.x, so last_error is normally None.
    """
    if _empty(text):
        return None
    return _server_stats(text)


def parse_tacacs_stats(text):
    if _empty(text):
        return None
    return _server_stats(text)


def parse_rfc3576_stats(text):
    """show radius rfc3576 statistics: controller totals plus per-server
    counters, all as {snake label: int}."""
    if _empty(text):
        return None
    blocks = _stat_blocks(text)
    first_index = None
    pairs = t.dotted_all(text)
    for i, (label, _) in enumerate(pairs):
        if label.lower() == "server index":
            first_index = i
            break
    head = pairs if first_index is None else pairs[:first_index]
    totals = {}
    for label, value in head:
        n = t.to_int(value)
        if n is not None:
            totals.setdefault(_snake(label), n)
    servers = {}
    for block in blocks:
        values = dict(reversed(block))
        index = t.to_int(t.lookup(values, "Server Index"))
        if index is None:
            continue
        counters = {_snake(k): t.to_int(v) for k, v in block
                    if k.lower() not in ("server index", "server address")
                    and t.to_int(v) is not None}
        servers[index] = {"server": t.lookup(values, "Server Address"), **counters}
    return {"totals": totals, "servers": servers}


def parse_tacacs_summary(text):
    if _empty(text):
        return None
    servers = []
    for use, rows in _server_tables(text):
        for row in rows:
            index = t.to_int(_col(row, "Idx", "Index"))
            ip = _col(row, "Server Address", "Address")
            if index is None or not ip:
                continue
            servers.append({
                "use": use,
                "index": index,
                "ip": ip,
                "port": t.to_int(t.lookup(row, "Port")),
                "admin": "Enabled" if t.enabled(_col(row, "State")) else "Disabled",
                "timeout_s": t.to_int(t.lookup(row, "Tout", "Timeout")),
                "mgmt_timeout_s": t.to_int(_col(row, "MgmtTout")),
            })
    return {"servers": servers}


def parse_aaa_auth(text):
    """show aaa auth. 8.x lists the order as numbered dotted lines; some
    older code prints it on one line after the colon."""
    if _empty(text):
        return None
    order = []
    for label, value in t.dotted_all(text):
        if label.isdigit() and value:
            order.append(value.strip().lower())
    if not order:
        m = re.search(r"server order:\s*(\S[^\n]*)", text, re.I)
        if m:
            order = [w.lower() for w in re.split(r"[\s,]+", m.group(1)) if w]
    return {"management_order": order,
            "local_only": order == ["local"],
            "has_tacacs": "tacacs" in order,
            "has_radius": "radius" in order}


def parse_local_auth_config(text):
    """show local-auth config.

    AireOS has no single on/off switch for local EAP: it is in use when a
    profile is configured on at least one WLAN, which is what enabled means
    here.
    """
    if _empty(text):
        return None
    pairs = t.dotted_all(text)
    values = dict(reversed(pairs))
    order = [v for k, v in pairs if k.lower() in ("primary", "secondary", "tertiary") and v]
    profiles = []
    for label, value in pairs:
        if label.lower() == "name":
            profiles.append({"name": value, "methods": [], "wlans": None,
                             "certificate_issuer": None})
        elif profiles and label.lower() == "enabled methods":
            profiles[-1]["methods"] = [m for m in re.split(r"[\s,]+", value) if m]
        elif profiles and label.lower() == "configured on wlans":
            profiles[-1]["wlans"] = [int(w) for w in re.findall(r"\d+", value)]
        elif profiles and label.lower() == "certificate issuer":
            profiles[-1]["certificate_issuer"] = value
    in_use = any(p["wlans"] for p in profiles)
    return {
        "enabled": in_use,
        "database_order": order,
        "active_timeout_s": t.to_int(t.lookup(values, "Active timeout")),
        "profiles": profiles,
        "pac_ttl": t.to_int(t.lookup(values, "TTL for the PAC")),
        "anonymous_provisioning": t.enabled(t.lookup(values, "Anonymous provision allowed")),
    }


def parse_local_auth_stats(text):
    if _empty(text):
        return None
    values = t.dotted(text)
    methods = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z][\w-]*)\s+(\d+)\s+(\d+)\s*$", line)
        if m:
            methods[m.group(1)] = {"success": int(m.group(2)), "fail": int(m.group(3))}
    return {
        "requests": t.to_int(t.lookup(values, "Requests received")),
        "responses": t.to_int(t.lookup(values, "Responses returned")),
        "dropped": _sum(t.to_int(t.lookup(values, "Requests dropped (no EAP AVP)")),
                        t.to_int(t.lookup(values, "Requests dropped (other reasons)"))),
        "timeouts": t.to_int(t.lookup(values, "Authentication timeouts")),
        "methods": methods,
    }


def _no_expiry(lifetime):
    v = (lifetime or "").strip().lower()
    return v in ("unlimited", "0", "infinite", "never")


def parse_netuser(text):
    """show netuser summary. Names are the collector's pseudonyms, never
    the real account names."""
    if _empty(text):
        return None
    users = []
    for rows in t.tables(text):
        for row in rows:
            name = _col(row, "User Name", "Username")
            if not name:
                continue
            users.append({
                "name": name.split()[0],
                "wlan": t.to_int(_col(row, "WLAN")),
                "type": _col(row, "Type"),
                "lifetime": _col(row, "Lifetime"),
            })
    return {"count": len(users),
            "no_expiry": sum(1 for u in users if _no_expiry(u["lifetime"])),
            "users": users}


_ACCESS = {"readwrite": "ReadWrite", "readonly": "ReadOnly", "lobbyadmin": "LobbyAdmin"}


def parse_mgmtuser(text):
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            name = _col(row, "User Name", "Username")
            if not name:
                continue
            raw = _col(row, "Permission", "Access") or ""
            out.append({
                "name": name,
                "access": _ACCESS.get(re.sub(r"[^a-z]", "", raw.lower()), raw or None),
                "description": _col(row, "Description") or None,
                "password_strength": _col(row, "Password Strength") or None,
                "telnet": t.enabled(_col(row, "Telnet")),
            })
    return out


# --- ACLs -----------------------------------------------------------------

def parse_acl_summary(text):
    """show acl summary: one entry per ACL, IPv4 and IPv6 tables both."""
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            key = next((k for k in row if "acl name" in k.lower()), None)
            if not key or not row[key]:
                continue
            out.append({"name": row[key].split()[0],
                        "applied": t.enabled(_col(row, "Applied")) is True,
                        "family": "IPv6" if "ipv6" in key.lower() else "IPv4"})
    return out


def parse_acl_counters(text):
    """'ACL Counter Status' from show acl summary: True / False / None."""
    m = re.search(r"ACL Counter Status\s*\.*\s*(\S+)", text or "", re.I)
    return t.enabled(m.group(1)) if m else None


_DIRECTIONS = ("in", "out", "any", "inbound", "outbound")
_ACTIONS = ("permit", "deny")


def _addr(token):
    """'10.0.0.0/255.0.0.0' -> ('10.0.0.0', '255.0.0.0'); IPv6 gives the
    prefix length as the mask."""
    if "/" in token:
        address, _, mask = token.rpartition("/")
        return address, mask
    return token, None


def _ports(token):
    return token if token else None


def _acl_rules(text):
    """Numbered rows of show acl detailed / show flexconnect acl detailed.

    Three layouts are read by position rather than header, because the
    header spans two lines and its labels differ by release:
      8.x controller ACL:  idx dir src/mask dst/mask proto sport dport dscp action [counter]
      older controller:    idx src/mask dst/mask proto sport dport dscp dir action [counter]
      FlexConnect ACL:     idx src/mask dst/mask proto sport dport dscp action
    """
    rules = []
    for line in (text or "").splitlines():
        toks = line.split()
        if len(toks) < 6 or not toks[0].isdigit():
            continue
        action_i = next((i for i, tok in enumerate(toks) if tok.lower() in _ACTIONS), None)
        if action_i is None:
            continue
        rest = toks[1:action_i]
        direction = None
        if rest and rest[0].lower() in _DIRECTIONS and "/" not in rest[0]:
            direction = rest.pop(0)
        if len(rest) < 2:
            continue
        src, src_mask = _addr(rest[0])
        dst, dst_mask = _addr(rest[1])
        mid = rest[2:]
        if len(mid) >= 5 and mid[4].lower() in _DIRECTIONS:
            direction = mid[4]
        mid += [None] * (4 - len(mid))
        after = toks[action_i + 1:]
        rules.append({
            "seq": int(toks[0]),
            "action": toks[action_i].capitalize(),
            "direction": direction,
            "protocol": mid[0],
            "source": src,
            "src_mask": src_mask,
            "destination": dst,
            "dst_mask": dst_mask,
            "src_ports": _ports(mid[1]),
            "dst_ports": _ports(mid[2]),
            "dscp": mid[3],
            "hits": t.to_int(after[0]) if after else None,
        })
    return rules


def parse_acl_detail(text, name=None):
    """show acl detailed <name>. The output does not repeat the ACL name,
    so the caller passes it from the command. hits is None when the
    release prints no Counter column; deny_hits is the implicit deny
    counter ('DenyCounter : n') printed when counters are on."""
    if _empty(text):
        return None
    m = re.search(r"DenyCounter\s*:\s*(\d+)", text, re.I)
    rules = _acl_rules(text)
    return {"name": name,
            "counters_enabled": any(r["hits"] is not None for r in rules) or bool(m),
            "deny_hits": int(m.group(1)) if m else None,
            "rules": rules}


def parse_acl_cpu(text):
    """show acl cpu: the CPU ACL name (None when unset) and which traffic
    it applies to."""
    if _empty(text):
        return None
    values = t.dotted(text)
    name = (t.lookup(values, "CPU Acl Name", "CPU ACL Name", "IPv4 CPU Acl Name") or "").strip()
    if name.lower() in ("", "none", "not configured"):
        name = None
    wired = t.enabled(t.lookup(values, "Wired Traffic"))
    wireless = t.enabled(t.lookup(values, "Wireless Traffic"))
    if wired and wireless:
        mode = "wired+wireless"
    elif wired:
        mode = "wired"
    elif wireless:
        mode = "wireless"
    else:
        mode = None
    return {"acl": name, "mode": mode if name else None, "wired": wired, "wireless": wireless}


def parse_flex_acl_summary(text):
    """show flexconnect acl summary. The status column reads Applied or
    Modified (changed but not yet pushed to APs)."""
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            name = _col(row, "ACL Name")
            if not name:
                continue
            status = _col(row, "Status") or ""
            out.append({"name": name.split()[0],
                        "applied": status.strip().lower() == "applied",
                        "status": status or None,
                        "family": "IPv6" if "ipv6" in " ".join(row).lower() else "IPv4"})
    return out


def parse_flex_acl_detail(text, name=None):
    if _empty(text):
        return None
    return {"name": name, "rules": _acl_rules(text)}


# --- WIPS, MFP, rogues ---------------------------------------------------------

def parse_wps_summary(text):
    """show wps summary: settings grouped by the unindented section titles,
    plus the client exclusion policy per reason."""
    if _empty(text):
        return None
    sections = {}
    current = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        m = re.match(r"^\s*(\S[^\n]*?)\s*\.{3,}\s*(.*?)\s*$", line)
        if m:
            sections.setdefault(current, {}).setdefault(m.group(1), m.group(2))
        elif not line.startswith(" "):
            current = line.strip().rstrip(":")
    flat = t.dotted(text)
    exclusion = {}
    for title, values in sections.items():
        if "exclusion" in title.lower():
            for label, value in values.items():
                state = t.enabled(value)
                if state is not None:
                    exclusion[label] = state
    return {
        "auto_immune": t.enabled(t.lookup(flat, "Auto-Immune")),
        "client_exclusion": exclusion,
        "max_8021x_failures": t.to_int(t.lookup(flat, "Maximum 802.1x-AAA failure attempts")),
        "signature_processing": t.enabled(t.lookup(flat, "Signature Processing")),
        "rldp": t.lookup(flat, "Rogue Location Discovery Protocol"),
        "infrastructure_mfp": t.enabled(t.lookup(flat, "Global Infrastructure MFP state",
                                                 "Management Frame Protection")),
        "sections": sections,
    }


def parse_mfp(text):
    """show wps mfp summary.

    The WLAN table repeats 'Protection' in its header, so it is read by
    position instead of through wlc_text.tables (which keys rows by header
    and would drop one of the two columns).
    """
    if _empty(text):
        return None
    values = t.dotted(text)
    infra = t.enabled(t.lookup(values, "Global Infrastructure MFP state",
                               "Global MFP state", "Infrastructure MFP"))
    wlans = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\S+)\s+(Enabled|Disabled)\s+(Enabled|Disabled)\s+(\S.*?)\s*$",
                     line, re.I)
        if m:
            wlans.append({"wlan": int(m.group(1)), "name": m.group(2),
                          "status": m.group(3), "infra_protection": m.group(4),
                          "client_protection": m.group(5)})
    client = {"required": 0, "optional": 0, "disabled": 0}
    for w in wlans:
        word = w["client_protection"].split()[0].lower()
        if word in client:
            client[word] += 1
    return {"infrastructure_mfp": infra,
            "time_source_valid": t.enabled(t.lookup(values, "Controller Time Source Valid")),
            "client_mfp": client if wlans else None,
            "wlans": wlans}


def parse_signatures(text):
    """show wps signature summary. standard_enabled and custom_enabled are
    counts of enabled signatures of each type."""
    if _empty(text):
        return None
    sigs = []
    for label, value in t.dotted_all(text):
        key = label.lower()
        if key == "signature-id":
            sigs.append({"id": t.to_int(value), "name": None, "type": None, "enabled": None})
        elif sigs and key == "signature name":
            sigs[-1]["name"] = value
        elif sigs and key == "type":
            sigs[-1]["type"] = value.lower()
        elif sigs and key == "state":
            sigs[-1]["enabled"] = t.enabled(value)
    std = [s for s in sigs if s["type"] == "standard"]
    custom = [s for s in sigs if s["type"] == "custom"]
    return {"total": len(sigs),
            "standard": len(std),
            "custom": len(custom),
            "standard_enabled": sum(1 for s in std if s["enabled"]),
            "custom_enabled": sum(1 for s in custom if s["enabled"]),
            "signatures": sigs}


def parse_ap_auth(text):
    """show wps ap-authentication summary: 'AP neighbor authentication is
    <disabled>.'"""
    if _empty(text):
        return None
    m = re.search(r"authentication is\s*<?\s*(enabled|disabled)", text, re.I)
    if not m:
        m = re.search(r"authentication\s*\.{3,}\s*(\S+)", text, re.I)
    threshold = re.search(r"alarm threshold is\s*(\d+)", text, re.I)
    return {"enabled": t.enabled(m.group(1)) if m else None,
            "alarm_threshold": int(threshold.group(1)) if threshold else None}


_ROGUE_CLASSES = ("Malicious", "Friendly", "Unclassified", "Custom")
_ROGUE_STATES = ("Contained Pending", "Contained", "Alert", "Internal", "External",
                 "Threat", "Pending", "Removed", "Unknown")


def _rogue_counts(text):
    by_class = {c: 0 for c in _ROGUE_CLASSES}
    by_state = {}
    on_wire = 0
    rows = _mac_rows(text)
    for line in rows:
        rest = " ".join(line.split()[1:])
        cls = next((c for c in _ROGUE_CLASSES if re.search(r"\b" + c + r"\b", rest, re.I)), None)
        if cls:
            by_class[cls] += 1
        state = next((s for s in _ROGUE_STATES if re.search(r"\b" + s + r"\b", rest, re.I)), None)
        if state:
            by_state[state] = by_state.get(state, 0) + 1
        if re.search(r"\bon[- ]?wire\b|\bwired\b", rest, re.I):
            on_wire += 1
    return len(rows), by_class, by_state, on_wire


def _settings(text):
    return {label: value for label, value in t.dotted(text).items()}


def parse_rogue_ap_summary(text):
    """show rogue ap summary: counts only, no rogue MACs or SSIDs.

    on_wire counts rows the release marks as seen on the wire; 8.x prints
    no such column in the summary, so it is usually 0 there and the
    detailed per-rogue command would be needed for a true count.
    """
    if _empty(text):
        return None
    total, by_class, by_state, on_wire = _rogue_counts(text)
    settings = _settings(text)
    return {"total": total,
            "by_class": by_class,
            "by_state": by_state,
            "contained": sum(n for s, n in by_state.items() if s.startswith("Contained")),
            "on_wire": on_wire,
            "classified_reported": t.to_int(t.lookup(settings, "Total Rogues classified")),
            "settings": settings}


def parse_rogue_client_summary(text):
    if _empty(text):
        return None
    total, _, by_state, _ = _rogue_counts(text)
    return {"total": total, "by_state": by_state, "settings": _settings(text)}


def parse_rogue_adhoc_summary(text):
    if _empty(text):
        return None
    total, _, by_state, _ = _rogue_counts(text)
    return {"total": total, "by_state": by_state, "settings": _settings(text)}


def parse_rogue_rules(text):
    """show rogue rule summary. Conditions are only in the per-rule detailed
    command, which is not collected, so conditions is None."""
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            priority = t.to_int(_col(row, "Priority"))
            name = _col(row, "Rule Name")
            if priority is None or not name:
                continue
            state_cell = t.lookup(row, "Rule state", "Rule State", "State")
            out.append({
                "priority": priority,
                "name": name,
                "class": _col(row, "Class", "Type"),
                "enabled": t.enabled(state_cell),
                "action": t.lookup(row, "State") if t.lookup(row, "Rule state", "Rule State")
                else None,
                "notify": _col(row, "Notify"),
                "match": _col(row, "Match"),
                "hits": t.to_int(_col(row, "Hit")),
                "conditions": None,
            })
    return out


def parse_auto_contain(text):
    """Containment settings from show rogue auto-contain, show rogue ap
    summary or show wps summary.

    any_enabled is True when an auto-contain switch is on or a rogue
    policy action is set to Contain; the containment level and
    'monitor AP only' are recorded but are not themselves containment.
    """
    if _empty(text):
        return None
    settings = {}
    hits = []
    for label, value in t.dotted_all(text):
        low = label.lower()
        if label in settings:
            continue
        relevant = "contain" in low or "rogue" in low or "ad-hoc" in low or "adhoc" in low \
            or "trusted" in low or "monitor" in low or "mis-configured" in low
        if not relevant:
            continue
        settings[label] = value
        if "level" in low or "monitor" in low:
            continue
        if ("contain" in low and t.enabled(value)) or re.match(r"^\s*(auto[- ]?)?contain",
                                                                value or "", re.I):
            hits.append(label)
    level = next((t.to_int(v) for k, v in settings.items() if "level" in k.lower()), None)
    return {"settings": settings, "level": level, "enabled_settings": hits,
            "any_enabled": bool(hits)}


# --- Mobility -------------------------------------------------------------

def _path_status(status):
    s = (status or "").strip().lower()
    if s == "up":
        return True, True
    if "control and data" in s and "down" in s:
        return False, False
    if "data path down" in s:
        return True, False
    if "control path down" in s:
        return False, True
    if s.startswith("down"):
        return False, False
    return None, None


def parse_mobility_summary(text):
    """show mobility summary. The peer table has no dash rule on most
    releases, so peers are read from lines that start with a MAC. 8.x
    may add a Public IP column between Multicast IP and Status."""
    if _empty(text):
        return None
    values = t.dotted(text)
    peers = []
    for line in _mac_rows(text):
        toks = line.split()
        if len(toks) < 5:
            continue
        mac, ip, group, mcast = toks[:4]
        rest = toks[4:]
        public_ip = rest.pop(0) if len(rest) > 1 and _is_ip(rest[0]) else None
        status = " ".join(rest)
        control, data = _path_status(status)
        peers.append({"mac": t.norm_mac(mac), "ip": ip, "group": group,
                      "multicast_ip": mcast, "public_ip": public_ip, "status": status,
                      "control_up": control, "data_up": data})
    mode = t.lookup(values, "Multicast Mode", "Mobility Multicast Mode")
    return {
        "group_name": t.lookup(values, "Default Mobility Domain", "Mobility Group Name"),
        "multicast_mode": mode,
        "multicast_ip": t.lookup(values, "Mobility Multicast Ip Address",
                                 "Mobility Multicast IP Address", "Multicast IP Address"),
        "encryption": t.enabled(t.lookup(values, "Mobility Encryption", "Encryption")),
        "dtls": t.enabled(t.lookup(values, "DTLS Mode", "Mobility DTLS")),
        "keepalive_interval": t.to_int(t.lookup(values, "Mobility Keepalive Interval")),
        "keepalive_count": t.to_int(t.lookup(values, "Mobility Keepalive Count")),
        "members_configured": t.to_int(t.lookup(values, "Mobility Group Members Configured")),
        "peers": peers,
    }


def parse_mobility_stats(text):
    """show mobility statistics. handoffs picks the headline counters;
    failures adds up denials, drops and errors; counters keeps every
    numeric line (first occurrence of a label wins)."""
    if _empty(text):
        return None
    c = _counters(text)
    handoffs = {
        "requests_sent": c.get("handoff_requests_sent"),
        "requests_received": c.get("handoff_requests_received"),
        "as_local": _sum(c.get("handoff_as_local_received"), c.get("client_handoff_as_local")),
        "as_foreign": _sum(c.get("handoff_as_foreign_received"),
                           c.get("client_handoff_as_foreign")),
    }
    failures = _sum(*(v for k, v in c.items()
                      if re.search(r"deny|denys|denied|dropped|errors|unavailable|disallowed", k)))
    return {"handoffs": handoffs, "failures": failures, "counters": c}


def parse_mobility_anchor(text):
    """show mobility anchor: one entry per WLAN (or guest LAN) anchor."""
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            key = next((k for k in row if re.match(r"(WLAN|GLAN)\s+ID", k, re.I)), None)
            ip = _col(row, "IP Address")
            if not key or t.to_int(row[key]) is None or not ip:
                continue
            out.append({"wlan": t.to_int(row[key]),
                        "kind": "guest-lan" if key.upper().startswith("GLAN") else "wlan",
                        "anchor_ip": ip,
                        "status": _col(row, "Status") or None,
                        "priority": t.to_int(_col(row, "Priority"))})
    return out


def parse_mobility_ap_list(text):
    """show mobility ap-list: number of APs the mobility group knows."""
    if _empty(text):
        return None
    return len(_mac_rows(text)) or sum(
        1 for line in text.splitlines()
        if len(line.split()) >= 3 and any(t.macs_in(tok) for tok in line.split()))


# --- FlexConnect groups ------------------------------------------------------

def parse_flex_group_detail(text, name=None):
    """show flexconnect group detail <name>.

    vlan_mappings is the AAA VLAN-ACL mapping ({vlan, ingress, egress});
    wlan_vlan_mappings the per-WLAN VLAN override; acl_mappings the
    WLAN-ACL tables (local split, web auth, web policy), each tagged with
    the section it came from.
    """
    if _empty(text):
        return None
    values = t.dotted(text)
    if name is None:
        m = re.search(r"Group Name\s*[:.]+\s*(\S+)", text, re.I)
        name = m.group(1) if m else None
    aps = []
    for line in _mac_rows(text):
        toks = line.split()
        aps.append({"mac": t.norm_mac(toks[0]),
                    "name": toks[1] if len(toks) > 1 else None,
                    "status": toks[2] if len(toks) > 2 else None})
    m = re.search(r"Number of AP'?s in Group\s*[:.]+\s*(\d+)", text, re.I)
    ap_count = int(m.group(1)) if m else len(aps)

    radius = []
    wlan_vlan, acl_maps, vlan_acl = [], [], []
    for heading, chunk in _chunks(text, r"^\s*\S[^.]*:\s*$"):
        title = heading.lower()
        for rows in t.tables(chunk):
            for row in rows:
                server = _col(row, "Server Address", "Server IP")
                if server is not None:
                    if _is_ip(server):
                        radius.append(server)
                    continue
                wlan = t.to_int(_col(row, "WLAN ID", "WLAN Id"))
                vlan = t.to_int(_col(row, "Vlan ID", "VLAN Id"))
                acl = _col(row, "ACL")
                if wlan is not None and vlan is not None:
                    wlan_vlan.append({"wlan": wlan, "vlan": vlan})
                elif wlan is not None and acl:
                    kind = "local-split" if "split" in title else \
                        "webauth" if "webauth" in title else \
                        "webpolicy" if "webpolic" in title else "wlan-acl"
                    acl_maps.append({"kind": kind, "wlan": wlan, "acl": acl})
                elif vlan is not None and (_col(row, "Ingress") or _col(row, "Egress")):
                    vlan_acl.append({"vlan": vlan, "ingress": _col(row, "Ingress") or None,
                                     "egress": _col(row, "Egress") or None})
    # Releases that print the VLAN-ACL mapping as dotted blocks instead.
    current = None
    for line in text.splitlines():
        m = re.match(r"^\s*ACL Mapping for Vlan ID\s*:?\s*(\d+)", line, re.I)
        if m:
            current = {"vlan": int(m.group(1)), "ingress": None, "egress": None}
            vlan_acl.append(current)
            continue
        m = re.match(r"^\s*(Ingress|Egress) ACL\s*\.+\s*(\S*)", line, re.I)
        if current is not None and m:
            current[m.group(1).lower()] = m.group(2) or None
    for label, value in t.dotted_all(text):
        if re.search(r"radius server", label, re.I) and _is_ip(value) and value not in radius:
            radius.append(value)

    local_auth = t.enabled(t.lookup(values, "AP RADIUS server", "Local Authentication",
                                    "FlexConnect Local Authentication"))
    master = t.lookup(values, "Efficient AP Image Upgrade Master AP", "Master AP")
    return {
        "name": name,
        "ap_count": ap_count,
        "aps": aps,
        "local_auth": bool(local_auth),
        "radius_servers": radius,
        "vlan_mode": t.enabled(t.lookup(values, "Vlan Mode")),
        "native_vlan": t.to_int(t.lookup(values, "Native Vlan")),
        "vlan_mappings": vlan_acl,
        "wlan_vlan_mappings": wlan_vlan,
        "acl_mappings": acl_maps,
        "efficient_upgrade": bool(t.enabled(t.lookup(values, "Efficient AP Image Upgrade"))),
        "master_ap": master if master and master.lower() not in ("none", "not configured")
        else None,
    }


# --- QoS, AVC, NetFlow, mDNS, NMSP, multicast ---------------------------------

_RATES = {"average data rate": "average_data", "average realtime rate": "average_realtime",
          "burst data rate": "burst_data", "burst realtime rate": "burst_realtime",
          "realtime burst data rate": "burst_realtime",
          "average real-time rate": "average_realtime", "burst real-time rate": "burst_realtime"}


def parse_qos_profile(text, name=None):
    """show qos platinum|gold|silver|bronze. The output does not name the
    profile, so the caller passes it.

    8.x prints each rate as 'upstream downstream'; older code prints one
    value, kept as downstream with upstream None. 0 means no limit.
    """
    if _empty(text):
        return None
    values = t.dotted(text)
    user, ssid = {}, {}
    current = None
    for label, value in t.dotted_all(text):
        low = label.lower()
        if "per-ssid" in low:
            current = ssid
            continue
        if "per-client" in low or "per-user" in low:
            current = user
            continue
        key = _RATES.get(low)
        if key and current is not None:
            nums = [int(n) for n in re.findall(r"\d+", value)]
            if len(nums) >= 2:
                current[key] = {"upstream": nums[0], "downstream": nums[1]}
            elif nums:
                current[key] = {"upstream": None, "downstream": nums[0]}
    if not name:
        m = re.search(r"\b(platinum|gold|silver|bronze)\b", text, re.I)
        name = m.group(1).lower() if m else None
    return {
        "name": name,
        "description": t.lookup(values, "Description"),
        "per_user_rate_limits": user,
        "per_ssid_rate_limits": ssid,
        "dot1p_tag": t.to_int(t.lookup(values, "dot1p Tag", "802.1p Tag", "802.1P Tag")),
        "wired_protocol": t.lookup(values, "protocol", "Wired Protocol"),
        "max_priority": t.lookup(values, "Maximum Priority"),
        "unicast_default_priority": t.lookup(values, "Unicast Default Priority"),
        "multicast_default_priority": t.lookup(values, "Multicast Default Priority"),
    }


def _colon_values(text):
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([A-Za-z][^:.]*?)\s*:\s*(\S.*?)\s*$", line)
        if m:
            out.setdefault(m.group(1), m.group(2))
    return out


def parse_qos_map(text):
    """show qos qosmap: 'Status : Enabled', 'Trust DSCP UpStream : ...',
    then the UP-to-DSCP rows and the DSCP exceptions. Rows are matched by
    shape because some releases rule the table with a single dash run."""
    if _empty(text):
        return None
    values = {**_colon_values(text), **t.dotted(text)}
    rows, exceptions = [], []
    in_exceptions = False
    for line in text.splitlines():
        if re.search(r"exception", line, re.I):
            in_exceptions = True
            continue
        m = re.match(r"^\s*([0-7])\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if m and not in_exceptions:
            rows.append({"up": int(m.group(1)), "dscp_default": int(m.group(2)),
                         "dscp_start": int(m.group(3)), "dscp_end": int(m.group(4))})
            continue
        m = re.match(r"^\s*(\d+)\s+([0-7])\s*$", line)
        if m and in_exceptions:
            exceptions.append({"dscp": int(m.group(1)), "up": int(m.group(2))})
    return {"enabled": bool(t.enabled(t.lookup(values, "Status", "QoS Map", "Qos Map Status"))),
            "trust_dscp_upstream": bool(t.enabled(t.lookup(values, "Trust DSCP UpStream",
                                                           "Trust DSCP Upstream"))),
            "map": rows,
            "exceptions": exceptions}


def _service_rows(text):
    return [row for rows in t.tables(_ruled(text)) for row in rows]


def parse_avc_profiles(text):
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        name = _col(row, "Profile")
        if name:
            out.append({"name": name, "rules": t.to_int(_col(row, "Rules"))})
    return out


def parse_flow_exporters(text):
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        name = _col(row, "Exporter-Name", "Exporter Name", "Name")
        ip = _col(row, "IP")
        if name and ip:
            out.append({"name": name, "ip": ip, "port": t.to_int(t.lookup(row, "Port"))})
    return out


def parse_flow_monitors(text):
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        name = _col(row, "Monitor-Name", "Monitor Name")
        if name:
            out.append({"name": name,
                        "exporter": _col(row, "Exporter-Name", "Exporter Name") or None,
                        "exporter_ip": _col(row, "Exporter-IP", "Exporter IP") or None,
                        "port": t.to_int(t.lookup(row, "Port")),
                        "record": _col(row, "Record") or None})
    return out


def parse_mdns_summary(text):
    if _empty(text):
        return None
    values = t.dotted(text)
    return {"enabled": t.enabled(t.lookup(values, "mDNS Global Snooping", "mDNS Snooping Status",
                                          "mDNS snooping", "Global mDNS Snooping")),
            "policy": t.enabled(t.lookup(values, "mDNS Policy")),
            "query_interval_min": t.to_int(t.lookup(values, "mDNS Query Interval")),
            "services": t.to_int(t.lookup(values, "Number of Services")),
            "profiles": t.to_int(t.lookup(values, "Number of Profiles")),
            "settings": values}


def parse_mdns_services(text):
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        name = _col(row, "Service-Name", "Service Name")
        if name:
            out.append({"name": name,
                        "lss": t.enabled(t.lookup(row, "LSS")),
                        "origin": _col(row, "Origin") or None,
                        "providers": t.to_int(_col(row, "No SP", "SP")),
                        "service_string": _col(row, "Service String") or None})
    return out


def parse_mdns_profiles(text):
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        name = _col(row, "ProfileName", "Profile Name", "Profile-Name")
        if name:
            out.append({"name": name,
                        "interfaces": t.to_int(t.lookup(row, "No. Interfaces")),
                        "interface_groups": t.to_int(_col(row, "Interface Groups")),
                        "wlans": t.to_int(_col(row, "Wlans", "WLANs")),
                        "ap_groups": t.to_int(_col(row, "Ap Groups", "AP Groups"))})
    return out


def parse_nmsp_status(text):
    """show nmsp status. 7.x heads the columns 'MSE IP Address / Tx Echo
    Resp / Rx Echo Req'; 8.x 'LocalIP / PeerIP / Echo Request Count ...'."""
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        ip = _col(row, "PeerIP", "Peer IP", "MSE IP")
        if not ip or not _is_ip(ip):
            continue
        out.append({"ip": ip,
                    "local_ip": _col(row, "LocalIP", "Local IP") or None,
                    "tx_echo": t.to_int(_col(row, "Tx Echo", "Echo Response")),
                    "rx_echo": t.to_int(_col(row, "Rx Echo", "Echo Request")),
                    "tx_data": t.to_int(_col(row, "Tx Data", "Data Packets Sent")),
                    "rx_data": t.to_int(_col(row, "Rx Data", "Data Packets Received")),
                    "transport": _col(row, "Transport") or None})
    return out


def parse_nmsp_subscription(text):
    """show nmsp subscription summary: services per server; a long service
    list wraps onto lines with an empty server column."""
    if _empty(text):
        return None
    out = []
    for row in _service_rows(text):
        ip = _col(row, "Server IP", "IP Address")
        services = _col(row, "Services") or ""
        if ip and _is_ip(ip):
            out.append({"ip": ip, "services": []})
        if out and services:
            out[-1]["services"] += [s.strip() for s in services.split(",") if s.strip()]
    if not out:
        values = t.dotted(text)
        ip = t.lookup(values, "Server IP Address", "Server IP")
        if ip:
            out.append({"ip": ip, "services": [s.strip() for s in
                                               (t.lookup(values, "Services") or "").split(",")
                                               if s.strip()]})
    return out


def parse_mgid(text):
    """show network multicast mgid summary: layer-2 MGID per interface and
    the number of layer-3 groups."""
    if _empty(text):
        return None
    layer2, layer3 = [], 0
    for row in _service_rows(text):
        interface = _col(row, "InterfaceName", "Interface Name")
        if interface:
            layer2.append({"interface": interface, "vlan": t.to_int(_col(row, "vlan")),
                           "mgid": t.to_int(_col(row, "MGID"))})
        elif _col(row, "Group address", "Group Address"):
            layer3 += 1
    reported = t.to_int(t.lookup(t.dotted(text), "Number of Layer3 MGIDs"))
    return {"layer2": layer2, "layer2_count": len(layer2),
            "layer3_count": reported if reported is not None else layer3}


def _multicast(value):
    """'Multicast   Address : 239.1.1.1' -> ('Multicast', '239.1.1.1')."""
    if not value:
        return None, None
    m = re.search(r"Address\s*:\s*(\S+)", value, re.I)
    return value.split()[0], m.group(1) if m else None


def parse_network_summary(text):
    """show network summary: management access and multicast."""
    if _empty(text):
        return None
    v = t.dotted(text)
    mode, group = _multicast(t.lookup(v, "IPv4 AP Multicast/Broadcast Mode",
                                      "AP Multicast/Broadcast Mode", "AP Multicast Mode"))
    v6_mode, v6_group = _multicast(t.lookup(v, "IPv6 AP Multicast/Broadcast Mode"))

    def flag(*labels):
        return t.enabled(t.lookup(v, *labels))

    return {
        "rf_network_name": t.lookup(v, "RF-Network Name"),
        "telnet": flag("Telnet"),
        "ssh": flag("Secure Shell (ssh)", "Secure Shell"),
        "ssh_cipher_high": flag("Secure Shell (ssh) Cipher-Option High"),
        "http": flag("Web Mode"),
        "https": flag("Secure Web Mode"),
        "secure_web_cipher_high": flag("Secure Web Mode Cipher-Option High"),
        "secure_web_ssl": flag("Secure Web Mode SSL Protocol"),
        "web_csrf_check": flag("Web CSRF check"),
        "web_auth_secure": flag("Web Auth Secure Web"),
        "web_auth_secure_redirect": flag("Web Auth Secure Redirection"),
        "mgmt_via_wireless": flag("Mgmt Via Wireless Interface", "Mgmt Via Wireless"),
        "mgmt_via_dynamic_interface": flag("Mgmt Via Dynamic Interface"),
        "multicast_mode": mode,
        "multicast_group": group,
        "ipv6_multicast_mode": v6_mode,
        "ipv6_multicast_group": v6_group,
        "ethernet_multicast_forwarding": flag("Ethernet Multicast Forwarding"),
        "igmp_snooping": flag("IGMP snooping"),
        "mld_snooping": flag("MLD snooping"),
        "multicast_vlan": t.lookup(v, "Multicast Vlan", "Multicast VLAN"),
        "fast_ssid_change": flag("Fast SSID Change"),
        "user_idle_timeout_s": t.to_int(t.lookup(v, "User Idle Timeout")),
        "arp_idle_timeout_s": t.to_int(t.lookup(v, "ARP Idle Timeout")),
        "ap_fallback": flag("AP Fallback"),
        "mdns_snooping": flag("mDNS snooping"),
        "settings": v,
    }


# --- SNMP and logging ------------------------------------------------------------

def parse_snmpversion(text):
    if _empty(text):
        return None
    out = {"v1": None, "v2c": None, "v3": None}
    for label, value in t.dotted_all(text):
        m = re.search(r"\bv(1|2c|3)\b", label, re.I)
        if m and out["v" + m.group(1).lower()] is None:
            out["v" + m.group(1).lower()] = t.enabled(value)
    return out


def _rw(value):
    v = re.sub(r"[^a-z]", "", (value or "").lower())
    if v in ("readonly", "ro"):
        return "RO"
    if v in ("readwrite", "rw"):
        return "RW"
    return value or None


def parse_snmpcommunity(text):
    """show snmpcommunity. Names come back as stored: masked to
    <REDACTED> by the collector. Whether a default name was in use is
    recorded by the collector before masking, not here."""
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            name = _col(row, "Community Name")
            if not name:
                continue
            out.append({"name": name,
                        "ip": _col(row, "Client IP Address", "IP Address") or None,
                        "mask": _col(row, "Client IP Mask", "IP Mask") or None,
                        "access": _rw(_col(row, "Access")),
                        "enabled": t.enabled(_col(row, "Status"))})
    return out


def parse_snmpv3user(text):
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            name = _col(row, "User Name")
            if not name:
                continue
            out.append({"name": name,
                        "access": _rw(_col(row, "Access")),
                        "auth_protocol": _col(row, "Authentication") or None,
                        "priv_protocol": _col(row, "Encryption", "Privacy") or None})
    return out


def parse_snmptrap(text):
    if _empty(text):
        return None
    out = []
    for rows in t.tables(text):
        for row in rows:
            name = _col(row, "Receiver Name", "Name")
            if not name:
                continue
            out.append({"name": name, "ip": _col(row, "IP Address") or None,
                        "enabled": t.enabled(_col(row, "Status"))})
    return out


def parse_logging(text):
    """show logging. 8.x prefixes each line with '- ' and lists remote
    hosts as 'Host 0 .... <ip>' with empty slots left blank."""
    if _empty(text):
        return None
    pairs = [(re.sub(r"^[-\s]+", "", k).rstrip(" :"), v) for k, v in t.dotted_all(text)]
    values = dict(reversed(pairs))
    hosts = [v.split()[0] for k, v in pairs if re.match(r"^(Syslog\s+)?Host\s*\d+$", k, re.I)
             and v.strip()]
    level = t.lookup(values, "Logging of system messages to syslog", "Syslog level",
                     "Level of logging to syslog")
    return {"syslog_hosts": hosts,
            "syslog_host_count": t.to_int(t.lookup(values, "Number of remote syslog hosts")),
            "syslog_level": level,
            "facility": t.lookup(values, "Syslog facility"),
            "buffered_level": t.lookup(values, "Level of logging to buffer"),
            "console_level": t.lookup(values, "Level of logging to console"),
            "syslog_tls": t.enabled(t.lookup(values, "syslog over tls"))}


# --- Certificates ----------------------------------------------------------------

def _cert_date(text):
    """'2026 Mar 29th, 11:53:47 GMT' or 'Mar 29 11:53:47 2026 GMT' -> '2026-03-29'."""
    s = text or ""
    m = re.search(r"(\d{4})\s+([A-Za-z]{3})\w*\s+(\d{1,2})", s)
    if m:
        year, mon, day = m.group(1), m.group(2), m.group(3)
    else:
        m = re.search(r"([A-Za-z]{3})\w*\s+(\d{1,2})\s+[\d:]+\s+(\d{4})", s)
        if not m:
            return None
        mon, day, year = m.group(1), m.group(2), m.group(3)
    month = _MONTHS.get(mon.lower())
    return f"{year}-{month:02d}-{int(day):02d}" if month else None


def _cert(use, **kw):
    entry = {"use": use, "source": None, "subject": None, "issuer": None, "valid_from": None,
             "valid_to": None, "key_size": None, "signature_algorithm": None,
             "self_signed": None}
    entry.update(kw)
    return entry


def _summary_certs(text):
    out = []
    for label, value in t.dotted_all(text):
        low = label.lower().rstrip(":")
        if not low.endswith("certificate"):
            continue
        use = "web-admin" if "administration" in low else \
            "web-auth" if "authentication" in low else _snake(label)
        src = value.strip()
        self_signed = True if re.search(r"locally generated|self", src, re.I) else \
            False if re.search(r"3rd party|third party|installed", src, re.I) else None
        out.append(_cert(use, source=src or None, self_signed=self_signed))
    return out


def _local_auth_certs(text):
    out = []
    issuer_group = None
    current = None
    for line in text.splitlines():
        m = re.match(r"^\s*Certificate issuer\s*\.+\s*(\S+)", line, re.I)
        if m:
            issuer_group = m.group(1)
            current = None
            continue
        m = re.match(r"^\s*(CA|Device) certificate\s*:", line, re.I)
        if m:
            current = _cert("local-eap-" + m.group(1).lower(), source=issuer_group)
            out.append(current)
            continue
        if current is None:
            continue
        m = re.match(r"^\s*(Subject|Issuer)\s*:\s*(.*?)\s*$", line, re.I)
        if m:
            current[m.group(1).lower()] = m.group(2) or None
            continue
        m = re.match(r"^\s*Valid\s*:\s*(.*?)\s+to\s+(.*?)\s*$", line, re.I)
        if m:
            current["valid_from"] = _cert_date(m.group(1))
            current["valid_to"] = _cert_date(m.group(2))
            continue
        if re.search(r"not installed", line, re.I):
            out.remove(current)
            current = None
    for c in out:
        if c["subject"] and c["issuer"]:
            c["self_signed"] = c["subject"] == c["issuer"]
    return out


def _lsc_certs(text):
    out = []
    values = t.dotted(text)
    key_size = t.to_int(t.lookup(values, "KeySize", "Key Size"))
    current = None
    expect_subject = False
    for line in text.splitlines():
        m = re.match(r"^\s*(CA|RA|Device)\s+Cert\s*\.+\s*(.*?)\s*$", line, re.I)
        if m:
            current = None
            if not re.search(r"not configured|none", m.group(2), re.I):
                current = _cert("lsc-" + m.group(1).lower(), source=m.group(2) or None,
                                self_signed=False,
                                key_size=key_size if m.group(1).lower() == "device" else None)
                out.append(current)
            continue
        if current is None:
            continue
        if re.match(r"^\s*Subject Name\s*:", line, re.I):
            rest = line.split(":", 1)[1].strip()
            if rest:
                current["subject"] = rest
            else:
                expect_subject = True
            continue
        if expect_subject and line.strip():
            current["subject"] = line.strip()
            expect_subject = False
            continue
        m = re.match(r"^\s*(Start|End)\s*:\s*(.*)$", line, re.I)
        if m:
            current["valid_from" if m.group(1).lower() == "start" else "valid_to"] = \
                _cert_date(m.group(2))
    return out


def parse_certificates(text):
    """Certificates from any of the three outputs, detected by content.

    show certificate summary names which certificate each web service uses
    and whether it is locally generated (self-signed) or third party; it
    shows no subject, dates, key size or algorithm. show certificate lsc
    summary gives a subject and validity for each configured LSC CA, RA or
    device certificate and the device key size from the LSC parameters;
    it shows no issuer or algorithm. show local-auth certificates gives
    subject, issuer and validity for each local EAP CA and device
    certificate; no key size or algorithm. Fields an output does not show
    are None.
    """
    if _empty(text):
        return None
    if re.search(r"Certificate issuer\s*\.", text, re.I):
        return _local_auth_certs(text)
    if re.search(r"\bLSC\b", text):
        return _lsc_certs(text)
    return _summary_certs(text)
