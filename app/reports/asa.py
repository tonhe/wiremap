"""
Cisco ASA report: platform, failover, interfaces, certificates, management
plane, health and the assessment's checks, one row per unit (and per context
on multiple-context units).

Every sheet starts with Hostname, Context and Site so any sheet filters the
same way. A value whose command was not collected or failed reads "n/a"; a
blank cell means the command ran and the value is empty.
"""
import re
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone

from .base import BaseReport
from .findings import format_device_list
from . import asa_checks as checks
from . import asa_policy as policy

try:
    from app.asa_identity import base_hostname
    from app.collectors.asa import RUNNING_CONFIG, split_raw
    from app.collectors.base import command_error_kinds
    from app.collectors.errors import NOT_APPLICABLE, error_reason
    from app.collectors.asa_parsers import mask_to_prefix
    from app.site_mapping import derive_site
except ImportError:
    from asa_identity import base_hostname
    from collectors.asa import RUNNING_CONFIG, split_raw
    from collectors.base import command_error_kinds
    from collectors.errors import NOT_APPLICABLE, error_reason
    from collectors.asa_parsers import mask_to_prefix
    from site_mapping import derive_site

COLLECTOR = "asa"
NA = "n/a"
LEAD = ["Hostname", "Context", "Site"]


def na(value):
    return NA if value is None else value


def yes_no(value):
    return NA if value is None else ("Yes" if value else "No")


def _join(items, sep=", "):
    return sep.join(str(i) for i in items if i not in (None, ""))


def _usable(parsed):
    return bool(parsed) and not parsed.get("not_applicable") and not parsed.get(
        "collector_failed")


class Unit:
    """One ASA unit as collected, with the joins the sheets need."""

    def __init__(self, key, device):
        self.key = key
        self.device = device
        data = device.get("collector_data", {}).get(COLLECTOR) or {}
        self.parsed = data.get("parsed") or {}
        self.raw = data.get("raw") or {}
        unit = device.get("asa_unit") or {}
        self.hostname = unit.get("hostname") or base_hostname(key)
        self.role = unit.get("role") or ("standby" if key != self.hostname else "standalone")
        self.site = derive_site(self.hostname)
        self.mgmt_ip = device.get("reached_ip") or device.get("mgmt_ip") or ""
        clock = (self.parsed.get("clock") or {}).get("utc")
        try:
            self.collected_at = datetime.fromisoformat(clock.replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            self.collected_at = datetime.now(timezone.utc)
        self.multiple = self.parsed.get("mode") == "multiple"
        self.contexts = sorted((self.parsed.get("contexts") or {}).items())
        self._unit_raw, self._ctx_raw = split_raw(self.raw)

    @property
    def is_standby(self):
        return self.role == "standby"

    def outputs_for(self, context):
        """{command: output} for a context (the unit in single mode), with
        rejected commands blanked so their error text is never parsed."""
        outputs = self._ctx_raw.get(context, {}) if context else self._unit_raw
        return {cmd: "" if error_reason(text or "") else (text or "")
                for cmd, text in outputs.items()}

    def config_for(self, context):
        return self.outputs_for(context).get(RUNNING_CONFIG) or ""

    def lead(self, context=""):
        return [self.hostname, context, self.site]


def units(inventory_data):
    out = []
    for key, device in sorted((inventory_data.get("devices") or {}).items()):
        parsed = (device.get("collector_data", {}).get(COLLECTOR) or {}).get("parsed")
        if _usable(parsed):
            out.append(Unit(key, device))
    return out


def pairs(unit_list):
    """{hostname: {"primary": Unit, "secondary": Unit, "units": [..]}} for
    units with failover on."""
    out = OrderedDict()
    for u in unit_list:
        fo = u.parsed.get("failover") or {}
        if not fo.get("enabled"):
            continue
        entry = out.setdefault(u.hostname, {"primary": None, "secondary": None, "units": []})
        entry["units"].append(u)
        role = (fo.get("this_host") or {}).get("failover_role") or fo.get("unit")
        if role in ("primary", "secondary") and entry[role] is None:
            entry[role] = u
    return out


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

DEVICE_HEADERS = LEAD + [
    "Unit Role", "Management IP", "Model", "Platform Type", "Serial Number", "ASA Version",
    "ASDM Version", "Boot Image", "Uptime", "Last Reload Reason", "Mode", "Firewall Mode",
    "Failover Role", "Failover State", "Licence", "ASAv Entitlement", "Memory Installed (MB)",
    "Memory Free %", "CPU 5 s %", "CPU 1 min %", "CPU 5 min %", "Flash Used %",
    "Conns In Use", "Conns Peak", "Conns Platform Max", "Xlates In Use", "Xlates Peak",
    "Interfaces Up", "Interfaces Total", "ACL Elements", "NAT Rules", "S2S Configured",
    "S2S Up", "AnyConnect Active", "AnyConnect Peak", "AnyConnect Licence", "NTP Synced",
    "NTP Stratum", "Config Saved", "Collected At (UTC)",
]


def _licence(v, status):
    if not v:
        return NA
    f = v.get("features") or {}
    parts = [v.get("licence_tier")]
    for label, name in (("VPN peers", "Total VPN Peers"),
                        ("AnyConnect Premium", "AnyConnect Premium Peers"),
                        ("AnyConnect Plus", "AnyConnect Plus"),
                        ("AnyConnect Apex", "AnyConnect Apex"),
                        ("Security Contexts", "Security Contexts"),
                        ("3DES-AES", "Encryption-3DES-AES")):
        if f.get(name):
            parts.append(f"{label} {f[name]}")
    mode = v.get("licence_mode") or ("Smart" if status else "")
    if mode:
        parts.append("Smart" if "smart" in mode.lower() else mode)
    return _join(parts, "; ")


def _entitlement(v, status):
    if not v or v.get("platform_type") != "ASAv":
        return ""
    return _join([v.get("model_id"), (status or {}).get("throughput")], ", ")


def _device_rows(u):
    p = u.parsed
    v = p.get("version")
    h = p.get("health") or {}
    cpu, mem, disk = h.get("cpu"), h.get("memory"), h.get("disk")
    conns, xlates = h.get("conns"), h.get("xlates")
    fo = p.get("failover")
    this = (fo or {}).get("this_host") or {}
    chassis = p.get("chassis") or {}
    status = p.get("licence_status")
    ntp = p.get("ntp")
    clock = p.get("clock") or {}
    platform = [
        u.role.capitalize(), u.mgmt_ip,
        na((v or {}).get("model") or chassis.get("pid") if v or chassis else None),
        na((v or {}).get("platform_type") if v else None),
        na(chassis.get("sn") or (v or {}).get("serial") if v or chassis else None),
        na((v or {}).get("asa_version") if v else None),
        na((v or {}).get("asdm_version") if v else None),
        na(p.get("boot") or (v or {}).get("boot_image") if v else p.get("boot")),
        na((v or {}).get("uptime") if v else None),
        (v or {}).get("last_reload_reason", "") if v else NA,
        na((p.get("mode") or "").capitalize() or None),
        na(p.get("firewall_mode")),
        NA if fo is None else ((this.get("failover_role") or fo.get("unit") or "").capitalize()
                               if fo.get("enabled") else "Standalone"),
        NA if fo is None or not fo.get("enabled") else this.get("state", ""),
        _licence(v, status), _entitlement(v, status),
        na((v or {}).get("ram_mb") if v else None),
        na(round(100 - mem["used_pct"], 1) if mem and mem.get("used_pct") is not None else None),
        na((cpu or {}).get("5s") if cpu else None), na((cpu or {}).get("1m") if cpu else None),
        na((cpu or {}).get("5m") if cpu else None),
        na(disk["used_pct"] if disk else None),
        na(conns["in_use"] if conns else None), na(conns["peak"] if conns else None),
        na((conns or {}).get("limit")),
        na(xlates["in_use"] if xlates else None), na(xlates["peak"] if xlates else None),
    ]
    tail = [yes_no(ntp["synced"] if ntp else None), na(ntp["stratum"] if ntp else None),
            yes_no(p.get("config_saved")), clock.get("utc") or clock.get("text") or NA]
    rows = []
    contexts = u.contexts or [("", {})]
    for name, ctx in contexts:
        c = (ctx or {}).get("counts") or {}
        if u.is_standby:
            counts = [NA] * 9
        else:
            counts = [na(c.get(k)) for k in ("interfaces_up", "interfaces_total",
                                             "acl_elements", "nat_rules", "s2s_configured",
                                             "s2s_up", "anyconnect_active",
                                             "anyconnect_peak")]
            counts.append(na(((v or {}).get("features") or {}).get(
                "AnyConnect Premium Peers") if v else None))
        rows.append(u.lead(name) + platform + counts + tail)
    return rows


# ---------------------------------------------------------------------------
# Failover
# ---------------------------------------------------------------------------

FAILOVER_HEADERS = LEAD + [
    "Pair Name", "Primary Hostname", "Primary Serial", "Secondary Hostname",
    "Secondary Serial", "Currently Active", "Last Failover Time", "Last Failover Reason",
    "Failovers in History", "Failover Link Interface", "Failover Link State",
    "Stateful Link Interface", "Stateful Link State", "Monitored Interfaces",
    "Named Interfaces", "Interfaces Failed or Waiting", "Unit Poll / Hold",
    "Interface Poll / Hold", "Failover Key Set", "Version Match", "Licence Match",
]


def _pair_name(hostname):
    return re.sub(r"[-_]?0?[12]$", "", hostname) or hostname


def _failover_row(hostname, pair):
    ref = next((u for u in pair["units"] if not u.is_standby), pair["units"][0])
    fo = ref.parsed.get("failover") or {}
    this = fo.get("this_host") or {}
    other = fo.get("other_host") or {}
    serial = fo.get("serial") or {}
    ours_role = this.get("failover_role") or fo.get("unit")
    serials = {ours_role: serial.get("ours"),
               ("secondary" if ours_role == "primary" else "primary"): serial.get("mate")}
    prim, sec = pair.get("primary"), pair.get("secondary")
    active = ("Primary" if str(this.get("state", "")).lower().startswith("active")
              and ours_role == "primary" else
              "Secondary" if str(this.get("state", "")).lower().startswith("active") else
              (other.get("failover_role") or "").capitalize() or NA)
    history = ref.parsed.get("failover_history") or []
    newest = history[-1] if history else None
    link, state = fo.get("failover_link"), fo.get("stateful_link")
    named = [i for _, c in ref.contexts for i in (c or {}).get("interfaces") or []
             if i.get("nameif")]
    bad = [f"{i['nameif']} ({i['status']}{', ' + i['monitor'] if i.get('monitor') else ''})"
           for i in this.get("interfaces") or []
           if i.get("status", "").lower() != "normal" or "waiting" in i.get("monitor", "").lower()]
    poll = fo.get("poll") or {}
    version = fo.get("version") or {}
    licence_match = None
    if prim and sec:
        fa = (prim.parsed.get("version") or {}).get("features")
        fb = (sec.parsed.get("version") or {}).get("features")
        if fa and fb:
            licence_match = fa == fb
    return [hostname, "", ref.site, _pair_name(hostname),
            prim.key if prim else (hostname if ours_role == "primary" else NA),
            na(serials.get("primary")),
            sec.key if sec else (hostname if ours_role == "secondary" else NA),
            na(serials.get("secondary")), active,
            newest["time"] if newest else NA,
            f"{newest['from']} -> {newest['to']}: {newest['reason']}" if newest else NA,
            sum(1 for e in history if "active" in e["to"].lower() and "standby" not in
                e["to"].lower()),
            link["interface"] if link else NA, link["state"] if link else NA,
            state["interface"] if state else NA, state["state"] if state else NA,
            na(fo.get("monitored")), len(named) if named else NA, _join(bad),
            _join([poll.get("unit"), poll.get("unit_hold")], " / ") or NA,
            _join([poll.get("interface"), poll.get("interface_hold")], " / ") or NA,
            yes_no(ref.parsed.get("failover_key_set")),
            yes_no(version["ours"] == version["mate"]) if version.get("ours") else NA,
            yes_no(licence_match)]


# ---------------------------------------------------------------------------
# Interfaces, certificates, management, health
# ---------------------------------------------------------------------------

INTERFACE_HEADERS = LEAD + [
    "Interface", "Nameif", "Security Level", "IP Address", "Mask", "Standby IP", "VLAN",
    "Admin Status", "Line Status", "Speed", "Duplex", "MTU", "Description",
    "Port-channel Member Of", "Management-only", "Input Rate (bps)", "Output Rate (bps)",
    "Input Errors", "CRC", "Overruns", "Underruns", "Output Drops", "Counters Cleared",
    "Monitored for Failover", "Same-security Permitted",
]


def _interface_rows(u):
    rows = []
    for name, ctx in u.contexts:
        same = ctx.get("same_security")
        same_text = NA if same is None else (_join(
            [k for k in ("inter", "intra") if same.get(k)]) or "none")
        for i in ctx.get("interfaces") or []:
            shown = "line" in i
            rows.append(u.lead(name) + [
                i["interface"], i.get("nameif", ""), na(i.get("security_level")),
                i.get("ip", ""), i.get("mask", ""), i.get("standby_ip", ""),
                "" if i.get("vlan") is None else i["vlan"],
                i.get("admin") or NA, i.get("line") if shown else NA,
                i.get("speed", "") if shown else NA, i.get("duplex", "") if shown else NA,
                na(i.get("mtu")) if shown else NA, i.get("description", ""),
                f"Port-channel{i['channel_group']}" if i.get("channel_group") else "",
                yes_no(i.get("management_only")),
                na(i.get("in_rate_bps")), na(i.get("out_rate_bps")),
                na(i.get("input_errors")), na(i.get("crc")), na(i.get("overruns")),
                na(i.get("underruns")), na(i.get("output_drops")),
                NA,  # ASA show interface does not report when counters were cleared
                yes_no(i.get("monitored")), same_text])
    return rows


CERT_HEADERS = LEAD + [
    "Trustpoint", "Type", "Subject CN", "Issuer CN", "Serial", "Valid From", "Valid To",
    "Days to Expiry", "Key Type", "Key Size", "Signature Algorithm", "Used By",
    "Expired or < 90 Days", "Self-signed",
]


def _cert_rows(u):
    rows = []
    for name, ctx in u.contexts:
        for c in ctx.get("certificates") or []:
            days = checks.certificate_days(c, u.collected_at)
            rows.append(u.lead(name) + [
                _join(c.get("trustpoints") or []), "CA" if c["type"] == "ca" else "Identity",
                c.get("subject_cn", ""), c.get("issuer_cn", ""), c.get("serial", ""),
                c.get("valid_from", ""), c.get("valid_to", ""), na(days),
                c.get("key_type", ""), na(c.get("key_size")), c.get("sig_alg", ""),
                _join(c.get("used_by") or []), yes_no(None if days is None else days < 90),
                yes_no(c.get("self_signed"))])
    return rows


MGMT_HEADERS = LEAD + [
    "SSH Allowed From", "SSH Version", "SSH Ciphers", "SSH Key Exchange", "Telnet Enabled",
    "Telnet From", "HTTP/ASDM Allowed From", "HTTP Server Enabled", "ICMP to the Box",
    "AAA Auth Console", "AAA Auth SSH", "AAA Auth HTTP", "AAA Auth Enable",
    "AAA Command Authorization", "AAA Accounting", "AAA Servers", "Local Usernames",
    "Local Privilege Levels", "Password Policy", "SNMP Versions", "SNMP Hosts",
    "SNMPv3 Users", "Syslog Hosts", "Logging Levels", "NetFlow Targets", "NTP Servers",
    "NTP Authentication", "DNS Servers", "Domain", "Banner Present",
    "Smart Licensing / Call-home", "Management-access Interface",
]


def _nets(entries):
    return _join(f"{e['net']}/{mask_to_prefix(e['mask'])} ({e['nameif']})" for e in entries)


def _mgmt_rows(u):
    rows = []
    status = u.parsed.get("licence_status") or {}
    for name, ctx in u.contexts:
        m = ctx.get("mgmt")
        if m is None:
            rows.append(u.lead(name) + [NA] * (len(MGMT_HEADERS) - len(LEAD)))
            continue
        reach = {(s["host"]): s["status"] for s in ctx.get("aaa_status") or []}
        servers = _join(
            f"{s['group']} {m['aaa_server_groups'].get(s['group'], '')} {s['host']} "
            f"({s['nameif']}){' ' + reach[s['host']] if s['host'] in reach else ''}"
            for s in m["aaa_servers"])
        versions = sorted({h["version"] for h in m["snmp"]["hosts"]}
                          | ({"2c"} if m["snmp"]["communities"] else set())
                          | ({"3"} if m["snmp"]["users"] else set()))
        policy = dict(m["password_policy"])
        if m["max_fail"]:
            policy["lockout after"] = m["max_fail"]
        levels = m["logging"]
        rows.append(u.lead(name) + [
            _nets(m["ssh"]), m["ssh_version"], m["ssh_ciphers"], m["ssh_kex"],
            yes_no(bool(m["telnet"])), _nets(m["telnet"]), _nets(m["http"]),
            yes_no(m["http_server"]),
            _join(f"{i['action']} {i['from']} {i['nameif']}" for i in m["icmp"]),
            m["aaa_auth"].get("serial", ""), m["aaa_auth"].get("ssh", ""),
            m["aaa_auth"].get("http", ""), m["aaa_auth"].get("enable", ""),
            yes_no(m["aaa_cmd_authz"]), yes_no(bool(m["aaa_accounting"])), servers,
            len(m["local_users"]),
            _join(sorted({str(x["privilege"]) for x in m["local_users"]})),
            _join(f"{k} {v}" for k, v in policy.items()),
            _join(f"v{v}" for v in versions),
            _join(f"{h['host']} ({h['nameif']}, {h['kind']}, v{h['version']})"
                  for h in m["snmp"]["hosts"]),
            _join(f"{x['user']} (auth {x['auth'] or 'none'}, priv {x['priv'] or 'none'})"
                  for x in m["snmp"]["users"]),
            _join(f"{h['host']} ({h['nameif']}, {h['protocol']}/{h['port']})"
                  for h in m["syslog_hosts"]),
            _join(f"{k} {levels[k]}" for k in ("buffered", "trap", "console", "monitor")
                  if k in levels) + ("; timestamp on" if levels.get("timestamp") else ""),
            _join(f"{f['host']}:{f['port']} ({f['nameif']})" for f in m["flow_export"]),
            _join(n["host"] + (" (key)" if n["key"] else "") for n in m["ntp_servers"]),
            yes_no(m["ntp_authenticate"]), _join(m["dns_servers"]), m["domain_name"],
            yes_no(bool(m["banners"])),
            _join([("smart licensing" + (f" {status['registration']}"
                                         if status.get("registration") else ""))
                   if m["smart_licensing"] else "", "call-home" if m["call_home"] else ""]),
            m["management_access"]])
    return rows


HEALTH_HEADERS = LEAD + [
    "Unit Role", "CPU 5 s %", "CPU 1 min %", "CPU 5 min %", "Top Processes by CPU", "Memory Used %",
    "Memory Free (bytes)", "Blocks with Low Watermark 0", "ASP Drops (top 10)",
    "Conns % of Limit", "Xlates % of Limit", "Interface with Most Errors",
    "Resources over 80% of Limit", "Crashinfo Present", "Last Crash Time", "Crash Thread",
    "Critical Logs (level 1-3)", "Last Critical Logs", "Threat-detection Top", "Uptime",
]


def _pct(used, limit):
    return round(100 * used / limit, 1) if used is not None and limit else None


def _health_row(u):
    p = u.parsed
    h = p.get("health") or {}
    cpu, mem = h.get("cpu"), h.get("memory")
    conns, xlates = h.get("conns") or {}, h.get("xlates") or {}
    resources = h.get("resources") or []
    xl_row = next((r for r in resources if r["resource"].lower() == "xlates"), None)
    worst = None
    for _, ctx in u.contexts:
        for i in ctx.get("interfaces") or []:
            errs = i.get("input_errors")
            if errs and (worst is None or errs > worst[1]):
                worst = (i["interface"], errs, i.get("input_packets"))
    over = [f"{r['resource']} {r['current']}/{r['limit']}" for r in resources
            if r.get("limit") and r["current"] > 0.8 * r["limit"]]
    crash = h.get("crashinfo")
    logs = h.get("critical_logs")
    threat = next((ctx.get("threat_top") for _, ctx in u.contexts if ctx.get("threat_top")), [])
    v = p.get("version") or {}
    return u.lead() + [
        u.role.capitalize(), na((cpu or {}).get("5s")), na((cpu or {}).get("1m")), na((cpu or {}).get("5m")),
        _join(f"{r['process']} {r['1m']}%" for r in h.get("processes") or []),
        na((mem or {}).get("used_pct")), na((mem or {}).get("free")),
        _join(h.get("blocks_low_zero") or []),
        _join((f"{d['reason']}: {d['count']}" for d in h.get("asp_drops") or []), "; "),
        na(_pct(conns.get("in_use"), conns.get("limit"))),
        na(_pct(xlates.get("in_use"), (xl_row or {}).get("limit"))),
        (f"{worst[0]} ({worst[1]} errors"
         + (f", {round(100 * worst[1] / worst[2], 2)}%" if worst[2] else "") + ")")
        if worst else "",
        _join(over), yes_no(crash["present"] if crash else None),
        (crash or {}).get("time") or "", (crash or {}).get("thread") or "",
        na(logs["count"] if logs else None), " | ".join((logs or {}).get("last") or []),
        " | ".join(threat or []), na(v.get("uptime") if v else None)]


# ---------------------------------------------------------------------------
# Summary, Changes and Hygiene, Collection Errors
# ---------------------------------------------------------------------------

SUMMARY_HEADERS = ["Check", "Severity", "Devices Affected", "Device List", "Detail"]
HYGIENE_HEADERS = LEAD + ["Check", "Severity", "Object", "Detail", "Config Lines"]
ERROR_HEADERS = LEAD + ["Command", "Error", "Kind"]


def _summary_rows(findings, unit_list):
    by_check = OrderedDict()
    for f in sorted(findings, key=lambda f: (checks.RATING_ORDER[f["rating"]], f["check"])):
        by_check.setdefault(f["check"], []).append(f)
    rows = []
    for check, items in by_check.items():
        hosts = sorted({f["hostname"] for f in items})
        detail = items[0]["description"] if len(items) == 1 else (
            f"{len(items)} instances across {len(hosts)} unit(s); e.g. "
            f"{items[0]['description']}")
        rows.append([check, items[0]["rating"], len(hosts),
                     format_device_list(hosts, limit=20), detail])
    rows.append(["", "", "", "", ""])
    contexts = [c for u in unit_list for c in u.contexts]
    counts = [c.get("counts") or {} for _, c in contexts]

    def total(key):
        values = [c.get(key) for c in counts if c.get(key) is not None]
        return sum(values) if values else NA

    expiring = sum(1 for u in unit_list if not u.is_standby for _, c in u.contexts
                   for cert in c.get("certificates") or []
                   if (checks.certificate_days(cert, u.collected_at) or 10 ** 6) < 90)
    for label, value in (
            ("Total devices", len({u.hostname for u in unit_list})),
            ("Total units", len(unit_list)),
            ("Total contexts", sum(1 for u in unit_list if u.multiple for _ in u.contexts)),
            ("Total interfaces", sum(len(c.get("interfaces") or []) for u in unit_list
                                     if not u.is_standby for _, c in u.contexts)),
            ("ACL lines (configured)", policy.totals([u for u in unit_list
                                                      if not u.is_standby])),
            ("ACL elements", total("acl_elements")), ("NAT rules", total("nat_rules")),
            ("S2S tunnels configured", total("s2s_configured")),
            ("S2S tunnels up", total("s2s_up")),
            ("AnyConnect sessions active", total("anyconnect_active")),
            ("AnyConnect sessions peak", total("anyconnect_peak")),
            ("Certificates expiring in 90 days", expiring)):
        rows.append([label, "", value, "", ""])
    return rows


def _hygiene_rows(findings, unit_by_key):
    rows = []
    for f in sorted(findings, key=lambda f: (checks.RATING_ORDER[f["rating"]], f["check"],
                                             f["hostname"])):
        u = unit_by_key[f["hostname"]]
        rows.append(u.lead(f.get("context", "")) + [
            f["check"], f["rating"], f.get("object", ""), f["description"],
            "\n".join(f.get("config_lines") or [])])
    return rows


def _error_rows(unit_list):
    rows = []
    for u in unit_list:
        kinds = command_error_kinds(u.parsed)
        errors = u.parsed.get("command_errors") or {}
        for cmd in u.parsed.get("failed_commands") or []:
            if kinds.get(cmd) == NOT_APPLICABLE:
                continue
            m = re.match(r"^context (\S+): (.+)$", cmd)
            rows.append(u.lead(m.group(1) if m else "") + [
                m.group(2) if m else cmd, errors.get(cmd, ""), kinds.get(cmd, "")])
    return rows


def analyze(inventory_data):
    unit_list = units(inventory_data)
    findings = []
    for u in unit_list:
        findings += checks.unit_findings(u)
        findings += policy.findings(u)
    for pair in pairs(unit_list).values():
        findings += checks.pair_findings(pair)
    return {"units": unit_list, "findings": findings}


def build_tabular(inventory_data, analysis=None):
    analysis = analysis or analyze(inventory_data)
    unit_list = analysis["units"]
    findings = analysis["findings"]
    active = [u for u in unit_list if not u.is_standby]
    sheets = OrderedDict()
    sheets["Summary"] = (SUMMARY_HEADERS, _summary_rows(findings, unit_list))
    sheets["Devices"] = (DEVICE_HEADERS, [r for u in unit_list for r in _device_rows(u)])
    sheets["Failover"] = (FAILOVER_HEADERS,
                          [_failover_row(h, p) for h, p in pairs(unit_list).items()])
    sheets["Interfaces"] = (INTERFACE_HEADERS, [r for u in active for r in _interface_rows(u)])
    sheets["Access Lists"] = (policy.ACL_HEADERS, [r for u in active for r in policy.acl_rows(u)])
    sheets["ACL Lines"] = (policy.LINE_HEADERS, [r for u in active for r in policy.line_rows(u)])
    sheets["Objects"] = (policy.OBJECT_HEADERS, [r for u in active for r in policy.object_rows(u)])
    sheets["NAT"] = (policy.NAT_HEADERS, [r for u in active for r in policy.nat_rows(u)])
    sheets["Certificates"] = (CERT_HEADERS, [r for u in active for r in _cert_rows(u)])
    sheets["Management Plane"] = (MGMT_HEADERS, [r for u in active for r in _mgmt_rows(u)])
    sheets["Health and Capacity"] = (HEALTH_HEADERS, [_health_row(u) for u in unit_list])
    sheets["Changes and Hygiene"] = (HYGIENE_HEADERS, _hygiene_rows(
        findings, {u.key: u for u in unit_list}))
    errors = _error_rows(unit_list)
    if errors:
        sheets["Collection Errors"] = (ERROR_HEADERS, errors)
    return sheets


class AsaReport(BaseReport):
    name = "asa"
    label = "Cisco ASA"
    description = ("ASA and ASAv platform, failover, interfaces, certificates, management "
                   "plane, health and assessment checks")
    category = "Compliance & Config"
    required_collectors = [COLLECTOR]
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def can_generate(self, inventory_data):
        return bool(units(inventory_data))

    def generate_tabular_data(self, inventory_data):
        return build_tabular(inventory_data)

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        return self._generate_for_format(inventory_data, fmt)
