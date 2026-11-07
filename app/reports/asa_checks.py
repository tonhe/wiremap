"""
Checks for the ASA report.

Each check carries the assessment's own rating (High / Medium / Low / Info)
next to the shared findings severity it maps to, so the ASA Summary shows
the rating the assessment defines while the findings machinery (aggregation,
counts) works as it does for every other report.
"""
import re
from datetime import datetime

from .findings import CRITICAL, WARNING, INFO, make_finding

HIGH, MEDIUM, LOW, INFO_RATING = "High", "Medium", "Low", "Info"
RATING_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO_RATING: 3}
_SEVERITY = {HIGH: CRITICAL, MEDIUM: WARNING, LOW: INFO, INFO_RATING: INFO}

# Check names as the assessment lists them; they are the Summary rows.
HA_ON_SECONDARY = "HA pair running on secondary"
HA_MISMATCH = "HA version or licence mismatch"
HA_LINK_DOWN = "Failover link or monitored interface down"
CERT_EXPIRED = "Certificates expired"
CERT_EXPIRING = "Certificates expiring within 90 days"
TELNET = "Telnet enabled"
MGMT_OPEN = "SSH or ASDM open from any / outside"
SSH_LOCAL_ONLY = "No AAA (LOCAL only) for SSH"
NO_AUTHZ_ACCT = "No command authorization or accounting"
SNMP_V12 = "SNMP v1/v2c in use"
NO_SYSLOG = "No syslog host"
NO_NTP_SYNC = "No NTP sync"
TRAP_VERBOSE = "Logging trap level higher than informational"
CPU_MEM = "CPU 5 min > 70% or memory > 80%"
CONNS_HIGH = "Conns > 70% of platform limit"
INTF_ERRORS = "Interfaces with errors > 0.1% of packets"
NOT_SAVED = "Running config not saved"
CRASHINFO = "Crashinfo in last 12 months"
NO_ENABLE = "Default credentials / enable password not set"

LOG_LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
              "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7}


def finding(unit, rating, check, detail, obj="", context="", config_lines=()):
    return make_finding(
        unit.key, _SEVERITY[rating], check, detail,
        finding_type="asa:" + re.sub(r"[^a-z0-9]+", "_", check.lower()).strip("_"),
        aggregate_key=check, rating=rating, check=check, context=context,
        object=obj, config_lines=list(config_lines), unit_hostname=unit.hostname)


def _lines_matching(config, pattern):
    return [l.rstrip() for l in (config or "").splitlines() if re.match(pattern, l)]


def _outside_names(ctx):
    """nameifs at security level 0, or named like an outside interface."""
    names = set()
    for i in ctx.get("interfaces") or []:
        name = i.get("nameif") or ""
        if not name:
            continue
        if i.get("security_level") == 0 or re.search(r"outside|internet|wan|isp", name, re.I):
            names.add(name)
    return names


def _days_until(iso, now):
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return (when - now).days


def certificate_days(cert, now):
    return _days_until(cert.get("valid_to"), now)


def unit_findings(unit):
    """Findings for one unit and its contexts."""
    out = []
    parsed = unit.parsed
    fo = parsed.get("failover") or {}
    this = fo.get("this_host") or {}

    # --- failover ---------------------------------------------------------
    if fo.get("enabled"):
        if this.get("failover_role") == "secondary" and \
                str(this.get("state", "")).lower().startswith("active"):
            out.append(finding(unit, LOW, HA_ON_SECONDARY,
                               "The secondary unit is active; the pair has failed over "
                               f"(last failover {fo.get('last_failover') or 'n/a'}).",
                               obj="failover"))
        version = fo.get("version") or {}
        if version.get("ours") and version.get("mate") and version["ours"] != version["mate"]:
            out.append(finding(unit, MEDIUM, HA_MISMATCH,
                               f"Software differs: this unit {version['ours']}, "
                               f"mate {version['mate']}.", obj="version"))
        if not unit.is_standby:
            for label, link in (("Failover link", fo.get("failover_link")),
                                ("Stateful link", fo.get("stateful_link"))):
                if link and link.get("state", "").lower() != "up":
                    out.append(finding(unit, MEDIUM, HA_LINK_DOWN,
                                       f"{label} {link['name']} ({link['interface']}) is "
                                       f"{link['state']}.", obj=link["interface"]))
            for i in this.get("interfaces") or []:
                if i.get("status", "").lower() != "normal":
                    out.append(finding(unit, MEDIUM, HA_LINK_DOWN,
                                       f"Monitored interface {i['nameif']} is {i['status']}"
                                       f" ({i.get('monitor') or 'n/a'}).", obj=i["nameif"]))

    # --- health --------------------------------------------------------------
    health = parsed.get("health") or {}
    cpu, mem = health.get("cpu") or {}, health.get("memory") or {}
    if (cpu.get("5m") or 0) > 70 or (mem.get("used_pct") or 0) > 80:
        out.append(finding(unit, MEDIUM, CPU_MEM,
                           f"CPU 5 min {cpu.get('5m', 'n/a')}%, memory used "
                           f"{mem.get('used_pct', 'n/a')}%.", obj="platform"))
    conns = health.get("conns") or {}
    if conns.get("limit") and conns.get("in_use") is not None \
            and conns["in_use"] > 0.7 * conns["limit"]:
        out.append(finding(unit, MEDIUM, CONNS_HIGH,
                           f"{conns['in_use']} connections of a {conns['limit']} limit "
                           f"({round(100 * conns['in_use'] / conns['limit'])}%).",
                           obj="conns"))
    if parsed.get("config_saved") is False:
        out.append(finding(unit, LOW, NOT_SAVED,
                           "Running and startup configuration checksums differ; changes "
                           "are lost on reload.", obj="config"))
    crash = health.get("crashinfo") or {}
    if crash.get("present"):
        days = _days_until(crash.get("time"), unit.collected_at) if crash.get("time") else None
        if days is None or days >= -365:
            when = crash.get("time") or "date not reported"
            out.append(finding(unit, MEDIUM, CRASHINFO,
                               f"Crash saved ({when}), thread "
                               f"{crash.get('thread') or 'n/a'}.", obj="crashinfo"))
    ntp = parsed.get("ntp")
    if ntp is not None and not ntp.get("synced"):
        out.append(finding(unit, MEDIUM, NO_NTP_SYNC,
                           f"Clock is not synchronised (stratum {ntp.get('stratum')}).",
                           obj="ntp"))

    # --- per context ------------------------------------------------------------
    if unit.is_standby:
        return out
    for name, ctx in unit.contexts:
        out += context_findings(unit, name, ctx)
    return out


def context_findings(unit, name, ctx):
    out = []
    config = unit.config_for(name)
    m = ctx.get("mgmt")
    if m is not None:
        outside = _outside_names(ctx)
        if m["telnet"]:
            out.append(finding(unit, HIGH, TELNET,
                               "Telnet management is allowed from "
                               + ", ".join(f"{t['net']}/{t['mask']} on {t['nameif']}"
                                           for t in m["telnet"]) + ".",
                               obj="telnet", context=name,
                               config_lines=_lines_matching(config, r"telnet \S+ \S+ \S+")))
        for proto, label in (("ssh", "SSH"), ("http", "ASDM")):
            open_ = [e for e in m[proto]
                     if (e["net"] in ("0.0.0.0", "any") and e["mask"] == "0.0.0.0")
                     or e["nameif"] in outside]
            if open_ and (proto == "ssh" or m["http_server"]):
                out.append(finding(unit, HIGH, MGMT_OPEN,
                                   f"{label} allowed from "
                                   + ", ".join(f"{e['net']}/{e['mask']} on {e['nameif']}"
                                               for e in open_) + ".",
                                   obj=label, context=name,
                                   config_lines=_lines_matching(config, rf"{proto} \S+ \S+ \S+")))
        ssh_auth = m["aaa_auth"].get("ssh", "")
        if not ssh_auth or ssh_auth.upper() == "LOCAL":
            out.append(finding(unit, MEDIUM, SSH_LOCAL_ONLY,
                               "SSH logins authenticate against local accounts only"
                               if ssh_auth else "No aaa authentication ssh console configured.",
                               obj="aaa", context=name,
                               config_lines=_lines_matching(config, r"aaa authentication ssh")))
        if not m["aaa_cmd_authz"] or not m["aaa_accounting"]:
            missing = [w for w, ok in (("command authorization", m["aaa_cmd_authz"]),
                                       ("accounting", m["aaa_accounting"])) if not ok]
            out.append(finding(unit, LOW, NO_AUTHZ_ACCT,
                               "Not configured: " + " and ".join(missing) + ".",
                               obj="aaa", context=name))
        old = [h for h in m["snmp"]["hosts"] if h["version"] in ("1", "2c")]
        if m["snmp"]["communities"] or old:
            out.append(finding(unit, MEDIUM, SNMP_V12,
                               f"{m['snmp']['communities']} community string(s); "
                               f"{len(old)} host(s) on SNMP v1/v2c.", obj="snmp", context=name,
                               config_lines=_lines_matching(
                                   config, r"snmp-server (community|host .* community)")))
        if not m["syslog_hosts"]:
            out.append(finding(unit, MEDIUM, NO_SYSLOG, "No logging host configured.",
                               obj="logging", context=name))
        trap = m["logging"].get("trap")
        level = LOG_LEVELS.get(trap, int(trap) if str(trap).isdigit() else None)
        if level is not None and level > LOG_LEVELS["informational"]:
            out.append(finding(unit, LOW, TRAP_VERBOSE,
                               f"logging trap {trap} sends debug-level messages to syslog.",
                               obj="logging", context=name,
                               config_lines=_lines_matching(config, r"logging trap")))
    if ctx.get("enable_password_set") is False:
        out.append(finding(unit, HIGH, NO_ENABLE,
                           "No enable password is set (or it is the empty default).",
                           obj="enable", context=name,
                           config_lines=_lines_matching(config, r"enable password")))
    for cert in ctx.get("certificates") or []:
        days = certificate_days(cert, unit.collected_at)
        if days is None:
            continue
        label = f"{cert.get('subject_cn') or cert.get('serial')} ({', '.join(cert['trustpoints'])})"
        if days < 0:
            out.append(finding(unit, HIGH, CERT_EXPIRED,
                               f"{label} expired {-days} days ago.", obj=label, context=name))
        elif days < 90:
            out.append(finding(unit, MEDIUM, CERT_EXPIRING,
                               f"{label} expires in {days} days.", obj=label, context=name))
    for i in ctx.get("interfaces") or []:
        pkts, errs = i.get("input_packets"), i.get("input_errors")
        if pkts and errs and errs / pkts > 0.001:
            out.append(finding(unit, LOW, INTF_ERRORS,
                               f"{i['interface']} ({i.get('nameif') or 'no nameif'}): "
                               f"{errs} input errors in {pkts} packets "
                               f"({round(100 * errs / pkts, 2)}%).",
                               obj=i["interface"], context=name))
    return out


def pair_findings(pair):
    """Findings that need both units of a pair (licence match)."""
    a, b = pair.get("primary"), pair.get("secondary")
    if not (a and b):
        return []
    fa = (a.parsed.get("version") or {}).get("features")
    fb = (b.parsed.get("version") or {}).get("features")
    if fa and fb and fa != fb:
        diff = sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))
        return [finding(a, MEDIUM, HA_MISMATCH,
                        "Licence features differ between the units: " + ", ".join(diff[:8])
                        + ".", obj="licence")]
    return []
