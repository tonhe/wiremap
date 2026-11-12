"""
Checks for the Cisco WLC report.

Each finding carries the assessment's rating (High / Medium / Low / Info) and
the items it counted (APs, WLANs, ports, servers), so the Summary can show
controllers affected, items affected and the first items by name. The shared
findings severity is derived from the rating, as for the ASA report.
"""
import re
from datetime import date

from .findings import CRITICAL, WARNING, INFO, make_finding

try:
    from app.wlc_models import version_tuple
except ImportError:
    from wlc_models import version_tuple

HIGH, MEDIUM, LOW, INFO_RATING = "High", "Medium", "Low", "Info"
RATING_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO_RATING: 3}
_SEVERITY = {HIGH: CRITICAL, MEDIUM: WARNING, LOW: INFO, INFO_RATING: INFO}

# Check names as the assessment lists them; they are the Summary rows.
CTRL_LDOS = "Controller past LDoS / EoSWM"
CTRL_RELEASE = "Controller on a release past end of support, or stuck below 8.10"
AP_LDOS = "APs past LDoS"
AP_9800 = "APs that can't move to 9800 (or only to 17.3)"
CAPACITY = "AP licence or platform max > 80% used"
NO_REDUNDANCY = "No controller redundancy"
PEER_DOWN = "Redundancy peer down or not Standby Hot"
LAG = "Uplink ports without LAG or with only one port up"
CRASH = "Coredumps or AP crash files present"
CPU_MEM = "CPU > 70% or memory free < 20%"
SYSLOG_NTP = "No syslog server / NTP not synchronised"

MIN_RELEASE = (8, 10)


def finding(ctrl, rating, check, detail, items=(), obj=""):
    return make_finding(
        ctrl.key, _SEVERITY[rating], check, detail,
        finding_type="wlc:" + re.sub(r"[^a-z0-9]+", "_", check.lower()).strip("_"),
        aggregate_key=check, rating=rating, check=check, items=list(items), object=obj,
        controller=ctrl.name)


def _date(text):
    try:
        return date.fromisoformat(str(text)[:10])
    except (TypeError, ValueError):
        return None


def lifecycle_findings(ctrl, life, today):
    out = []
    hw = life.get("hw") or {}
    ldos, eoswm = _date(hw.get("last_date_of_support")), _date(hw.get("end_of_sw_maintenance"))
    if ldos and ldos < today:
        out.append(finding(ctrl, HIGH, CTRL_LDOS,
                           f"{ctrl.model} passed last date of support on {ldos}.",
                           items=[ctrl.model]))
    elif eoswm and eoswm < today:
        out.append(finding(ctrl, MEDIUM, CTRL_LDOS,
                           f"{ctrl.model} passed end of software maintenance on {eoswm}.",
                           items=[ctrl.model]))
    sw = life.get("sw") or {}
    sw_ldos = _date(sw.get("last_date_of_support"))
    cap = life.get("facts", {}).get("max_aireos")
    reasons = []
    if sw_ldos and sw_ldos < today:
        reasons.append(f"AireOS {ctrl.version} passed last date of support on {sw_ldos}")
    if cap and version_tuple(cap) < MIN_RELEASE:
        reasons.append(f"{ctrl.model} cannot run past AireOS {cap}")
    if reasons:
        out.append(finding(ctrl, HIGH, CTRL_RELEASE, "; ".join(reasons) + ".",
                           items=[ctrl.version or ctrl.model]))
    return out


def platform_findings(ctrl):
    out = []
    info = ctrl.sysinfo or {}
    joined = ctrl.ap_count
    limits = [(n, label) for n, label in ((ctrl.licensed_aps, "licensed"),
                                          (info.get("max_aps"), "platform maximum")) if n]
    for limit, label in limits:
        if joined is not None and joined > 0.8 * limit:
            out.append(finding(ctrl, MEDIUM, CAPACITY,
                               f"{joined} APs joined of {limit} {label} "
                               f"({round(100 * joined / limit)}%).", items=[label]))
            break

    red = ctrl.redundancy or {}
    if red.get("mode") == "SSO":
        local, peer = (red.get("local_state") or "").upper(), (red.get("peer_state") or "").upper()
        healthy = ("ACTIVE" in local and "STANDBY HOT" in peer) or \
                  ("STANDBY HOT" in local and "ACTIVE" in peer)
        if not healthy:
            out.append(finding(ctrl, HIGH, PEER_DOWN,
                               f"SSO local state {red.get('local_state') or 'n/a'}, peer "
                               f"{red.get('peer_state') or 'n/a'}.", items=["SSO peer"]))
    elif not red.get("ha_sku") and ctrl.redundancy is not None \
            and ctrl.backup_controllers_on_aps is False:
        out.append(finding(ctrl, MEDIUM, NO_REDUNDANCY,
                           "No SSO pair, not an HA-SKU secondary, and no AP names a "
                           "secondary or tertiary controller.", items=[ctrl.name]))

    ports = ctrl.ports or []
    up = [p for p in ports if (p.get("link") or "").lower() == "up"]
    if ports and not ctrl.is_virtual:
        if ctrl.lag is False and len(up) > 1:
            out.append(finding(ctrl, MEDIUM, LAG,
                               f"{len(up)} ports up without LAG.",
                               items=[f"port {p['port']}" for p in up]))
        elif len(up) == 1 and len(ports) > 1:
            out.append(finding(ctrl, MEDIUM, LAG,
                               f"Only port {up[0]['port']} of {len(ports)} is up.",
                               items=[f"port {up[0]['port']}"]))

    dumps = ctrl.coredumps or {}
    crash = ctrl.ap_crash_files or []
    if dumps.get("present") or crash:
        items = list(dumps.get("files") or (["controller core dump"] if dumps.get("present")
                                             else [])) + crash
        out.append(finding(ctrl, INFO_RATING, CRASH,
                           f"{len(items)} core dump / AP crash file(s) on the controller.",
                           items=items))

    cpu = (ctrl.cpu or {}).get("current_pct")
    if cpu is None:
        cpu = info.get("cpu_current")
    free = (ctrl.memory or {}).get("free_pct")
    if free is None and info.get("memory_current") is not None:
        free = 100 - info["memory_current"]
    problems = []
    if cpu is not None and cpu > 70:
        problems.append(f"CPU {cpu}%")
    if free is not None and free < 20:
        problems.append(f"memory free {round(free, 1)}%")
    if problems:
        out.append(finding(ctrl, MEDIUM, CPU_MEM, ", ".join(problems) + ".", items=problems))

    time = ctrl.time
    if time is not None:
        if not time.get("ntp_servers"):
            out.append(finding(ctrl, MEDIUM, SYSLOG_NTP, "No NTP server configured.",
                               items=["NTP"]))
        elif time.get("ntp_synced") is False:
            out.append(finding(ctrl, MEDIUM, SYSLOG_NTP, "No NTP server is in sync.",
                               items=["NTP"]))
    return out
