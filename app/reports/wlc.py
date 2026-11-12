"""
Cisco WLC report: AireOS controllers' platform, lifecycle, redundancy,
interfaces, ports, health and the assessment's checks.

Every sheet starts with Controller, Site and Model so any sheet filters the
same way. Sheets parse the stored raw output when the report is built, so a
scan taken before a parser existed renders it later without recollecting. A
value whose command failed or was not run reads "n/a"; a blank cell means
the command ran and the value is empty.
"""
import logging
import re
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from functools import cached_property

from .base import BaseReport
from .findings import format_device_list
from . import wlc_checks as checks

try:
    from app.collectors import wlc_platform as P
    from app.collectors import wlc_text as t
    from app.collectors.base import command_error_kinds
    from app.collectors.errors import error_reason
    from app.collectors.wlc import RUN_CONFIG, ap_names
    from app.identity import normalize_hostname
    from app.site_mapping import derive_site
    from app.wlc_models import ap_facts, controller_facts
    from app.wlc_session import SYSINFO
except ImportError:
    from collectors import wlc_platform as P
    from collectors import wlc_text as t
    from collectors.base import command_error_kinds
    from collectors.errors import error_reason
    from collectors.wlc import RUN_CONFIG, ap_names
    from identity import normalize_hostname
    from site_mapping import derive_site
    from wlc_models import ap_facts, controller_facts
    from wlc_session import SYSINFO

logger = logging.getLogger(__name__)

COLLECTOR = "wlc"
NA = "n/a"
LEAD = ["Controller", "Site", "Model"]


def na(value):
    return NA if value is None else value


def yes_no(value):
    return NA if value is None else ("Yes" if value else "No")


def _join(items, sep=", "):
    return sep.join(str(i) for i in items if i not in (None, ""))


def _usable(parsed):
    return bool(parsed) and not parsed.get("collector_failed")


_BACKUP_CTRL = re.compile(r"^\s*(?:Secondary|Tertiary) Cisco Switch (?:Name|IP Address)\.+\s*(\S.*?)\s*$",
                          re.M)


class Controller:
    """One AireOS controller as collected, parsed on first use."""

    def __init__(self, key, device, collected_at=None):
        self.key = key
        self.device = device
        data = device.get("collector_data", {}).get(COLLECTOR) or {}
        self.parsed = data.get("parsed") or {}
        self._raw = data.get("raw") or {}
        self.mgmt_ip = device.get("reached_ip") or device.get("mgmt_ip") or ""
        self.collected_at = collected_at or datetime.now(timezone.utc)

    def out(self, cmd):
        """The command's output, or None when it was not run or was rejected."""
        text = self._raw.get(cmd)
        if text is None or error_reason(text):
            return None
        return text

    def ran(self, cmd):
        return self.out(cmd) is not None

    def commands(self, prefix):
        return {cmd: text for cmd, text in self._raw.items()
                if cmd.startswith(prefix) and not error_reason(text or "")}

    @cached_property
    def sysinfo(self):
        return P.parse_sysinfo(self.out(SYSINFO))

    @cached_property
    def inventory(self):
        return P.parse_inventory(self.out("show inventory"))

    @property
    def name(self):
        return (self.sysinfo or {}).get("system_name") or self.key

    @property
    def site(self):
        return derive_site(self.name)

    @property
    def model(self):
        return ((self.inventory or {}).get("model") or self.device.get("model")
                or self.device.get("platform") or "")

    @property
    def serial(self):
        return (self.inventory or {}).get("serial") or self.device.get("serial") or ""

    @property
    def version(self):
        return (self.sysinfo or {}).get("version") or self.parsed.get("product_version") or ""

    @property
    def is_virtual(self):
        return "CTVM" in self.model.upper()

    def lead(self):
        return [self.name, self.site, self.model or NA]

    @cached_property
    def boot(self):
        return P.parse_boot(self.out("show boot"))

    @cached_property
    def licence(self):
        return P.parse_license(self.out("show license summary"),
                               self.out("show license capacity"), self.out("show license all"))

    @property
    def licensed_aps(self):
        return (self.licence or {}).get("licensed_aps")

    @cached_property
    def cpu(self):
        return P.parse_cpu(self.out("show cpu"))

    @cached_property
    def memory(self):
        return P.parse_memory(self.out("show memory statistics"))

    @cached_property
    def redundancy(self):
        return P.parse_redundancy_summary(self.out("show redundancy summary"))

    @cached_property
    def redundancy_detail(self):
        return P.parse_redundancy_detail(self.out("show redundancy detail"))

    @cached_property
    def redundancy_stats(self):
        return P.parse_redundancy_statistics(self.out("show redundancy statistics"))

    @cached_property
    def redundancy_timers(self):
        return P.parse_redundancy_timers(self.out("show redundancy timers"))

    @cached_property
    def peer_routes(self):
        return P.parse_peer_route(self.out("show redundancy peer-route summary"))

    @cached_property
    def interfaces(self):
        return P.parse_interface_summary(self.out("show interface summary"))

    @cached_property
    def interface_groups(self):
        return P.interface_group_members(self.out(RUN_CONFIG))

    @cached_property
    def ports(self):
        return P.parse_port_summary(self.out("show port summary"))

    @cached_property
    def lag(self):
        return (P.parse_lag(self.out("show lag summary")) or {}).get("enabled")

    @cached_property
    def cdp(self):
        return P.parse_cdp_neighbors(self.out("show cdp neighbors detail"))

    @cached_property
    def time(self):
        return P.parse_time(self.out("show time"))

    @cached_property
    def coredumps(self):
        return P.parse_coredumps(self.out("show coredump summary"))

    @cached_property
    def ap_crash_files(self):
        return P.parse_ap_crash_files(self.out("show ap crash-file"))

    @cached_property
    def ap_rows(self):
        """show ap summary rows, or None when it was not collected."""
        text = self.out("show ap summary")
        return None if text is None else t.table(text)

    @property
    def ap_count(self):
        return None if self.ap_rows is None else len(ap_names(self.out("show ap summary")))

    @cached_property
    def wlan_rows(self):
        text = self.out("show wlan summary")
        return None if text is None else t.table(text)

    @cached_property
    def backup_controllers_on_aps(self):
        """True when any AP names a secondary or tertiary controller, None
        when no AP's configuration was collected."""
        configs = self.commands("show ap config general ")
        if not configs:
            return None
        for text in configs.values():
            for m in _BACKUP_CTRL.finditer(text):
                value = m.group(1)
                if value and not re.match(r"not configured|0\.0\.0\.0|unknown", value, re.I):
                    return True
        return False

    @cached_property
    def mobility_group(self):
        text = self.out("show mobility summary") or ""
        m = re.search(r"Default Mobility Domain\.+\s*(\S+)", text)
        return m.group(1) if m else ("" if text else None)


def _collected_at(inventory_data):
    stamp = inventory_data.get("timestamp")
    try:
        return datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def controllers(inventory_data):
    when = _collected_at(inventory_data)
    out = []
    for key, device in sorted((inventory_data.get("devices") or {}).items()):
        parsed = (device.get("collector_data", {}).get(COLLECTOR) or {}).get("parsed")
        if _usable(parsed) and not parsed.get("not_applicable"):
            out.append(Controller(key, device, when))
    return out


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def ap_models(ctrl):
    """{model: count} from show ap summary."""
    counts = defaultdict(int)
    for row in ctrl.ap_rows or []:
        model = t.lookup(row, "AP Model")
        if model:
            counts[model] += 1
    return counts


def eox_records(ctrl_list):
    """(hardware {pid: record}, software {"version|WLC": record}) from the EOX
    report's cache and API lookup; empty when unavailable."""
    devices = {}
    for c in ctrl_list:
        devices[c.key] = {"device_type": "cisco_wlc", "collector_data": {"device_inventory": {
            "parsed": {"inventory": [{"pid": c.model}],
                       "version": [{"version": c.version}] if c.version else []}}}}
    pids = sorted({m for c in ctrl_list for m in ap_models(c)})
    if pids:
        # APs are not scan devices; a stand-in record carries their PIDs.
        devices["access points"] = {"device_type": "cisco_ap", "collector_data": {
            "device_inventory": {"parsed": {"inventory": [{"pid": p} for p in pids]}}}}
    if not devices:
        return {}, {}
    try:
        from .eox_lifecycle import EoxLifecycleReport
        return EoxLifecycleReport()._get_eox_data({"devices": devices})
    except Exception as e:  # pragma: no cover - API or plugin trouble
        logger.warning("EOX lookup for the WLC report failed: %s", e)
        return {}, {}


def _sw_record(sw, version):
    if not version:
        return None
    if f"{version}|WLC" in sw:
        return sw[f"{version}|WLC"]
    try:
        from .eox_lifecycle import _normalize_sw_version
        return sw.get(f"{_normalize_sw_version(version, 'WLC')}|WLC")
    except Exception:
        return None


def lifecycle(ctrl_list, hw, sw):
    """{controller key: {...}} and {ap model: {...}}."""
    ctrls = {}
    for c in ctrl_list:
        ctrls[c.key] = {"hw": hw.get(c.model), "sw": _sw_record(sw, c.version),
                        "facts": controller_facts(c.model)}
    aps = OrderedDict()
    for c in ctrl_list:
        for model, n in sorted(ap_models(c).items()):
            entry = aps.setdefault(model, {"count": 0, "sites": set(), "versions": set(),
                                           "hw": hw.get(model), "facts": ap_facts(model)})
            entry["count"] += n
            entry["sites"].add(c.site or c.name)
            if c.version:
                entry["versions"].add(c.version)
    return {"controllers": ctrls, "aps": aps}


LIFECYCLE_HEADERS = LEAD + [
    "Type", "Count", "Sites", "Running Version", "End of Sale", "End of SW Maintenance",
    "Last Date of Support", "Max AireOS", "Supported on Catalyst 9800", "Wi-Fi Generation",
    "CX Coverage"]


def _eox_cells(record):
    if not record:
        return [NA, NA, NA]
    return [record.get("end_of_sale", ""), record.get("end_of_sw_maintenance", ""),
            record.get("last_date_of_support", "")]


def lifecycle_rows(ctrl_list, life):
    rows = []
    for c in ctrl_list:
        info = life["controllers"][c.key]
        f = info["facts"]
        rows.append(c.lead() + ["Controller", 1, c.site, c.version or NA]
                    + _eox_cells(info["hw"])
                    + [f["max_aireos"] or NA, f["c9800"] or NA, f["wifi"], NA])
    for model, info in life["aps"].items():
        f = info["facts"]
        rows.append(["", _join(sorted(info["sites"])), model, "AP", info["count"],
                     _join(sorted(info["sites"])), _join(sorted(info["versions"]))]
                    + _eox_cells(info["hw"])
                    + [f["max_aireos"] or NA, f["c9800"] or NA, f["wifi"] or NA, NA])
    return rows


# ---------------------------------------------------------------------------
# Controllers, Redundancy, Interfaces, Ports, Health
# ---------------------------------------------------------------------------

CONTROLLER_HEADERS = LEAD + [
    "Location", "Management IP", "Serial", "AireOS Version", "Field Recovery Image",
    "Primary Boot Image", "Backup Boot Image", "Uptime", "Last Reset Reason",
    "Max APs Supported", "Licensed AP Count", "APs Joined", "AP Licence Used %",
    "Clients Total", "WLANs Configured", "WLANs Enabled", "Dynamic Interfaces", "HA Mode",
    "Redundancy State", "Redundancy Peer", "Mobility Group", "Country Codes", "Time",
    "NTP State", "CPU %", "Memory Free %", "Temperature (C)", "Fans", "Power Supplies",
    "Config Saved", "Collected At (UTC)"]


def ha_mode(c):
    red = c.redundancy
    if red is None:
        return NA
    if red.get("mode") == "SSO":
        return "SSO"
    if red.get("ha_sku"):
        return "N+1 secondary (HA-SKU)"
    if c.backup_controllers_on_aps:
        return "N+1 primary"
    return "None"


def _ntp_state(time):
    if time is None:
        return NA
    servers = time.get("ntp_servers") or []
    if not servers:
        return "No NTP servers"
    synced = time.get("ntp_synced")
    state = "In sync" if synced else ("Not synced" if synced is False else "Status not shown")
    return f"{state} ({_join(s['server'] for s in servers)})"


def _pct(part, whole):
    return round(100 * part / whole, 1) if part is not None and whole else None


def _controller_row(c):
    info = c.sysinfo or {}
    boot = c.boot or {}
    red = c.redundancy or {}
    wlans = c.wlan_rows
    enabled = None if wlans is None else sum(
        1 for r in wlans if (t.lookup(r, "Status") or "").lower().startswith("enable"))
    dynamic = None if c.interfaces is None else sum(
        1 for i in c.interfaces if i.get("type") == "Dynamic")
    mem_free = (c.memory or {}).get("free_pct")
    if mem_free is None and info.get("memory_current") is not None:
        mem_free = 100 - info["memory_current"]
    cpu = (c.cpu or {}).get("current_pct")
    peer = (c.redundancy_detail or {}).get("peer_redundancy_mgmt_ip") or ""
    return c.lead() + [
        info.get("location", NA) if c.sysinfo else NA, c.mgmt_ip, c.serial or NA,
        c.version or NA, info.get("field_recovery", NA) if c.sysinfo else NA,
        boot.get("primary", NA) if c.boot else NA, boot.get("backup", NA) if c.boot else NA,
        info.get("uptime", NA) if c.sysinfo else NA,
        info.get("last_reset", NA) if c.sysinfo else NA, na(info.get("max_aps")),
        na(c.licensed_aps), na(c.ap_count), na(_pct(c.ap_count, c.licensed_aps)),
        na(info.get("clients")), NA if wlans is None else len(wlans), na(enabled),
        na(dynamic), ha_mode(c),
        _join([red.get("local_state"), red.get("peer_state") and f"peer {red['peer_state']}"])
        if c.redundancy else NA, peer if c.redundancy_detail else NA, na(c.mobility_group),
        info.get("country", NA) if c.sysinfo else NA, (c.time or {}).get("time", NA),
        _ntp_state(c.time), na(cpu if cpu is not None else info.get("cpu_current")),
        na(round(mem_free, 1) if mem_free is not None else None),
        na(info.get("temperature_c")), info.get("fan_status", NA) if c.sysinfo else NA,
        _join(info.get("power_supplies") or [], "; ") if c.sysinfo else NA, NA,
        c.collected_at.strftime("%Y-%m-%d %H:%M")]


REDUNDANCY_HEADERS = LEAD + [
    "Redundancy Mode", "Local State", "Peer State", "Unit", "Redundancy Mgmt IP",
    "Peer Redundancy Mgmt IP", "Redundancy Port IP", "Peer Redundancy Port IP",
    "Redundancy Port State", "Peer Routes", "Last Switchover Time", "Last Switchover Reason",
    "Switchovers", "Keepalive (ms)", "Peer Search (s)", "Backup Controller on APs"]


def _redundancy_row(c):
    red = c.redundancy
    det = c.redundancy_detail
    stats = c.redundancy_stats
    timers = c.redundancy_timers

    def get(d, key):
        return NA if d is None else d.get(key, "")
    routes = c.peer_routes
    return c.lead() + [
        get(red, "mode"), get(red, "local_state"), get(red, "peer_state"),
        (red.get("unit", "") + (" (HA-SKU)" if red.get("ha_sku") else "")) if red else NA,
        get(det, "redundancy_mgmt_ip"), get(det, "peer_redundancy_mgmt_ip"),
        get(det, "redundancy_port_ip"), get(det, "peer_redundancy_port_ip"),
        get(det, "redundancy_port_state"),
        NA if routes is None else _join(f"{r['network']}/{r['mask']} via {r['gateway']}"
                                        for r in routes),
        get(stats, "last_switchover_time"), get(stats, "last_switchover_reason"),
        NA if stats is None else na(stats.get("switchovers")),
        NA if timers is None else na(timers.get("keepalive_ms")),
        NA if timers is None else na(timers.get("peer_search_s")),
        yes_no(c.backup_controllers_on_aps)]


INTERFACE_HEADERS = LEAD + [
    "Interface", "Type", "VLAN", "IP Address", "Mask", "Gateway", "Physical Port",
    "Backup Port", "LAG", "DHCP Primary", "DHCP Secondary", "DHCP Proxy", "ACL",
    "Interface Group", "AP Manager", "Guest LAN", "Quarantine", "NAS-ID", "IPv6 Address",
    "WLANs Using It"]


def _wlans_by_interface(c):
    out = defaultdict(list)
    for row in c.wlan_rows or []:
        iface = t.lookup(row, "Interface Name")
        wid = t.lookup(row, "WLAN ID", "WLAN Id")
        profile = (t.lookup(row, "WLAN Profile Name / SSID") or "").split(" / ")[0]
        if iface and wid:
            out[iface].append(f"{wid} {profile}".strip())
    return out


def _interface_rows(c):
    rows = []
    groups = defaultdict(list)
    for group, members in (c.interface_groups or {}).items():
        for m in members:
            groups[m].append(group)
    wlans = _wlans_by_interface(c)
    for i in c.interfaces or []:
        name = i["name"]
        detail = P.parse_interface_detail(c.out(f"show interface detailed {name}"))
        d = detail or {}

        def get(key):
            return NA if detail is None else d.get(key, "")
        rows.append(c.lead() + [
            name, i.get("type", ""), d.get("vlan") or i.get("vlan", ""),
            d.get("ip") or i.get("ip", ""), get("mask"), get("gateway"),
            d.get("port") or i.get("port", ""), get("backup_port"),
            yes_no(c.lag) if (d.get("port") or i.get("port", "")).upper() == "LAG" else "No",
            get("dhcp_primary"), get("dhcp_secondary"), get("dhcp_proxy"), get("acl"),
            _join(groups.get(name, [])) or (d.get("interface_group") or ""),
            yes_no(i.get("ap_manager")), yes_no(d.get("guest_lan") if detail else i.get("guest")),
            yes_no(d.get("quarantine")) if detail else NA, get("nas_id"), get("ipv6"),
            "; ".join(wlans.get(name, [])) if c.wlan_rows is not None else NA])
    return rows


PORT_HEADERS = LEAD + [
    "Port", "Admin", "Link", "Speed (Mbps)", "Duplex", "Media", "LAG Enabled",
    "Neighbour Device", "Neighbour Port", "Neighbour Platform", "Neighbour In Wiremap",
    "Input Errors", "Output Errors", "Input Drops", "Output Drops", "CRC"]


def _known(inventory_data):
    names = set()
    for key, d in (inventory_data.get("devices") or {}).items():
        names.add(normalize_hostname(key))
        if d.get("hostname"):
            names.add(normalize_hostname(d["hostname"]))
    return names


def _port_rows(c, known):
    rows = []
    by_port = {str(n.get("local_port")): n for n in c.cdp or []}
    for p in c.ports or []:
        stats = P.parse_port_stats(c.out(f"show stats port detailed {p['port']}"))
        n = by_port.get(str(p["port"]))

        def stat(key):
            return NA if stats is None else na(stats.get(key))
        rows.append(c.lead() + [
            p["port"], p.get("admin", ""), p.get("link", ""), na(p.get("speed_mbps")),
            p.get("duplex", ""), p.get("media", ""), yes_no(c.lag),
            (n or {}).get("device_id", "") if c.cdp is not None else NA,
            (n or {}).get("remote_port", "") if c.cdp is not None else NA,
            (n or {}).get("platform", "") if c.cdp is not None else NA,
            (yes_no(normalize_hostname(n["device_id"]) in known) if n else "")
            if c.cdp is not None else NA,
            stat("input_errors"), stat("output_errors"), stat("input_drops"),
            stat("output_drops"), stat("crc")])
    return rows


HEALTH_HEADERS = LEAD + [
    "CPU %", "Memory Free %", "Temperature (C)", "Fans", "Power Supplies", "APs Joined",
    "Max APs", "Licensed APs", "Clients Now", "Coredumps Present", "AP Crash Files",
    "Port Errors", "Uptime"]


def _health_row(c):
    info = c.sysinfo or {}
    cpu = (c.cpu or {}).get("current_pct")
    mem = (c.memory or {}).get("free_pct")
    if mem is None and info.get("memory_current") is not None:
        mem = 100 - info["memory_current"]
    errors = None
    for p in c.ports or []:
        stats = P.parse_port_stats(c.out(f"show stats port detailed {p['port']}"))
        for key in ("input_errors", "output_errors"):
            if stats and stats.get(key) is not None:
                errors = (errors or 0) + stats[key]
    dumps = c.coredumps
    crash = c.ap_crash_files
    return c.lead() + [
        na(cpu if cpu is not None else info.get("cpu_current")),
        na(round(mem, 1) if mem is not None else None), na(info.get("temperature_c")),
        info.get("fan_status", NA) if c.sysinfo else NA,
        _join(info.get("power_supplies") or [], "; ") if c.sysinfo else NA,
        na(c.ap_count), na(info.get("max_aps")), na(c.licensed_aps), na(info.get("clients")),
        yes_no(dumps.get("present") if dumps else None),
        NA if crash is None else len(crash), na(errors),
        info.get("uptime", NA) if c.sysinfo else NA]


# ---------------------------------------------------------------------------
# Summary and Collection Errors
# ---------------------------------------------------------------------------

SUMMARY_HEADERS = ["Check", "Severity", "Controllers Affected", "Items Affected", "Item List",
                   "Detail"]
ERROR_HEADERS = LEAD + ["Command", "Error", "Kind"]


def _summary_rows(findings, ctrl_list):
    by_check = OrderedDict()
    for f in sorted(findings, key=lambda f: (checks.RATING_ORDER[f["rating"]], f["check"])):
        by_check.setdefault(f["check"], []).append(f)
    rows = []
    for check, items in by_check.items():
        ctrls = sorted({f["controller"] for f in items})
        listed = []
        for f in items:
            for i in f.get("items") or [f["controller"]]:
                label = i if len(ctrls) == 1 else f"{f['controller']}: {i}"
                if label not in listed:
                    listed.append(label)
        detail = items[0]["description"] if len(items) == 1 else (
            f"{len(items)} instances across {len(ctrls)} controller(s); e.g. "
            f"{items[0]['description']}")
        rows.append([check, items[0]["rating"], len(ctrls), len(listed),
                     format_device_list(listed, limit=20), detail])
    rows.append([""] * len(SUMMARY_HEADERS))
    models = defaultdict(int)
    for c in ctrl_list:
        for m, n in ap_models(c).items():
            models[m] += n
    aps = [c.ap_count for c in ctrl_list if c.ap_count is not None]
    wlan_rows = [r for c in ctrl_list for r in c.wlan_rows or []]
    enabled = sum(1 for r in wlan_rows
                  if (t.lookup(r, "Status") or "").lower().startswith("enable"))
    ssids = {(t.lookup(r, "WLAN Profile Name / SSID") or "").split(" / ")[-1].strip()
             for r in wlan_rows} - {""}
    clients = [(c.sysinfo or {}).get("clients") for c in ctrl_list
               if (c.sysinfo or {}).get("clients") is not None]
    for label, value in (
            ("Controllers", len(ctrl_list)),
            ("APs joined", sum(aps) if aps else NA),
            ("APs by model", _join(f"{m} {n}" for m, n in sorted(models.items())) or NA),
            ("WLANs (enabled / disabled)",
             f"{enabled} / {len(wlan_rows) - enabled}" if wlan_rows else NA),
            ("Unique SSIDs", len(ssids) if wlan_rows else NA),
            ("Clients", sum(clients) if clients else NA)):
        rows.append([label, "", value, "", "", ""])
    return rows


def _error_rows(ctrl_list):
    rows = []
    for c in ctrl_list:
        kinds = command_error_kinds(c.parsed)
        errors = c.parsed.get("command_errors") or {}
        for cmd in c.parsed.get("failed_commands") or []:
            rows.append(c.lead() + [cmd, errors.get(cmd, ""), kinds.get(cmd, "")])
    return rows


def analyze(inventory_data):
    ctrl_list = controllers(inventory_data)
    hw, sw = eox_records(ctrl_list) if ctrl_list else ({}, {})
    life = lifecycle(ctrl_list, hw, sw)
    today = (ctrl_list[0].collected_at if ctrl_list else datetime.now(timezone.utc)).date()
    findings = []
    for c in ctrl_list:
        findings += checks.lifecycle_findings(c, life["controllers"][c.key], today)
        findings += checks.platform_findings(c)
    return {"controllers": ctrl_list, "findings": findings, "lifecycle": life}


def build_tabular(inventory_data, analysis=None):
    analysis = analysis or analyze(inventory_data)
    ctrl_list = analysis["controllers"]
    known = _known(inventory_data)
    sheets = OrderedDict()
    sheets["Summary"] = (SUMMARY_HEADERS, _summary_rows(analysis["findings"], ctrl_list))
    sheets["Controllers"] = (CONTROLLER_HEADERS, [_controller_row(c) for c in ctrl_list])
    sheets["Lifecycle"] = (LIFECYCLE_HEADERS, lifecycle_rows(ctrl_list, analysis["lifecycle"]))
    sheets["Redundancy"] = (REDUNDANCY_HEADERS, [_redundancy_row(c) for c in ctrl_list])
    sheets["Interfaces"] = (INTERFACE_HEADERS, [r for c in ctrl_list for r in _interface_rows(c)])
    sheets["Ports and Uplinks"] = (PORT_HEADERS,
                                   [r for c in ctrl_list for r in _port_rows(c, known)])
    sheets["Health and Capacity"] = (HEALTH_HEADERS, [_health_row(c) for c in ctrl_list])
    errors = _error_rows(ctrl_list)
    if errors:
        sheets["Collection Errors"] = (ERROR_HEADERS, errors)
    return sheets


class WlcReport(BaseReport):
    name = "wlc"
    label = "Cisco WLC"
    description = ("AireOS controller platform, lifecycle, redundancy, interfaces, ports, "
                   "health and assessment checks")
    category = "Compliance & Config"
    required_collectors = [COLLECTOR]
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def can_generate(self, inventory_data):
        return bool(controllers(inventory_data))

    def generate_tabular_data(self, inventory_data):
        return build_tabular(inventory_data)

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        return self._generate_for_format(inventory_data, fmt)
