"""
Device Inventory report -- hostname, IP, platform, version, serial.
Sheets: Devices, Stack Members, Modules / Line Cards, Failed Devices,
and Not Collected when any device was controller-managed or not attempted.
"""
import io
import re
from collections import OrderedDict
from openpyxl import Workbook

from .base import BaseReport
from .xlsx_utils import create_sheet
try:
    from app.device_facts import extract_device_facts, extract_version_details
except ImportError:
    from device_facts import extract_device_facts, extract_version_details
try:
    from app.collectors.device_inventory import (
        _parse_ios_show_module, _parse_show_switch_detail, _usable)
except ImportError:
    from collectors.device_inventory import (
        _parse_ios_show_module, _parse_show_switch_detail, _usable)
try:
    from app.site_mapping import derive_site, naming_flags
except ImportError:
    from site_mapping import derive_site, naming_flags
try:
    from app.failures import (failure_record, REASON_LABELS, SKIP_HINTS,
                              AUTH, REFUSED, TIMEOUT, LEGACY_CRYPTO,
                              NO_TELNET_DRIVER, OTHER)
except ImportError:
    from failures import (failure_record, REASON_LABELS, SKIP_HINTS,
                          AUTH, REFUSED, TIMEOUT, LEGACY_CRYPTO,
                          NO_TELNET_DRIVER, OTHER)


def _normalize_keys(d: dict) -> dict:
    """Lowercase all dict keys for consistent field access."""
    return {k.lower(): v for k, v in d.items()}


# Common PID -> friendly platform description.
# Falls back to raw PID for unknown models.
_PLATFORM_DESCRIPTIONS = {
    # Cisco Catalyst 9000
    "C9200-24P": "Cisco Catalyst 9200 24-Port PoE",
    "C9200-48P": "Cisco Catalyst 9200 48-Port PoE",
    "C9200L-24P": "Cisco Catalyst 9200L 24-Port PoE",
    "C9200L-48P": "Cisco Catalyst 9200L 48-Port PoE",
    "C9300-24T": "Cisco Catalyst 9300 24-Port",
    "C9300-24P": "Cisco Catalyst 9300 24-Port PoE+",
    "C9300-48T": "Cisco Catalyst 9300 48-Port",
    "C9300-48P": "Cisco Catalyst 9300 48-Port PoE+",
    "C9300-48U": "Cisco Catalyst 9300 48-Port UPOE",
    "C9300L-24T": "Cisco Catalyst 9300L 24-Port",
    "C9300L-48T": "Cisco Catalyst 9300L 48-Port",
    "C9300L-48P": "Cisco Catalyst 9300L 48-Port PoE+",
    "C9300X-48HX": "Cisco Catalyst 9300X 48-Port mGig",
    "C9400": "Cisco Catalyst 9400 Series",
    "C9500-40X": "Cisco Catalyst 9500 40-Port 10G",
    "C9500-48Y4C": "Cisco Catalyst 9500 48-Port 25G",
    "C9600": "Cisco Catalyst 9600 Series",
    # Cisco Catalyst Classic
    "WS-C2960X-24": "Cisco Catalyst 2960-X 24-Port",
    "WS-C2960X-48": "Cisco Catalyst 2960-X 48-Port",
    "WS-C2960X-48FPD-L": "Cisco Catalyst 2960-X 48-Port PoE",
    "WS-C2960X-48FPS-L": "Cisco Catalyst 2960-X 48-Port PoE",
    "WS-C2960X-48LPD-L": "Cisco Catalyst 2960-X 48-Port PoE",
    "WS-C2960X-48LPS-L": "Cisco Catalyst 2960-X 48-Port PoE",
    "WS-C2960X-48TD-L": "Cisco Catalyst 2960-X 48-Port",
    "WS-C2960X-48TS-L": "Cisco Catalyst 2960-X 48-Port",
    "WS-C2960X-24PD-L": "Cisco Catalyst 2960-X 24-Port PoE",
    "WS-C2960X-24PS-L": "Cisco Catalyst 2960-X 24-Port PoE",
    "WS-C2960X-24TD-L": "Cisco Catalyst 2960-X 24-Port",
    "WS-C2960X-24TS-L": "Cisco Catalyst 2960-X 24-Port",
    "WS-C2960S-48": "Cisco Catalyst 2960-S 48-Port",
    "WS-C2960S-24": "Cisco Catalyst 2960-S 24-Port",
    "WS-C2960X-48FPD": "Cisco Catalyst 2960-X 48-Port PoE",
    "WS-C2960S-48FPD-L": "Cisco Catalyst 2960-S 48-Port PoE",
    "WS-C2960S-48LPD-L": "Cisco Catalyst 2960-S 48-Port PoE",
    "WS-C3560X-24": "Cisco Catalyst 3560-X 24-Port",
    "WS-C3560X-48": "Cisco Catalyst 3560-X 48-Port",
    "WS-C3750X-24": "Cisco Catalyst 3750-X 24-Port",
    "WS-C3750X-48": "Cisco Catalyst 3750-X 48-Port",
    "WS-C3750-48P": "Cisco Catalyst 3750 48-Port PoE",
    "WS-C3750-48P-S": "Cisco Catalyst 3750 48-Port PoE",
    "WS-C3850-24T": "Cisco Catalyst 3850 24-Port",
    "WS-C3850-48T": "Cisco Catalyst 3850 48-Port",
    "WS-C3850-48P": "Cisco Catalyst 3850 48-Port PoE+",
    "WS-C3850-24P": "Cisco Catalyst 3850 24-Port PoE+",
    "WS-C4500X-16": "Cisco Catalyst 4500-X 16-Port 10G",
    "WS-C4500X-32": "Cisco Catalyst 4500-X 32-Port 10G",
    # Cisco 2960 non-X
    "WS-C2960-48": "Cisco Catalyst 2960 48-Port",
    "WS-C2960-24": "Cisco Catalyst 2960 24-Port",
    "WS-C2960S-48FPS-L": "Cisco Catalyst 2960-S 48-Port PoE",
    "WS-C2960S-24PS-L": "Cisco Catalyst 2960-S 24-Port PoE",
    # Cisco Nexus
    "N5K-C5548UP": "Cisco Nexus 5548 Unified Ports",
    "N5K-C5596UP": "Cisco Nexus 5596 Unified Ports",
    "N5K-C56128P": "Cisco Nexus 56128P",
    "N7K-C7009": "Cisco Nexus 7009",
    "N7K-C7010": "Cisco Nexus 7010",
    "N7K-C7018": "Cisco Nexus 7018",
    "N9K-C9332PQ": "Cisco Nexus 9332PQ",
    "N9K-C9372PX": "Cisco Nexus 9372PX",
    "N9K-C93180YC-EX": "Cisco Nexus 93180YC-EX",
    "N9K-C93108TC-EX": "Cisco Nexus 93108TC-EX",
    "N9K-C9336C-FX2": "Cisco Nexus 9336C-FX2",
    # Cisco Routers / Voice Gateways
    "ISR4331": "Cisco ISR 4331",
    "ISR4351": "Cisco ISR 4351",
    "ISR4431": "Cisco ISR 4431",
    "ISR4451": "Cisco ISR 4451",
    "C1111-8P": "Cisco ISR 1100 8-Port",
    "CISCO2911/K9": "Cisco 2911",
    "Cisco VG310": "Cisco Voice Gateway 310",
    "Cisco VG320": "Cisco Voice Gateway 320",
    "Cisco VG224": "Cisco Voice Gateway 224",
    # Cisco ASR
    "ASR1001-X": "Cisco ASR 1001-X",
    "ASR1002-X": "Cisco ASR 1002-X",
    "ASR1006-X": "Cisco ASR 1006-X",
    # Cisco WAN / XR
    "WS-C2960XR-48FPD-I": "Cisco Catalyst 2960-XR 48-Port PoE",
    "NCS-5501": "Cisco NCS 5501",
    # Arista
    "DCS-7050TX-48": "Arista 7050TX 48-Port",
    "DCS-7050SX-64": "Arista 7050SX 64-Port",
    "DCS-7280SR-48C6": "Arista 7280R 48-Port",
    "DCS-7150S-24": "Arista 7150S 24-Port",
    "DCS-7050CX3-32S": "Arista 7050CX3 32-Port",
}

# Components to skip when falling back to show inventory
_SKIP_INVENTORY_TYPES = {
    "fan", "power supply", "psu", "sfp", "transceiver",
    "sensor", "clk", "usb",
}

# Patterns for models that are chassis/switch PIDs, not real modules.
_CHASSIS_MODEL_RE = re.compile(
    r"^("
    r"WS-C\d|"            # Catalyst 2960/3560/3750/3850/4500
    r"C9[2-6]\d{2}[LX]?-\d|"  # Catalyst 9200/9300/9400/9500/9600
    r"CISCO\d|"           # CISCO871, CISCO881, etc.
    r"ISR\d.*/K9|"        # ISR4331/K9, ISR4451-X/K9
    r"VG[23]\d{2}"        # VG224, VG310, VG320 chassis
    r")", re.IGNORECASE
)

# Patterns for module types/models to exclude.
_SKIP_MODULE_RE = re.compile(
    r"("
    r"stack|"             # stacking modules
    r"PVDM|"             # DSP modules
    r"GBIC|"             # GBICs
    r"built-in|"         # ISR built-in controllers/processors
    r"onboard.*voice|"   # onboard FXS voice interfaces
    r"ISR\d{4}\S*-\d+x\d+GE"  # ISR4331-3x1GE, ISR4451-X-4x1GE built-in ports
    r")", re.IGNORECASE
)


def _is_real_module(model, mod_type):
    """Return True if this module entry is a real line card / network module."""
    if _CHASSIS_MODEL_RE.match(model):
        return False
    if _SKIP_MODULE_RE.search(model) or _SKIP_MODULE_RE.search(mod_type):
        return False
    return True


_MODULE_HEADERS = ["Hostname", "Mgmt IP", "Slot", "Type",
                   "Model", "Serial", "Status", "Ports"]

# show inventory names that point at a show platform slot:
# "module R0", "module 0", "SPA subslot 0/0", "NIM subslot 1/0"
_INV_SLOT_RE = re.compile(r"\b(?:module|subslot)\s+(\S+)\s*$", re.I)
_INV_SWITCH_RE = re.compile(r"^\s*switch\s+(\d+)\s*$", re.I)


def _module_status_sources(parsed, raw=None):
    """({stack member number: state}, {platform slot: state},
    {(switch, module): show module status}).

    Scans collected before the status tables were parsed still hold the raw
    show module and show switch detail output, so status is read from there
    when the parsed data has none.
    """
    raw = raw or {}
    members = parsed.get("stack_members", []) or []
    if not any(_normalize_keys(m).get("state") for m in members):
        members = _parse_show_switch_detail(_usable(raw.get("show switch detail")))
    stack = {}
    for member in members:
        m = _normalize_keys(member)
        num = str(m.get("switch") or m.get("member") or "")
        state = m.get("state") or m.get("status") or ""
        if num and state:
            stack[num] = state
    slots = {str(s.get("slot", "")): s.get("state", "")
             for s in parsed.get("platform_slots", []) or []
             if s.get("slot") and s.get("state")}
    _, module_status = _parse_ios_show_module(_usable(raw.get("show module")))
    return stack, slots, module_status


def _module_status(m, slot, slot_state, module_status):
    if m.get("status"):
        return m["status"]
    sw = str(m.get("switch_number") or "")
    value = module_status.get((sw, slot))
    if value is None and not sw:
        hits = [v for (s, n), v in module_status.items() if n == slot]
        value = hits[0] if len(hits) == 1 else None
    return value or slot_state.get(slot, "")


def _module_rows(inventory_data):
    """Modules sheet rows: show module when the platform has it, otherwise
    the non-chassis show inventory entries. Status comes from the platform's
    own status column, the stack member state, or the show platform slot
    state, whichever the device reports."""
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        inv = device.get("collector_data", {}).get("device_inventory", {})
        parsed = inv.get("parsed", {})
        raw = inv.get("raw") if isinstance(inv.get("raw"), dict) else {}
        modules = parsed.get("modules", [])
        mgmt_ip = device.get("mgmt_ip", "")
        stack_state, slot_state, module_status = _module_status_sources(
            parsed, raw)

        if modules:
            for mod in modules:
                m = _normalize_keys(mod)
                model = m.get("model") or ""
                # ntc's IOS template names these cardtype and port
                mod_type = (m.get("type") or m.get("module_type")
                            or m.get("cardtype") or "")
                if not _is_real_module(model, mod_type):
                    continue
                slot = str(m.get("module") or m.get("slot") or "")
                rows.append([
                    hostname,
                    mgmt_ip,
                    slot,
                    mod_type,
                    model,
                    m.get("serial") or m.get("serialnum") or "",
                    _module_status(m, slot, slot_state,
                                   module_status),
                    m.get("ports") or m.get("port") or "",
                ])
        else:
            for item in parsed.get("inventory", []):
                it = _normalize_keys(item)
                descr = (it.get("descr")
                         or it.get("description") or "").lower()
                name = (it.get("name") or "").lower()
                if any(skip in descr or skip in name
                       for skip in _SKIP_INVENTORY_TYPES):
                    continue
                if "chassis" in name:
                    continue
                raw_name = it.get("name") or ""
                status = ""
                sw = _INV_SWITCH_RE.match(raw_name)
                if sw:
                    status = stack_state.get(sw.group(1), "")
                else:
                    sl = _INV_SLOT_RE.search(raw_name)
                    if sl:
                        status = slot_state.get(sl.group(1), "")
                rows.append([
                    hostname,
                    mgmt_ip,
                    raw_name,
                    it.get("descr") or it.get("description") or "",
                    it.get("pid") or "",
                    it.get("sn") or it.get("serial_number") or "",
                    status,
                    "",
                ])
    return rows


def _get_platform_description(pid: str) -> str:
    """Look up friendly platform name from PID. Falls back to empty string."""
    if not pid:
        return ""
    if pid in _PLATFORM_DESCRIPTIONS:
        return _PLATFORM_DESCRIPTIONS[pid]
    # Try prefix match (strip trailing -S, -L suffixes)
    base = pid.rstrip("-").rsplit("-", 1)[0] if "-" in pid else pid
    if base in _PLATFORM_DESCRIPTIONS:
        return _PLATFORM_DESCRIPTIONS[base]
    # Try without /K9 suffix
    base = pid.split("/")[0]
    if base in _PLATFORM_DESCRIPTIONS:
        return _PLATFORM_DESCRIPTIONS[base]
    return ""


def _parsed(device, collector):
    data = (device.get("collector_data") or {}).get(collector) or {}
    return data.get("parsed") or {}


def _pair_info(parsed):
    """Domain and per-member interconnect/DAD ports of an SVL or VSS pair."""
    svl = parsed.get("stackwise_virtual")
    if svl:
        links, dad = {}, {}
        for link in svl.get("links", []):
            links.setdefault(str(link.get("switch")), []).append(link.get("port"))
        for port in svl.get("dad_ports", []):
            dad.setdefault(str(port.get("switch")), []).append(port.get("port"))
        return {"type": "stackwise-virtual", "domain": svl.get("domain", ""),
                "links": links, "dad": dad}
    vss = parsed.get("vss")
    if vss:
        links = {}
        for port in vss.get("links", []):
            # VSS ports are named switch/slot/port: Te1/5/4 is on chassis 1.
            m = re.search(r"(\d+)/", port)
            if m:
                links.setdefault(m.group(1), []).append(port)
        return {"type": "vss", "domain": vss.get("domain", ""),
                "links": links, "dad": {}}
    return None


def _redundancy(device):
    """How this device is made redundant: standalone, stack, SVL, VSS, vPC,
    an HSRP/GLBP/VRRP pair, or a firewall HA pair. Blank when nothing was
    collected."""
    inv = _parsed(device, "device_inventory")
    modes = []
    if inv.get("stackwise_virtual"):
        modes.append("stackwise-virtual")
    elif inv.get("vss"):
        modes.append("vss")
    elif len(inv.get("stack_members") or []) > 1:
        modes.append("stack")
    if inv.get("vpc"):
        modes.append("vpc")

    hsrp = _parsed(device, "hsrp")
    for proto, states in (("HSRP", ("active", "standby")),
                          ("GLBP", ("active", "standby", "listen")),
                          ("VRRP", ("master", "backup"))):
        if any((e.get("protocol") or "HSRP") == proto
               and str(e.get("state", "")).lower() in states
               for e in hsrp.get("entries") or []):
            modes.append(f"{proto.lower()}-pair")
    if device.get("ha_state") and not modes:
        modes.append("ha-pair")

    if modes:
        return "+".join(modes)
    if device.get("login_succeeded") and inv and not inv.get("collector_failed"):
        return "standalone"
    return ""


_SOURCE_LABELS = {
    "snmp": "snmp",
    "cdp": "cdp",
    "lldp": "lldp",
    "routing_adjacency": "routing",
    "next_hop": "next-hop",
    "hsrp_vrrp": "fhrp",
}


def _neighbour_protocols(hostname, device, inventory_data):
    """Which of CDP/LLDP the devices that saw this one heard it on."""
    devices = inventory_data.get("devices", {})
    name = hostname.lower()
    ip = device.get("mgmt_ip")
    found = set()
    for ev in device.get("evidence") or []:
        if ev.get("source") != "cdp_lldp":
            continue
        seer = devices.get(ev.get("seen_from")) or {}
        for n in _parsed(seer, "cdp_lldp").get("neighbors") or []:
            remote = str(n.get("remote_device") or "").lower()
            if (remote and (remote == name or remote.split(".")[0] == name
                            or remote.split("(")[0] == name)) \
                    or (ip and n.get("remote_ip") == ip):
                found.update(str(p).lower() for p in n.get("protocols") or [])
    return found


def _discovered_via(hostname, device, inventory_data):
    """seed, target-list, cdp, lldp, snmp, ... -- how the device was found."""
    # Newer scans record this per device; older ones are inferred below.
    if device.get("discovered_via"):
        return device["discovered_via"]
    source = device.get("discovery_source") or ""
    ip = device.get("mgmt_ip")
    if source in ("", "login"):
        params = inventory_data.get("params") or {}
        if ip and ip in (params.get("target_ips") or []):
            return "target-list"
        if ip and ip == inventory_data.get("seed_ip"):
            return "seed"
        return source
    if source == "cdp_lldp":
        protocols = _neighbour_protocols(hostname, device, inventory_data)
        return "+".join(sorted(protocols)) if protocols else "cdp/lldp"
    return _SOURCE_LABELS.get(source, source)


def _failure_reason(entry):
    """Short reason from a scan_summary failure.

    Newer scans store a dict with a classified reason; older ones a plain
    error string, which is classified here.
    """
    if isinstance(entry, dict):
        if entry.get("reason"):
            return str(entry["reason"])
        entry = entry.get("message") or ""
    text = str(entry or "").lower()
    if not text:
        return "error"
    if "auth" in text or "permission denied" in text or "password" in text:
        return "auth_failed"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "refused" in text:
        return "connection_refused"
    if "unreachable" in text or "no route" in text:
        return "unreachable"
    return "error"


def _collection_status(device, inventory_data):
    """collected, partial:<collectors>, failed:<reason> or skipped:<reason>.

    partial lists only collectors that lost data they should have had. A
    command the platform does not support (show ip vrf on a LAN Base switch)
    is not applicable and leaves the device collected.
    """
    try:
        from app.collectors.base import collector_has_failures
    except ImportError:
        from collectors.base import collector_has_failures

    summary = inventory_data.get("scan_summary") or {}
    ip = device.get("mgmt_ip")

    if device.get("login_succeeded"):
        failed = sorted(
            name for name, data in (device.get("collector_data") or {}).items()
            if collector_has_failures((data or {}).get("parsed")))
        return "partial:" + ",".join(failed) if failed else "collected"

    skipped = (summary.get("skipped") or {}).get(ip) if ip else None
    if skipped or device.get("managed_by"):
        reason = (skipped.get("reason") if isinstance(skipped, dict)
                  else skipped) or "controller_managed"
        return f"skipped:{reason}"

    failed = (summary.get("failed") or {}).get(ip) if ip else None
    if failed:
        return f"failed:{_failure_reason(failed)}"
    if device.get("login_error"):
        return f"failed:{_failure_reason(device['login_error'])}"
    if not ip:
        return "skipped:no_mgmt_ip"
    if ip in (summary.get("out_of_scope") or []):
        return "skipped:out_of_scope"
    return "skipped:not_crawled"


class DeviceInventoryReport(BaseReport):
    name = "device_inventory"
    label = "Device Inventory"
    description = "Device details: hostname, IP, platform, software version, serial numbers"
    category = "Discovery & Topology"
    required_collectors = ["device_inventory"]
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        if fmt == "xlsx":
            wb = Workbook()
            wb.remove(wb.active)

            self._build_devices_sheet(wb, inventory_data)
            self._build_stack_sheet(wb, inventory_data)
            self._build_modules_sheet(wb, inventory_data)
            self._build_licenses_sheet(wb, inventory_data)
            build_failed_devices_sheets(wb, inventory_data)
            build_targets_sheet(wb, inventory_data)
            sources = self._extract_merge_sources(inventory_data)
            if sources:
                create_sheet(wb, "Merge Sources", *sources)
            conflicts = self._extract_merge_conflicts(inventory_data)
            if conflicts:
                create_sheet(wb, "Merge Conflicts", *conflicts)

            buf = io.BytesIO()
            wb.save(buf)
            return buf.getvalue()

        return self._generate_for_format(inventory_data, fmt)

    def generate_tabular_data(self, inventory_data):
        result = OrderedDict()
        result["Devices"] = self._extract_devices_data(inventory_data)
        result["Stack Members"] = self._extract_stack_data(inventory_data)
        result["Modules"] = self._extract_modules_data(inventory_data)
        licenses = self._extract_licenses_data(inventory_data)
        if licenses[1]:
            result["Licenses"] = licenses
        result.update(failed_devices_tabular(inventory_data))
        targets = extract_targets_data(inventory_data)
        if targets:
            result["Targets"] = targets
        sources = self._extract_merge_sources(inventory_data)
        if sources:
            result["Merge Sources"] = sources
        conflicts = self._extract_merge_conflicts(inventory_data)
        if conflicts:
            result["Merge Conflicts"] = conflicts
        return result

    def _extract_merge_sources(self, inventory_data):
        """Where a merged inventory came from, and what it had to choose between.

        Only present on merged scans -- a merge that silently picks winners
        should still be able to show what it set aside.
        """
        merged_from = inventory_data.get("merged_from") or []
        if not merged_from:
            return None

        headers = ["Source Scan", "File", "Seed IP", "Scanned", "Devices",
                   "Notes"]
        rows = []
        conflicts = inventory_data.get("merge_conflicts") or []
        for source in merged_from:
            source_id = source.get("discovery_id", "")
            kept = sum(1 for c in conflicts if c.get("kept_from") == source_id)
            dropped = sum(1 for c in conflicts
                          if c.get("discarded_from") == source_id)
            notes = []
            if kept:
                notes.append(f"{kept} device(s) taken from here on conflict")
            if dropped:
                notes.append(f"{dropped} superseded by another scan")
            rows.append([
                source_id,
                source.get("filename", ""),
                source.get("seed_ip", ""),
                (source.get("timestamp", "") or "").split("T")[0],
                source.get("device_count", ""),
                "; ".join(notes),
            ])

        return headers, rows

    def _extract_merge_conflicts(self, inventory_data):
        """Devices that appeared in more than one scan, and which won."""
        conflicts = inventory_data.get("merge_conflicts") or []
        if not conflicts:
            return None

        headers = ["Device", "Also Seen As", "Kept From", "Superseded",
                   "Why"]
        rows = [[
            c.get("hostname", ""),
            c.get("also_named", ""),
            c.get("kept_from", ""),
            c.get("discarded_from", ""),
            c.get("reason", ""),
        ] for c in conflicts]
        return headers, rows

    def _extract_devices_data(self, inventory_data):
        headers = [
            "Hostname", "Mgmt IP", "Device Type", "Category",
            "Platform", "Platform Description", "Software Version",
            "Serial Number", "Discovery Source", "Logged In", "Login Error",
            "Redundancy", "HA State", "Uptime", "Last Reload Reason",
            "Image", "License", "Discovered Via", "Collection Status",
            "Site", "Site Naming",
        ]
        devices = inventory_data.get("devices", {})
        site_flags = naming_flags(list(devices))
        # Scans from before login accounts were recorded have none to show.
        login_users = any(d.get("login_user") for d in devices.values())
        if login_users:
            headers.append("Login User")
        # Only meaningful on a merged inventory, so the column is not there
        # to be ignored on every ordinary scan.
        merged = bool(inventory_data.get("merged_from"))
        if merged:
            headers.append("Source Scan")
        rows = []
        for hostname, device in sorted(
            inventory_data.get("devices", {}).items()
        ):
            inv_data = (device.get("collector_data", {})
                        .get("device_inventory", {}))
            parsed = inv_data.get("parsed", {})

            facts = extract_device_facts(parsed)
            details = extract_version_details(parsed)
            sw_version = facts["software_version"]
            serial = facts["serial"]
            platform = device.get("platform", "") or facts["model"]
            if isinstance(platform, list):
                platform = ", ".join(str(x) for x in platform)
            # A stack reports one model per member; describe the first.
            first_pid = platform.split(",")[0].strip() if platform else ""
            description = (_get_platform_description(first_pid)
                           or details["platform_description"])

            # Provenance: a device seen only in a neighbour table has no
            # serial or version, and must not read as fully collected.
            row = [
                hostname,
                device.get("mgmt_ip", ""),
                device.get("device_type", ""),
                device.get("device_category", ""),
                platform,
                description,
                sw_version,
                serial,
                device.get("discovery_source", "") or "",
                "Yes" if device.get("login_succeeded") else "No",
                device.get("login_error", "") or "",
                _redundancy(device),
                device.get("ha_state", "") or "",
                details["uptime"],
                details["reload_reason"],
                details["image"],
                details["license"],
                _discovered_via(hostname, device, inventory_data),
                _collection_status(device, inventory_data),
                derive_site(hostname),
                site_flags.get(hostname, ""),
            ]
            if login_users:
                row.append(device.get("login_user", "") or "")
            if merged:
                row.append(device.get("source_scan", "") or "")
            rows.append(row)

        return (headers, rows)

    def _extract_stack_data(self, inventory_data):
        headers = [
            "Hostname", "Mgmt IP", "Member #", "Role",
            "Model", "Serial", "MAC", "Priority", "State",
            "Stack Type", "Domain", "Interconnect Ports", "DAD Ports",
        ]
        rows = []
        for hostname, device in sorted(
            inventory_data.get("devices", {}).items()
        ):
            inv_data = (device.get("collector_data", {})
                        .get("device_inventory", {}))
            parsed = inv_data.get("parsed", {})
            stack = parsed.get("stack_members", [])
            if not stack:
                continue

            pair = _pair_info(parsed)
            mgmt_ip = device.get("mgmt_ip", "")
            for member in stack:
                m = _normalize_keys(member)
                num = str(m.get("switch") or m.get("member") or "")
                stack_type = m.get("stack_type") or (
                    pair["type"] if pair else "stack")
                rows.append([
                    hostname,
                    mgmt_ip,
                    num,
                    m.get("role") or "",
                    m.get("model") or m.get("hw_ver") or "",
                    m.get("serial") or m.get("serialnum") or "",
                    m.get("mac_address") or m.get("mac") or "",
                    m.get("priority") or "",
                    m.get("state") or m.get("status") or "",
                    stack_type,
                    pair["domain"] if pair else "",
                    ", ".join(pair["links"].get(num, [])) if pair else "",
                    ", ".join(pair["dad"].get(num, [])) if pair else "",
                ])

        return (headers, rows)

    def _extract_modules_data(self, inventory_data):
        return (list(_MODULE_HEADERS), _module_rows(inventory_data))

    def _extract_licenses_data(self, inventory_data):
        """One row per licence; a device with Smart Licensing or call-home
        state but no licence rows still gets a row so its status shows."""
        headers = [
            "Hostname", "Mgmt IP", "License", "Entitlement", "Count", "Status",
            "Smart Licensing", "Registration / Status", "Authorization",
            "Transport", "Last Usage ACK", "Call-Home", "Call-Home Transport",
        ]
        rows = []
        for hostname, device in sorted(
            inventory_data.get("devices", {}).items()
        ):
            parsed = _parsed(device, "device_inventory")
            licenses = parsed.get("licenses") or []
            smart = parsed.get("smart_licensing") or {}
            call_home = parsed.get("call_home") or {}
            if not (licenses or smart or call_home):
                continue
            if call_home:
                ch_state = "enabled" if call_home.get("enabled") else "disabled"
            else:
                ch_state = ""
            shared = [
                smart.get("mode", ""),
                smart.get("registration") or smart.get("status", ""),
                smart.get("authorization", ""),
                smart.get("transport", ""),
                smart.get("last_ack", ""),
                ch_state,
                call_home.get("transport", ""),
            ]
            mgmt_ip = device.get("mgmt_ip", "")
            for lic in licenses or [{}]:
                rows.append([
                    hostname, mgmt_ip,
                    lic.get("name", ""), lic.get("entitlement", ""),
                    lic.get("count", ""), lic.get("status", ""),
                ] + shared)
        return headers, rows

    def _build_licenses_sheet(self, wb, inventory_data):
        headers, rows = self._extract_licenses_data(inventory_data)
        # Older scans and non-Cisco networks have no licensing data; an
        # empty sheet there would read as "nothing licensed".
        if rows:
            create_sheet(wb, "Licenses", headers, rows)

    def _build_devices_sheet(self, wb, inventory_data):
        headers, rows = self._extract_devices_data(inventory_data)
        create_sheet(wb, "Devices", headers, rows)

    def _build_stack_sheet(self, wb, inventory_data):
        headers, rows = self._extract_stack_data(inventory_data)
        create_sheet(wb, "Stack Members", headers, rows)

    def _build_modules_sheet(self, wb, inventory_data):
        create_sheet(wb, "Modules", list(_MODULE_HEADERS),
                     _module_rows(inventory_data))



# --- Failed and controller-managed devices ----------------------------------
# Kept apart from the Devices sheet: these explain coverage gaps -- which
# hosts were not collected and why -- without opening the inventory JSON.

def _neighbour_record(inventory_data, ip, hostname=None):
    """The device record a failed or skipped IP is known by, if any."""
    devices = inventory_data.get("devices", {}) or {}
    if hostname and hostname in devices:
        return devices[hostname]
    for dev in devices.values():
        if dev.get("mgmt_ip") == ip:
            return dev
    return {}


def _ip_sort_key(ip):
    parts = str(ip).split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, str(ip))


# Failure categories, in the order the Failed Devices sheet lists them.
# The reader is usually someone fixing access, so each category maps to one
# kind of fix: credentials, vty ACL, reachability, SSH keys, DNS.
CATEGORY_LABELS = {
    AUTH: "Auth rejected",
    REFUSED: "Port refused",
    TIMEOUT: "No response",
    LEGACY_CRYPTO: "Legacy crypto",
    NO_TELNET_DRIVER: "No telnet driver",
    "dns": "DNS failure",
    OTHER: "Other",
}
_CATEGORY_ORDER = {label: i for i, label in enumerate(CATEGORY_LABELS.values())}

CONTROLLER_MANAGED = "Controller-managed"
NOT_ATTEMPTED = "Not attempted"
_NOT_COLLECTED_ORDER = {CONTROLLER_MANAGED: 0, NOT_ATTEMPTED: 1}

DNS_HINT = ("Target name did not resolve from the wiremap host; check the "
            "spelling or DNS, or list the management IP instead")
NOT_ATTEMPTED_HINT = ("Discovered but never logged into: the scan ended "
                      "(stopped, or a device or time limit was reached) "
                      "before this host was reached")


def _format_attempt(attempt, show_credential=True):
    """One attempt as 'ssh/22 (cisco_ios): Connection refused, 12ms'.
    With several credential sets offered, which one was tried is added."""
    proto = attempt.get("protocol") or ""
    port = attempt.get("port")
    where = f"{proto}/{port}" if port else proto
    if attempt.get("device_type"):
        where += f" ({attempt['device_type']})"
    reason = attempt.get("reason")
    what = (REASON_LABELS.get(reason) if reason else None) \
        or attempt.get("exception_class") or attempt.get("message") or "failed"
    if show_credential and attempt.get("credential_set"):
        where += f" as {attempt.get('username') or '?'} (set {attempt['credential_set']})"
    elapsed = attempt.get("elapsed_ms")
    took = f", {elapsed}ms" if elapsed else ""
    return f"{where.strip()}: {what}{took}".strip()


def _likely_cause(record):
    """The hint, prefixed for an auth failure that tried several sets."""
    if record["reason"] == AUTH:
        sets = {a.get("credential_set") for a in record["attempts"]
                if a.get("credential_set")}
        if len(sets) > 1:
            return (f"All {len(sets)} credential sets were rejected; "
                    f"{record['hint']}")
    return record["hint"]


def _failed_sort_key(row):
    return (_CATEGORY_ORDER.get(row[0], len(_CATEGORY_ORDER)),
            _ip_sort_key(row[1]) if row[1] else (2, str(row[2])))


def extract_failed_devices_data(inventory_data):
    """(headers, rows) for hosts that could not be logged into, plus
    target-list names that never resolved. Sorted by category then IP."""
    summary = inventory_data.get("scan_summary") or {}
    headers = ["Category", "Mgmt IP", "Hostname", "Platform",
               "Likely cause", "Attempts", "Error"]
    # One set offered: naming it on every attempt is noise.
    several_sets = len((inventory_data.get("params") or {})
                       .get("credential_usernames") or []) > 1
    rows = []
    for ip, value in (summary.get("failed") or {}).items():
        record = failure_record(value)
        device = _neighbour_record(inventory_data, ip, record["hostname"])
        rows.append([
            CATEGORY_LABELS.get(record["reason"], CATEGORY_LABELS[OTHER]),
            ip,
            record["hostname"] or device.get("hostname") or "",
            device.get("platform") or "",
            _likely_cause(record),
            "; ".join(_format_attempt(a, several_sets or len(
                {x.get("credential_set") for x in record["attempts"]}) > 1)
                      for a in record["attempts"]),
            record["message"],
        ])
    for entry in summary.get("unresolved") or []:
        if isinstance(entry, dict):
            name, error = entry.get("input") or "", entry.get("error") or ""
        else:
            name, error = str(entry), ""
        rows.append([CATEGORY_LABELS["dns"], "", name, "", DNS_HINT, "", error])
    rows.sort(key=_failed_sort_key)
    return headers, rows


def _not_attempted_entries(summary):
    """(ip, entry dict) pairs from scan_summary['not_attempted'], which may
    be a map keyed by IP or a list of IPs or records."""
    value = summary.get("not_attempted") or {}
    if isinstance(value, dict):
        items = value.items()
    else:
        items = []
        for entry in value:
            if isinstance(entry, dict):
                items.append((entry.get("ip") or entry.get("mgmt_ip") or "", entry))
            else:
                items.append((str(entry), {}))
    out = []
    for ip, entry in items:
        if not isinstance(entry, dict):
            entry = {"reason": str(entry)} if entry else {}
        out.append((ip, entry))
    return out


def extract_skipped_devices_data(inventory_data):
    """(headers, rows) for hosts deliberately or never logged into --
    controller-managed and not-attempted. These are coverage gaps, not
    failures, so they get their own sheet. None when there are none, so
    ordinary scans get no empty sheet."""
    summary = inventory_data.get("scan_summary") or {}
    headers = ["Category", "Mgmt IP", "Hostname", "Platform", "Managed By",
               "Likely cause"]
    rows = []
    for ip, entry in (summary.get("skipped") or {}).items():
        entry = entry if isinstance(entry, dict) else {"reason": entry}
        device = _neighbour_record(inventory_data, ip, entry.get("hostname"))
        managed_by = entry.get("managed_by") or device.get("managed_by") or ""
        rows.append([
            CONTROLLER_MANAGED,
            ip,
            entry.get("hostname") or device.get("hostname") or "",
            entry.get("platform") or device.get("platform") or "",
            _MANAGED_BY_LABELS.get(managed_by, managed_by),
            SKIP_HINTS.get(managed_by, ""),
        ])
    for ip, entry in _not_attempted_entries(summary):
        device = _neighbour_record(inventory_data, ip, entry.get("hostname"))
        reason = entry.get("hint") or entry.get("reason") or ""
        rows.append([
            NOT_ATTEMPTED,
            ip,
            entry.get("hostname") or device.get("hostname") or "",
            entry.get("platform") or device.get("platform") or "",
            "",
            f"{NOT_ATTEMPTED_HINT} ({reason})" if reason else NOT_ATTEMPTED_HINT,
        ])
    if not rows:
        return None
    rows.sort(key=lambda r: (_NOT_COLLECTED_ORDER.get(r[0], 9), _ip_sort_key(r[1])))
    return headers, rows


_MANAGED_BY_LABELS = {"aci": "ACI (APIC)", "ucsm": "UCS Manager"}

NOT_COLLECTED_SHEET = "Not Collected"


def failed_devices_tabular(inventory_data):
    """OrderedDict of the Failed Devices sheet and, when any host was
    skipped or not attempted, the Not Collected sheet."""
    sheets = OrderedDict()
    sheets["Failed Devices"] = extract_failed_devices_data(inventory_data)
    skipped = extract_skipped_devices_data(inventory_data)
    if skipped:
        sheets[NOT_COLLECTED_SHEET] = skipped
    return sheets


def build_failed_devices_sheets(wb, inventory_data):
    """Append the Failed Devices sheet, and a Not Collected sheet for
    controller-managed and not-attempted hosts."""
    for title, (headers, rows) in failed_devices_tabular(inventory_data).items():
        create_sheet(wb, title, headers, rows)


# --- Targets ----------------------------------------------------------------
# What became of each host in a targeted scan's list, so a target that was
# folded into another device or never reached still has a row.

_TARGET_OUTCOME_LABELS = {
    "collected": "Collected",
    "merged_into": "Merged into another device",
    "failed": "Failed",
    "skipped": "Skipped",
    "unresolved": "Unresolved",
    "not_attempted": "Not attempted",
}


def extract_targets_data(inventory_data):
    """(headers, rows) for scan_summary targets, or None for a scan
    without a target list or from before targets carried an outcome."""
    targets = (inventory_data.get("scan_summary") or {}).get("targets") or []
    if not any(t.get("outcome") for t in targets):
        return None
    headers = ["Target", "Resolved IP", "Outcome", "Hostname", "Reason"]
    rows = []
    for t in targets:
        reason = t.get("reason") or ""
        if t.get("outcome") == "failed":
            reason = REASON_LABELS.get(reason, reason)
        rows.append([
            t.get("input") or "",
            t.get("resolved_ip") or "",
            _TARGET_OUTCOME_LABELS.get(t.get("outcome"), t.get("outcome") or ""),
            t.get("hostname") or "",
            reason,
        ])
    return headers, rows


def build_targets_sheet(wb, inventory_data):
    data = extract_targets_data(inventory_data)
    if data:
        create_sheet(wb, "Targets", *data)
