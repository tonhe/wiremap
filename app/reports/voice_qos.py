"""
Voice and QoS report: whether voice traffic is classified, marked and
prioritised end to end, from the qos collector's counters joined with
neighbours, switchports and interface counters.

Severity follows the findings rubric. Checks that show voice is not being
protected (QoS off, untrusted voice ports, no priority queue on an uplink or
WAN circuit, EF mapped away from the priority queue) are Critical;
priority-queue drops, lost EF marking and policy drift are Warning; the rest
are Info.

Every drop count is shown next to the window it accumulated over: counters
since they were last cleared, or since boot, which on a router can be most of
a year.
"""
import re
from collections import OrderedDict, defaultdict
from ipaddress import IPv4Address, IPv4Network, AddressValueError

from .base import BaseReport
from .internet_edge import _device_addresses, _is_public_ip
from .findings import (
    CRITICAL, WARNING, INFO, AGGREGATE_HEADERS, DETAIL_SHEET,
    make_finding, overfire_check, aggregate_rows, summary_count_rows,
)

try:
    from app.collectors.qos import (
        DEFAULT_DSCP_OUTPUT_Q, FAMILY_CLASSIC, FAMILY_UNKNOWN, FAMILY_ROUTER,
        FAMILY_ROUTER_QFP, SWITCH_FAMILIES, TRUSTS_BY_DEFAULT, QUEUE_STATS_CAP,
        map_queue,
    )
    from app.collectors.base import command_error_kinds
    from app.collectors.errors import NOT_APPLICABLE
    from app.device_role import is_voice_gateway_model
    from app.ifname import canonical_ifname
except ImportError:
    from collectors.qos import (
        DEFAULT_DSCP_OUTPUT_Q, FAMILY_CLASSIC, FAMILY_UNKNOWN, FAMILY_ROUTER,
        FAMILY_ROUTER_QFP, SWITCH_FAMILIES, TRUSTS_BY_DEFAULT, QUEUE_STATS_CAP,
        map_queue,
    )
    from collectors.base import command_error_kinds
    from collectors.errors import NOT_APPLICABLE
    from device_role import is_voice_gateway_model
    from ifname import canonical_ifname

COLLECTOR = "qos"
EF = "46"
CS3 = "24"
VOICE_CLASSES = ("phone", "vg", "ap")
ROUTER_FAMILIES = (FAMILY_ROUTER, FAMILY_ROUTER_QFP)
# Counters older than this make a drop count close to meaningless as a rate.
STALE_COUNTER_WEEKS = 12

_NOT_WAN_RE = re.compile(
    r"^(?:Loopback|Null|NVI|Vlan|VirtualPortGroup|Embedded-Service|"
    r"BDI|Virtual-Access|Virtual-Template|Dialer|Tunnel)", re.I)
_MGMT_RE = re.compile(r"^GigabitEthernet0$|^Management|^mgmt", re.I)
# A router interface with no CDP neighbour is only treated as a WAN circuit
# with evidence: a public address, a BGP peer on its subnet, ip nat outside,
# or a description that names a circuit.
_WAN_DESC_RE = re.compile(
    r"(?<![a-z])(?:wan|mpls|inet|internet|isp|dci|megaport)(?![a-z])", re.I)
_NAT_OUTSIDE_RE = re.compile(r"^\s+ip\s+nat\s+outside\b")


def _parent(name):
    return name.split(".")[0]


def _nat_outside_interfaces(device):
    names = set()
    config = _parsed(device, "config").get("config")
    current = None
    for line in (config if isinstance(config, str) else "").splitlines():
        if line.startswith("interface "):
            current = canonical_ifname(line.split(None, 1)[1].strip())
        elif line and not line[0].isspace():
            current = None
        elif current and _NAT_OUTSIDE_RE.match(line):
            names.add(current)
    stats = _parsed(device, "edge_services").get("nat_statistics") or {}
    names.update(canonical_ifname(n) for n in stats.get("outside_interfaces") or [])
    return names


def _wan_evidence(device, counters):
    """{interface: reason} for interfaces that look like a WAN circuit."""
    evidence = {}
    peers = []
    for p in _parsed(device, "routing_detail").get("bgp_summary", []):
        try:
            peers.append(IPv4Address(str(p.get("neighbor", "")).strip()))
        except (AddressValueError, ValueError):
            pass
    for addr in _device_addresses(device):
        name = canonical_ifname(addr["interface"])
        if _is_public_ip(addr["ip"]):
            evidence.setdefault(name, f"public address {addr['ip']}")
            continue
        try:
            net = IPv4Network(f"{addr['ip']}/{addr['prefix']}", strict=False)
        except (AddressValueError, ValueError):
            continue
        if net.prefixlen < 16:
            continue
        peer = next((p for p in peers if p in net and str(p) != addr["ip"]), None)
        if peer:
            evidence.setdefault(name, f"BGP peer {peer}")
    for name in _nat_outside_interfaces(device):
        evidence.setdefault(name, "ip nat outside")
    for name, row in counters.items():
        m = _WAN_DESC_RE.search(row.get("description") or "")
        if m:
            evidence.setdefault(name, f"description ({m.group(0)})")
    return evidence


def _parsed(device, name):
    return (device.get("collector_data", {}).get(name) or {}).get("parsed") or {}


def _usable(qos):
    return bool(qos) and not qos.get("not_applicable") and not qos.get("collector_failed")


def _uptime_weeks(uptime):
    if not uptime:
        return None
    weeks = 0.0
    for num, unit in re.findall(r"(\d+)\s+(year|week|day)", uptime):
        n = int(num)
        weeks += n * 52 if unit == "year" else n if unit == "week" else n / 7
    return weeks


def _class_drops(cls):
    """Drops for one class. IOS-XE can report a priority class's drops both
    as b/w exceed drops and in its queue line; they are the same packets."""
    values = [cls.get(k) for k in ("priority_drops", "drops") if cls.get(k) is not None]
    return max(values) if values else None


class Device:
    """One device's QoS data with the joins the sheets need."""

    def __init__(self, hostname, device):
        self.hostname = hostname
        self.qos = _parsed(device, COLLECTOR)
        inv = _parsed(device, "device_inventory")
        details = inv.get("version_details") or {}
        self.model = (details.get("model") or device.get("model")
                      or device.get("platform") or "")
        self.uptime = details.get("uptime") or ""
        glob = self.qos.get("qos_global") or {}
        self.family = glob.get("platform_family") or FAMILY_UNKNOWN
        self.mls = glob.get("mls_qos_enabled")
        self.interfaces = {i["interface"]: i for i in self.qos.get("interfaces", [])}
        self.counters = {canonical_ifname(r.get("interface")): r
                         for r in _parsed(device, "interface_counters").get("interfaces", [])}
        self.queues = defaultdict(list)
        for q in self.qos.get("queues", []):
            self.queues[q["interface"]].append(q)
        self.dscp = {(d["interface"], d["direction"]): d.get("dscp") or {}
                     for d in self.qos.get("dscp_counters", [])}
        self.policies = defaultdict(list)
        for p in self.qos.get("policies", []):
            self.policies[(p["interface"], p["direction"])].append(p)
        self.wan_evidence = (_wan_evidence(device, self.counters)
                             if self.family in ROUTER_FAMILIES else {})
        es = _parsed(device, "edge_services")
        self.acl_names = ({a.get("name") for a in es.get("access_lists", [])}
                          if "access_lists" in es else None)

    @property
    def is_switch(self):
        if self.family in SWITCH_FAMILIES:
            return True
        return self.family == FAMILY_UNKNOWN and self.mls is not None

    @property
    def is_router(self):
        return self.family in ROUTER_FAMILIES

    @property
    def is_voice_gateway(self):
        return is_voice_gateway_model(self.model)

    @property
    def classic(self):
        return self.family == FAMILY_CLASSIC or (
            self.family == FAMILY_UNKNOWN and self.mls is not None)

    def voice_ports(self):
        return [i for i in self.interfaces.values()
                if i.get("neighbor_class") in VOICE_CLASSES or i.get("voice_vlan")]

    def counters_since(self, interface):
        row = self.counters.get(interface) or {}
        cleared = (row.get("counters_cleared") or "").strip()
        if cleared and cleared.lower() != "never":
            return f"cleared {cleared} ago"
        if self.uptime:
            return f"since boot ({self.uptime})"
        return "since boot"

    def output_drops(self, interface):
        return (self.counters.get(interface) or {}).get("output_drops")

    # -- trust --------------------------------------------------------------

    def trust_status(self, intf):
        """How a voice port treats incoming markings."""
        ingress = intf.get("ingress_policy")
        if self.classic:
            if self.mls is False:
                return "QoS disabled"
            state = (intf.get("trust_state") or "").lower()
            if state and state != "not trusted":
                return "Trusted"
            if ingress and self._marks(intf["interface"], "input"):
                return "Marking policy"
            if ingress:
                return "Policy (no marking)"
            return "Not trusted" if state else "Unknown"
        if self.family in TRUSTS_BY_DEFAULT:
            return "Marking policy" if ingress else "Trusted (platform default)"
        return "Marking policy" if ingress else "n/a"

    def _marks(self, interface, direction):
        return any(c.get("set") for p in self.policies.get((interface, direction), [])
                   for c in p.get("classes", []))

    # -- egress priority -----------------------------------------------------

    def egress(self, interface):
        """Egress protection on an interface: policy, priority class, rate, drops.

        Classic switches queue with srr; their priority queue is the egress
        expedite queue. Everything else uses an MQC output policy, on the
        interface or on its parent for a subinterface.
        """
        intf = self.interfaces.get(interface) or {}
        result = {"policy": "", "priority_class": "", "priority_rate": "",
                  "priority_drops": None, "has_priority": False}
        if self.classic:
            expedite = intf.get("expedite_queue")
            if expedite:
                result.update(policy="srr expedite queue", priority_class="queue 1",
                              has_priority=self.mls is not False)
            if intf.get("egress_policy"):
                result["policy"] = intf["egress_policy"]
            pq = [q for q in self.queues.get(interface, []) if q.get("is_priority")]
            if pq:
                result["priority_drops"] = sum(q.get("dropped") or 0 for q in pq)
            return result

        policies = self.policies.get((interface, "output"), [])
        if not policies and "." in interface:
            policies = self.policies.get((interface.split(".")[0], "output"), [])
        if not policies:
            return result
        result["policy"] = policies[0]["policy_name"]
        drops = None
        for p in policies:
            for c in p.get("classes", []):
                if not c.get("is_priority"):
                    continue
                result["has_priority"] = True
                result["priority_class"] = c["class_name"]
                if c.get("priority_percent") is not None:
                    result["priority_rate"] = f"{c['priority_percent']}%"
                elif c.get("priority_kbps") is not None:
                    result["priority_rate"] = f"{c['priority_kbps']} kbps"
                class_drops = _class_drops(c)
                if class_drops is not None:
                    drops = (drops or 0) + class_drops
            pq = p.get("priority_queue") or {}
            if drops is None and pq.get("drops") is not None:
                drops = pq["drops"]
        if drops is None:
            pq = [q for q in self.queues.get(interface, []) if q.get("is_priority")]
            if pq:
                drops = sum(q.get("dropped") or 0 for q in pq)
        result["priority_drops"] = drops
        return result

    def queue_drops(self, interface):
        rows = self.queues.get(interface, [])
        if rows:
            return sum(q.get("dropped") or 0 for q in rows)
        drops = [_class_drops(c) for p in self.policies.get((interface, "output"), [])
                 for c in p.get("classes", [])]
        drops = [d for d in drops if d is not None]
        return sum(drops) if drops else None

    # -- which interfaces are uplinks / WAN ----------------------------------

    def uplink_rows(self):
        """(interface, role, neighbour) for uplinks, WAN circuits and router LAN."""
        rows = []
        if self.is_switch:
            for name, intf in sorted(self.interfaces.items()):
                if intf.get("is_uplink"):
                    rows.append((name, "Switch uplink", intf.get("neighbor", "")))
        elif self.is_router:
            names = {n for n, r in self.counters.items()
                     if r.get("status") == "up" and r.get("protocol") == "up"}
            names |= {i for i, d in self.policies if d == "output" and i != "Control Plane"}
            for name in sorted(names):
                if _NOT_WAN_RE.match(name) or _MGMT_RE.match(name):
                    continue
                intf = self.interfaces.get(name) or {}
                if not intf.get("neighbor_class"):
                    intf = self.interfaces.get(_parent(name)) or intf
                nclass = intf.get("neighbor_class") or "none"
                if nclass == "switch":
                    role = "Router LAN (to switch)"
                elif nclass in ("router", "firewall"):
                    role = f"Router to {nclass}"
                elif nclass in VOICE_CLASSES:
                    continue
                elif self.wan_reason(name):
                    role = "Router WAN/DCI"
                elif _parent(name).startswith("Port-channel"):
                    role = "Router LAN (no CDP neighbour)"
                else:
                    role = "Router, unclassified (no CDP neighbour)"
                rows.append((name, role, intf.get("neighbor", "")))
        return rows

    def wan_reason(self, name):
        """Why an interface counts as WAN; a subinterface inherits its parent's."""
        return self.wan_evidence.get(name) or self.wan_evidence.get(_parent(name), "")


def _devices(inventory_data):
    out = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        if _usable(_parsed(device, COLLECTOR)):
            out.append(Device(hostname, device))
    return out


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _device_findings(dev):
    out = []
    voice = dev.voice_ports()
    if dev.classic and dev.mls is False and voice:
        out.append(make_finding(
            dev.hostname, CRITICAL, "mls qos disabled with voice endpoints",
            (f"QoS is globally disabled but {len(voice)} port(s) have a phone, "
             f"voice gateway or AP attached or a voice VLAN. No marking is "
             f"trusted and no egress queue is prioritised. Enable 'mls qos' "
             f"and set port trust."),
            finding_type="qos:mls_disabled",
            aggregate_key="QoS globally disabled on a switch with voice endpoints",
        ))

    untrusted = [i["interface"] for i in voice if dev.trust_status(i) == "Not trusted"]
    if untrusted:
        shown = ", ".join(untrusted[:10]) + (f", +{len(untrusted) - 10} more"
                                            if len(untrusted) > 10 else "")
        out.append(make_finding(
            dev.hostname, CRITICAL, "Voice ports not trusted",
            (f"{len(untrusted)} voice port(s) neither trust the endpoint's "
             f"marking nor apply a marking policy, so voice is re-marked to "
             f"best effort on entry: {shown}."),
            finding_type="qos:voice_untrusted",
            aggregate_key="Voice ports with no trust and no marking policy",
        ))

    if dev.classic and dev.mls is not False:
        dmap = (dev.qos.get("maps") or {}).get("dscp_output_q") or {}
        if EF in dmap and map_queue(dmap[EF]) != 1:
            out.append(make_finding(
                dev.hostname, CRITICAL, "EF mapped outside the priority queue",
                (f"DSCP 46 (EF) maps to egress queue-threshold {dmap[EF]}; the "
                 f"expedite queue is queue 1, so voice is not prioritised."),
                finding_type="qos:ef_queue",
                aggregate_key=f"EF mapped to queue {map_queue(dmap[EF])}",
            ))

    stale_window = False
    uplinks = dev.uplink_rows()
    for name, role, _ in uplinks:
        eg = dev.egress(name)
        switch_uplink = role == "Switch uplink"
        protected = switch_uplink or role.startswith("Router WAN")
        if protected and not dev.is_voice_gateway and not eg["has_priority"]:
            what = "egress policy" if not eg["policy"] else "priority class"
            label = "Switch uplink" if switch_uplink else "WAN/DCI interface"
            out.append(make_finding(
                dev.hostname, CRITICAL,
                f"{'Uplink' if switch_uplink else 'WAN interface'} with no {what}",
                (f"{name} ({role.lower()}) has "
                 + (f"egress policy {eg['policy']} without a priority class"
                    if eg["policy"] else "no egress priority queue")
                 + "; voice queues behind data under congestion."),
                finding_type="qos:uplink_no_priority" if switch_uplink else "qos:wan_no_llq",
                aggregate_key=f"{label} with no {what}",
                interface=name,
            ))
        if eg["priority_drops"]:
            since = dev.counters_since(name)
            stale_window = stale_window or since.startswith("since boot")
            out.append(make_finding(
                dev.hostname, WARNING, "Priority-queue drops",
                (f"{name}: {eg['priority_drops']} priority-queue drops "
                 f"(counters {since}). The priority class is undersized or "
                 f"policing voice."),
                finding_type="qos:pq_drops",
                aggregate_key="Drops in the priority queue",
                interface=name,
            ))
    uplink_names = {name for name, _, _ in uplinks}
    for intf in voice:
        if intf["interface"] in uplink_names:
            continue
        eg = dev.egress(intf["interface"])
        if eg["priority_drops"]:
            out.append(make_finding(
                dev.hostname, WARNING, "Priority-queue drops",
                (f"{intf['interface']}: {eg['priority_drops']} priority-queue "
                 f"drops toward a {intf.get('neighbor_class')} (counters "
                 f"{dev.counters_since(intf['interface'])})."),
                finding_type="qos:pq_drops",
                aggregate_key="Drops in the priority queue",
                interface=intf["interface"],
            ))

    if dev.classic:
        ef_in = sum(int(dev.dscp.get((i["interface"], "in"), {}).get(EF, 0))
                    for i in voice if not i.get("is_uplink"))
        counted = [n for n, i in dev.interfaces.items() if i.get("is_uplink")
                   and (n, "out") in dev.dscp]
        if ef_in and counted and not any(
                int(dev.dscp[(n, "out")].get(EF, 0)) for n in counted):
            out.append(make_finding(
                dev.hostname, WARNING, "EF marking lost before the uplink",
                (f"{ef_in} EF packets arrived on voice ports but none left "
                 f"the uplink(s) {', '.join(sorted(counted))} as EF. Marking "
                 f"is being rewritten on the way through."),
                finding_type="qos:ef_lost",
                aggregate_key="EF arrives on access ports, none leaves the uplinks",
            ))

    phones = [i for i in dev.interfaces.values() if i.get("neighbor_class") == "phone"]
    with_auto = [i for i in phones if i.get("auto_qos_macro")]
    if with_auto and len(with_auto) < len(phones):
        out.append(make_finding(
            dev.hostname, INFO, "Auto-QoS applied inconsistently",
            (f"{len(with_auto)} of {len(phones)} phone ports use auto-QoS; the "
             f"rest are configured by hand or not at all."),
            finding_type="qos:auto_partial",
            aggregate_key="Auto-QoS on some phone ports but not others",
        ))

    weeks = _uptime_weeks(dev.uptime)
    if stale_window and weeks is not None and weeks >= STALE_COUNTER_WEEKS:
        out.append(make_finding(
            dev.hostname, INFO, "Counters accumulated since boot",
            (f"Drop counters have never been cleared and the device has been "
             f"up {dev.uptime}. Treat absolute drop counts as totals over that "
             f"window, not as a current rate; clear and re-collect to measure."),
            finding_type="qos:stale_counters",
            aggregate_key=f"Counters never cleared, uptime over {STALE_COUNTER_WEEKS} weeks",
        ))
    return out


def policy_catalog(devices):
    """{name: {hash: {"devices": set, "classes": [...], "attachments": n}}}."""
    catalog = defaultdict(dict)
    for dev in devices:
        attached = defaultdict(int)
        for (iface, _), plist in dev.policies.items():
            for p in plist:
                attached[p["policy_name"]] += 1
        for p in dev.qos.get("policy_definitions", []):
            entry = catalog[p["name"]].setdefault(
                p["hash"], {"devices": set(), "classes": p.get("classes", []),
                            "attachments": 0})
            entry["devices"].add(dev.hostname)
            entry["attachments"] += attached.get(p["name"], 0)
    return catalog


def class_catalog(devices):
    """{name: {hash: {...}}} plus per-device missing-ACL and unused flags."""
    catalog = defaultdict(dict)
    for dev in devices:
        used = {c["name"] for p in dev.qos.get("policy_definitions", [])
                for c in p.get("classes", [])}
        for c in dev.qos.get("class_definitions", []):
            if c["name"] == "class-default":
                continue
            entry = catalog[c["name"]].setdefault(
                c["hash"], {"devices": set(), "match_type": c.get("match_type", ""),
                            "match": c.get("match", []), "acls": c.get("acls", []),
                            "missing_acl": set(), "unused": set()})
            entry["devices"].add(dev.hostname)
            if dev.acl_names is not None:
                if any(a not in dev.acl_names for a in c.get("acls", [])):
                    entry["missing_acl"].add(dev.hostname)
            if dev.qos.get("policy_definitions") and c["name"] not in used:
                entry["unused"].add(dev.hostname)
    return catalog


def _drift_findings(pcat):
    """One finding per device carrying a policy-map that exists in more than
    one version, so the Findings row counts and lists every device."""
    out = []
    for name, variants in sorted(pcat.items()):
        if len(variants) < 2:
            continue
        sizes = sorted((len(v["devices"]) for v in variants.values()), reverse=True)
        key = (f"Policy-map {name} exists in {len(variants)} versions (devices "
               f"per version: {', '.join(map(str, sizes))}); see the Policy Catalog")
        ranked = sorted(variants.values(), key=lambda v: -len(v["devices"]))
        for idx, v in enumerate(ranked, 1):
            for host in sorted(v["devices"]):
                out.append(make_finding(
                    host, WARNING, "Policy-map has multiple versions",
                    (f"{name} on this device is version {idx} of {len(variants)}; "
                     f"see the Policy Catalog sheet."),
                    finding_type="qos:policy_drift",
                    aggregate_key=key,
                ))
    return out


def analyze(inventory_data):
    devices = _devices(inventory_data)
    findings = []
    for dev in devices:
        findings += _device_findings(dev)
    overfire_check(findings, len(devices))
    # Drift is a fact about the fleet, not a per-device heuristic, so it is
    # left out of the over-fire ratio.
    pcat = policy_catalog(devices)
    findings += _drift_findings(pcat)
    return {"devices": devices, "findings": findings, "policy_catalog": pcat,
            "class_catalog": class_catalog(devices)}


# ---------------------------------------------------------------------------
# Sheets
# ---------------------------------------------------------------------------

def _yes_no(value):
    if value is None:
        return "n/a"
    return "Yes" if value else "No"


def _on_off(value):
    if value is None:
        return "n/a"
    return "On" if value else "Off"


def _blank(value):
    return "" if value is None else value


POSTURE_HEADERS = ["Device", "Model", "QoS Family", "mls qos", "Auto-QoS",
                   "Phone Ports", "VG Ports", "AP Ports", "Voice Ports Trusted",
                   "Access Policies", "Uplink Egress", "Queue-Set",
                   "DSCP-to-Queue Map", "EF Queue", "Uptime"]
VOICE_HEADERS = ["Device", "Interface", "Neighbour", "Neighbour Type", "Voice VLAN",
                 "Trust State", "Trust Device", "QoS Status", "Auto-QoS",
                 "Ingress Policy", "Ingress EF (pkts)", "Ingress CS3 (pkts)",
                 "Output Drops", "Counters", "Flag"]
UPLINK_HEADERS = ["Device", "Interface", "Role", "Neighbour", "WAN Evidence",
                  "Egress Policy",
                  "Priority Class", "Priority Rate", "Priority Drops", "Queue Drops",
                  "Output Drops", "Output Rate (bps)", "Queueing Strategy",
                  "Counters", "Flag"]
POLICY_HEADERS = ["Policy Map", "Version", "Body Hash", "Versions of Name",
                  "Device Count", "Devices", "Attachments", "Classes and Actions"]
CLASS_HEADERS = ["Class Map", "Match Type", "Match", "Version", "Versions of Name",
                 "Device Count", "Devices", "ACLs", "Flags"]
ERROR_HEADERS = ["Device", "Command", "Error", "Kind"]
FINDINGS_DETAIL_HEADERS = ["Device", "Severity", "Finding", "Details"]


def _posture_row(dev):
    voice = dev.voice_ports()
    by_class = defaultdict(int)
    for i in voice:
        by_class[i.get("neighbor_class")] += 1
    trusted = sum(1 for i in voice if dev.trust_status(i) not in
                  ("Not trusted", "QoS disabled", "Unknown"))
    access = sorted({i["ingress_policy"] for i in voice if i.get("ingress_policy")})
    uplink_egress = sorted({dev.egress(n)["policy"] or "none"
                            for n, _, _ in dev.uplink_rows()})
    auto = (dev.qos.get("qos_global") or {}).get("auto_qos_applied")
    macros = sorted({i["auto_qos_macro"] for i in dev.interfaces.values()
                     if i.get("auto_qos_macro")})
    dmap = (dev.qos.get("maps") or {}).get("dscp_output_q") or {}
    off = bool((dev.qos.get("qos_global") or {}).get("deep_skipped")) and dev.classic
    if off:
        map_state = "QoS off"
    elif not dmap:
        map_state = "n/a"
    else:
        map_state = "Default" if dmap == DEFAULT_DSCP_OUTPUT_Q else "Modified"
    tuned = (dev.qos.get("qos_global") or {}).get("queue_set_tuned")
    return [dev.hostname, dev.model, dev.family, _on_off(dev.mls),
            ("Yes: " + "; ".join(macros)) if auto and macros else _yes_no(auto),
            by_class["phone"], by_class["vg"], by_class["ap"],
            f"{trusted} of {len(voice)}" if voice else "",
            ", ".join(access) or ("" if dev.policies else "No policies attached"),
            ", ".join(uplink_egress),
            "QoS off" if off else ("n/a" if tuned is None else ("Tuned" if tuned else "Default")),
            map_state, "QoS off" if off else dmap.get(EF, "n/a"), dev.uptime]


def _voice_rows(dev):
    rows = []
    for intf in sorted(dev.voice_ports(), key=lambda i: i["interface"]):
        name = intf["interface"]
        status = dev.trust_status(intf)
        dscp_in = dev.dscp.get((name, "in"))
        flag = "No trust or marking" if status == "Not trusted" else (
            "QoS disabled" if status == "QoS disabled" else "")
        rows.append([dev.hostname, name, intf.get("neighbor", ""),
                     intf.get("neighbor_class", ""), intf.get("voice_vlan", ""),
                     intf.get("trust_state", ""), intf.get("trust_device", ""),
                     status, intf.get("auto_qos_macro", ""),
                     intf.get("ingress_policy", ""),
                     "" if dscp_in is None else dscp_in.get(EF, 0),
                     "" if dscp_in is None else dscp_in.get(CS3, 0),
                     _blank(dev.output_drops(name)), dev.counters_since(name), flag])
    return rows


def _uplink_rows(dev):
    rows = []
    for name, role, neighbor in dev.uplink_rows():
        eg = dev.egress(name)
        counters = dev.counters.get(name) or {}
        flags = []
        if role == "Switch uplink" or role.startswith("Router WAN"):
            if not eg["policy"]:
                flags.append("No egress policy")
            elif not eg["has_priority"]:
                flags.append("No priority class")
        if eg["priority_drops"]:
            flags.append("Priority drops")
        rows.append([dev.hostname, name, role, neighbor,
                     dev.wan_reason(name) if role == "Router WAN/DCI" else "",
                     eg["policy"],
                     eg["priority_class"], eg["priority_rate"],
                     _blank(eg["priority_drops"]), _blank(dev.queue_drops(name)),
                     _blank(counters.get("output_drops")),
                     _blank(counters.get("output_rate_bps")),
                     counters.get("queueing_strategy", ""),
                     dev.counters_since(name), ", ".join(flags)])
    return rows


def _policy_rows(pcat):
    rows = []
    for name in sorted(pcat):
        variants = sorted(pcat[name].items(),
                          key=lambda kv: (-len(kv[1]["devices"]), kv[0]))
        for idx, (h, v) in enumerate(variants, 1):
            body = "; ".join(f"{c['name']}: {', '.join(c.get('actions', [])) or '-'}"
                             for c in v["classes"])
            rows.append([name, f"{idx} of {len(variants)}", h, len(variants),
                         len(v["devices"]), ", ".join(sorted(v["devices"])),
                         v["attachments"], body])
    return rows


def _class_rows(ccat):
    rows = []
    for name in sorted(ccat):
        variants = sorted(ccat[name].items(),
                          key=lambda kv: (-len(kv[1]["devices"]), kv[0]))
        for idx, (h, v) in enumerate(variants, 1):
            flags = []
            if v["missing_acl"]:
                flags.append("ACL missing on " + ", ".join(sorted(v["missing_acl"])))
            if v["unused"]:
                flags.append("Unused on " + ", ".join(sorted(v["unused"])))
            rows.append([name, v["match_type"], "; ".join(v["match"]),
                         f"{idx} of {len(variants)}", len(variants),
                         len(v["devices"]), ", ".join(sorted(v["devices"])),
                         ", ".join(v["acls"]), "; ".join(flags)])
    return rows


def _error_rows(inventory_data):
    rows = []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        qos = _parsed(device, COLLECTOR)
        if not qos:
            continue
        kinds = command_error_kinds(qos)
        errors = qos.get("command_errors") or {}
        for cmd in qos.get("failed_commands") or []:
            kind = kinds.get(cmd, "")
            if kind == NOT_APPLICABLE:
                continue
            rows.append([hostname, cmd, errors.get(cmd, ""), kind])
        if qos.get("collector_failed") and not qos.get("failed_commands"):
            rows.append([hostname, "", qos.get("collector_error", ""), "failed"])
        skipped_cmds = qos.get("skipped_commands") or []
        if skipped_cmds:
            reason = (qos.get("qos_global") or {}).get("deep_skipped", "")
            rows.append([hostname, f"{len(skipped_cmds)} per-port QoS commands",
                         f"not run: {reason}", "skipped"])
        sel = qos.get("queue_stats_ports") or {}
        if sel.get("capped") and not sel.get("not_run"):
            skipped = sel.get("skipped")
            text = (f"capped at {sel.get('cap', QUEUE_STATS_CAP)} of "
                    f"{sel.get('eligible')} eligible ports; uplinks were "
                    f"collected first")
            if skipped is not None:
                uplinks = {i["interface"] for i in qos.get("interfaces", [])
                           if i.get("is_uplink")}
                missed = [p for p in skipped if p in uplinks]
                text += (f". {len(skipped)} skipped"
                         + (f", including uplinks {', '.join(missed)}" if missed
                            else ", no uplinks among them")
                         + f": {', '.join(skipped)}")
            rows.append([hostname, "per-port queue counters", text, "capped"])
    return rows


def build_tabular(inventory_data, analysis):
    devices = analysis["devices"]
    findings = analysis["findings"]
    switches = [d for d in devices if d.is_switch]
    posture, voice, uplinks = [], [], []
    for dev in devices:
        if dev.is_switch:
            posture.append(_posture_row(dev))
        voice += _voice_rows(dev)
        uplinks += _uplink_rows(dev)

    def count(ftype):
        return sum(1 for f in findings if f.get("type") == ftype)

    def hosts(*ftypes):
        return len({f["hostname"] for f in findings
                    if f.get("type") in ftypes and f.get("hostname")})

    sheets = OrderedDict()
    sheets["Summary"] = (["Metric", "Value"], [
        ["Devices with QoS data", len(devices)],
        ["Switches with QoS data", len(switches)],
        ["Switches with mls qos off", sum(1 for d in switches
                                          if d.classic and d.mls is False)],
        ["Switches with voice endpoints and no trust",
         hosts("qos:mls_disabled", "qos:voice_untrusted")],
        ["Uplinks with no egress priority", count("qos:uplink_no_priority")],
        ["WAN interfaces with no LLQ", count("qos:wan_no_llq")],
        ["Interfaces with priority-queue drops", count("qos:pq_drops")],
        ["Switches losing EF marking before the uplink", count("qos:ef_lost")],
    ] + summary_count_rows(findings))
    sheets["Switch QoS Posture"] = (POSTURE_HEADERS, posture)
    sheets["Voice Ports"] = (VOICE_HEADERS, voice)
    sheets["Uplinks and WAN"] = (UPLINK_HEADERS, uplinks)
    sheets["Policy Catalog"] = (POLICY_HEADERS, _policy_rows(analysis["policy_catalog"]))
    sheets["Class Catalog"] = (CLASS_HEADERS, _class_rows(analysis["class_catalog"]))
    sheets["Findings"] = (list(AGGREGATE_HEADERS), aggregate_rows(findings))
    sheets[DETAIL_SHEET] = (list(FINDINGS_DETAIL_HEADERS),
                            [[f.get("hostname", ""), f.get("severity", INFO),
                              f.get("title", ""), f.get("description", "")]
                             for f in findings])
    errors = _error_rows(inventory_data)
    if errors:
        sheets["Collection Errors"] = (ERROR_HEADERS, errors)
    return sheets


class VoiceQosReport(BaseReport):
    name = "voice_qos"
    label = "Voice & QoS"
    description = ("QoS posture per switch, voice port trust, uplink and WAN "
                   "priority queues, policy and class-map drift, with counters")
    category = "Compliance & Config"
    required_collectors = [COLLECTOR]
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def can_generate(self, inventory_data):
        return any(_usable(_parsed(d, COLLECTOR))
                   for d in inventory_data.get("devices", {}).values())

    def generate_tabular_data(self, inventory_data):
        return build_tabular(inventory_data, analyze(inventory_data))

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        return self._generate_for_format(inventory_data, fmt)
