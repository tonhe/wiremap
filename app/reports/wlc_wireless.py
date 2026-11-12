"""
Cisco WLC report: WLANs, AP groups, RF, radios, access points, AP join
issues and clients, with their checks.

APs are keyed by base radio MAC, since names repeat across sites. show ap
config general does not always print it, so it is taken from the join
statistics or the radio summary when it is missing there.
"""
import re
from collections import OrderedDict, defaultdict
from datetime import datetime

from .wlc_checks import HIGH, MEDIUM, LOW, finding
from . import wlc_checks as checks

try:
    from app.collectors import wlc_platform as P
    from app.collectors import wlc_wireless as W
    from app.wlc_models import ap_facts
except ImportError:
    from collectors import wlc_platform as P
    from collectors import wlc_wireless as W
    from wlc_models import ap_facts

NA = "n/a"
LEAD = ["Controller", "Site", "Model"]

OPEN_WLAN = "Open WLAN without web auth"
WEP_TKIP = "WEP or WPA-TKIP on any WLAN"
PSK_CORP = "PSK on a WLAN that isn't guest or IoT"
WPA3_PMF = "WPA3 or SAE without PMF"
GUEST_ANCHOR = "Guest WLAN not anchored, or guest on a corporate interface/VLAN"
LOW_RATES = "802.11b rates 1 / 2 / 5.5 / 11 enabled"
WIDE_CHANNELS = "40/80 MHz in 2.4 GHz, or 80/160 MHz in 5 GHz at high-density sites"
CLEANAIR_OFF = "CleanAir off on capable APs"
SINGLE_RADIUS = "Single RADIUS server for a WLAN"
VOICE_QOS = "Voice WLAN not on platinum or WMM off"
NO_PRIMARY = "APs with no primary controller configured"
DEFAULT_GROUP = "APs in default-group"
MIXED_IMAGES = "Mixed AP images on one controller"
POE_LOW = "APs on PoE low power"
SLOW_UPLINK = "AP uplinks below 1 Gb or half duplex"
JOIN_FAIL = "AP join failures in the last 30 days"

_GUEST = re.compile(r"guest|visitor|public|hotspot", re.I)
_IOT = re.compile(r"iot|device|scan|sensor|camera|printer|ot-|building", re.I)
_VOICE = re.compile(r"voice|voip|phone|vocera|spectralink|ascom|wifi-?call", re.I)
_B_RATES = {"1", "2", "5.5", "11"}


def na(value):
    return NA if value is None else value


def yes_no(value):
    return NA if value is None else ("Yes" if value else "No")


def _join(items, sep=", "):
    return sep.join(str(i) for i in items if i not in (None, ""))


def _ctrl_text(ctrl):
    if not ctrl:
        return ""
    return _join([ctrl.get("name"), ctrl.get("ip")], " / ")


class Wireless:
    """The wireless-side parses for one controller, each done once."""

    def __init__(self, c):
        out = c.out
        self.wlan_summary = W.parse_wlan_summary(out("show wlan summary"))
        self.wlans = []
        for row in self.wlan_summary or []:
            w = W.parse_wlan(out(f"show wlan {row['id']}"))
            self.wlans.append(w or {"id": row["id"], "profile": row["profile"],
                                    "ssid": row["ssid"], "status": row["status"],
                                    "interface": row.get("interface"), "_summary_only": True})
        self.apgroups = W.parse_apgroups(out("show wlan apgroups"), self.wlan_summary)
        self.band = {"5": W.parse_band(out("show 802.11a")), "2.4": W.parse_band(out("show 802.11b"))}
        self.channel = {b: W.parse_channel(out(f"show advanced 802.11{x} channel"))
                        for b, x in (("5", "a"), ("2.4", "b"))}
        self.txpower = {b: W.parse_txpower(out(f"show advanced 802.11{x} txpower"))
                        for b, x in (("5", "a"), ("2.4", "b"))}
        self.coverage = {b: W.parse_coverage(out(f"show advanced 802.11{x} coverage"))
                         for b, x in (("5", "a"), ("2.4", "b"))}
        self.group = {b: W.parse_group(out(f"show advanced 802.11{x} group"))
                      for b, x in (("5", "a"), ("2.4", "b"))}
        self.cleanair = {b: W.parse_cleanair(out(f"show 802.11{x} cleanair config"))
                         for b, x in (("5", "a"), ("2.4", "b"))}
        self.fra = W.parse_fra(out("show advanced fra"))
        self.dot11h = W.parse_dot11h(out("show 802.11h"))
        self.rf_profile_summary = W.parse_rf_profile_summary(out("show rf-profile summary"))
        self.rf_profiles = [W.parse_rf_profile(out(f"show rf-profile details {p['name']}"), p["name"])
                            or {"name": p["name"], "band": p.get("band"),
                                "description": p.get("description"), "_summary_only": True}
                            for p in self.rf_profile_summary or []]
        self.radio_summary = {"5": W.parse_radio_summary(out("show advanced 802.11a summary")),
                              "2.4": W.parse_radio_summary(out("show advanced 802.11b summary"))}
        self.air_quality = {}
        for b, x in (("5", "a"), ("2.4", "b")):
            self.air_quality.update(W.parse_air_quality(
                out(f"show 802.11{x} cleanair air-quality summary")) or {})
        self.ap_summary = W.parse_ap_summary(out("show ap summary"))
        self.ap_inventory = W.parse_ap_inventory(out("show ap inventory all"))
        self.ap_cdp = W.parse_ap_cdp(out("show ap cdp neighbors all"))
        self.ap_image = W.parse_ap_image(out("show ap image all"))
        self.ap_uptime = W.parse_ap_uptime(out("show ap uptime"))
        self.join_summary = W.parse_join_summary(out("show ap join stats summary all"))
        self.join_details = {cmd.rsplit(" ", 1)[-1]: W.parse_join_detail(text)
                             for cmd, text in c.commands("show ap join stats detailed ").items()}
        self.link_encryption = W.parse_link_encryption(out("show ap link-encryption all"))
        self.ethernet = W.parse_ap_ethernet(out("show ap stats ethernet summary"))
        self.tcp_mss = W.parse_tcp_mss(out("show ap tcp-mss-adjust all"))
        self.retransmit = W.parse_retransmit(out("show ap retransmit all"))
        self.crash_files = P.parse_ap_crash_files(out("show ap crash-file"))
        self.clients = W.parse_client_summary(out("show client summary"))
        self.client_counts = W.client_counts(self.clients) if self.clients is not None else None
        self.exclusion = W.parse_exclusionlist(out("show exclusionlist"))
        self.general = {}
        self.radios = {}
        for row in self.ap_summary or []:
            name = row["name"]
            self.general[name] = W.parse_ap_config_general(out(f"show ap config general {name}"))
            radios = []
            for x in ("a", "b"):
                text = out(f"show ap config 802.11{x} {name}")
                radios += W.parse_ap_radio_config(text, "5" if x == "a" else "2.4") or []
            self.radios[name] = radios
        self.aps = self._aps()

    def _aps(self):
        base = {}
        for r in self.join_summary or []:
            if r.get("name") and r.get("base_mac"):
                base[r["name"]] = r["base_mac"]
        for rows in self.radio_summary.values():
            for r in rows or []:
                base.setdefault(r["ap_name"], r.get("mac"))
        cdp = {r["ap_name"]: r for r in self.ap_cdp or []}
        aps = []
        for row in self.ap_summary or []:
            name = row["name"]
            g = self.general.get(name) or {}
            inv = (self.ap_inventory or {}).get(name) or {}
            aps.append({
                "name": name, "mac": g.get("base_mac") or base.get(name) or "",
                "ethernet_mac": g.get("ethernet_mac") or row.get("ethernet_mac") or "",
                "model": inv.get("pid") or g.get("model") or row.get("model") or "",
                "serial": inv.get("sn") or g.get("serial") or "",
                "ip": g.get("ip") or row.get("ip") or "", "summary": row, "general": self.general.get(name),
                "cdp": cdp.get(name), "image": (self.ap_image or {}).get(name),
                "uptime": (self.ap_uptime or {}).get(name),
                "ethernet": (self.ethernet or {}).get(name),
                "radios": self.radios.get(name) or [],
            })
        return aps


def wireless(c):
    if not hasattr(c, "_wireless"):
        c._wireless = Wireless(c)
        # The services sheets read WLANs for ACL use and WLAN QoS.
        c.wlans = [w for w in c._wireless.wlans if not w.get("_summary_only")]
    return c._wireless


# ---------------------------------------------------------------------------
# WLANs and AP groups
# ---------------------------------------------------------------------------

WLAN_HEADERS = LEAD + [
    "WLAN ID", "Profile Name", "SSID", "Status", "Broadcast SSID", "Radio Policy", "Interface",
    "Interface Group", "Layer 2 Security", "Encryption", "AKM", "PSK Set", "PMF",
    "Fast Transition (802.11r)", "802.11k", "802.11v", "Layer 3 Security", "MAC Filtering",
    "Auth Servers", "Acct Servers", "AAA Override", "Session Timeout (s)", "Idle Timeout (s)",
    "Client Exclusion", "Exclusion Timeout (s)", "Max Clients", "P2P Blocking",
    "DHCP Required", "QoS Profile", "WMM", "AVC", "NetFlow Monitor", "Mobility Anchors",
    "FlexConnect Local Switching", "FlexConnect Local Auth", "mDNS Snooping", "mDNS Profile",
    "Multicast VLAN", "DTIM (a / b)", "Band Select", "Load Balancing", "Clients Now"]


def _servers(w, key, global_key):
    servers = w.get(key) or []
    if servers:
        return _join(servers)
    return "Global servers" if w.get(global_key) else ""


def wlan_rows(c):
    s = wireless(c)
    rows = []
    for w in s.wlans:
        if w.get("_summary_only"):
            rows.append(c.lead() + [w["id"], w.get("profile", ""), w.get("ssid", ""),
                                    w.get("status", ""), NA, NA, w.get("interface") or ""]
                        + [NA] * (len(WLAN_HEADERS) - 10))
            continue
        dtim = (f"{na(w.get('dtim_a'))} / {na(w.get('dtim_b'))}"
                if w.get("dtim_a") is not None or w.get("dtim_b") is not None else NA)
        rows.append(c.lead() + [
            w["id"], w.get("profile") or "", w.get("ssid") or "", w.get("status") or "",
            yes_no(w.get("broadcast_ssid")), w.get("radio_policy") or "",
            w.get("interface") or "", w.get("interface_group") or "",
            w.get("l2_security") or "", _join(w.get("encryption") or []),
            _join(w.get("akm") or []), yes_no(w.get("psk_set")), w.get("pmf") or NA,
            yes_no(w.get("ft")), yes_no(w.get("dot11k")), yes_no(w.get("dot11v")),
            w.get("l3_security") or "", yes_no(w.get("mac_filtering")),
            _servers(w, "auth_servers", "auth_global"), _servers(w, "acct_servers", "acct_global"),
            yes_no(w.get("aaa_override")), na(w.get("session_timeout_s")),
            na(w.get("idle_timeout_s")), yes_no(w.get("exclusion")),
            na(w.get("exclusion_timeout_s")), na(w.get("max_clients")),
            w.get("p2p_blocking") or "", yes_no(w.get("dhcp_required")),
            w.get("qos_profile") or NA, w.get("wmm") or NA, yes_no(w.get("avc")),
            w.get("netflow_monitor") or "",
            _join(f"{a['ip']} ({a.get('status') or ''})" for a in w.get("mobility_anchors") or []),
            yes_no(w.get("flex_local_switching")), yes_no(w.get("flex_local_auth")),
            yes_no(w.get("mdns_snooping")), w.get("mdns_profile") or "",
            w.get("multicast_vlan") or "", dtim, yes_no(w.get("band_select")),
            yes_no(w.get("load_balancing")),
            na((s.client_counts or {}).get("by_wlan", {}).get(w["id"],
                                                             0 if s.client_counts else None))
            if s.client_counts is not None else na(w.get("clients"))])
    return rows


APGROUP_HEADERS = LEAD + [
    "AP Group", "Description", "WLAN ID", "SSID", "Interface Override", "RF Profile 5 GHz",
    "RF Profile 2.4 GHz", "AP Count"]


def _group_counts(s):
    counts = defaultdict(int)
    for ap in s.aps:
        g = (ap["general"] or {}).get("ap_group")
        if g:
            counts[g] += 1
    for grp in s.apgroups or []:
        if grp.get("aps") and not counts.get(grp["name"]):
            counts[grp["name"]] = len(grp["aps"])
    return counts


def apgroup_rows(c):
    s = wireless(c)
    counts = _group_counts(s)
    ssid = {w["id"]: w.get("ssid") for w in s.wlans}
    default_iface = {w["id"]: w.get("interface") for w in s.wlans}
    rows = []
    for g in s.apgroups or []:
        for w in g.get("wlans") or [{"id": "", "interface": ""}]:
            iface = w.get("interface") or ""
            override = iface if iface and iface != default_iface.get(w.get("id")) else ""
            rows.append(c.lead() + [
                g["name"], g.get("description") or "", w.get("id"),
                w.get("ssid") or ssid.get(w.get("id")) or "", override,
                g.get("rf_profile_a") or "", g.get("rf_profile_b") or "",
                counts.get(g["name"], 0) if s.aps else NA])
    return rows


# ---------------------------------------------------------------------------
# RF
# ---------------------------------------------------------------------------

RF_GLOBAL_HEADERS = LEAD + [
    "Band", "Network Enabled", "Mandatory Rates", "Supported Rates", "Disabled Rates",
    "802.11n", "802.11ac", "802.11ax", "Beacon Interval", "DTIM", "Fragmentation",
    "DCA Mode", "DCA Interval (s)", "DCA Sensitivity", "Channel Width", "Channel List",
    "DFS Channels in List", "TPC Mode", "TPC Threshold (dBm)", "TPC Min / Max (dBm)",
    "Coverage Hole Detection", "RF Group Mode", "RF Group Leader", "RF Group Members",
    "CleanAir", "EDRRM", "FRA", "802.11h"]


def rf_global_rows(c):
    s = wireless(c)
    rows = []
    for band in ("2.4", "5"):
        b, ch, tx = s.band[band], s.channel[band], s.txpower[band]
        cov, grp, ca = s.coverage[band], s.group[band], s.cleanair[band]
        if b is None and ch is None and tx is None:
            continue
        rows.append(c.lead() + [
            band, yes_no((b or {}).get("network_enabled")) if b else NA,
            _join((b or {}).get("mandatory_rates") or []) if b else NA,
            _join((b or {}).get("supported_rates") or []) if b else NA,
            _join((b or {}).get("disabled_rates") or []) if b else NA,
            yes_no((b or {}).get("n_enabled")) if b else NA,
            yes_no((b or {}).get("ac_enabled")) if b else NA,
            yes_no((b or {}).get("ax_enabled")) if b else NA,
            na((b or {}).get("beacon_interval")) if b else NA,
            na((b or {}).get("dtim")) if b else NA, na((b or {}).get("fragmentation")) if b else NA,
            (ch or {}).get("dca_mode") or NA, na((ch or {}).get("interval_s")) if ch else NA,
            (ch or {}).get("sensitivity") or NA, (ch or {}).get("width") or NA,
            _join((ch or {}).get("channels") or []) if ch else NA,
            _join((ch or {}).get("dfs_channels_in_list") or []) if ch else NA,
            (tx or {}).get("tpc_mode") or NA, na((tx or {}).get("threshold_dbm")) if tx else NA,
            f"{na(tx.get('min_dbm'))} / {na(tx.get('max_dbm'))}" if tx else NA,
            yes_no(cov.get("enabled")) if cov else NA,
            (grp or {}).get("mode") or NA,
            _join([((grp or {}).get("leader") or {}).get("name"),
                   ((grp or {}).get("leader") or {}).get("ip")], " / ") if grp else NA,
            _join(m.get("name") or m.get("ip") for m in (grp or {}).get("members") or [])
            if grp else NA,
            yes_no(ca.get("enabled")) if ca else NA, yes_no(ca.get("edrrm")) if ca else NA,
            yes_no((s.fra or {}).get("enabled")) if s.fra else NA,
            _join(f"{k} {v}" for k, v in (s.dot11h or {}).items() if v is not None)
            if s.dot11h is not None and band == "5" else ("" if band == "2.4" else NA)])
    return rows


RF_PROFILE_HEADERS = LEAD + [
    "RF Profile", "Band", "Description", "TPC Min / Max", "TPC Threshold", "Mandatory Rates",
    "Supported Rates", "Disabled Rates", "DCA Channels", "Channel Width",
    "Client Load Balancing", "Coverage Settings", "AP Groups Using It"]


def rf_profile_rows(c):
    s = wireless(c)
    users = defaultdict(list)
    for g in s.apgroups or []:
        for key in ("rf_profile_a", "rf_profile_b"):
            if g.get(key):
                users[g[key]].append(g["name"])
    rows = []
    for p in s.rf_profiles:
        if p.get("_summary_only"):
            rows.append(c.lead() + [p["name"], p.get("band") or "", p.get("description") or ""]
                        + [NA] * 9 + [_join(users.get(p["name"], []))])
            continue
        lb = p.get("load_balancing") or {}
        cov = p.get("coverage") or {}
        rows.append(c.lead() + [
            p["name"], p.get("band") or "", p.get("description") or "",
            f"{na(p.get('tpc_min'))} / {na(p.get('tpc_max'))}", na(p.get("tpc_threshold")),
            _join(p.get("mandatory_rates") or []), _join(p.get("supported_rates") or []),
            _join(p.get("disabled_rates") or []), _join(p.get("channels") or []),
            p.get("width_mhz") and f"{p['width_mhz']} MHz" or (p.get("width") or ""),
            _join(f"{k} {v}" for k, v in lb.items() if v is not None),
            _join(f"{k} {v}" for k, v in cov.items() if v is not None),
            _join(users.get(p["name"], []))])
    return rows


RADIO_HEADERS = LEAD + [
    "AP Name", "AP MAC", "Band", "Slot", "Admin", "Oper", "Channel", "Width (MHz)",
    "Tx Power Level", "Tx Power (dBm)", "Channel Utilisation %", "Noise (dBm)",
    "Interference %", "Air Quality", "Clients", "CleanAir Capable", "CleanAir Enabled",
    "Coverage Status"]


def radio_rows(c):
    s = wireless(c)
    summary = {}
    for band, rows in s.radio_summary.items():
        for r in rows or []:
            summary[(r["ap_name"], band, r["slot"])] = r
    out = []
    seen = set()
    for ap in s.aps:
        for r in ap["radios"]:
            key = (ap["name"], r.get("band"), r.get("slot"))
            seen.add(key)
            sm = summary.get(key) or {}
            aq = s.air_quality.get((ap["name"], r.get("slot")))
            out.append(c.lead() + [
                ap["name"], ap["mac"], r.get("band") or "", na(r.get("slot")),
                r.get("admin") or sm.get("admin") or "", r.get("oper") or sm.get("oper") or "",
                na(r.get("channel") or sm.get("channel")), na(r.get("width") or sm.get("width")),
                na(r.get("tx_power_level") or sm.get("tx_power_level")),
                na(r.get("tx_power_dbm") or sm.get("tx_power_dbm")), na(r.get("utilization")),
                na(r.get("noise")), na(r.get("interference")),
                na((aq or {}).get("avg")) if s.air_quality else NA, na(r.get("clients")),
                yes_no(r.get("cleanair_capable")), yes_no(r.get("cleanair_enabled")),
                r.get("coverage_status") or NA])
    for (name, band, slot), sm in summary.items():
        if (name, band, slot) in seen:
            continue
        aq = s.air_quality.get((name, slot))
        out.append(c.lead() + [
            name, sm.get("mac") or "", band, slot, sm.get("admin") or "", sm.get("oper") or "",
            na(sm.get("channel")), na(sm.get("width")), na(sm.get("tx_power_level")),
            na(sm.get("tx_power_dbm")), NA, NA, NA, na((aq or {}).get("avg")) if aq else NA,
            NA, NA, NA, NA])
    return out


# ---------------------------------------------------------------------------
# Access points, join issues, clients
# ---------------------------------------------------------------------------

AP_HEADERS = LEAD + [
    "AP Name", "Base Radio MAC", "Ethernet MAC", "AP Model", "Serial", "IP Address", "Mask",
    "Gateway", "Addressing", "Mode", "AP Group", "FlexConnect Group", "Location",
    "Primary Controller", "Secondary Controller", "Tertiary Controller", "Joined Controller",
    "Software Version", "Boot Version", "Uptime", "Join Uptime", "Join Date",
    "Last Reboot Reason", "Last Disconnect Reason", "Power", "Ethernet Speed (Mbps)",
    "Duplex", "Switch", "Switch Port", "Switch IP", "Switch In Wiremap", "Admin State",
    "Operational State", "Country", "LED State", "Link Encryption (DTLS)", "TCP MSS",
    "Retransmit", "Crash Files", "Clients 2.4 GHz", "Clients 5 GHz", "Last Date of Support",
    "Supported on Catalyst 9800", "CX Coverage"]


def _ap_clients(s):
    out = defaultdict(lambda: {"2.4": 0, "5": 0})
    for r in s.clients or []:
        if r.get("ap") and r.get("band") in ("2.4", "5"):
            out[r["ap"]][r["band"]] += 1
    return out


def ap_rows(c, known, life):
    s = wireless(c)
    clients = _ap_clients(s)
    crash = s.crash_files or []
    rows = []
    for ap in s.aps:
        g = ap["general"]
        gg = g or {}

        def gen(key):
            return NA if g is None else (gg.get(key) if gg.get(key) is not None else "")
        cdp = ap["cdp"] or {}
        eth = ap["ethernet"] or {}
        up = ap["uptime"] or {}
        model_life = (life.get("aps") or {}).get(ap["model"]) or {}
        hw = model_life.get("hw") or {}
        facts = ap_facts(ap["model"])
        retrans = (s.retransmit or {}).get(ap["name"])
        mss = (s.tcp_mss or {}).get(ap["name"])
        rows.append(c.lead() + [
            ap["name"], ap["mac"] or NA, ap["ethernet_mac"], ap["model"], ap["serial"] or NA,
            ap["ip"], gen("mask"), gen("gateway"), gen("ip_mode"), gen("mode")
            if g is not None else (ap["summary"].get("mode") or NA),
            gen("ap_group"), gen("flex_group"), gen("location") if g is not None
            else (ap["summary"].get("location") or ""),
            _ctrl_text(gg.get("primary_controller")) if g is not None else NA,
            _ctrl_text(gg.get("secondary_controller")) if g is not None else NA,
            _ctrl_text(gg.get("tertiary_controller")) if g is not None else NA,
            c.name, gen("sw_version") if g is not None
            else ((ap["image"] or {}).get("primary") or NA), gen("boot_version"),
            up.get("uptime") or gen("uptime"), up.get("join_uptime") or gen("join_uptime"),
            gen("join_date"), gen("last_reboot_reason"), gen("last_disconnect_reason"),
            gen("power"), na(eth.get("speed_mbps")) if s.ethernet is not None else NA,
            (eth.get("duplex") or "") if s.ethernet is not None else NA,
            cdp.get("neighbor", "") if s.ap_cdp is not None else NA,
            cdp.get("port", "") if s.ap_cdp is not None else NA,
            cdp.get("neighbor_ip", "") if s.ap_cdp is not None else NA,
            (yes_no(_short(cdp["neighbor"]) in known) if cdp.get("neighbor") else "")
            if s.ap_cdp is not None else NA,
            gen("admin_state"), gen("oper_state"), gen("country"), yes_no(gg.get("led_state"))
            if g is not None else NA,
            yes_no((s.link_encryption or {}).get(ap["name"])) if s.link_encryption is not None
            else NA,
            (("on " + str(mss.get("mss"))) if mss.get("enabled") else "off")
            if mss else (na(gg.get("tcp_mss")) if g is not None else NA),
            f"{retrans.get('interval')} s x {retrans.get('count')}" if retrans else NA,
            sum(1 for f in crash if ap["name"] in f) if s.crash_files is not None else NA,
            clients[ap["name"]]["2.4"] if s.clients is not None else NA,
            clients[ap["name"]]["5"] if s.clients is not None else NA,
            hw.get("last_date_of_support") or NA if hw else NA, facts["c9800"] or NA, NA])
    return rows


def _short(name):
    try:
        from app.identity import normalize_hostname
    except ImportError:
        from identity import normalize_hostname
    return normalize_hostname(name)


JOIN_HEADERS = LEAD + [
    "AP MAC", "AP Name", "IP Address", "Status", "Last Join Attempt", "Last Error Type",
    "Last Error", "Last Successful Join", "Join Attempts", "Failures", "Failure Reason"]


def join_rows(c):
    s = wireless(c)
    rows = []
    for r in s.join_summary or []:
        detail = s.join_details.get(r["base_mac"])
        if (r.get("status") or "").lower() == "joined" and not (detail and detail.get("failures")):
            continue
        d = detail or {}

        def get(key):
            return NA if detail is None else na(d.get(key))
        rows.append(c.lead() + [
            r["base_mac"], r.get("name") or "", r.get("ip") or "", r.get("status") or "",
            get("last_join_attempt"), get("last_error_type"), get("last_error"),
            get("last_success"), get("attempts"), get("failures"), get("failure_reason")])
    return rows


CLIENT_HEADERS = LEAD + ["WLAN ID", "SSID", "Band", "Protocol", "Security", "Clients",
                         "Excluded Clients", "Top Exclusion Reasons"]


def _security(w):
    if not w or w.get("_summary_only"):
        return NA
    akm = w.get("akm") or []
    if w.get("l3_security") and w["l3_security"] != "none":
        return w["l3_security"]
    if "SAE" in akm or "PSK" in akm or "FT-PSK" in akm:
        return "PSK" if "SAE" not in akm else "SAE"
    if any("802.1X" in a for a in akm) or w.get("l2_security") == "WEP":
        return "802.1X"
    return "open" if (w.get("l2_security") or "None") == "None" else w["l2_security"]


def client_rows(c):
    s = wireless(c)
    if s.client_counts is None:
        return []
    wl = {w["id"]: w for w in s.wlans}
    excl = s.exclusion
    reasons = _join(f"{k} {v}" for k, v in sorted((excl or {}).get("reasons", {}).items(),
                                                   key=lambda kv: -kv[1])[:5])
    rows = []
    for g in s.client_counts.get("groups") or []:
        w = wl.get(g["wlan"]) or {}
        rows.append(c.lead() + [g["wlan"], w.get("ssid") or "", g.get("band") or "",
                                g.get("protocol") or "", _security(w), g["count"],
                                na((excl or {}).get("count")) if excl is not None else NA,
                                reasons if excl is not None else NA])
    if not rows and excl is not None:
        rows.append(c.lead() + ["", "", "", "", "", 0, na(excl.get("count")), reasons])
    return rows


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _within_30_days(stamp, now):
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})", str(stamp or ""))
    if not m:
        return True
    try:
        when = datetime.strptime(f"{m.group(1)} {m.group(2)} {now.year}", "%b %d %Y")
    except ValueError:
        return True
    if when.date() > now.date():
        when = when.replace(year=now.year - 1)
    return (now.date() - when.date()).days <= 30


def _radius_servers(c):
    try:
        from .wlc_services import services
        return [x for x in (services(c).radius or {}).get("servers", [])
                if x["use"] == "auth" and x["admin"] == "Enabled" and x.get("network_user")]
    except Exception:
        return []


def findings(c, life, today):
    s = wireless(c)
    out = []
    enabled = [w for w in s.wlans if (w.get("status") or "").lower() == "enabled"
               and not w.get("_summary_only")]

    def label(w):
        return f"WLAN {w['id']} {w.get('ssid') or w.get('profile') or ''}".strip()

    open_wlans = [label(w) for w in enabled if (w.get("l2_security") or "None") == "None"
                  and (w.get("l3_security") or "none") == "none"]
    if open_wlans:
        out.append(finding(c, HIGH, OPEN_WLAN, f"{len(open_wlans)} enabled open WLAN(s) "
                           "without web authentication.", items=open_wlans))
    weak = [label(w) for w in s.wlans if not w.get("_summary_only") and (
        "WEP" in (w.get("l2_security") or "") or "TKIP" in (w.get("encryption") or [])
        or "WEP" in (w.get("encryption") or []))]
    if weak:
        out.append(finding(c, HIGH, WEP_TKIP, f"WEP or WPA-TKIP enabled on {len(weak)} WLAN(s).",
                           items=weak))
    psk = [label(w) for w in enabled
           if any(a in ("PSK", "FT-PSK", "PMF-PSK") for a in w.get("akm") or [])
           and not _GUEST.search(f"{w.get('profile')} {w.get('ssid')} {w.get('interface')}")
           and not _IOT.search(f"{w.get('profile')} {w.get('ssid')} {w.get('interface')}")]
    if psk:
        out.append(finding(c, MEDIUM, PSK_CORP, f"PSK on {len(psk)} WLAN(s) not named as guest "
                           "or IoT; review whether they carry corporate users.", items=psk))
    nopmf = [label(w) for w in enabled
             if (w.get("l2_security") in ("WPA3", "WPA2+WPA3") or "SAE" in (w.get("akm") or []))
             and w.get("pmf") != "required"]
    if nopmf:
        out.append(finding(c, LOW, WPA3_PMF, f"WPA3/SAE without PMF required on {len(nopmf)} "
                           "WLAN(s).", items=nopmf))
    guest = []
    for w in enabled:
        is_guest = (w.get("l3_security") in ("web auth", "web passthrough", "splash")
                    or _GUEST.search(f"{w.get('profile')} {w.get('ssid')}"))
        if not is_guest:
            continue
        if not w.get("mobility_anchors"):
            guest.append(f"{label(w)} (not anchored)")
        elif (w.get("interface") or "").lower() == "management":
            guest.append(f"{label(w)} (on the management interface)")
    if guest:
        out.append(finding(c, MEDIUM, GUEST_ANCHOR, f"{len(guest)} guest WLAN(s) not anchored "
                           "to a DMZ controller or sharing a corporate interface.", items=guest))
    single = []
    servers = _radius_servers(c)
    for w in enabled:
        if not any("802.1X" in a for a in w.get("akm") or []):
            continue
        count = len(w.get("auth_servers") or []) if w.get("auth_servers") else (
            len(servers) if w.get("auth_global") else 0)
        if count == 1:
            single.append(label(w))
    if single:
        out.append(finding(c, MEDIUM, SINGLE_RADIUS, f"{len(single)} 802.1X WLAN(s) with a "
                           "single RADIUS server.", items=single))
    voice = [label(w) for w in enabled if _VOICE.search(f"{w.get('profile')} {w.get('ssid')}")
             and ((w.get("qos_profile") or "").lower() != "platinum"
                  or (w.get("wmm") or "").lower() == "disabled")]
    if voice:
        out.append(finding(c, MEDIUM, VOICE_QOS, f"{len(voice)} voice WLAN(s) not on Platinum "
                           "or with WMM disabled.", items=voice))

    b = s.band.get("2.4") or {}
    low = sorted(_B_RATES & set((b.get("mandatory_rates") or []) + (b.get("supported_rates") or [])),
                 key=float)
    if low:
        out.append(finding(c, LOW, LOW_RATES, f"802.11b rates {_join(low)} Mbps enabled in "
                           "2.4 GHz.", items=[f"{r} Mbps" for r in low]))
    wide = []
    w24 = (s.channel.get("2.4") or {}).get("width_mhz")
    if w24 and w24 > 20:
        wide.append(f"2.4 GHz global {w24} MHz")
    w5 = (s.channel.get("5") or {}).get("width_mhz")
    if w5 and w5 >= 80:
        wide.append(f"5 GHz global {w5} MHz")
    for p in s.rf_profiles:
        if p.get("width_mhz") and ((p.get("band") == "2.4" and p["width_mhz"] > 20)
                                   or (p.get("band") == "5" and p["width_mhz"] >= 80)):
            wide.append(f"RF profile {p['name']} {p['width_mhz']} MHz")
    if wide:
        out.append(finding(c, LOW, WIDE_CHANNELS, "Wide channels configured; at high-density "
                           "sites they cut the number of non-overlapping channels.", items=wide))
    no_ca = [f"{ap['name']} slot {r.get('slot')}" for ap in s.aps for r in ap["radios"]
             if r.get("cleanair_capable") and r.get("cleanair_enabled") is False]
    if no_ca:
        out.append(finding(c, LOW, CLEANAIR_OFF, f"CleanAir off on {len(no_ca)} capable "
                           "radio(s).", items=no_ca))

    # --- APs ----------------------------------------------------------------
    ap_life = life.get("aps") or {}
    past, blocked = [], []
    for ap in s.aps:
        hw = (ap_life.get(ap["model"]) or {}).get("hw") or {}
        ldos = checks._date(hw.get("last_date_of_support"))
        if ldos and ldos < today:
            past.append(f"{ap['name']} ({ap['model']})")
        facts = ap_facts(ap["model"])
        if facts["c9800"] in ("No", "Up to 17.3"):
            blocked.append(f"{ap['name']} ({ap['model']}: {facts['c9800']})")
    if past:
        out.append(finding(c, HIGH, checks.AP_LDOS, f"{len(past)} AP(s) past last date of "
                           "support.", items=past))
    if blocked:
        out.append(finding(c, HIGH, checks.AP_9800, f"{len(blocked)} AP(s) cannot join a "
                           "Catalyst 9800 or only up to 17.3.", items=blocked))
    configured = [ap for ap in s.aps if ap["general"] is not None]
    noprim = [ap["name"] for ap in configured if not ap["general"].get("primary_controller")]
    if noprim:
        out.append(finding(c, LOW, NO_PRIMARY, f"{len(noprim)} AP(s) with no primary "
                           "controller configured.", items=noprim))
    default = [ap["name"] for ap in configured
               if (ap["general"].get("ap_group") or "") == "default-group"]
    if not configured:
        default = [n for g in s.apgroups or [] if g["name"] == "default-group"
                   for n in g.get("aps") or []]
    if default:
        out.append(finding(c, LOW, DEFAULT_GROUP, f"{len(default)} AP(s) in default-group.",
                           items=default))
    images = defaultdict(list)
    for ap in s.aps:
        ver = (ap["general"] or {}).get("sw_version") or (ap["image"] or {}).get("primary")
        if ver:
            images[ver].append(ap["name"])
    if len(images) > 1:
        out.append(finding(c, LOW, MIXED_IMAGES, f"{len(images)} AP software versions on one "
                           "controller.", items=[f"{v}: {len(n)} AP(s)" for v, n in
                                                 sorted(images.items())]))
    poe = [ap["name"] for ap in configured if ap["general"].get("power") == "PoE low power"]
    if poe:
        out.append(finding(c, MEDIUM, POE_LOW, f"{len(poe)} AP(s) on PoE low power with "
                           "degraded radios.", items=poe))
    slow = [f"{ap['name']} ({(ap['ethernet'] or {}).get('speed_mbps')} Mbps "
            f"{(ap['ethernet'] or {}).get('duplex') or ''})".replace(" )", ")")
            for ap in s.aps if ap["ethernet"] and (
                ((ap["ethernet"].get("speed_mbps") or 1000) < 1000)
                or ap["ethernet"].get("duplex") == "half")]
    if slow:
        out.append(finding(c, LOW, SLOW_UPLINK, f"{len(slow)} AP uplink(s) below 1 Gb or half "
                           "duplex.", items=slow))
    now = datetime.combine(today, datetime.min.time())
    failed = []
    for r in s.join_summary or []:
        d = s.join_details.get(r["base_mac"]) or {}
        not_joined = (r.get("status") or "").lower() != "joined"
        if (not_joined or d.get("failures")) and _within_30_days(
                d.get("last_failure") or d.get("last_join_attempt"), now):
            failed.append(f"{r.get('name') or r['base_mac']}"
                          + (f" ({d['failure_reason']})" if d.get("failure_reason") else ""))
    if failed:
        out.append(finding(c, MEDIUM, JOIN_FAIL, f"{len(failed)} AP(s) with join failures in "
                           "the last 30 days.", items=failed))
    return out
