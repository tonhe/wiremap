"""
Cisco WLC report: AAA, ACLs, security and WIPS, mobility, FlexConnect, QoS
and services, management plane and certificates, with their checks.
"""
from datetime import date

from . import wlc_checks as checks
from .wlc_checks import HIGH, MEDIUM, LOW, finding

try:
    from app.collectors import wlc_platform as P
    from app.collectors import wlc_services as S
except ImportError:
    from collectors import wlc_platform as P
    from collectors import wlc_services as S

NA = "n/a"
LEAD = ["Controller", "Site", "Model"]

RADIUS_TIMEOUTS = "RADIUS timeouts > 2%"
NO_TACACS = "No TACACS+ for management (local only)"
TELNET_HTTP = "Telnet or HTTP management enabled"
MGMT_WIRELESS = "Management over wireless enabled"
SNMP_WEAK = "SNMP v1/v2c enabled, or default community"
AUTO_CONTAIN = "Rogue auto-containment enabled"
MFP_OFF = "Infrastructure MFP disabled"
MOBILITY_DOWN = "Mobility peer control or data path down"
QOS_MAP_OFF = "QoS map disabled (DSCP trust)"
CERT = "Certificates expired / < 90 days"
WEBAUTH_SELF_SIGNED = "Web auth using the default self-signed certificate"
NETUSER_NO_EXPIRY = "Local net users with no expiry"

QOS_PROFILES = ("platinum", "gold", "silver", "bronze")


def na(value):
    return NA if value is None else value


def yes_no(value):
    return NA if value is None else ("Yes" if value else "No")


def _join(items, sep=", "):
    return sep.join(str(i) for i in items if i not in (None, ""))


class Services:
    """The services-side parses for one controller, each done once."""

    def __init__(self, c):
        self.c = c
        out = c.out
        self.radius = S.parse_radius_summary(out("show radius summary"))
        self.radius_auth = S.parse_radius_stats(out("show radius auth statistics"))
        self.radius_acct = S.parse_radius_stats(out("show radius acct statistics"))
        self.tacacs = S.parse_tacacs_summary(out("show tacacs summary"))
        self.tacacs_auth = S.parse_tacacs_stats(out("show tacacs auth statistics"))
        self.aaa = S.parse_aaa_auth(out("show aaa auth"))
        self.local_auth = S.parse_local_auth_config(out("show local-auth config"))
        self.netuser = S.parse_netuser(out("show netuser summary"))
        self.mgmtuser = S.parse_mgmtuser(out("show mgmtuser"))
        self.acls = S.parse_acl_summary(out("show acl summary"))
        self.acl_cpu = S.parse_acl_cpu(out("show acl cpu"))
        self.flex_acls = S.parse_flex_acl_summary(out("show flexconnect acl summary"))
        self.wps = S.parse_wps_summary(out("show wps summary"))
        self.mfp = S.parse_mfp(out("show wps mfp summary"))
        self.signatures = S.parse_signatures(out("show wps signature summary"))
        self.ap_auth = S.parse_ap_auth(out("show wps ap-authentication summary"))
        self.rogue_ap = S.parse_rogue_ap_summary(out("show rogue ap summary"))
        self.rogue_client = S.parse_rogue_client_summary(out("show rogue client summary"))
        self.rogue_adhoc = S.parse_rogue_adhoc_summary(out("show rogue adhoc summary"))
        self.rogue_rules = S.parse_rogue_rules(out("show rogue rule summary"))
        self.auto_contain = S.parse_auto_contain(out("show rogue auto-contain"))
        self.mobility = S.parse_mobility_summary(out("show mobility summary"))
        self.mobility_stats = S.parse_mobility_stats(out("show mobility statistics"))
        self.anchors = S.parse_mobility_anchor(out("show mobility anchor"))
        self.qos = {n: S.parse_qos_profile(out(f"show qos {n}"), n) for n in QOS_PROFILES}
        self.qos_map = S.parse_qos_map(out("show qos qosmap"))
        self.avc = S.parse_avc_profiles(out("show avc profile summary"))
        self.exporters = S.parse_flow_exporters(out("show flow exporter summary"))
        self.monitors = S.parse_flow_monitors(out("show flow monitor summary"))
        self.mdns = S.parse_mdns_summary(out("show mdns summary"))
        self.mdns_services = S.parse_mdns_services(out("show mdns service summary"))
        self.mdns_profiles = S.parse_mdns_profiles(out("show mdns profile summary"))
        self.nmsp = S.parse_nmsp_status(out("show nmsp status"))
        self.network = S.parse_network_summary(out("show network summary"))
        self.snmp_version = S.parse_snmpversion(out("show snmpversion"))
        self.communities = S.parse_snmpcommunity(out("show snmpcommunity"))
        self.v3users = S.parse_snmpv3user(out("show snmpv3user"))
        self.traps = S.parse_snmptrap(out("show snmptrap"))
        self.logging = S.parse_logging(out("show logging"))
        self.switchconfig = P.parse_switchconfig(out("show switchconfig"))
        self.sessions = P.parse_sessions(out("show sessions"))
        self.certificates = []
        self.certs_collected = False
        for cmd in ("show certificate summary", "show certificate lsc summary",
                    "show local-auth certificates"):
            certs = S.parse_certificates(out(cmd))
            if certs is not None:
                self.certs_collected = True
                self.certificates += certs
        self.flex_groups = {cmd.split(" ", 4)[-1]: S.parse_flex_group_detail(text, cmd.split(" ", 4)[-1])
                            for cmd, text in c.commands("show flexconnect group detail ").items()}


def services(c):
    if not hasattr(c, "_services"):
        c._services = Services(c)
    return c._services


# ---------------------------------------------------------------------------
# AAA Servers
# ---------------------------------------------------------------------------

AAA_HEADERS = LEAD + [
    "Protocol", "Use", "Index", "Server IP", "Port", "Admin", "Network User", "Management",
    "Timeout (s)", "Keywrap", "RFC 3576 (CoA)", "Requests", "Accepts", "Rejects", "Timeouts",
    "Timeout %", "Last Error", "Server Name"]


def _timeout_pct(stats):
    if not stats:
        return None
    sent = (stats.get("requests") or 0) + (stats.get("retransmissions") or 0)
    if not sent or stats.get("timeouts") is None:
        return None
    return round(100 * stats["timeouts"] / sent, 2)


def aaa_rows(c, names):
    s = services(c)
    rows = []
    for srv in (s.radius or {}).get("servers", []):
        stats = (s.radius_auth if srv["use"] == "auth" else s.radius_acct) or {}
        st = stats.get(srv["index"])
        rows.append(c.lead() + [
            "RADIUS", srv["use"], srv["index"], srv["ip"], srv["port"], srv["admin"],
            yes_no(srv.get("network_user")), yes_no(srv.get("management")),
            na(srv.get("timeout_s")), yes_no(srv.get("keywrap")), yes_no(srv.get("rfc3576")),
            *(([na(st.get(k)) for k in ("requests", "accepts", "rejects", "timeouts")]
               + [na(_timeout_pct(st)), st.get("last_error") or ""]) if st else [NA] * 6),
            names.get(srv["ip"], "")])
    for srv in (s.tacacs or {}).get("servers", []):
        st = (s.tacacs_auth or {}).get(srv["index"]) if srv["use"] == "auth" else None
        rows.append(c.lead() + [
            "TACACS+", srv["use"], srv["index"], srv["ip"], srv["port"], srv["admin"], "",
            "Yes", na(srv.get("timeout_s")), "", "",
            *(([na(st.get(k)) for k in ("requests", "accepts", "rejects", "timeouts")]
               + [na(_timeout_pct(st)), st.get("last_error") or ""]) if st else [NA] * 6),
            names.get(srv["ip"], "")])
    return rows


# ---------------------------------------------------------------------------
# ACLs and ACL rules
# ---------------------------------------------------------------------------

ACL_HEADERS = LEAD + ["ACL", "Type", "Family", "Rule Count", "Applied", "Applied To"]
ACL_RULE_HEADERS = LEAD + [
    "ACL", "Type", "Seq", "Action", "Direction", "Protocol", "Source", "Source Mask",
    "Destination", "Destination Mask", "Source Ports", "Destination Ports", "DSCP", "Hits"]


def _acl_uses(c, s):
    uses = {}

    def add(acl, where):
        if acl:
            uses.setdefault(acl, []).append(where)
    for i in c.interfaces or []:
        detail = P.parse_interface_detail(c.out(f"show interface detailed {i['name']}")) or {}
        add(detail.get("acl"), f"interface {i['name']}")
    if s.acl_cpu and s.acl_cpu.get("acl"):
        add(s.acl_cpu["acl"], "CPU")
    for name, group in s.flex_groups.items():
        for m in (group or {}).get("acl_mappings") or []:
            add(m.get("acl"), f"FlexConnect {name}")
        for m in (group or {}).get("vlan_mappings") or []:
            add(m.get("ingress"), f"FlexConnect {name} VLAN {m.get('vlan')}")
    for wlan in getattr(c, "wlans", None) or []:
        add(wlan.get("acl"), f"WLAN {wlan.get('id')}")
    return uses


def _acl_list(c, s):
    out = []
    for a in s.acls or []:
        detail = S.parse_acl_detail(c.out(f"show acl detailed {a['name']}"), a["name"])
        out.append(("Controller", a, detail))
    for a in s.flex_acls or []:
        detail = S.parse_flex_acl_detail(c.out(f"show flexconnect acl detailed {a['name']}"),
                                         a["name"])
        out.append(("FlexConnect", a, detail))
    return out


def acl_rows(c):
    s = services(c)
    uses = _acl_uses(c, s)
    rows = []
    for kind, a, detail in _acl_list(c, s):
        where = uses.get(a["name"], [])
        if kind == "Controller" and s.acl_cpu and s.acl_cpu.get("acl") == a["name"]:
            kind = "Controller / CPU"
        rows.append(c.lead() + [
            a["name"], kind, a.get("family", ""),
            NA if detail is None else len(detail.get("rules") or []),
            yes_no(a.get("applied")), "; ".join(dict.fromkeys(where))])
    return rows


def acl_rule_rows(c):
    rows = []
    for kind, a, detail in _acl_list(c, services(c)):
        for r in (detail or {}).get("rules") or []:
            rows.append(c.lead() + [
                a["name"], kind, r.get("seq"), r.get("action", ""), r.get("direction") or "",
                r.get("protocol", ""), r.get("source", ""), r.get("src_mask", ""),
                r.get("destination", ""), r.get("dst_mask", ""), r.get("src_ports", ""),
                r.get("dst_ports", ""), r.get("dscp", ""), na(r.get("hits"))])
    return rows


# ---------------------------------------------------------------------------
# Security and WIPS
# ---------------------------------------------------------------------------

SECURITY_HEADERS = LEAD + [
    "Rogue APs", "Malicious", "Friendly", "Unclassified", "Custom", "On Wire", "Contained",
    "Rogue Clients", "Ad-hoc Rogues", "Rogue Rules", "Auto-Containment Level",
    "Auto-Containment Enabled", "Infrastructure MFP", "Client MFP", "Standard Signatures Enabled",
    "Custom Signatures Enabled", "AP Authentication", "Client Exclusion Policies"]


def security_row(c):
    s = services(c)
    rogue = s.rogue_ap
    by = (rogue or {}).get("by_class") or {}

    def cls(name):
        return NA if rogue is None else by.get(name, 0)
    ac = s.auto_contain
    mfp = s.mfp
    client_mfp = (mfp or {}).get("client_mfp")
    sig = s.signatures
    excl = (s.wps or {}).get("client_exclusion")
    return c.lead() + [
        NA if rogue is None else na(rogue.get("total")), cls("Malicious"), cls("Friendly"),
        cls("Unclassified"), cls("Custom"), NA if rogue is None else na(rogue.get("on_wire")),
        NA if rogue is None else na(rogue.get("contained")),
        NA if s.rogue_client is None else na(s.rogue_client.get("total")),
        NA if s.rogue_adhoc is None else na(s.rogue_adhoc.get("total")),
        NA if s.rogue_rules is None else "; ".join(
            f"{r['name']} ({r.get('class') or ''}, {r.get('action') or 'no action'}, "
            f"{'enabled' if r.get('enabled') else 'disabled'})" for r in s.rogue_rules),
        NA if ac is None else na(ac.get("level")),
        NA if ac is None else (_join(ac.get("enabled_settings") or []) or "None"),
        yes_no((mfp or {}).get("infrastructure_mfp")) if mfp else NA,
        NA if not client_mfp else _join(f"{k} {v}" for k, v in client_mfp.items()),
        NA if sig is None else na(sig.get("standard_enabled")),
        NA if sig is None else na(sig.get("custom_enabled")),
        yes_no((s.ap_auth or {}).get("enabled")) if s.ap_auth else NA,
        NA if excl is None else _join(k for k, v in excl.items() if v)]


# ---------------------------------------------------------------------------
# Mobility, FlexConnect, QoS and services
# ---------------------------------------------------------------------------

MOBILITY_HEADERS = LEAD + [
    "Kind", "Peer MAC", "Peer IP", "Peer Group", "Multicast IP", "Control Path", "Data Path",
    "Status", "Anchored WLAN", "Own Group", "Multicast Mode", "DTLS", "Handoffs (local / foreign)",
    "Handoff Failures"]


def _up(value):
    return NA if value is None else ("Up" if value else "Down")


def mobility_rows(c):
    s = services(c)
    mob = s.mobility
    if mob is None and s.anchors is None:
        return []
    stats = s.mobility_stats or {}
    hand = stats.get("handoffs") or {}
    common = [(mob or {}).get("group_name") or "", (mob or {}).get("multicast_mode") or "",
              yes_no((mob or {}).get("dtls")) if mob else NA,
              f"{na(hand.get('as_local'))} / {na(hand.get('as_foreign'))}" if hand else NA,
              na(stats.get("failures")) if s.mobility_stats else NA]
    rows = []
    for p in (mob or {}).get("peers") or []:
        rows.append(c.lead() + ["Peer", p.get("mac", ""), p.get("ip", ""), p.get("group", ""),
                                p.get("multicast_ip") or "", _up(p.get("control_up")),
                                _up(p.get("data_up")), p.get("status", ""), ""] + common)
    for a in s.anchors or []:
        rows.append(c.lead() + ["Anchor", "", a.get("anchor_ip", ""), "", "", "", "",
                                a.get("status", ""), a.get("wlan")] + common)
    return rows


FLEX_HEADERS = LEAD + [
    "Group", "AP Count", "Local Auth", "RADIUS Servers", "VLAN Mode", "Native VLAN",
    "VLAN ACL Mappings", "WLAN-VLAN Mappings", "ACL Mappings", "Efficient Image Upgrade",
    "Master AP"]


def flex_rows(c):
    rows = []
    for name, g in sorted(services(c).flex_groups.items()):
        if g is None:
            continue
        rows.append(c.lead() + [
            name, na(g.get("ap_count")), yes_no(g.get("local_auth")),
            _join(g.get("radius_servers") or []), yes_no(g.get("vlan_mode")),
            na(g.get("native_vlan")),
            _join((f"VLAN {m['vlan']} in {m.get('ingress') or '-'} out {m.get('egress') or '-'}"
                   for m in g.get("vlan_mappings") or []), "; "),
            _join((f"WLAN {m['wlan']} -> VLAN {m['vlan']}"
                   for m in g.get("wlan_vlan_mappings") or []), "; "),
            _join((f"{m['kind']} WLAN {m.get('wlan')}: {m['acl']}"
                   for m in g.get("acl_mappings") or []), "; "),
            yes_no(g.get("efficient_upgrade")), g.get("master_ap") or ""])
    return rows


QOS_HEADERS = LEAD + ["Block", "Item", "Detail"]


def _limits(d):
    parts = []
    for k, v in (d or {}).items():
        if v and (v.get("upstream") or v.get("downstream")):
            parts.append(f"{k.replace('_', ' ')} {v.get('upstream') or 0}/{v.get('downstream') or 0}")
    return _join(parts, "; ") or "none"


def qos_rows(c):
    s = services(c)
    rows = []

    def add(block, item, detail):
        rows.append(c.lead() + [block, item, detail])
    for name, q in s.qos.items():
        if q is None:
            continue
        add("QoS profile", name, (
            f"per-user {_limits(q.get('per_user_rate_limits'))}; per-SSID "
            f"{_limits(q.get('per_ssid_rate_limits'))}; 802.1p {na(q.get('dot1p_tag'))}; "
            f"wired {q.get('wired_protocol') or 'none'}; max priority "
            f"{q.get('max_priority') or 'n/a'}"))
    if s.qos_map is not None:
        m = s.qos_map
        add("QoS map", "DSCP-to-UP", (
            f"{'enabled' if m.get('enabled') else 'disabled'}; trust DSCP upstream "
            f"{'yes' if m.get('trust_dscp_upstream') else 'no'}; "
            + _join((f"UP {r['up']}: {r['dscp_start']}-{r['dscp_end']} (default "
                     f"{r['dscp_default']})" for r in m.get("map") or []), "; ")))
    for wlan in getattr(c, "wlans", None) or []:
        add("WLAN QoS", f"{wlan.get('id')} {wlan.get('profile') or ''}".strip(),
            f"{wlan.get('qos_profile') or 'n/a'}, WMM {wlan.get('wmm') or 'n/a'}")
    for p in s.avc or []:
        add("AVC", p.get("name", ""), f"{na(p.get('rules'))} rules")
    for e in s.exporters or []:
        add("NetFlow exporter", e.get("name", ""), f"{e.get('ip') or ''}:{e.get('port') or ''}")
    for m in s.monitors or []:
        add("NetFlow monitor", m.get("name", ""),
            f"exporter {m.get('exporter') or ''} record {m.get('record') or ''}")
    n = s.network
    if n is not None:
        add("Multicast", "mode", (
            f"{n.get('multicast_mode') or 'n/a'} {n.get('multicast_group') or ''}; IGMP snooping "
            f"{yes_no(n.get('igmp_snooping'))}; MLD snooping {yes_no(n.get('mld_snooping'))}; "
            f"multicast VLAN {yes_no(n.get('multicast_vlan'))}").replace("  ", " "))
    if s.mdns is not None:
        add("mDNS", "global", (f"{'enabled' if s.mdns.get('enabled') else 'disabled'}; "
                               f"{na(s.mdns.get('services'))} services, "
                               f"{na(s.mdns.get('profiles'))} profiles"))
    for p in s.mdns_profiles or []:
        add("mDNS profile", p.get("name", ""), f"services {na(p.get('services'))}")
    return rows


# ---------------------------------------------------------------------------
# Management plane and certificates
# ---------------------------------------------------------------------------

MGMT_HEADERS = LEAD + [
    "Telnet", "SSH", "HTTP", "HTTPS", "Secure Web Cipher High", "Web Auth Secure",
    "Mgmt Via Wireless", "Mgmt Via Dynamic Interface", "CLI Session Timeout (min)",
    "SNMP v1", "SNMP v2c", "SNMP v3", "SNMP Communities", "Community Access",
    "Default Communities", "SNMPv3 Users", "Trap Receivers", "Syslog Servers", "Syslog Level",
    "Syslog Facility", "NTP Servers", "NTP Synced", "Time Zone", "Prime / CMX (NMSP)",
    "Strong Password Checks", "Login Lockout", "Management Auth Order", "Local EAP Profiles",
    "Local Net Users", "Net Users Without Expiry", "Management Users", "Login Banner"]


def mgmt_row(c):
    s = services(c)
    n = s.network or {}
    v = s.snmp_version or {}
    sc = s.switchconfig or {}
    time = c.time or {}
    strong = [k[len("strong_password_"):] for k, val in sc.items()
              if k.startswith("strong_password_") and str(val).lower().startswith("enable")]
    lockout = sc.get("mgmt_user_password_lockout")
    defaults = c.parsed.get("snmp_default_communities")
    config = c.out("show run-config commands")
    banner = None if config is None else any(
        l.strip().startswith("config loginbanner") for l in config.splitlines())

    def net(key):
        return yes_no(n.get(key)) if s.network else NA

    def snmp(key):
        return yes_no(v.get(key)) if s.snmp_version else NA
    return c.lead() + [
        net("telnet"), net("ssh"), net("http"), net("https"), net("secure_web_cipher_high"),
        net("web_auth_secure"), net("mgmt_via_wireless"), net("mgmt_via_dynamic_interface"),
        NA if s.sessions is None else na(s.sessions.get("cli_timeout_min")),
        snmp("v1"), snmp("v2c"), snmp("v3"),
        NA if s.communities is None else len(s.communities),
        NA if s.communities is None else _join(sorted({f"{x['access']} from {x['ip']}/{x['mask']}"
                                                       for x in s.communities})),
        NA if defaults is None else (_join(defaults) or "None"),
        NA if s.v3users is None else _join(f"{u['name']} ({u['auth_protocol']}/"
                                           f"{u['priv_protocol']})" for u in s.v3users),
        NA if s.traps is None else _join(f"{t['ip']}{'' if t['enabled'] else ' (disabled)'}"
                                         for t in s.traps),
        NA if s.logging is None else _join(s.logging.get("syslog_hosts") or []),
        NA if s.logging is None else s.logging.get("syslog_level") or "",
        NA if s.logging is None else s.logging.get("facility") or "",
        NA if c.time is None else _join(x["server"] for x in time.get("ntp_servers") or []),
        NA if c.time is None else yes_no(time.get("ntp_synced")),
        NA if c.time is None else time.get("timezone") or "",
        NA if s.nmsp is None else _join(f"{x['ip']} ({x.get('transport') or ''})"
                                        for x in s.nmsp),
        NA if s.switchconfig is None else (_join(strong) or "None"),
        NA if s.switchconfig is None else (lockout or ""),
        NA if s.aaa is None else _join(s.aaa.get("management_order") or [], " > "),
        NA if s.local_auth is None else _join(p["name"] for p in s.local_auth.get("profiles") or []),
        NA if s.netuser is None else s.netuser.get("count"),
        NA if s.netuser is None else s.netuser.get("no_expiry"),
        NA if s.mgmtuser is None else _join(f"{u['name']} ({u['access']})" for u in s.mgmtuser),
        yes_no(banner)]


CERT_HEADERS = LEAD + [
    "Use", "Source", "Subject", "Issuer", "Valid From", "Valid To", "Days Left", "Key Size",
    "Signature Algorithm", "Self-signed"]


def _days_left(cert, today):
    try:
        return (date.fromisoformat(cert.get("valid_to") or "") - today).days
    except ValueError:
        return None


def cert_rows(c, today):
    rows = []
    for cert in services(c).certificates:
        days = _days_left(cert, today)
        rows.append(c.lead() + [
            cert.get("use", ""), cert.get("source") or "", cert.get("subject") or NA,
            cert.get("issuer") or NA, cert.get("valid_from") or NA, cert.get("valid_to") or NA,
            na(days), na(cert.get("key_size")), na(cert.get("signature_algorithm")),
            yes_no(cert.get("self_signed"))])
    return rows


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def findings(c, today):
    s = services(c)
    out = []
    slow = []
    for srv in (s.radius or {}).get("servers", []):
        stats = (s.radius_auth if srv["use"] == "auth" else s.radius_acct) or {}
        pct = _timeout_pct(stats.get(srv["index"]))
        if pct is not None and pct > 2:
            slow.append(f"{srv['ip']} {srv['use']} {pct}%")
    if slow:
        out.append(finding(c, MEDIUM, RADIUS_TIMEOUTS,
                           f"{len(slow)} RADIUS server(s) time out on more than 2% of requests.",
                           items=slow))

    tacacs_auth = [x for x in (s.tacacs or {}).get("servers", [])
                   if x["use"] == "auth" and x["admin"] == "Enabled"]
    if s.aaa is not None and not s.aaa.get("has_tacacs") and not (
            s.aaa.get("has_radius") and any(x.get("management") for x in
                                             (s.radius or {}).get("servers", []))):
        out.append(finding(c, MEDIUM, NO_TACACS,
                           "Management logins are authenticated locally only "
                           f"(order: {_join(s.aaa.get('management_order') or [], ' > ')}).",
                           items=["management auth"]))
    elif s.aaa is not None and s.aaa.get("has_tacacs") and not tacacs_auth and s.tacacs is not None:
        out.append(finding(c, MEDIUM, NO_TACACS,
                           "TACACS+ is in the management order but no TACACS+ "
                           "authentication server is enabled.", items=["TACACS+"]))

    n = s.network or {}
    if n.get("telnet"):
        out.append(finding(c, HIGH, TELNET_HTTP, "Telnet management is enabled.",
                           items=["telnet"]))
    if n.get("http"):
        out.append(finding(c, MEDIUM, TELNET_HTTP, "HTTP (unencrypted) web management is "
                           "enabled.", items=["http"]))
    if n.get("mgmt_via_wireless"):
        out.append(finding(c, MEDIUM, MGMT_WIRELESS,
                           "Wireless clients can reach the controller's management interfaces.",
                           items=["management via wireless"]))

    v = s.snmp_version or {}
    defaults = c.parsed.get("snmp_default_communities") or []
    if defaults:
        out.append(finding(c, HIGH, SNMP_WEAK,
                           f"Default SNMP community configured ({_join(defaults)}).",
                           items=defaults))
    elif v.get("v1") or v.get("v2c"):
        on = [k for k in ("v1", "v2c") if v.get(k)]
        out.append(finding(c, MEDIUM, SNMP_WEAK, f"SNMP {_join(on)} enabled.", items=on))

    if s.logging is not None and not s.logging.get("syslog_hosts"):
        out.append(finding(c, MEDIUM, checks.SYSLOG_NTP, "No syslog server configured.",
                           items=["syslog"]))

    if s.auto_contain and s.auto_contain.get("any_enabled"):
        out.append(finding(c, MEDIUM, AUTO_CONTAIN,
                           "Rogue auto-containment is on: "
                           f"{_join(s.auto_contain.get('enabled_settings') or [])}. "
                           "Containing neighbours' APs carries legal and RF risk.",
                           items=s.auto_contain.get("enabled_settings") or ["auto-contain"]))
    contain_rules = [r["name"] for r in s.rogue_rules or []
                     if r.get("enabled") and (r.get("action") or "").lower() == "contain"]
    if contain_rules:
        out.append(finding(c, MEDIUM, AUTO_CONTAIN,
                           f"Rogue rules that contain automatically: {_join(contain_rules)}.",
                           items=contain_rules))

    if s.mfp is not None and s.mfp.get("infrastructure_mfp") is False:
        out.append(finding(c, LOW, MFP_OFF, "Infrastructure MFP is disabled.",
                           items=["infrastructure MFP"]))

    down = [f"{p['ip']} ({p.get('status')})" for p in (s.mobility or {}).get("peers") or []
            if p.get("control_up") is False or p.get("data_up") is False]
    down += [f"anchor {a['anchor_ip']} WLAN {a['wlan']} ({a.get('status')})"
             for a in s.anchors or [] if (a.get("status") or "").lower() != "up"]
    if down:
        out.append(finding(c, HIGH, MOBILITY_DOWN,
                           f"{len(down)} mobility peer(s) or anchor(s) with a path down.",
                           items=down))

    if s.qos_map is not None and not s.qos_map.get("enabled"):
        out.append(finding(c, LOW, QOS_MAP_OFF,
                           "The DSCP-to-UP QoS map is disabled, so client DSCP is not trusted.",
                           items=["qos map"]))

    expired, soon = [], []
    for cert in s.certificates:
        days = _days_left(cert, today)
        label = f"{cert.get('use')}: {cert.get('subject') or cert.get('source') or ''}".strip()
        if days is not None and days < 0:
            expired.append(label)
        elif days is not None and days < 90:
            soon.append(f"{label} ({days} days)")
    if expired:
        out.append(finding(c, HIGH, CERT, f"{len(expired)} certificate(s) expired.",
                           items=expired))
    if soon:
        out.append(finding(c, MEDIUM, CERT, f"{len(soon)} certificate(s) expire within 90 days.",
                           items=soon))
    if any(x.get("use") == "web-auth" and x.get("self_signed") for x in s.certificates):
        out.append(finding(c, LOW, WEBAUTH_SELF_SIGNED,
                           "Guest web authentication uses the controller's locally generated "
                           "certificate, so clients see a certificate warning.",
                           items=["web-auth certificate"]))

    if s.netuser and s.netuser.get("no_expiry"):
        names = [u["name"] for u in s.netuser.get("users") or []
                 if str(u.get("lifetime")).lower() in ("unlimited", "0")]
        out.append(finding(c, LOW, NETUSER_NO_EXPIRY,
                           f"{s.netuser['no_expiry']} local net user(s) never expire.",
                           items=names))
    return out


def server_names(inventory_data):
    """{ip: device name} for addresses wiremap reached, to name AAA servers."""
    out = {}
    for key, d in (inventory_data.get("devices") or {}).items():
        for ip in (d.get("reached_ip"), d.get("mgmt_ip")):
            if ip:
                out.setdefault(ip, key)
    return out
