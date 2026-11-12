"""Cisco WLC report with a fully collected controller: WLANs, RF, APs,
clients, AAA, ACLs, WIPS, mobility, FlexConnect, QoS, management plane,
certificates, hygiene, relationships and the AP topology."""
import io
import json

import openpyxl
import pytest

import app.collectors.wlc as wlc_mod
import app.reports.wlc as rep
from app.collectors.wlc import WlcCollector
from app.reports import wlc_checks as checks
from app.reports import wlc_services as svc
from app.reports import wlc_wireless as wl
from app.wlc_topology import ap_links
from tests.test_collectors import wlc_fixtures as fx
from tests.test_collectors import wlc_platform_fixtures as pf
from tests.test_collectors import wlc_services_fixtures as sf
from tests.test_collectors import wlc_wireless_fixtures as wf

WLAN_SUMMARY = """\
Number of WLANs.................................. 6

WLAN ID  WLAN Profile Name / SSID               Status    Interface Name        PMIPv6 Mobility
-------  -------------------------------------  --------  --------------------  ---------------
1        lab-corp / lab-corp                     Enabled   management            none
2        lab-guest / lab-guest                   Enabled   lab-guest             none
3        lab-open / lab-open                     Disabled  management            none
4        lab-scanners / lab-scanners             Enabled   lab-scan-grp          none
5        lab-iot / lab-iot                       Enabled   lab-iot               none
6        lab-legacy-wep / lab-legacy-wep         Enabled   management            none
"""

FULL = dict(fx.CONTROLLER, **{
    "show inventory": pf.INVENTORY_5520,
    "show redundancy summary": pf.REDUNDANCY_SUMMARY_SSO,
    "show time": pf.TIME_810,
    "show cdp neighbors detail": pf.CDP_NEIGHBORS,
    "show wlan summary": WLAN_SUMMARY,
    "show wlan 1": wf.WLAN_CORP, "show wlan 2": wf.WLAN_GUEST, "show wlan 3": wf.WLAN_OPEN,
    "show wlan 4": wf.WLAN_LEGACY, "show wlan 5": wf.WLAN_WPA3, "show wlan 6": wf.WLAN_WEP,
    "show wlan apgroups": wf.APGROUPS,
    "show 802.11a": wf.BAND_A, "show 802.11b": wf.BAND_B,
    "show advanced 802.11a channel": wf.CHANNEL_A, "show advanced 802.11b channel": wf.CHANNEL_B,
    "show advanced 802.11a txpower": wf.TXPOWER_A, "show advanced 802.11a coverage": wf.COVERAGE_A,
    "show advanced 802.11a group": wf.GROUP_A, "show 802.11a cleanair config": wf.CLEANAIR_A,
    "show 802.11b cleanair config": wf.CLEANAIR_B_OFF, "show advanced fra": wf.FRA,
    "show 802.11h": wf.DOT11H, "show rf-profile summary": wf.RF_PROFILE_SUMMARY_TWO,
    "show rf-profile details lab-rf-5g": wf.RF_PROFILE_5G,
    "show advanced 802.11a summary": wf.RADIO_SUMMARY_A,
    "show advanced 802.11b summary": wf.RADIO_SUMMARY_B,
    "show 802.11a cleanair air-quality summary": wf.AIR_QUALITY_A,
    "show ap inventory all": wf.AP_INVENTORY, "show ap cdp neighbors all": wf.AP_CDP,
    "show ap image all": wf.AP_IMAGE, "show ap uptime": wf.AP_UPTIME,
    "show ap join stats detailed 00:11:22:aa:00:03": wf.JOIN_DETAIL,
    "show ap config general lab-ap-01": wf.AP_GENERAL,
    "show ap config general lab-ap-02": wf.AP_GENERAL_FLEX,
    "show ap config 802.11a lab-ap-01": wf.AP_RADIO_A,
    "show ap config 802.11b lab-ap-01": wf.AP_RADIO_B,
    "show ap link-encryption all": wf.LINK_ENCRYPTION, "show ap stats ethernet summary": wf.AP_ETHERNET,
    "show ap tcp-mss-adjust all": wf.TCP_MSS, "show ap retransmit all": wf.RETRANSMIT,
    "show client summary": wf.CLIENT_SUMMARY_SCRUBBED, "show exclusionlist": wf.EXCLUSION_SCRUBBED,
    "show radius summary": sf.RADIUS_SUMMARY, "show radius auth statistics": sf.RADIUS_AUTH_STATS,
    "show radius acct statistics": sf.RADIUS_ACCT_STATS, "show tacacs summary": sf.TACACS_SUMMARY,
    "show tacacs auth statistics": sf.TACACS_AUTH_STATS, "show aaa auth": sf.AAA_AUTH_LOCAL,
    "show local-auth config": sf.LOCAL_AUTH_CONFIG, "show mgmtuser": sf.MGMTUSER,
    "show acl summary": sf.ACL_SUMMARY, "show acl detailed lab-preauth": sf.ACL_DETAIL,
    "show acl cpu": sf.ACL_CPU, "show flexconnect acl summary": sf.FLEX_ACL_SUMMARY,
    "show flexconnect acl detailed lab-flex-acl": sf.FLEX_ACL_DETAIL,
    "show wps summary": sf.WPS_SUMMARY, "show wps mfp summary": sf.MFP_SUMMARY_OFF,
    "show wps signature summary": sf.SIGNATURES, "show wps ap-authentication summary": sf.AP_AUTH_ON,
    "show rogue ap summary": sf.ROGUE_AP_SUMMARY, "show rogue client summary": sf.ROGUE_CLIENT_SUMMARY,
    "show rogue adhoc summary": sf.ROGUE_ADHOC_SUMMARY, "show rogue rule summary": sf.ROGUE_RULES,
    "show rogue auto-contain": sf.AUTO_CONTAIN, "show mobility summary": sf.MOBILITY_SUMMARY,
    "show mobility statistics": sf.MOBILITY_STATS, "show mobility anchor": sf.MOBILITY_ANCHOR,
    "show flexconnect group detail lab-flex-01": sf.FLEX_GROUP_DETAIL,
    "show qos platinum": sf.QOS_PLATINUM, "show qos bronze": sf.QOS_BRONZE_OLD,
    "show qos qosmap": sf.QOS_MAP_OFF, "show avc profile summary": sf.AVC_PROFILES,
    "show flow exporter summary": sf.FLOW_EXPORTERS, "show flow monitor summary": sf.FLOW_MONITORS,
    "show mdns summary": sf.MDNS_SUMMARY, "show mdns profile summary": sf.MDNS_PROFILES,
    "show nmsp status": sf.NMSP_STATUS, "show network summary": sf.NETWORK_SUMMARY,
    "show snmpversion": sf.SNMPVERSION, "show snmpv3user": sf.SNMPV3USER,
    "show snmptrap": sf.SNMPTRAP, "show logging": sf.LOGGING_NO_HOSTS,
    "show certificate summary": sf.CERT_SUMMARY, "show local-auth certificates": sf.LOCAL_AUTH_CERTS,
    "show switchconfig": pf.SWITCHCONFIG, "show sessions": pf.SESSIONS,
})


class FakeConn:
    def send_command(self, cmd, **kwargs):
        return FULL.get(cmd, "Incorrect usage. Use the '?' or <TAB> key to list commands.")


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(wlc_mod, "redact_secrets_enabled", lambda: True)
    monkeypatch.setattr(rep, "eox_records", lambda ctrls: (
        {"AIR-CAP2602I-A-K9": {"last_date_of_support": "2022-01-31"}}, {}))


def _inventory():
    result = WlcCollector().collect(FakeConn(), "cisco_wlc")
    return {"timestamp": "2026-11-12T10:00:00Z", "devices": {
        "lab-wlc-01": {"device_type": "cisco_wlc", "reached_ip": "192.0.2.40",
                       "collector_data": {"wlc": result}},
        "lab-sw-01": {"device_type": "cisco_xe", "reached_ip": "192.0.2.2", "collector_data": {}},
        "lab-ise-01": {"device_type": "linux", "mgmt_ip": "192.0.2.50", "collector_data": {}},
    }}


@pytest.fixture(scope="module")
def built():
    import app.collectors.wlc as m
    saved = m.redact_secrets_enabled
    m.redact_secrets_enabled = lambda: True
    saved_eox = rep.eox_records
    rep.eox_records = lambda ctrls: ({"AIR-CAP2602I-A-K9": {"last_date_of_support": "2022-01-31"}}, {})
    try:
        inv = _inventory()
        analysis = rep.analyze(inv)
        sheets = rep.build_tabular(inv, analysis)
    finally:
        m.redact_secrets_enabled = saved
        rep.eox_records = saved_eox
    return inv, analysis, sheets


def rows(built, name):
    headers, data = built[2][name]
    return [dict(zip(headers, r)) for r in data]


def checks_fired(built):
    return {f["check"]: f for f in built[1]["findings"]}


def test_wlans(built):
    w = {r["WLAN ID"]: r for r in rows(built, "WLANs")}
    assert w[1]["Layer 2 Security"] == "WPA2" and "802.1X" in w[1]["AKM"]
    assert w[1]["Auth Servers"] == "192.0.2.50:1812, 192.0.2.51:1812"
    assert w[2]["Layer 3 Security"] == "web auth" and "198.51.100.20" in w[2]["Mobility Anchors"]
    assert w[4]["Encryption"] == "TKIP" and w[4]["PSK Set"] == "Yes"
    assert w[1]["Clients Now"] == 3 and w[3]["Clients Now"] == 0


def test_wlan_checks(built):
    fired = checks_fired(built)
    assert "WLAN 4 lab-scanners" in fired[wl.WEP_TKIP]["items"]
    assert "WLAN 6 lab-legacy-wep" in fired[wl.WEP_TKIP]["items"]
    assert fired[wl.WEP_TKIP]["rating"] == checks.HIGH
    # The disabled open WLAN does not count.
    assert wl.OPEN_WLAN not in fired
    # Scanners and IoT WLANs are expected to use a PSK.
    assert wl.PSK_CORP not in fired
    assert "WLAN 5 lab-iot" in fired[wl.WPA3_PMF]["items"]
    # The anchored guest WLAN passes; the web-passthrough one has no anchor.
    assert fired[wl.GUEST_ANCHOR]["items"] == ["WLAN 6 lab-legacy-wep (not anchored)"]
    assert fired[wl.LOW_RATES]["items"] == ["1 Mbps", "2 Mbps", "5.5 Mbps", "11 Mbps"]
    assert "RF profile lab-rf-5g 80 MHz" in fired[wl.WIDE_CHANNELS]["items"]


def test_aps_radios_joins_clients(built):
    aps = {r["AP Name"]: r for r in rows(built, "Access Points")}
    a1, a2 = aps["lab-ap-01"], aps["lab-ap-02"]
    assert a1["Base Radio MAC"] == "00:11:22:aa:00:01"
    assert a1["Primary Controller"] == "lab-wlc-01 / 192.0.2.40"
    assert a1["Switch Port"] == "GigabitEthernet1/0/10" and a1["Switch In Wiremap"] == "Yes"
    assert a1["Clients 5 GHz"] == 2 and a1["Clients 2.4 GHz"] == 1
    assert a2["Power"] == "PoE low power" and a2["Last Date of Support"] == "2022-01-31"
    assert a2["Supported on Catalyst 9800"] == "No"
    radios = rows(built, "Radios")
    assert any(r["AP Name"] == "lab-ap-01" and r["Band"] == "5" and r["Channel"] == 36
               for r in radios)
    joins = rows(built, "AP Join Issues")
    assert [j["AP MAC"] for j in joins] == ["00:11:22:aa:00:03"]
    assert joins[0]["Failure Reason"] == "Regulatory domain check failed"
    clients = rows(built, "Clients")
    assert sum(r["Clients"] for r in clients) == 5
    assert {r["Security"] for r in clients if r["WLAN ID"] == 2} == {"web auth"}
    fired = checks_fired(built)
    assert fired[checks.AP_LDOS]["items"] == ["lab-ap-02 (AIR-CAP2602I-A-K9)"]
    assert any("lab-ap-02" in i for i in fired[checks.AP_9800]["items"])
    assert fired[wl.POE_LOW]["items"] == ["lab-ap-02"]
    assert any("lab-ap-02" in i for i in fired[wl.SLOW_UPLINK]["items"])
    assert wl.JOIN_FAIL in fired and wl.MIXED_IMAGES in fired


def test_rf_and_groups(built):
    rf = {r["Band"]: r for r in rows(built, "RF Global")}
    assert rf["5"]["DCA Mode"] == "auto" and "52" in rf["5"]["DFS Channels in List"]
    assert rf["2.4"]["Mandatory Rates"] == "1, 2, 5.5, 11"
    profiles = {r["RF Profile"]: r for r in rows(built, "RF Profiles")}
    assert profiles["lab-rf-5g"]["AP Groups Using It"] == "lab-site-a"
    assert profiles["lab-rf-24g"]["Channel Width"] == "n/a"
    groups = rows(built, "AP Groups")
    assert {g["AP Group"] for g in groups} == {"lab-site-a", "default-group"}


def test_services_sheets(built):
    aaa = rows(built, "AAA Servers")
    r1 = next(r for r in aaa if r["Protocol"] == "RADIUS" and r["Use"] == "auth"
              and r["Index"] == 1)
    assert r1["Timeout %"] == round(100 * 30 / 1040, 2) and r1["Server Name"] == "lab-ise-01"
    assert any(r["Protocol"] == "TACACS+" for r in aaa)
    acls = {r["ACL"]: r for r in rows(built, "ACLs")}
    assert acls["lab-preauth"]["Rule Count"] >= 2
    assert acls["lab-guest-acl"]["Rule Count"] == "n/a"
    assert "FlexConnect lab-flex-01" in acls["lab-flex-acl"]["Applied To"]
    assert any(r["ACL"] == "lab-preauth" and r["Hits"] == 42 for r in rows(built, "ACL Rules"))
    sec = rows(built, "Security and WIPS")[0]
    assert sec["Malicious"] == 1 and sec["Infrastructure MFP"] == "No"
    mob = rows(built, "Mobility")
    assert any(r["Kind"] == "Peer" and r["Data Path"] == "Down" for r in mob)
    assert any(r["Kind"] == "Anchor" for r in mob)
    flex = rows(built, "FlexConnect")[0]
    assert flex["Group"] == "lab-flex-01" and flex["Master AP"] == "lab-ap-01"
    qos = {(r["Block"], r["Item"]) for r in rows(built, "QoS and Services")}
    assert ("QoS profile", "platinum") in qos and ("QoS map", "DSCP-to-UP") in qos
    assert any(b == "WLAN QoS" for b, _ in qos)
    mgmt = rows(built, "Management Plane")[0]
    assert mgmt["Telnet"] == "Yes" and mgmt["Default Communities"] == "public"
    assert mgmt["Management Auth Order"] == "local" and mgmt["Syslog Servers"] == ""
    certs = rows(built, "Certificates")
    assert any(c["Use"] == "web-admin" and c["Self-signed"] == "Yes" for c in certs)
    expired = [c for c in certs if isinstance(c["Days Left"], int) and c["Days Left"] < 0]
    assert expired


def test_services_checks(built):
    fired = checks_fired(built)
    assert fired[svc.RADIUS_TIMEOUTS]["rating"] == checks.MEDIUM
    assert fired[svc.NO_TACACS]
    telnet = [f for f in built[1]["findings"] if f["check"] == svc.TELNET_HTTP]
    assert {f["rating"] for f in telnet} == {checks.HIGH}
    assert fired[svc.MGMT_WIRELESS] and fired[svc.SNMP_WEAK]["rating"] == checks.HIGH
    assert fired[svc.AUTO_CONTAIN] and fired[svc.MFP_OFF]["rating"] == checks.LOW
    assert fired[svc.MOBILITY_DOWN]["rating"] == checks.HIGH
    assert fired[svc.QOS_MAP_OFF]
    assert any(f["check"] == svc.CERT and f["rating"] == checks.HIGH
               for f in built[1]["findings"])
    assert any(f["check"] == checks.SYSLOG_NTP and "syslog" in f["description"]
               for f in built[1]["findings"])


def test_hygiene_and_relationships(built):
    hyg = {r["Item"]: r for r in rows(built, "Configuration Hygiene")}
    assert hyg["WLANs configured but disabled"]["List"] == "3 lab-open"
    assert "redundancy-management" not in hyg["Interfaces not used by any WLAN"]["List"]
    assert hyg["APs in default-group"]["List"] == "lab-ap-02"
    assert checks_fired(built)[wl.DEFAULT_GROUP]["items"] == ["lab-ap-02"]
    assert hyg["Same SSID with different security across controllers"]["Count"] == 0
    rel = rows(built, "Relationships")
    kinds = {r["Relationship"] for r in rel}
    assert {"uplink (CDP)", "AP access port (AP CDP)", "mobility peer", "anchor",
            "AAA server (RADIUS auth)", "management target (NTP)"} <= kinds
    ise = next(r for r in rel if r["Side B"].startswith("192.0.2.50:1812"))
    assert ise["Side B In Wiremap"] == "Yes"


def test_summary_totals(built):
    totals = {r["Check"]: r["Controllers Affected"] for r in rows(built, "Summary")
              if r["Severity"] == ""}
    assert totals["Clients 2.4 / 5 GHz"] == "2 / 3"
    assert totals["Mobility peers (up / down)"] == "1 / 3"
    assert totals["RADIUS servers"] == 3


def test_ap_topology_and_diagram():
    inv = _inventory()
    links = ap_links(inv)
    assert {(l["ap"], l["switch_port"]) for l in links} == {
        ("lab-ap-01", "GigabitEthernet1/0/10"), ("lab-ap-02", "GigabitEthernet1/0/11")}
    from app.reports.diagram_data import DiagramDataReport
    data = DiagramDataReport().generate_tabular_data(inv)
    devices = [r[0] for r in data["Devices"][1]]
    assert "lab-ap-01" in devices and "lab-ap-02" in devices
    l2 = [r for r in data["L2 Links"][1] if r[-1] == "wlc ap cdp"]
    assert len(l2) == 2
    from app.reports.topology_map import TopologyMapReport
    html = TopologyMapReport().generate(inv).decode()
    assert "lab-ap-01" in html


def test_workbook_has_no_secrets(built):
    inv = built[0]
    data = rep.WlcReport().generate_tabular_data(inv)
    text = json.dumps(inv) + json.dumps({k: v[1] for k, v in data.items()}, default=str)
    for value in fx.SECRETS + fx.CLIENT_IDS:
        assert value not in text, value
