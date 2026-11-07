"""ASA report: sheets, n/a handling, failover pairs and the assessment checks,
built from synthetic units collected through the real collector."""
import io
import json

import pytest
from openpyxl import load_workbook

from app.collectors.asa import AsaCollector
from app.reports import get_registry
from app.reports.asa import AsaReport, analyze, build_tabular
from tests.test_collectors import asa_fixtures as fx
from tests.test_collectors import asa_policy_fixtures as pfx
from tests.test_collectors import asa_net_fixtures as nfx

HW_EOX = {"FPR-2130": {"end_of_sale": "2025-01-01", "end_of_sw_maintenance": "2026-01-01",
                      "last_date_of_support": "2030-01-31", "bulletin_number": "EOL-LAB",
                      "bulletin_url": "https://example.invalid/eol"}}
SW_EOX = {"9.16(4)|ASA": {"end_of_sale": "2024-01-01", "last_date_of_support": "2026-06-30"}}


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    import app.collectors.asa as mod
    import app.reports.asa_network as net
    monkeypatch.setattr(mod, "redact_secrets_enabled", lambda: True)
    monkeypatch.setattr(net, "eox_records", lambda inv: (HW_EOX, SW_EOX))


def _device(outputs, role, hostname, contexts=None, ip="192.0.2.10", timeout=()):
    fake = fx.FakeAsa(outputs, contexts=contexts, timeout=timeout)
    data = AsaCollector().collect(fake, "cisco_asa", context={"asa_unit": {"role": role}})
    return {"hostname": hostname, "device_type": "cisco_asa", "reached_ip": ip,
            "asa_unit": {"hostname": hostname.split("/")[0], "role": role},
            "collector_data": {"asa": data}}


def _inventory():
    active = fx.single_mode_outputs(fx.FAILOVER_ACTIVE)
    standby = fx.single_mode_outputs(fx.FAILOVER_ACTIVE.replace(
        "This host: Primary - Active", "This host: Secondary - Standby Ready").replace(
        "Other host: Secondary - Standby Ready", "Other host: Primary - Active").replace(
        "Failover unit Primary", "Failover unit Secondary"))
    asav = fx.single_mode_outputs()
    asav.update({"show version": fx.VERSION_ASAV, "show inventory": "", "show ntp status": fx.NTP_UNSYNCED,
                 "show startup-config | include Cryptochecksum": fx.STARTUP_SAME,
                 "show running-config": "hostname LAB-VFW-01\nenable password 8Ry2YjIyt7RRXU24 encrypted\n",
                 "show crashinfo | include Saved|Traceback|Thread Name|ERROR": ""})
    policy = fx.single_mode_outputs()
    policy.update({"show running-config": pfx.POLICY_CONFIG,
                   "show access-list": pfx.SHOW_ACCESS_LIST,
                   "show nat detail": pfx.NAT_DETAIL})
    net = fx.single_mode_outputs()
    net.update({"show running-config": nfx.VPN_CONFIG, "show route": nfx.SHOW_ROUTE,
                "show route summary": nfx.ROUTE_SUMMARY, "show ospf neighbor": nfx.OSPF_NEIGHBOR,
                "show ospf interface brief": nfx.OSPF_INTERFACE_BRIEF,
                "show bgp summary": nfx.BGP_SUMMARY, "show bgp neighbors": nfx.BGP_NEIGHBORS,
                "show track": nfx.SHOW_TRACK, "show vpn-sessiondb detail l2l": nfx.L2L_DETAIL,
                "show vpn-sessiondb anyconnect": nfx.ANYCONNECT,
                "show ip local pool": nfx.IP_LOCAL_POOL,
                "show nat detail": "", "show interface": ""})
    multi = fx.single_mode_outputs()
    multi.update({"show mode": fx.MODE_MULTIPLE, "show context": fx.CONTEXTS})
    contexts = {"admin": {"show running-config": "hostname admin\n"},
                "lab-ctx-a": {"show running-config": fx.CONTEXT_CONFIG,
                              "show interface ip brief": fx.IP_BRIEF}}
    return {"devices": {
        "LAB-FW-01": _device(active, "active", "LAB-FW-01"),
        "LAB-FW-01/stby": _device(standby, "standby", "LAB-FW-01/stby", ip="192.0.2.11"),
        "LAB-VFW-01": _device(asav, "standalone", "LAB-VFW-01", ip="192.0.2.12",
                              timeout=["show route"]),
        "LAB-CTX-01": _device(multi, "standalone", "LAB-CTX-01", contexts=contexts,
                              ip="192.0.2.13"),
        "LAB-PFW-01": _device(policy, "standalone", "LAB-PFW-01", ip="192.0.2.14"),
        "LAB-NFW-01": _device(net, "standalone", "LAB-NFW-01", ip="192.0.2.15"),
        "LAB-RTR-01": {"hostname": "LAB-RTR-01", "collector_data": {"interfaces": {
            "parsed": {"ip_interfaces": [{"interface": "Gi0/0",
                                            "ip_address": "10.0.0.2"}]}}}},
        "LAB-SW-01": {"hostname": "LAB-SW-01", "collector_data": {}},
    }, "params": {}}


def _rows(sheets, name):
    headers, rows = sheets[name]
    return [dict(zip(headers, r)) for r in rows]


@pytest.fixture(scope="module")
def inv():
    import app.collectors.asa as mod
    original = mod.redact_secrets_enabled
    mod.redact_secrets_enabled = lambda: True
    try:
        return _inventory()
    finally:
        mod.redact_secrets_enabled = original


@pytest.fixture(scope="module")
def sheets(inv):
    import app.reports.asa_network as net
    original = net.eox_records
    net.eox_records = lambda data: (HW_EOX, SW_EOX)
    try:
        return build_tabular(inv)
    finally:
        net.eox_records = original


def test_registered_and_generates_only_with_asa_data(inv):
    report = get_registry()["asa"]
    assert report.can_generate(inv)
    assert not report.can_generate({"devices": {"LAB-SW-01": {"collector_data": {}}}})


def test_sheet_order_and_lead_columns(sheets):
    assert list(sheets) == [
        "Summary", "Devices", "Lifecycle", "Failover", "Interfaces",
        "Zones and Reachability", "Routes Summary", "Static Routes", "Routing Neighbours",
        "Access Lists", "ACL Lines", "Objects", "NAT", "Site-to-site VPN",
        "Remote Access VPN", "VPN Sessions", "Certificates", "Management Plane",
        "Health and Capacity", "Changes and Hygiene", "Relationships", "Collection Errors"]
    for name, (headers, _) in sheets.items():
        if name != "Summary":
            assert headers[:3] == ["Hostname", "Context", "Site"], name


def test_devices_one_row_per_unit_and_context(sheets):
    rows = _rows(sheets, "Devices")
    keys = [(r["Hostname"], r["Context"], r["Unit Role"]) for r in rows]
    assert ("LAB-FW-01", "", "Active") in keys and ("LAB-FW-01", "", "Standby") in keys
    assert ("LAB-CTX-01", "admin", "Standalone") in keys
    assert ("LAB-CTX-01", "lab-ctx-a", "Standalone") in keys
    fw = next(r for r in rows if r["Unit Role"] == "Active")
    assert fw["Site"] == "LAB"
    assert fw["Model"] == "FPR-2130" and fw["Serial Number"] == "JAD00000AAA"
    assert fw["Platform Type"] == "Firepower running ASA"
    assert fw["Failover Role"] == "Primary" and fw["Failover State"] == "Active"
    assert fw["CPU 5 min %"] == 72 and fw["Conns Platform Max"] == 100000
    assert fw["ACL Elements"] == 15 and fw["NAT Rules"] == 2
    assert fw["S2S Configured"] == 2 and fw["S2S Up"] == 1
    assert fw["AnyConnect Active"] == 12 and fw["AnyConnect Licence"] == "250"
    assert fw["Config Saved"] == "No" and fw["Collected At (UTC)"] == "2026-11-07T14:22:31Z"
    assert "Security Contexts 2" in fw["Licence"]
    # A standby unit's traffic counters were not collected: n/a, not blank.
    stby = next(r for r in rows if r["Unit Role"] == "Standby")
    assert stby["ACL Elements"] == "n/a" and stby["Failover Role"] == "Secondary"
    asav = next(r for r in rows if r["Hostname"] == "LAB-VFW-01")
    assert asav["Platform Type"] == "ASAv" and asav["ASAv Entitlement"] == "ASAv30"
    assert asav["Failover Role"] == "Standalone" and asav["Failover State"] == "n/a"


def test_failover_pair_row(sheets):
    [row] = _rows(sheets, "Failover")
    assert row["Pair Name"] == "LAB-FW"
    assert row["Primary Hostname"] == "LAB-FW-01"
    assert row["Secondary Hostname"] == "LAB-FW-01/stby"
    assert row["Secondary Serial"] == "JAD00000AAB"
    assert row["Currently Active"] == "Primary"
    assert row["Last Failover Reason"] == "Negotiation -> Just Active: No Active unit found"
    assert row["Failovers in History"] == 1
    assert row["Stateful Link State"] == "down"
    assert row["Interfaces Failed or Waiting"] == "dmz (Failed, Waiting)"
    assert row["Version Match"] == "No" and row["Licence Match"] == "Yes"
    assert row["Failover Key Set"] == "Yes"


def test_interfaces_certificates_management(sheets):
    intf = {(r["Hostname"], r["Interface"]): r for r in _rows(sheets, "Interfaces")}
    assert not any(h == "LAB-FW-01" and r["Context"] for (h, _), r in intf.items())
    out = intf[("LAB-FW-01", "GigabitEthernet0/0")]
    assert out["Standby IP"] == "198.51.100.3" and out["Monitored for Failover"] == "Yes"
    assert out["Counters Cleared"] == "n/a" and out["Input Errors"] == 500
    assert intf[("LAB-FW-01", "GigabitEthernet0/1")]["Port-channel Member Of"] == "Port-channel1"
    assert out["Same-security Permitted"] == "inter"
    certs = _rows(sheets, "Certificates")
    ident = next(c for c in certs if c["Hostname"] == "LAB-FW-01" and c["Type"] == "Identity")
    assert ident["Days to Expiry"] == 23 and ident["Expired or < 90 Days"] == "Yes"
    assert ident["Used By"] == "ssl outside, tunnel-group LAB-RA"
    mgmt = {(r["Hostname"], r["Context"]): r for r in _rows(sheets, "Management Plane")}
    fw = mgmt[("LAB-FW-01", "")]
    assert fw["Telnet Enabled"] == "Yes" and fw["Telnet From"] == "10.0.0.0/8 (inside)"
    assert fw["SNMP Versions"] == "v1, v2c, v3"
    assert fw["AAA Servers"] == "LAB-TACACS tacacs+ 10.0.0.20 (inside) FAILED"
    assert fw["Local Usernames"] == 2 and fw["Local Privilege Levels"] == "15, 5"
    assert mgmt[("LAB-CTX-01", "lab-ctx-a")]["Telnet From"] == "0.0.0.0/0 (outside)"
    assert ("LAB-FW-01", "") in mgmt and len([k for k in mgmt if k[0] == "LAB-FW-01"]) == 1


def test_health(sheets):
    rows = {(r["Hostname"], r["Unit Role"]): r for r in _rows(sheets, "Health and Capacity")}
    assert ("LAB-FW-01", "Standby") in rows
    fw = rows[("LAB-FW-01", "Active")]
    assert fw["Conns % of Limit"] == 80.0
    assert fw["Interface with Most Errors"] == "GigabitEthernet0/0 (500 errors, 0.5%)"
    assert fw["Blocks with Low Watermark 0"] == "1550"
    assert fw["Crashinfo Present"] == "Yes" and fw["Crash Thread"] == "DATAPATH-1-1826"
    assert fw["Critical Logs (level 1-3)"] == 2


def _checks(analysis, host=None):
    return {(f["check"], f["rating"]) for f in analysis["findings"]
            if host is None or f["hostname"] == host}


def test_checks(inv):
    analysis = analyze(inv)
    fw = _checks(analysis, "LAB-FW-01")
    for check, rating in [
            ("Telnet enabled", "High"),
            ("SSH or ASDM open from any / outside", "High"),
            ("No AAA (LOCAL only) for SSH", "Medium"),
            ("No command authorization or accounting", "Low"),
            ("SNMP v1/v2c in use", "Medium"),
            ("Logging trap level higher than informational", "Low"),
            ("CPU 5 min > 70% or memory > 80%", "Medium"),
            ("Conns > 70% of platform limit", "Medium"),
            ("Running config not saved", "Low"),
            ("Crashinfo in last 12 months", "Medium"),
            ("Certificates expiring within 90 days", "Medium"),
            ("HA version or licence mismatch", "Medium"),
            ("Failover link or monitored interface down", "Medium"),
            ("Interfaces with errors > 0.1% of packets", "Low")]:
        assert (check, rating) in fw, check
    assert ("Default credentials / enable password not set", "High") not in fw
    asav = _checks(analysis, "LAB-VFW-01")
    assert ("No NTP sync", "Medium") in asav
    assert ("Default credentials / enable password not set", "High") in asav
    assert ("No syslog host", "Medium") in asav
    # The standby unit is not reported for policy it only mirrors.
    stby = _checks(analysis, "LAB-FW-01/stby")
    assert ("Telnet enabled", "High") not in stby
    ctx = [f for f in analysis["findings"] if f["hostname"] == "LAB-CTX-01"
           and f["check"] == "Telnet enabled"]
    assert ctx and ctx[0]["context"] == "lab-ctx-a"


def test_summary_and_hygiene(sheets):
    summary = _rows(sheets, "Summary")
    telnet = next(r for r in summary if r["Check"] == "Telnet enabled")
    assert telnet["Severity"] == "High" and telnet["Devices Affected"] == 2
    assert telnet["Device List"] == "LAB-CTX-01, LAB-FW-01"
    ratings = [r["Severity"] for r in summary if r["Severity"]]
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    assert ratings == sorted(ratings, key=order.get)
    totals = {r["Check"]: r["Devices Affected"] for r in summary if not r["Severity"]}
    assert totals["Total units"] == 6 and totals["Total devices"] == 5
    assert totals["Total contexts"] == 2 and totals["NAT rules"] == 8
    hygiene = _rows(sheets, "Changes and Hygiene")
    tel = next(r for r in hygiene if r["Check"] == "Telnet enabled"
               and r["Context"] == "lab-ctx-a")
    assert tel["Config Lines"] == "telnet 0.0.0.0 0.0.0.0 outside"


def test_collection_errors_skip_unsupported_commands(sheets):
    errors = _rows(sheets, "Collection Errors")
    assert [(r["Hostname"], r["Command"], r["Kind"]) for r in errors] == [
        ("LAB-VFW-01", "show route", "failed")]


def test_no_secret_reaches_any_output(inv):
    report = AsaReport()
    for fmt in ("json", "csv", "xml"):
        assert b"Plain-ctx-secret" not in report.generate(inv, fmt)
    assert "Plain-ctx-secret" not in json.dumps(inv)


def test_xlsx_opens_with_every_sheet(inv):
    wb = load_workbook(io.BytesIO(AsaReport().generate(inv, "xlsx")))
    assert wb.sheetnames[0] == "Summary" and "Health and Capacity" in wb.sheetnames
    assert wb["Devices"].freeze_panes == "A2"


def _pfw(sheets, name):
    return [r for r in _rows(sheets, name) if r["Hostname"] == "LAB-PFW-01"]


def test_access_list_summary(sheets):
    acls = {r["ACL Name"]: r for r in _pfw(sheets, "Access Lists")}
    out = acls["LAB-OUTSIDE-IN"]
    assert out["Bound To"] == "outside in" and out["Lines (Config)"] == 7
    assert out["Elements (Expanded)"] == 9
    assert (out["Permit Lines"], out["Deny Lines"]) == (5, 1)
    assert out["Zero-hit Lines"] == 3 and out["Any-any Permit Lines"] == 1
    assert out["Remarks"] == 1 and out["Log Lines"] == 1 and out["Inactive Lines"] == 1
    assert out["Shadow Check"] == "done"
    assert acls["LAB-ORPHAN"]["Bound To"] == "unbound"
    assert acls["LAB-ORPHAN"]["Elements (Expanded)"] == "n/a"


def test_acl_lines(sheets):
    lines = {(r["ACL Name"], r["Line"]): r for r in _pfw(sheets, "ACL Lines")}
    first = lines[("LAB-OUTSIDE-IN", 2)]
    assert first["Destination Expanded"] == "10.1.0.10/32; 10.1.0.11/32; 10.3.0.0/16"
    assert first["Ports Expanded"] == "tcp 80; tcp 443"
    assert first["Hit Count"] == 12 and first["Hash"] == "0x11111111"
    assert first["Remark Above"] == "allow the web servers"
    assert lines[("LAB-OUTSIDE-IN", 3)]["Flags"] == "redundant by line 2, zero hits"
    assert lines[("LAB-OUTSIDE-IN", 4)]["Flags"] == "shadowed by line 2, zero hits"
    assert lines[("LAB-OUTSIDE-IN", 5)]["Flags"] == "any-port, zero hits"
    assert lines[("LAB-OUTSIDE-IN", 6)]["Flags"] == "any-any"
    assert lines[("LAB-OUTSIDE-IN", 7)]["Time-range / Inactive"] == "LAB-HOURS inactive"
    assert lines[("LAB-ORPHAN", 1)]["Hit Count"] == "n/a"


def test_objects_and_nat(sheets):
    objs = {r["Name"]: r for r in _pfw(sheets, "Objects")}
    assert objs["LAB-UNUSED"]["Unused"] == "Yes"
    assert objs["LAB-WEB-COPY"]["Duplicate Of"] == "LAB-WEB"
    assert objs["LAB-SERVERS"]["Referenced By"] == "ACL LAB-OUTSIDE-IN"
    assert objs["LAB-WEB-PORTS"]["Expanded Prefixes or Ports"] == "tcp 80; tcp 443"
    nat = {(r["Section"], r["Rule"]): r for r in _pfw(sheets, "NAT")}
    static = nat[(2, 1)]
    assert static["Type"] == "static" and static["Public IP Exposed"] == "Yes"
    assert static["Zero Hits"] == "Yes"
    assert static["Real Source"] == "LAB-DMZ-WEB (10.1.0.20/32)"
    assert nat[(1, 1)]["Flags"] == "no-proxy-arp, route-lookup"


def test_policy_checks(inv):
    found = {(f["check"], f["rating"]): f for f in analyze(inv)["findings"]
             if f["hostname"] == "LAB-PFW-01"}
    anyany = found[("Any-any permit inbound on a lower-security interface", "High")]
    assert anyany["object"] == "LAB-OUTSIDE-IN line 6"
    assert anyany["config_lines"] == ["access-list LAB-OUTSIDE-IN extended permit ip any any"]
    assert ("Any-port permit to internal subnets", "Medium") in found
    zero = found[("Rules with zero hits", "Low")]
    assert "3 of 5 lines" in zero["description"] and "120 days" in zero["description"]
    shadow = found[("Shadowed or redundant ACL lines", "Low")]
    assert "1 shadowed (lines 4); 1 redundant (lines 3)" in shadow["description"]
    assert ("Unused objects / object-groups", "Info") in found
    nat = found[("Static NAT exposing internal hosts publicly with zero hits", "Medium")]
    assert "203.0.113.20/32" in nat["description"]
    # The inside ACL faces the highest-security interface: not inbound from lower.
    assert not any("LAB-INSIDE-IN" in f["object"] for f in found.values()
                   if f["check"].startswith("Any"))


def _nfw(sheets, name):
    return [r for r in _rows(sheets, name) if r["Hostname"] == "LAB-NFW-01"]


def test_lifecycle(sheets):
    rows = {(r["Hostname"]): r for r in _rows(sheets, "Lifecycle") if r["Context"] == ""}
    fw = rows["LAB-NFW-01"]
    assert fw["Model"] == "FPR-2130" and fw["Units of This Model"] == 5
    assert fw["Hardware Last Date of Support"] == "2030-01-31"
    assert fw["EoX Bulletin"] == "EOL-LAB https://example.invalid/eol"
    assert fw["Software Status"] == "Past end of support"
    assert fw["Months to LDoS"] == 38 and fw["Recommended Release"] == "n/a"
    assert rows["LAB-VFW-01"]["Hardware End of Sale"] == "n/a"


def test_site_to_site(sheets):
    rows = {r["Peer IP"]: r for r in _nfw(sheets, "Site-to-site VPN")}
    one = rows["203.0.113.9"]
    assert (one["Crypto Map"], one["Sequence"], one["Interface"]) == ("LAB-MAP", 10, "outside")
    assert one["Peer Description"] == "lab branch one"
    assert one["IKE Version"] == "ikev1" and one["Auth Method"] == "PSK"
    assert one["Local Protected Networks"] == "10.0.0.0/24"
    assert one["Remote Protected Networks"] == "172.16.50.0/24"
    assert one["Status"] == "Up" and one["Bytes Rx"] == 2000
    assert one["NAT Exemption Present"] == "Yes" and one["Weak Crypto"] == "Yes"
    two = rows["203.0.113.10"]
    assert two["Status"] == "Down" and two["NAT Exemption Present"] == "No"
    assert two["Auth Method"] == "certificate" and two["Weak Crypto"] == "No"


def test_remote_access_and_sessions(sheets):
    ra = {r["Tunnel-group"]: r for r in _nfw(sheets, "Remote Access VPN")}
    ldap = ra["LAB-RA"]
    assert ldap["Authentication"] == "AAA (LAB-LDAP, ldap)"
    assert ldap["Pool Size"] == 254 and ldap["Pool In Use"] == 2
    assert ldap["Split Tunnel Policy"] == "tunnelspecified"
    assert ldap["Split Tunnel Networks"] == "10.0.0.0/24"
    assert ldap["HostScan"] == "Yes" and ldap["DAP Records"] == "LAB-DAP"
    assert ldap["Active Sessions"] == 1
    assert ra["LAB-RA-CERT"]["Authentication"] == "certificate"
    sessions = _nfw(sheets, "VPN Sessions")
    assert [r["Assigned IP"] for r in sessions] == ["10.10.0.5", "10.10.0.6"]
    assert "lab-person" not in repr(sheets) and "198.51.100.50" not in repr(sheets)


def test_routing_sheets(sheets):
    [summary] = _nfw(sheets, "Routes Summary")
    assert (summary["Static"], summary["OSPF"], summary["OSPF E2"], summary["BGP"]) == (2, 2, 1, 1)
    assert summary["Default Route Next Hop"] == "198.51.100.1"
    assert summary["Floating Statics"] == 1 and summary["Tracked Statics"] == 1
    statics = _nfw(sheets, "Static Routes")
    tracked = statics[0]
    assert tracked["SLA Target"] == "198.51.100.1 (outside)" and tracked["Track State"] == "Up"
    assert tracked["In RIB"] == "Yes" and statics[1]["In RIB"] == "No"
    nbrs = {(r["Protocol"], r["Neighbour IP"]): r for r in _nfw(sheets, "Routing Neighbours")}
    ospf = nbrs[("OSPF", "10.0.0.2")]
    assert ospf["Area"] == "0" and ospf["Authentication Configured"] == "Yes"
    assert ospf["Redistribution into Protocol"] == (
        "static (no route-map), connected (route-map LAB-RM)")
    bgp = nbrs[("BGP", "203.0.113.1")]
    assert (bgp["Prefixes Received"], bgp["Prefixes Sent"]) == (5, 3)
    assert bgp["Authentication Configured"] == "No"


def test_zones_and_relationships(sheets):
    zones = {r["Nameif"]: r for r in _nfw(sheets, "Zones and Reachability")}
    inside = zones["inside"]
    assert inside["Connected Subnets"] == "10.0.0.0/24"
    # Summarised: 10.6.0.0/16 and 10.7.0.0/16 collapse into one /15.
    assert inside["Routed Subnets Behind It"] == "10.5.0.0/16; 10.6.0.0/15"
    assert inside["Route Count"] == 4 and inside["Default Route via This Interface"] == "No"
    assert zones["outside"]["Default Route via This Interface"] == "Yes"
    rel = _rows(sheets, "Relationships")
    kinds = {(r["Hostname"], r["Relationship"], r["Device B"]) for r in rel}
    assert ("LAB-FW-01", "failover pair", "LAB-FW-01/stby") in kinds
    assert ("LAB-NFW-01", "same subnet", "LAB-RTR-01") in kinds
    assert ("LAB-NFW-01", "OSPF neighbour", "LAB-RTR-01") in kinds
    assert any(r["Relationship"] == "S2S tunnel" and r["IP B"] == "203.0.113.9" for r in rel)


def test_network_checks(inv):
    import app.reports.asa_network as net
    net_eox = net.eox_records
    net.eox_records = lambda data: (HW_EOX, SW_EOX)
    try:
        found = {(f["check"], f["rating"], f["object"]) for f in analyze(inv)["findings"]
                 if f["hostname"] == "LAB-NFW-01"}
    finally:
        net.eox_records = net_eox
    checks = {(c, r) for c, r, _ in found}
    assert ("Weak S2S crypto (DES/3DES/MD5/DH 1-2-5/IKEv1 aggressive)", "High",
            "203.0.113.9 (LAB-MAP 10)") in found
    assert ("SHA1 or DH 14 only", "Low", "203.0.113.10 (LAB-MAP 20)") in found
    assert ("S2S tunnels configured but down", "Low", "203.0.113.10 (LAB-MAP 20)") in found
    assert ("RA VPN without certificate or MFA", "High", "LAB-RA") in found
    assert ("RA VPN without certificate or MFA", "High", "LAB-RA-CERT") not in found
    assert ("RA split tunnel = tunnel all vs excluded", "Info") in checks
    assert ("Routing protocol without authentication", "Medium", "BGP 203.0.113.1") in found
    assert ("Routing protocol without authentication", "Medium", "OSPF 10.0.0.2") not in found
    assert ("Redistribution without route-map", "Medium", "router ospf 1") in found
    assert ("Software past end of support", "High") in checks
    assert ("Hardware past end of SW maintenance", "Medium") in checks
    assert ("Hardware past LDoS", "High") not in checks
