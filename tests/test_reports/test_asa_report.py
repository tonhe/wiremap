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


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    import app.collectors.asa as mod
    monkeypatch.setattr(mod, "redact_secrets_enabled", lambda: True)


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
    asav.update({"show version": fx.VERSION_ASAV, "show ntp status": fx.NTP_UNSYNCED,
                 "show startup-config | include Cryptochecksum": fx.STARTUP_SAME,
                 "show running-config": "hostname LAB-VFW-01\nenable password 8Ry2YjIyt7RRXU24 encrypted\n",
                 "show crashinfo | include Saved|Traceback|Thread Name|ERROR": ""})
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
    return build_tabular(inv)


def test_registered_and_generates_only_with_asa_data(inv):
    report = get_registry()["asa"]
    assert report.can_generate(inv)
    assert not report.can_generate({"devices": {"LAB-SW-01": {"collector_data": {}}}})


def test_sheet_order_and_lead_columns(sheets):
    assert list(sheets) == ["Summary", "Devices", "Failover", "Interfaces", "Certificates",
                            "Management Plane", "Health and Capacity",
                            "Changes and Hygiene", "Collection Errors"]
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
    assert totals["Total units"] == 4 and totals["Total devices"] == 3
    assert totals["Total contexts"] == 2 and totals["NAT rules"] == 4
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
