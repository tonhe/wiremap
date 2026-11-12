"""Cisco WLC report: sheets, n/a handling and checks, built from scans the wlc
collector produced from synthetic controller output."""
import io
import json

import openpyxl
import pytest

import app.collectors.wlc as wlc_mod
import app.reports.wlc as rep
from app.collectors.wlc import WlcCollector
from app.reports import wlc_checks as checks
from tests.test_collectors import wlc_fixtures as fx
from tests.test_collectors import wlc_platform_fixtures as pf

SSO_PAIR = dict(fx.CONTROLLER, **{
    "show inventory": pf.INVENTORY_5520,
    "show boot": pf.BOOT,
    "show license capacity": pf.LICENSE_CAPACITY,
    "show cpu": pf.CPU,
    "show redundancy summary": pf.REDUNDANCY_SUMMARY_SSO,
    "show redundancy detail": pf.REDUNDANCY_DETAIL,
    "show redundancy statistics": pf.REDUNDANCY_STATISTICS,
    "show redundancy timers": pf.REDUNDANCY_TIMERS,
    "show redundancy peer-route summary": pf.PEER_ROUTE,
    "show interface detailed management": pf.INTERFACE_DETAIL_MGMT,
    "show lag summary": pf.LAG_ON,
    "show stats port detailed 1": pf.PORT_STATS,
    "show cdp neighbors detail": pf.CDP_NEIGHBORS,
    "show time": pf.TIME_810,
    "show coredump summary": pf.COREDUMP_NONE,
    "show ap crash-file": pf.AP_CRASH_NONE,
    "show mobility summary": "Default Mobility Domain.......................... lab-mobility\n",
})

OLD_5508 = {
    "show sysinfo": pf.SYSINFO_85,
    "show inventory": pf.INVENTORY_5508,
    "show cpu": "Current CPU(s) load: 85%\n",
    "show redundancy summary": pf.REDUNDANCY_SUMMARY_OFF.replace(" (HA SKU)", ""),
    "show port summary": pf.PORT_SUMMARY_85,
    "show lag summary": pf.LAG_OFF,
    "show time": pf.TIME_NOT_SYNCED,
    "show coredump summary": pf.COREDUMP_PRESENT,
    "show ap crash-file": pf.AP_CRASH,
    "show ap summary": fx.AP_SUMMARY,
    "show ap config general lab-ap-01": "Primary Cisco Switch Name........ lab-wlc-02\n"
                                        "Secondary Cisco Switch Name...... Not Configured\n",
    "show license capacity": pf.LICENSE_CAPACITY.replace("500 ", "2   "),
}


class FakeConn:
    def __init__(self, outputs):
        self.outputs = outputs

    def send_command(self, cmd, **kwargs):
        return self.outputs.get(cmd, "Incorrect usage. Use the '?' or <TAB> key to list commands.")


def _device(outputs, ip):
    result = WlcCollector().collect(FakeConn(outputs), "cisco_wlc")
    return {"device_type": "cisco_wlc", "reached_ip": ip,
            "collector_data": {"wlc": result}}


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(wlc_mod, "redact_secrets_enabled", lambda: True)
    monkeypatch.setattr(rep, "eox_records", lambda ctrls: (
        {"AIR-CT5508-K9": {"end_of_sale": "2018-04-01", "end_of_sw_maintenance": "2019-04-01",
                           "last_date_of_support": "2023-04-30"},
         "AIR-CAP2602I-A-K9": {"last_date_of_support": "2022-01-31"}},
        {}))


def _inventory():
    return {"timestamp": "2026-11-12T10:00:00Z", "devices": {
        "lab-wlc-01": _device(SSO_PAIR, "192.0.2.40"),
        "lab-wlc-02": _device(OLD_5508, "192.0.2.60"),
        "lab-sw-01": {"device_type": "cisco_xe", "collector_data": {}},
    }}


def _sheets():
    return rep.build_tabular(_inventory())


def _rows(sheet, headers=None):
    hdr, rows = _sheets()[sheet] if headers is None else headers
    return [dict(zip(hdr, r)) for r in rows]


def test_sheets_in_spec_order_and_lead_columns():
    sheets = _sheets()
    assert list(sheets) == [
        "Summary", "Controllers", "Lifecycle", "Redundancy", "Interfaces", "Ports and Uplinks",
        "WLANs", "AP Groups", "RF Global", "RF Profiles", "Radios", "Access Points",
        "AP Join Issues", "Clients", "AAA Servers", "ACLs", "ACL Rules", "Security and WIPS",
        "Mobility", "FlexConnect", "QoS and Services", "Management Plane", "Certificates",
        "Health and Capacity", "Configuration Hygiene", "Relationships", "Collection Errors"]
    for name, (headers, _) in sheets.items():
        if name not in ("Summary",):
            assert headers[:3] == ["Controller", "Site", "Model"], name


def test_controllers_sheet():
    rows = {r["Controller"]: r for r in _rows("Controllers")}
    a, b = rows["lab-wlc-01"], rows["lab-wlc-02"]
    assert a["Model"] == "AIR-CT5520-K9" and a["Serial"] == "FCW0000A001"
    assert a["AireOS Version"] == "8.10.185.0" and a["Primary Boot Image"].startswith("8.10.185.0")
    assert a["APs Joined"] == 2 and a["Licensed AP Count"] == 500 and a["AP Licence Used %"] == 0.4
    assert a["WLANs Configured"] == 3 and a["WLANs Enabled"] == 2
    assert a["Dynamic Interfaces"] == 2 and a["HA Mode"] == "SSO"
    assert a["Mobility Group"] == "lab-mobility"
    assert a["Management IP"] == "192.0.2.40" and a["Config Saved"] == "n/a"
    assert a["NTP State"].startswith("In sync")
    # Not collected reads n/a, never blank.
    assert b["WLANs Configured"] == "n/a" and b["Mobility Group"] == "n/a"
    assert b["HA Mode"] == "None" and b["AireOS Version"] == "8.5.182.0"


def test_lifecycle_rows_for_controllers_and_ap_models():
    rows = _rows("Lifecycle")
    ctrl = {r["Controller"]: r for r in rows if r["Type"] == "Controller"}
    assert ctrl["lab-wlc-02"]["Max AireOS"] == "8.5"
    assert ctrl["lab-wlc-02"]["Last Date of Support"] == "2023-04-30"
    assert ctrl["lab-wlc-01"]["End of Sale"] == "n/a"
    aps = {r["Model"]: r for r in rows if r["Type"] == "AP"}
    assert aps["AIR-CAP2602I-A-K9"]["Count"] == 2
    assert aps["AIR-CAP2602I-A-K9"]["Supported on Catalyst 9800"] == "No"
    assert aps["AIR-AP2802I-B-K9"]["Wi-Fi Generation"] == "5 Wave 2"
    assert all(r["CX Coverage"] == "n/a" for r in rows)


def test_redundancy_interfaces_ports_health():
    red = {r["Controller"]: r for r in _rows("Redundancy")}
    assert red["lab-wlc-01"]["Peer State"] == "STANDBY HOT"
    assert red["lab-wlc-01"]["Peer Redundancy Mgmt IP"] == "192.0.2.42"
    assert red["lab-wlc-02"]["Peer Redundancy Mgmt IP"] == "n/a"
    assert red["lab-wlc-02"]["Backup Controller on APs"] == "No"

    intf = {(r["Controller"], r["Interface"]): r for r in _rows("Interfaces")}
    mgmt = intf[("lab-wlc-01", "management")]
    assert mgmt["Gateway"] and mgmt["WLANs Using It"] == "1 lab-corp"
    assert intf[("lab-wlc-01", "lab-guest")]["Gateway"] == "n/a"
    assert intf[("lab-wlc-01", "lab-guest")]["WLANs Using It"] == "2 lab-guest"

    ports = {(r["Controller"], r["Port"]): r for r in _rows("Ports and Uplinks")}
    p1 = ports[("lab-wlc-01", 1)]
    assert p1["Neighbour Port"] == "TenGigabitEthernet1/0/1" and p1["Neighbour In Wiremap"] == "Yes"
    assert ports[("lab-wlc-01", 2)]["Neighbour Device"] == "lab-sw-02"
    assert ports[("lab-wlc-01", 2)]["Neighbour In Wiremap"] == "No"
    assert ports[("lab-wlc-02", 1)]["Neighbour Device"] == "n/a"
    assert isinstance(p1["Input Errors"], int)

    health = {r["Controller"]: r for r in _rows("Health and Capacity")}
    assert health["lab-wlc-02"]["CPU %"] == 85 and health["lab-wlc-02"]["Coredumps Present"] == "Yes"
    assert health["lab-wlc-01"]["AP Crash Files"] == 0


def test_checks_fire_on_the_old_controller_only():
    analysis = rep.analyze(_inventory())
    by = {}
    for f in analysis["findings"]:
        by.setdefault(f["controller"], set()).add(f["check"])
    old = by["lab-wlc-02"]
    assert {checks.CTRL_LDOS, checks.CTRL_RELEASE, checks.CAPACITY, checks.NO_REDUNDANCY,
            checks.LAG, checks.CRASH, checks.CPU_MEM, checks.SYSLOG_NTP} <= old
    assert not by.get("lab-wlc-01", set()) & {checks.PEER_DOWN, checks.NO_REDUNDANCY,
                                               checks.CPU_MEM, checks.CAPACITY}


def test_peer_not_standby_hot_is_high():
    outputs = dict(SSO_PAIR, **{"show redundancy summary": pf.REDUNDANCY_SUMMARY_SSO.replace(
        "STANDBY HOT", "UNKNOWN")})
    inv = {"devices": {"lab-wlc-01": _device(outputs, "192.0.2.40")}}
    found = [f for f in rep.analyze(inv)["findings"] if f["check"] == checks.PEER_DOWN]
    assert found and found[0]["rating"] == checks.HIGH


def test_summary_lists_checks_then_totals():
    rows = _rows("Summary")
    first = rows[0]
    assert first["Severity"] == "High"
    ldos = next(r for r in rows if r["Check"] == checks.CTRL_LDOS)
    assert ldos["Controllers Affected"] == 1 and "AIR-CT5508-K9" in ldos["Item List"]
    totals = {r["Check"]: r["Controllers Affected"] for r in rows if r["Severity"] == ""}
    assert totals["Controllers"] == 2 and totals["APs joined"] == 4
    assert totals["WLANs (enabled / disabled)"] == "2 / 1"
    assert "AIR-CAP2602I-A-K9 2" in totals["APs by model"]


def test_collection_errors_list_every_rejection():
    rows = _rows("Collection Errors")
    cmds = {(r["Controller"], r["Command"]): r["Kind"] for r in rows}
    assert cmds[("lab-wlc-01", "config paging disable")] == "not_applicable"
    assert ("lab-wlc-02", "show wlan summary") in cmds


def test_workbook_renders_without_secrets():
    report = rep.WlcReport()
    inv = _inventory()
    assert report.can_generate(inv)
    data = report.generate(inv, "xlsx")
    wb = openpyxl.load_workbook(io.BytesIO(data))
    assert wb.sheetnames[0] == "Summary" and "Controllers" in wb.sheetnames
    text = json.dumps(inv) + "".join(str(c.value) for ws in wb for row in ws.iter_rows()
                                     for c in row)
    for value in fx.SECRETS + fx.CLIENT_IDS:
        assert value not in text, value


def test_no_controllers_no_report():
    assert not rep.WlcReport().can_generate({"devices": {"lab-sw-01": {"collector_data": {}}}})
