"""Severity and calibration of L2 discovery findings."""
from app.reports.findings import OVERFIRE_TYPE
from app.reports.l2_discovery import _build_findings


def _vlan(name="", priority="", consistent=True, root_device=""):
    return {"best_name": name, "names": {}, "root_priority": priority,
            "root_device": root_device, "consistent": consistent,
            "root_bridges": {}}


def _inv(n):
    return {"devices": {f"SW-{i}": {} for i in range(n)}}


def _svi(prefix):
    return [{"hostname": "SW-0", "ip": "10.0.0.1", "prefix": prefix}]


def _by_title(findings, needle):
    return [f for f in findings if needle in f["title"]]


def test_every_finding_has_severity_and_type():
    vlans = {"10": _vlan("USERS", priority="32778", root_device="SW-0"),
             "20": _vlan(consistent=False)}
    vlans["20"]["root_bridges"] = {"aaaa.bbbb.cccc": {"SW-0"},
                                   "dddd.eeee.ffff": {"SW-1"}}
    blocked = [{"switch": "SW-1", "interface": "Gi0/2", "vlan_id": "10",
                "status": "BLK", "reason": ""}]
    findings = _build_findings(vlans, blocked, {"10": _svi("16")}, _inv(2))
    assert findings
    for f in findings:
        assert f["severity"] in ("Critical", "Warning", "Info")
        assert f["type"]
    assert _by_title(findings, "root bridge mismatch")[0]["severity"] == "Critical"
    assert _by_title(findings, "default STP priority")[0]["severity"] == "Warning"


def test_large_subnet_warning_for_user_vlan():
    findings = _build_findings({"10": _vlan("USERS")}, [], {"10": _svi("16")}, _inv(1))
    f = _by_title(findings, "/16 subnet")[0]
    assert f["severity"] == "Warning"
    assert f["type"] == "Large subnet"


def test_large_subnet_info_for_infra_vlans():
    for name in ("ACI-INFRA", "vtep-pool", "Fabric_Underlay", "aci_tep"):
        findings = _build_findings({"3967": _vlan(name)}, [],
                                   {"3967": _svi("16")}, _inv(1))
        f = _by_title(findings, "/16 subnet")[0]
        assert f["severity"] == "Info", name
        assert "fabric infrastructure" in f["description"]


def test_large_subnet_aci_needs_whole_token():
    findings = _build_findings({"30": _vlan("FACILITIES")}, [],
                               {"30": _svi("16")}, _inv(1))
    assert _by_title(findings, "/16 subnet")[0]["severity"] == "Warning"


def test_blocked_port_severity():
    blocked = [
        {"switch": "SW-1", "interface": "Gi0/2", "vlan_id": "10",
         "status": "BLK", "reason": ""},
        {"switch": "SW-1", "interface": "Gi0/3", "vlan_id": "10",
         "status": "BKN", "reason": "*PVST_Inc"},
    ]
    findings = _build_findings({}, blocked, {}, _inv(2))
    assert _by_title(findings, "Gi0/2")[0]["severity"] == "Info"
    assert _by_title(findings, "Gi0/3")[0]["severity"] == "Warning"


def test_overfire_note_for_default_priority_everywhere():
    vlans = {str(v): _vlan(priority=str(32768 + v), root_device=f"SW-{v}")
             for v in range(1, 5)}
    findings = _build_findings(vlans, [], {}, _inv(4))
    meta = [f for f in findings if f["type"] == OVERFIRE_TYPE]
    assert [m["about"] for m in meta] == ["Default STP priority on root"]


def test_findings_sheets_show_severity(sample_inventory):
    import io
    from openpyxl import load_workbook
    from app.reports.l2_discovery import L2DiscoveryReport
    report = L2DiscoveryReport()
    sheets = report.generate_tabular_data(sample_inventory)
    assert sheets["Findings"][0][0] == "Severity"
    assert sheets["Findings (detail)"][0][4] == "Severity"
    wb = load_workbook(io.BytesIO(report.generate(sample_inventory)))
    assert wb["Findings"].cell(row=1, column=1).value == "Severity"
    assert wb["Findings (detail)"].cell(row=1, column=5).value == "Severity"


def test_l2_findings_sheet_is_aggregated(sample_inventory):
    from app.reports.l2_discovery import L2DiscoveryReport
    sheets = L2DiscoveryReport().generate_tabular_data(sample_inventory)
    headers, _rows = sheets["Findings"]
    assert headers == ["Severity", "Finding", "Details", "Device count", "Devices"]
    dheaders, _drows = sheets["Findings (detail)"]
    assert dheaders == ["Hostname", "Site/Location", "Port", "Notes", "Severity"]
