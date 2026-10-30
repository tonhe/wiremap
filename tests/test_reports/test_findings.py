import pytest

from app.reports.findings import (
    CRITICAL, WARNING, INFO, OVERFIRE_TYPE,
    make_finding, overfire_check, count_by_severity,
)


def test_make_finding_defaults_type_to_title():
    f = make_finding("RTR-A", WARNING, "Single-homed BGP", "one peer")
    assert f == {
        "hostname": "RTR-A", "severity": "Warning",
        "title": "Single-homed BGP", "description": "one peer",
        "type": "Single-homed BGP",
    }


def test_make_finding_extra_fields_and_explicit_type():
    f = make_finding(None, INFO, "VLAN 10 -- /16 subnet", "d",
                     finding_type="large-subnet", vlan="10")
    assert f["hostname"] == ""
    assert f["type"] == "large-subnet"
    assert f["vlan"] == "10"


def test_make_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        make_finding("RTR-A", "High", "t", "d")


def _many(ftype, hosts, sev=WARNING):
    return [make_finding(h, sev, ftype, "d") for h in hosts]


def test_overfire_adds_meta_note_above_threshold():
    findings = _many("Dead ACL", ["R1", "R2", "R3"])
    overfire_check(findings, device_count=4)
    meta = [f for f in findings if f["type"] == OVERFIRE_TYPE]
    assert len(meta) == 1
    assert meta[0]["severity"] == INFO
    assert meta[0]["about"] == "Dead ACL"
    assert "3 of 4" in meta[0]["description"]


def test_overfire_counts_devices_not_findings():
    # Ten findings on one device out of four is not over-firing.
    findings = _many("Dead ACL", ["R1"] * 10)
    overfire_check(findings, device_count=4)
    assert not any(f["type"] == OVERFIRE_TYPE for f in findings)


def test_overfire_at_threshold_is_quiet():
    findings = _many("Dead ACL", ["R1", "R2"])
    overfire_check(findings, device_count=4)
    assert not any(f["type"] == OVERFIRE_TYPE for f in findings)


def test_overfire_below_min_devices_is_quiet():
    findings = _many("Dead ACL", ["R1", "R2", "R3"])
    overfire_check(findings, device_count=3)
    assert not any(f["type"] == OVERFIRE_TYPE for f in findings)


def test_overfire_ignores_fabric_wide_findings():
    findings = _many("STP root mismatch", ["", "", "", ""], sev=CRITICAL)
    overfire_check(findings, device_count=4)
    assert not any(f["type"] == OVERFIRE_TYPE for f in findings)


def test_overfire_one_note_per_type():
    findings = _many("A", ["R1", "R2", "R3"]) + _many("B", ["R1", "R2", "R3", "R4"])
    overfire_check(findings, device_count=4)
    about = sorted(f["about"] for f in findings if f["type"] == OVERFIRE_TYPE)
    assert about == ["A", "B"]


def test_count_by_severity():
    findings = [make_finding("R", CRITICAL, "a", ""),
                make_finding("R", INFO, "b", ""),
                {"title": "legacy", "description": ""}]
    assert count_by_severity(findings) == {CRITICAL: 1, WARNING: 0, INFO: 2}
