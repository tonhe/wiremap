import pytest

from app.reports.findings import (
    CRITICAL, WARNING, INFO, OVERFIRE_TYPE,
    make_finding, overfire_check, count_by_severity,
    aggregate_findings, aggregate_rows, format_device_list, summary_count_rows,
    default_aggregate_key,
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


# --- aggregation (#26) ----------------------------------------------------

def _unref(host, rules):
    return make_finding(
        host, INFO, "Unreferenced ACL",
        f"ACL 'ACL-TEMPLATE-REDIRECT' ({rules} rules) is not referenced",
        aggregate_key="ACL 'ACL-TEMPLATE-REDIRECT' is unreferenced")


def test_aggregate_collapses_same_acl_across_devices():
    findings = [_unref(f"SW{i}", i) for i in range(1, 6)]
    agg = aggregate_findings(findings)
    assert len(agg) == 1
    assert agg[0]["device_count"] == 5
    assert agg[0]["details"] == "ACL 'ACL-TEMPLATE-REDIRECT' is unreferenced"
    assert agg[0]["devices"] == ["SW1", "SW2", "SW3", "SW4", "SW5"]


def test_aggregate_keeps_different_details_apart():
    findings = [make_finding("SW1", WARNING, "NAT pool", "pool A at 90%"),
                make_finding("SW2", WARNING, "NAT pool", "pool B at 95%")]
    assert len(aggregate_findings(findings)) == 2


def test_aggregate_keeps_severities_apart():
    findings = [make_finding("SW1", WARNING, "t", "d"),
                make_finding("SW2", INFO, "t", "d")]
    assert len(aggregate_findings(findings)) == 2


def test_default_key_strips_own_hostname():
    a = make_finding("SW1", INFO, "t", "sw1 has no  peers")
    b = make_finding("SW2", INFO, "t", "SW2 has no peers")
    assert default_aggregate_key(a) == "<device> has no peers"
    agg = aggregate_findings([a, b])
    assert len(agg) == 1
    assert agg[0]["device_count"] == 2


def test_aggregate_custom_key_fn():
    findings = [make_finding("SW1", INFO, "t", "x"),
                make_finding("SW2", INFO, "t", "y")]
    agg = aggregate_findings(findings, key_fn=lambda f: "same")
    assert len(agg) == 1


def test_aggregate_title_falls_back_to_type_when_titles_differ():
    findings = [make_finding("SW1", INFO, "VLAN 10 -- x", "d", finding_type="T"),
                make_finding("SW2", INFO, "VLAN 20 -- x", "d", finding_type="T")]
    assert aggregate_findings(findings)[0]["title"] == "T"


def test_aggregate_sorted_by_severity_then_device_count():
    findings = (
        [make_finding(f"SW{i}", INFO, "many", "d") for i in range(1, 5)]
        + [make_finding("SW1", INFO, "few", "d")]
        + [make_finding("SW1", WARNING, "warn", "d")]
        + [make_finding("SW2", CRITICAL, "crit", "d")]
    )
    assert [a["title"] for a in aggregate_findings(findings)] == [
        "crit", "warn", "many", "few"]


def test_aggregate_keeps_overfire_notes():
    findings = [_unref(f"SW{i}", 3) for i in range(1, 5)]
    overfire_check(findings, device_count=4)
    rows = aggregate_rows(findings)
    assert len(rows) == 2
    assert any(r[1].startswith("Check may be miscalibrated") and r[3] == 0
               for r in rows)


def test_device_list_truncates_after_ten():
    hosts = [f"SW{i:02d}" for i in range(1, 13)]
    assert format_device_list(hosts) == (
        ", ".join(hosts[:10]) + ", +2 more")
    assert format_device_list(["SW2", "SW1"]) == "SW1, SW2"


def test_aggregate_rows_columns():
    rows = aggregate_rows([_unref("SW2", 1), _unref("SW1", 2)])
    assert rows == [[INFO, "Unreferenced ACL",
                     "ACL 'ACL-TEMPLATE-REDIRECT' is unreferenced", 2, "SW1, SW2"]]


def test_summary_count_rows_raw_and_distinct():
    findings = [_unref(f"SW{i}", 1) for i in range(1, 4)]
    findings.append(make_finding("SW1", CRITICAL, "c", "d"))
    assert dict(summary_count_rows(findings)) == {
        "Critical Findings": 1, "Warning Findings": 0, "Info Findings": 3,
        "Critical Finding Types": 1, "Warning Finding Types": 0,
        "Info Finding Types": 1,
    }
