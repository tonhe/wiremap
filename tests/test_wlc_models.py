"""Controller and AP lifecycle table."""
import pytest

from app import wlc_models as m


@pytest.mark.parametrize("pid,max_aireos", [
    ("AIR-CT5508-K9", "8.5"), ("AIR-CT5520-K9", "8.10"), ("AIR-CT8540-K9", "8.10"),
    ("air-ctvm-k9", "8.10"), ("UNKNOWN", ""), ("", ""),
])
def test_controller_facts(pid, max_aireos):
    assert m.controller_facts(pid)["max_aireos"] == max_aireos


@pytest.mark.parametrize("model,series,c9800,wifi", [
    ("AIR-CAP2602I-A-K9", "2602", "No", "4 (n)"),
    ("AIR-LAP1142N-A-K9", "1142", "No", "4 (n)"),
    ("AIR-CAP3702I-B-K9", "3702", "Up to 17.3", "5 Wave 1"),
    ("AIR-AP2802I-B-K9", "2802", "Yes", "5 Wave 2"),
    ("AIR-AP1815I-B-K9", "1815", "Yes", "5 Wave 2"),
    ("C9120AXI-B", "9120", "Yes", "6"),
    ("AIR-AP9999", "9999", "", ""),
])
def test_ap_facts(model, series, c9800, wifi):
    assert m.ap_series(model) == series
    facts = m.ap_facts(model)
    assert facts["c9800"] == c9800 and facts["wifi"] == wifi


def test_version_tuple_orders_releases():
    assert m.version_tuple("8.10.185.0") > m.version_tuple("8.5.182.0")
    assert m.version_tuple("") == ()


def test_custom_table(tmp_path):
    path = tmp_path / "models.yaml"
    path.write_text("controllers:\n  LAB-CT: {max_aireos: '9.9'}\n")
    table = m.load(str(path))
    assert m.controller_facts("LAB-CT-1", table)["max_aireos"] == "9.9"
    assert m.ap_facts("AIR-AP2802I", table)["wifi"] == ""
