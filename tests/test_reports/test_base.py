import pytest
from app.reports.base import BaseReport


class DummyReport(BaseReport):
    name = "dummy"
    label = "Dummy Report"
    description = "Test report"
    required_collectors = ["cdp_lldp"]
    supported_formats = ["xlsx"]

    def generate(self, inventory_data, fmt="xlsx"):
        return b"fake report bytes"


def test_base_report_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseReport()


def test_dummy_report_has_required_attrs():
    r = DummyReport()
    assert r.name == "dummy"
    assert r.required_collectors == ["cdp_lldp"]
    assert "xlsx" in r.supported_formats


def test_generate_returns_bytes():
    r = DummyReport()
    assert isinstance(r.generate({}), bytes)


def test_can_generate_checks_collectors():
    r = DummyReport()
    inventory_with = {"devices": {"SW1": {"collector_data": {"cdp_lldp": {}}}}}
    inventory_without = {"devices": {"SW1": {"collector_data": {"arp": {}}}}}
    assert r.can_generate(inventory_with) is True
    assert r.can_generate(inventory_without) is False


def test_can_generate_empty_inventory():
    r = DummyReport()
    assert r.can_generate({"devices": {}}) is False


def test_base_report_has_category():
    r = DummyReport()
    # DummyReport doesn't set category, so it should get the default
    assert r.category == "General"


def test_base_report_custom_category():
    class CategorizedReport(BaseReport):
        name = "cat_test"
        label = "Cat Test"
        description = "Test"
        category = "Testing"
        required_collectors = []
        def generate(self, inventory_data, fmt="xlsx"):
            return b""

    r = CategorizedReport()
    assert r.category == "Testing"


from app.reports import get_registry

VALID_CATEGORIES = [
    "Discovery & Topology",
    "Layer 2 Analysis",
    "Layer 3 & Routing",
    "Compliance & Config",
]


def test_all_reports_have_valid_category():
    registry = get_registry()
    assert len(registry) > 0
    for name, report in registry.items():
        assert report.category in VALID_CATEGORIES, (
            f"Report '{name}' has invalid category '{report.category}'"
        )
