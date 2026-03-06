from app.reports import get_registry, get_report


def test_registry_returns_dict():
    reg = get_registry()
    assert isinstance(reg, dict)


def test_registry_keys_are_report_names():
    reg = get_registry()
    for name, report in reg.items():
        assert name == report.name


def test_get_report_returns_none_for_unknown():
    assert get_report("nonexistent_report_xyz") is None
