import pytest
from app.collectors import get_registry, get_collector


def test_registry_returns_dict():
    reg = get_registry()
    assert isinstance(reg, dict)


def test_registry_keys_are_collector_names():
    reg = get_registry()
    for name, collector in reg.items():
        assert name == collector.name


def test_get_collector_returns_none_for_unknown():
    assert get_collector("nonexistent_collector_xyz") is None
