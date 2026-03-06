import pytest
from app.collectors.base import BaseCollector


class DummyCollector(BaseCollector):
    name = "dummy"
    label = "Dummy Collector"
    description = "Test collector"
    enabled_by_default = True

    def get_commands(self, device_type):
        if device_type == "cisco_ios":
            return ["show version"]
        return []

    def parse(self, raw_outputs, device_type):
        return {"version": raw_outputs.get("show version", "")}


def test_base_collector_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseCollector()


def test_dummy_collector_has_required_attrs():
    c = DummyCollector()
    assert c.name == "dummy"
    assert c.label == "Dummy Collector"
    assert c.enabled_by_default is True


def test_get_commands_returns_list():
    c = DummyCollector()
    cmds = c.get_commands("cisco_ios")
    assert cmds == ["show version"]
    assert c.get_commands("unknown_type") == []


def test_parse_returns_dict():
    c = DummyCollector()
    result = c.parse({"show version": "Cisco IOS 15.2"}, "cisco_ios")
    assert result == {"version": "Cisco IOS 15.2"}
