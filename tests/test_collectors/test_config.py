import pytest
from app.collectors.config import ConfigCollector


@pytest.fixture
def collector():
    return ConfigCollector()


def test_name_and_attrs(collector):
    assert collector.name == "config"
    assert collector.label
    assert collector.enabled_by_default is False


def test_get_commands_cisco_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert cmds == ["show running-config"]


def test_get_commands_juniper(collector):
    cmds = collector.get_commands("juniper_junos")
    assert cmds == ["show configuration"]


def test_get_commands_unknown(collector):
    cmds = collector.get_commands("some_unknown")
    assert cmds == ["show running-config"]


def test_parse_returns_raw_config(collector):
    config_text = "!\nhostname SW1\n!\ninterface Gi0/1\n ip address 10.1.1.1 255.255.255.0\n!"
    result = collector.parse({"show running-config": config_text}, "cisco_ios")
    assert result["config"] == config_text


def test_parse_empty_output(collector):
    result = collector.parse({"show running-config": ""}, "cisco_ios")
    assert result["config"] == ""
