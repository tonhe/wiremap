from unittest.mock import MagicMock

import pytest
import app.settings as settings_module
from app.collectors.config import ConfigCollector

SECRET_CONFIG = (
    "hostname SW1\n"
    "enable secret 9 $9$abcdefgh\n"
    "snmp-server community s3cr3tComm RO 10\n"
    "tacacs-server host 192.0.2.5 key 7 0822455D0A16\n"
)


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_module, "DEFAULT_CONFIG_DIR", str(tmp_path))
    return tmp_path


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
    assert result["redacted"] is True


def test_parse_empty_output(collector):
    result = collector.parse({"show running-config": ""}, "cisco_ios")
    assert result["config"] == ""


def test_uses_custom_collect_so_raw_is_redacted(collector):
    assert collector.needs_custom_collect is True


def test_parse_redacts_secrets_by_default(collector):
    result = collector.parse({"show running-config": SECRET_CONFIG}, "cisco_ios")
    assert "s3cr3tComm" not in result["config"]
    assert "$9$" not in result["config"]
    assert "0822455D0A16" not in result["config"]
    assert "snmp-server community <REDACTED> RO 10" in result["config"]
    assert result["config"].count("\n") == SECRET_CONFIG.count("\n")
    assert result["redacted"] is True


def test_collect_redacts_raw_and_parsed(collector):
    conn = MagicMock()
    conn.send_command.return_value = SECRET_CONFIG
    result = collector.collect(conn, "cisco_ios")
    raw = result["raw"]["show running-config"]
    assert "s3cr3tComm" not in raw
    assert "<REDACTED>" in raw
    assert "s3cr3tComm" not in result["parsed"]["config"]
    assert result["parsed"]["redacted"] is True


def test_collect_opt_out_keeps_secrets(collector, isolated_settings):
    settings_module.save_discovery_settings({"redact_secrets": False},
                                            config_dir=str(isolated_settings))
    conn = MagicMock()
    conn.send_command.return_value = SECRET_CONFIG
    result = collector.collect(conn, "cisco_ios")
    assert result["raw"]["show running-config"] == SECRET_CONFIG
    assert result["parsed"]["config"] == SECRET_CONFIG
    assert result["parsed"]["redacted"] is False
