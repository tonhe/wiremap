import pytest
from app.connection_manager import ConnectionManager


def test_build_device_params_ssh():
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "admin", "pass123")
    params = cm._build_device_params()
    assert params["device_type"] == "cisco_ios"
    assert params["host"] == "192.168.1.1"
    assert params["username"] == "admin"
    assert params["password"] == "pass123"


def test_build_device_params_telnet():
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "admin", "pass123",
                           protocol="telnet")
    params = cm._build_device_params()
    assert params["device_type"] == "cisco_ios_telnet"


def test_build_device_params_auto_defaults_ssh():
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "admin", "pass123",
                           protocol="auto")
    params = cm._build_device_params()
    assert params["device_type"] == "cisco_ios"


def test_get_fallback_types():
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "admin", "pass123")
    fallbacks = cm._get_fallback_types("cisco_ios")
    assert "cisco_xe" in fallbacks
    assert "cisco_nxos" in fallbacks


def test_telnet_suffix_not_doubled():
    cm = ConnectionManager("192.168.1.1", "cisco_ios_telnet", "admin", "pass",
                           protocol="telnet")
    params = cm._build_device_params()
    assert params["device_type"] == "cisco_ios_telnet"
    assert "_telnet_telnet" not in params["device_type"]


def test_build_device_params_includes_timeouts():
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "admin", "pass123")
    params = cm._build_device_params()
    assert params["timeout"] == 10
    assert params["session_timeout"] == 20
    assert params["auth_timeout"] == 10
    assert params["banner_timeout"] == 10
    assert params["fast_cli"] is True


def test_get_fallback_types_unknown_device():
    cm = ConnectionManager("192.168.1.1", "unknown_os", "admin", "pass123")
    fallbacks = cm._get_fallback_types("unknown_os")
    assert fallbacks == []


def test_build_device_params_override_type():
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "admin", "pass123")
    params = cm._build_device_params(device_type="cisco_nxos")
    assert params["device_type"] == "cisco_nxos"
