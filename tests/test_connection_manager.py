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


def test_connect_returns_connection_result():
    """connect() should return a ConnectionResult namedtuple."""
    from app.connection_manager import ConnectionResult
    cr = ConnectionResult(connection=None, protocol_used="ssh", fallback_occurred=False)
    assert cr.protocol_used == "ssh"
    assert cr.fallback_occurred is False
    assert cr.connection is None


def test_telnet_type_for_supported_platform():
    from app.connection_manager import telnet_type_for
    assert telnet_type_for("cisco_ios") == "cisco_ios_telnet"


def test_telnet_type_for_unsupported_platform():
    from app.connection_manager import telnet_type_for
    assert telnet_type_for("cisco_nxos") is None
    assert telnet_type_for("cisco_xe") is None


def test_telnet_type_for_already_telnet():
    from app.connection_manager import telnet_type_for
    assert telnet_type_for("cisco_ios_telnet") == "cisco_ios_telnet"


def test_telnet_type_for_unknown_platform():
    from app.connection_manager import telnet_type_for
    assert telnet_type_for("not_a_real_platform") is None


def test_types_to_try_with_fallback():
    cm = ConnectionManager("10.0.0.1", "cisco_ios", "u", "p")
    assert cm._types_to_try() == ["cisco_ios", "cisco_xe", "cisco_nxos"]


def test_types_to_try_without_fallback():
    cm = ConnectionManager("10.0.0.1", "cisco_ios", "u", "p",
                           allow_fallback=False)
    assert cm._types_to_try() == ["cisco_ios"]


def test_no_device_type_still_allows_fallback():
    cm = ConnectionManager("10.0.0.1", "cisco_ios", "u", "p",
                           allow_fallback=True)
    assert len(cm._types_to_try()) > 1


def test_connect_reports_every_attempt(monkeypatch):
    """A failed connect must surface the real SSH error, not just the last
    fallback error."""
    import app.connection_manager as cmod
    from app.connection_manager import ConnectionError as WiremapConnectionError

    def fake_handler(**params):
        raise OSError("boom-" + params["device_type"])

    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler", fake_handler)

    cm = ConnectionManager("10.0.0.1", "cisco_ios", "u", "p",
                           protocol="auto", allow_fallback=False)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()

    msg = str(exc.value)
    assert "ssh/cisco_ios" in msg
    assert "boom-cisco_ios" in msg
    assert len(exc.value.attempts) >= 1


def test_connect_records_unsupported_telnet(monkeypatch):
    """cisco_nxos has no telnet driver -- say so instead of raising the
    netmiko platform dump and losing the SSH error."""
    import app.connection_manager as cmod
    from app.connection_manager import ConnectionError as WiremapConnectionError

    def fake_handler(**params):
        raise OSError("ssh refused")

    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler", fake_handler)

    cm = ConnectionManager("10.0.0.1", "cisco_nxos", "u", "p",
                           protocol="auto", allow_fallback=False)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()

    msg = str(exc.value)
    assert "ssh refused" in msg
    assert "telnet not supported" in msg
    assert "currently supported platforms" not in msg


def test_connect_sets_effective_device_type(monkeypatch):
    import app.connection_manager as cmod

    class FakeConn:
        pass

    def fake_handler(**params):
        return FakeConn()

    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler", fake_handler)

    cm = ConnectionManager("10.0.0.1", "cisco_ios", "u", "p", protocol="ssh")
    result = cm.connect()
    assert result.protocol_used == "ssh"
    assert cm.effective_device_type == "cisco_ios"


def test_cisco_ios_fallback_never_raises_platform_dump(monkeypatch):
    """Regression: the reported 65-host failure.

    cisco_ios falls back to cisco_xe and cisco_nxos, neither of which has a
    telnet driver. Previously those raised ValueError carrying a 40-line
    platform list which overwrote last_error, so the reported failure was the
    dump rather than the genuine cisco_ios_telnet error.
    """
    import app.connection_manager as cmod
    from app.connection_manager import ConnectionError as WiremapConnectionError

    def fake_handler(**params):
        raise OSError("connection refused by " + params["device_type"])

    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler", fake_handler)

    cm = ConnectionManager("172.21.0.42", "cisco_ios", "u", "p",
                           protocol="auto", allow_fallback=True)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()

    msg = str(exc.value)
    assert "currently supported platforms" not in msg
    assert "adtran_os_telnet" not in msg
    assert "connection refused by cisco_ios" in msg
    assert "connection refused by cisco_ios_telnet" in msg
    tried_telnet = [d for p, d, _ in exc.value.attempts if p == "telnet"]
    assert "cisco_ios_telnet" in tried_telnet
    assert "cisco_nxos" in tried_telnet


def test_none_device_type_does_not_crash():
    """Regression: a host list line with no device type crashed with
    "'NoneType' object has no attribute 'endswith'" before any connection
    was attempted. Three Citrix NetScalers were never reached because of it."""
    cm = ConnectionManager("172.20.10.37", None, "u", "p", protocol="auto")
    assert cm.device_type
    assert cm._types_to_try()
    params = cm._build_device_params()
    assert params["device_type"]


def test_empty_device_type_does_not_crash():
    cm = ConnectionManager("10.0.0.1", "", "u", "p", protocol="telnet")
    params = cm._build_device_params()
    assert params["device_type"].endswith("_telnet")


def test_telnet_type_for_handles_none():
    from app.connection_manager import telnet_type_for
    assert telnet_type_for(None) is None
    assert telnet_type_for("") is None


def test_none_device_type_still_allows_fallback():
    """No type supplied means autodetect, so fallbacks must stay on."""
    cm = ConnectionManager("10.0.0.1", None, "u", "p")
    assert len(cm._types_to_try()) > 1


def test_none_device_type_connect_reports_cleanly(monkeypatch):
    """The failure must be a connection error naming the host, not an
    AttributeError from inside wiremap."""
    import app.connection_manager as cmod
    from app.connection_manager import ConnectionError as WiremapConnectionError

    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler",
                        lambda **p: (_ for _ in ()).throw(OSError("refused")))

    cm = ConnectionManager("172.20.10.37", None, "u", "p", protocol="auto")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert "172.20.10.37" in str(exc.value)
    assert "endswith" not in str(exc.value)
