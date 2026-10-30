"""TCP pre-probe before netmiko, and telnet only when allowed."""
import errno
import socket

import pytest

import app.connection_manager as cmod
from app.connection_manager import ConnectionManager, ConnectionError as WiremapConnectionError


class _Recorder:
    def __init__(self):
        self.calls = 0

    def acquire(self):
        self.calls += 1
        return 0


@pytest.fixture
def handler(monkeypatch):
    """Record every netmiko call; fn decides what each one does."""
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    calls = []

    def install(fn):
        def fake(**params):
            calls.append(params)
            return fn(**params)
        monkeypatch.setattr(cmod, "_connect_handler", fake)
        return calls
    return install


@pytest.fixture
def ports(monkeypatch):
    """Stub the probe: ports maps port -> None (open) or a probe result."""
    probed = []
    table = {}

    def probe(host, port, timeout=None):
        probed.append(port)
        return table.get(port)
    monkeypatch.setattr(cmod, "_tcp_probe", probe)
    return table, probed


_TIMEOUT = ("timeout", "TimeoutError", "tcp probe: no answer on port 22 within 1.5s")
_REFUSED = ("refused", "ConnectionRefusedError", "tcp probe: port 22 refused")


# --- the probe itself, against a monkeypatched socket ----------------------

# Taken at import, before the autouse fixture in conftest.py stubs it.
_ORIGINAL_PROBE = cmod._tcp_probe


def test_probe_open_port_returns_none_and_closes(monkeypatch):
    closed = []

    class Sock:
        def close(self):
            closed.append(True)
    seen = {}

    def connect(addr, timeout=None):
        seen["addr"], seen["timeout"] = addr, timeout
        return Sock()
    monkeypatch.setattr(socket, "create_connection", connect)
    assert _ORIGINAL_PROBE("192.0.2.10", 22) is None
    assert closed == [True]
    assert seen == {"addr": ("192.0.2.10", 22),
                    "timeout": cmod.TCP_PROBE_TIMEOUT}


def test_probe_timeout_is_classified_timeout(monkeypatch):
    def connect(addr, timeout=None):
        raise socket.timeout("timed out")
    monkeypatch.setattr(socket, "create_connection", connect)
    reason, _, message = _ORIGINAL_PROBE("192.0.2.10", 22)
    assert reason == "timeout"
    assert message.startswith("tcp probe")


def test_probe_refused_is_classified_refused(monkeypatch):
    def connect(addr, timeout=None):
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
    monkeypatch.setattr(socket, "create_connection", connect)
    reason, exc_class, _ = _ORIGINAL_PROBE("192.0.2.10", 23)
    assert reason == "refused"
    assert exc_class == "ConnectionRefusedError"


def test_probe_no_route_counts_as_timeout(monkeypatch):
    def connect(addr, timeout=None):
        raise OSError(errno.EHOSTUNREACH, "No route to host")
    monkeypatch.setattr(socket, "create_connection", connect)
    assert _ORIGINAL_PROBE("192.0.2.10", 22)[0] == "timeout"


def test_probe_other_errors_leave_the_verdict_to_netmiko(monkeypatch):
    def connect(addr, timeout=None):
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(socket, "create_connection", connect)
    assert _ORIGINAL_PROBE("sw1.invalid", 22) is None


# --- connect() with the probe ----------------------------------------------

def test_filtered_ssh_port_skips_netmiko(handler, ports):
    table, probed = ports
    table[22] = _TIMEOUT
    calls = handler(lambda **p: "conn")
    limiter = _Recorder()
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p",
                           protocol="ssh", login_limiter=limiter)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert calls == []
    assert probed == [22]
    assert exc.value.reason == "timeout"
    [attempt] = exc.value.attempts
    assert attempt["protocol"] == "ssh"
    assert attempt["port"] == 22
    assert attempt["note"] == "tcp probe"
    # The probe is not a login, so it costs no rate-limiter token.
    assert limiter.calls == 0


def test_refused_ssh_port_skips_netmiko(handler, ports):
    table, _ = ports
    table[22] = _REFUSED
    calls = handler(lambda **p: "conn")
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="ssh")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert calls == []
    assert exc.value.reason == "refused"
    assert exc.value.attempts[0]["note"] == "tcp probe"


def test_open_ssh_port_runs_netmiko(handler, ports):
    calls = handler(lambda **p: "conn")
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="ssh")
    assert cm.connect().connection == "conn"
    assert len(calls) == 1


def test_auto_without_allow_telnet_never_tries_telnet(handler, ports):
    table, probed = ports
    table[22] = _TIMEOUT
    calls = handler(lambda **p: "conn")
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert probed == [22]
    assert calls == []
    assert [a["protocol"] for a in exc.value.attempts] == ["ssh"]


def test_auto_without_allow_telnet_after_netmiko_failure(handler, ports):
    def fn(**p):
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
    calls = handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p",
                           protocol="auto", allow_fallback=False)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert all(not c["device_type"].endswith("_telnet") for c in calls)
    assert all(a["protocol"] == "ssh" for a in exc.value.attempts)


def test_auto_with_allow_telnet_probes_port_23(handler, ports):
    table, probed = ports
    table[22] = _TIMEOUT
    table[23] = ("refused", "ConnectionRefusedError", "tcp probe: port 23 refused")
    calls = handler(lambda **p: "conn")
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p",
                           protocol="auto", allow_telnet=True)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert probed == [22, 23]
    assert calls == []
    telnet = [a for a in exc.value.attempts if a["protocol"] == "telnet"]
    assert telnet[0]["port"] == 23
    assert telnet[0]["note"] == "tcp probe"
    # Judged on SSH, as before.
    assert exc.value.reason == "timeout"


def test_auto_with_allow_telnet_falls_back_when_23_open(handler, ports):
    table, _ = ports
    table[22] = _TIMEOUT
    calls = handler(lambda **p: "conn")
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p",
                           protocol="auto", allow_telnet=True)
    result = cm.connect()
    assert result.protocol_used == "telnet"
    assert result.fallback_occurred is True
    assert calls[0]["device_type"] == "cisco_ios_telnet"


def test_explicit_telnet_works_without_allow_telnet(handler, ports):
    _, probed = ports
    calls = handler(lambda **p: "conn")
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p",
                           protocol="telnet")
    assert cm.connect().protocol_used == "telnet"
    assert probed == [23]
    assert calls[0]["device_type"] == "cisco_ios_telnet"


def test_mock_mode_is_not_probed(monkeypatch, ports):
    _, probed = ports
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    cm = ConnectionManager("192.168.1.1", "cisco_ios", "u", "p", protocol="ssh")
    assert cm.connect().protocol_used == "mock"
    assert probed == []


# --- plumbing ---------------------------------------------------------------

def test_allow_telnet_setting_defaults_off(tmp_path):
    from app.settings import get_discovery_settings, save_discovery_settings
    assert get_discovery_settings(config_dir=str(tmp_path))["allow_telnet"] is False
    save_discovery_settings({"allow_telnet": True}, config_dir=str(tmp_path))
    assert get_discovery_settings(config_dir=str(tmp_path))["allow_telnet"] is True


def test_engine_passes_allow_telnet_to_connection_manager(monkeypatch, tmp_path):
    import app.discovery_engine as mod
    seen = []

    class FakeCM:
        def __init__(self, **kwargs):
            seen.append(kwargs)

        def connect(self):
            raise WiremapConnectionError("no", attempts=[], reason="timeout")
    monkeypatch.setattr(mod, "ConnectionManager", FakeCM)
    for allow in (False, True):
        engine = mod.DiscoveryEngine(
            seed_ip="192.0.2.10", seed_device_type="cisco_ios",
            username="u", password="p", max_depth=0, allow_telnet=allow,
            inventory_dir=str(tmp_path))
        engine.discover()
    assert [kw["allow_telnet"] for kw in seen] == [False, True]
