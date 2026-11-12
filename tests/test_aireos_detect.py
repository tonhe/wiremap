"""An untyped AireOS controller is found at login and collected as cisco_wlc."""
from unittest.mock import MagicMock, patch

import pytest

import app.connection_manager as cmod
from app.connection_manager import ConnectionManager, ConnectionResult
from app.connection_manager import ConnectionError as WiremapConnectionError
from app.discovery_engine import DiscoveryEngine
from app.wlc_session import SYSINFO, looks_like_aireos


@pytest.mark.parametrize("text, expected", [
    ("\r\n(Cisco Controller)\r\nUser:", True),
    ("(Cisco Controller)\nUser: ", True),
    ("(lab-wlc-01) >", True),
    ("(Cisco Controller) >\n", True),
    ("lab-sw-01>", False),
    ("lab-sw-01#", False),
    ("lab-sw-01(config)#", False),
    ("Username:", False),
    ("", False),
    (None, False),
])
def test_looks_like_aireos(text, expected):
    assert looks_like_aireos(text) is expected


class StallsOnUser(Exception):
    """What an IOS driver raises when its login lands on AireOS's User: prompt."""

    def __init__(self):
        super().__init__("Pattern not detected: '[>#]' in output.")


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    state = {"drivers": [], "probes": [], "aireos": True, "wlc_ok": True}

    def handler(**params):
        state["drivers"].append(params["device_type"])
        if params["device_type"] == "cisco_wlc" and state["wlc_ok"]:
            return MagicMock(name="wlc-session")
        raise StallsOnUser()

    def probe(host, username, password, **kw):
        state["probes"].append((host, username))
        return state["aireos"]

    monkeypatch.setattr(cmod, "_connect_handler", handler)
    monkeypatch.setattr(cmod, "_aireos_probe", probe)
    return state


def _untyped():
    return ConnectionManager("192.0.2.30", None, "admin", "pw", protocol="ssh",
                             allow_fallback=True)


def test_untyped_controller_is_connected_on_the_aireos_driver(lab):
    cm = _untyped()
    result = cm.connect()
    assert lab["drivers"] == ["cisco_ios", "cisco_wlc"]
    assert lab["probes"] == [("192.0.2.30", "admin")]
    assert cm.effective_device_type == "cisco_wlc"
    assert result.protocol_used == "ssh"


def test_nothing_aireos_about_it_fails_as_before(lab):
    lab["aireos"] = False
    with pytest.raises(WiremapConnectionError):
        _untyped().connect()
    assert "cisco_wlc" not in lab["drivers"]
    assert len(lab["probes"]) == 1


def test_a_typed_device_is_never_second_guessed(lab):
    cm = ConnectionManager("192.0.2.30", "cisco_ios", "admin", "pw", protocol="ssh",
                           allow_fallback=False)
    with pytest.raises(WiremapConnectionError):
        cm.connect()
    assert lab["probes"] == [] and lab["drivers"] == ["cisco_ios"]


@pytest.mark.parametrize("error", [
    OSError("TCP connection to device failed."),
    ConnectionRefusedError("refused"),
])
def test_no_look_when_the_session_never_got_going(lab, monkeypatch, error):
    def handler(**params):
        lab["drivers"].append(params["device_type"])
        raise error
    monkeypatch.setattr(cmod, "_connect_handler", handler)
    with pytest.raises(WiremapConnectionError):
        _untyped().connect()
    assert lab["probes"] == []


def test_authentication_failure_is_not_a_controller(lab, monkeypatch):
    class AuthenticationException(Exception):
        pass

    def handler(**params):
        raise AuthenticationException("Authentication failed.")
    monkeypatch.setattr(cmod, "_connect_handler", handler)
    with pytest.raises(WiremapConnectionError) as err:
        _untyped().connect()
    assert err.value.error_type == "auth" and lab["probes"] == []


def test_the_look_happens_once(lab):
    lab["wlc_ok"] = False
    with pytest.raises(WiremapConnectionError):
        _untyped().connect()
    assert len(lab["probes"]) == 1


# --- the engine -------------------------------------------------------------

SYSINFO_OUT = "System Name...................................... lab-wlc-01\n"


@pytest.fixture
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _engine_run(sessions):
    """sessions: device_type -> (prompt, effective type reported by connect)."""
    sent = []
    opened = []

    def connect(self):
        prompt, effective = sessions[self.device_type]
        conn = MagicMock()
        conn.find_prompt.return_value = prompt

        def send(cmd, **kw):
            sent.append((self.device_type, cmd))
            return SYSINFO_OUT if cmd == SYSINFO else ""
        conn.send_command.side_effect = send
        conn.write_channel = MagicMock()
        opened.append(self.device_type)
        self.effective_device_type = effective
        self.credential = self.credentials[0]
        return ConnectionResult(connection=conn, protocol_used="ssh", fallback_occurred=False)

    engine = DiscoveryEngine(
        seed_ip="192.0.2.30", seed_device_type=None, username="admin", password="admin",
        max_depth=0, protocol="ssh", inventory_dir=None, max_workers=1)
    with patch.object(ConnectionManager, "connect", autospec=True, side_effect=connect), \
            patch("app.discovery_engine.WlcConnection", side_effect=lambda c: c):
        inventory = engine.discover()
    return inventory, opened, sent


def test_engine_adopts_a_controller_the_connection_manager_found(_no_snmp_network):
    inventory, opened, sent = _engine_run({"cisco_ios": ("(Cisco Controller) >", "cisco_wlc")})
    assert opened == ["cisco_ios"]
    assert inventory.devices["lab-wlc-01"]["device_type"] == "cisco_wlc"
    assert not any("Adaptive Security" in cmd for _, cmd in sent)


def test_engine_reopens_an_ios_login_that_landed_on_an_aireos_prompt(_no_snmp_network):
    inventory, opened, _ = _engine_run({
        "cisco_ios": ("(Cisco Controller) >", "cisco_ios"),
        "cisco_wlc": ("(Cisco Controller) >", "cisco_wlc")})
    assert opened == ["cisco_ios", "cisco_wlc"]
    assert inventory.devices["lab-wlc-01"]["device_type"] == "cisco_wlc"


def test_engine_leaves_an_ios_switch_alone(_no_snmp_network):
    inventory, opened, _ = _engine_run({"cisco_ios": ("lab-sw-01#", "cisco_ios")})
    assert opened == ["cisco_ios"]
    assert "lab-sw-01" in inventory.devices
