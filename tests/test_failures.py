"""Failure classification and structured per-attempt records."""
import errno
import socket

import pytest
from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.ssh_exception import (IncompatiblePeer, NoValidConnectionsError,
                                    SSHException)

import app.connection_manager as cmod
from app.connection_manager import ConnectionManager
from app.connection_manager import ConnectionError as WiremapConnectionError
from app.failures import (classify_exception, classify_message,
                          failure_record, pick_reason, reason_counts, HINTS)


def _wrapped(outer, inner):
    """Raise outer while handling inner, as netmiko does."""
    try:
        try:
            raise inner
        except BaseException:
            raise outer
    except BaseException as e:
        return e


# --- classify_exception -----------------------------------------------------

def test_netmiko_timeout_is_timeout():
    assert classify_exception(NetmikoTimeoutException("TCP connection to device failed.")) == "timeout"


def test_socket_timeout_is_timeout():
    assert classify_exception(socket.timeout("timed out")) == "timeout"


def test_refused_wrapped_in_netmiko_timeout_is_refused():
    """netmiko reports a TCP RST as NetmikoTimeoutException with no errno in
    its message; the refusal lives on the chained paramiko error."""
    refused = ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
    inner = NoValidConnectionsError({("192.0.2.10", 22): refused})
    exc = _wrapped(NetmikoTimeoutException("TCP connection to device failed."), inner)
    assert classify_exception(exc) == "refused"


def test_unreachable_wrapped_in_netmiko_timeout_is_timeout():
    unreach = OSError(errno.EHOSTUNREACH, "No route to host")
    inner = NoValidConnectionsError({("192.0.2.10", 22): unreach})
    exc = _wrapped(NetmikoTimeoutException("TCP connection to device failed."), inner)
    assert classify_exception(exc) == "timeout"


def test_errno_111_message_is_refused():
    assert classify_exception(OSError("[Errno 111] Connection refused")) == "refused"


def test_bare_connection_refused_error_is_refused():
    assert classify_exception(ConnectionRefusedError()) == "refused"


def test_auth_is_auth():
    assert classify_exception(NetmikoAuthenticationException("Authentication to device failed.")) == "auth"


def test_incompatible_peer_is_legacy_crypto():
    assert classify_exception(IncompatiblePeer("Incompatible ssh peer (no acceptable kex algorithm)")) == "legacy_crypto"


def test_ssh_exception_wrapped_as_timeout_is_legacy_crypto():
    """netmiko re-raises paramiko SSHException as NetmikoTimeoutException;
    the message is what says it was negotiation."""
    msg = ("\nA paramiko SSHException occurred during connection creation:\n\n"
           "Incompatible ssh server (no acceptable ciphers)\n")
    exc = _wrapped(NetmikoTimeoutException(msg), SSHException("Incompatible ssh server (no acceptable ciphers)"))
    assert classify_exception(exc) == "legacy_crypto"


def test_unknown_error_is_other():
    assert classify_exception(ValueError("Unsupported 'device_type'")) == "other"


# --- helpers ----------------------------------------------------------------

def test_pick_reason_priority():
    assert pick_reason(["timeout", "auth"]) == "auth"
    assert pick_reason(["timeout", "refused"]) == "refused"
    assert pick_reason(["refused", "legacy_crypto"]) == "legacy_crypto"
    assert pick_reason(["other", "timeout"]) == "timeout"
    assert pick_reason(["skipped"]) == "other"


def test_failure_record_accepts_old_string():
    rec = failure_record("Authentication failed to 192.0.2.5")
    assert rec["reason"] == "auth"
    assert rec["hint"] == HINTS["auth"]
    assert rec["message"] == "Authentication failed to 192.0.2.5"
    assert rec["attempts"] == []
    assert rec["hostname"] is None


def test_failure_record_passes_dict_through():
    value = {"hostname": "sw1", "reason": "refused", "hint": "h",
             "message": "m", "attempts": [{"protocol": "ssh"}]}
    assert failure_record(value) == value


def test_failure_record_fills_missing_dict_fields():
    rec = failure_record({"reason": "timeout"})
    assert rec["hint"] == HINTS["timeout"]
    assert rec["attempts"] == []


def test_classify_message_legacy_strings():
    assert classify_message("ssh/cisco_ios: timeout: TCP connection") == "timeout"
    assert classify_message("[Errno 111] Connection refused") == "refused"
    assert classify_message("") == "other"


def test_reason_counts_mixes_shapes():
    counts = reason_counts({
        "192.0.2.1": "Authentication failed to 192.0.2.1",
        "192.0.2.2": {"reason": "refused"},
        "192.0.2.3": {"reason": "refused"},
    })
    assert counts[0]["reason"] == "refused"
    assert counts[0]["count"] == 2
    assert counts[0]["hint"] == HINTS["refused"]
    assert counts[1]["reason"] == "auth"


def test_refused_hint_names_the_vty_acl():
    assert "access-class" in HINTS["refused"]


# --- ConnectionManager.connect ----------------------------------------------

@pytest.fixture
def handler(monkeypatch):
    """Install a fake ConnectHandler driven by a function of params."""
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    calls = []

    def install(fn):
        def fake(**params):
            calls.append(params)
            return fn(**params)
        monkeypatch.setattr(cmod, "_connect_handler", fake)
        return calls
    return install


def _refused():
    return _wrapped(NetmikoTimeoutException("TCP connection to device failed."),
                    ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"))


def test_attempts_are_structured(handler):
    handler(lambda **p: (_ for _ in ()).throw(_refused()))
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="ssh")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    a = exc.value.attempts[0]
    assert a["protocol"] == "ssh"
    assert a["port"] == 22
    assert a["device_type"] == "cisco_ios"
    assert a["exception_class"] == "NetmikoTimeoutException"
    assert a["message"] == "TCP connection to device failed."
    assert isinstance(a["elapsed_ms"], int)
    assert exc.value.reason == "refused"
    rec = exc.value.to_record(hostname="sw1")
    assert rec["hostname"] == "sw1"
    assert rec["reason"] == "refused"
    assert "access-class" in rec["hint"]
    assert rec["attempts"] == exc.value.attempts


def test_timeout_does_not_cycle_device_types(handler):
    calls = handler(lambda **p: (_ for _ in ()).throw(NetmikoTimeoutException("timed out")))
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="ssh")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert [c["device_type"] for c in calls] == ["cisco_ios"]
    assert exc.value.reason == "timeout"


def test_other_error_still_cycles_device_types(handler):
    calls = handler(lambda **p: (_ for _ in ()).throw(ValueError("prompt not found")))
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="ssh")
    with pytest.raises(WiremapConnectionError):
        cm.connect()
    assert [c["device_type"] for c in calls] == ["cisco_ios", "cisco_xe", "cisco_nxos"]


def test_auth_failure_raises_immediately(handler):
    calls = handler(lambda **p: (_ for _ in ()).throw(
        NetmikoAuthenticationException("Authentication to device failed.")))
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert len(calls) == 1
    assert exc.value.reason == "auth"
    assert exc.value.error_type == "auth"


def test_legacy_crypto_retries_once_with_legacy_algorithms(handler):
    def fn(**p):
        if p.get("disabled_algorithms"):
            return "conn"
        raise IncompatiblePeer("Incompatible ssh peer (no acceptable kex algorithm)")
    calls = handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto")
    result = cm.connect()
    assert result.connection == "conn"
    assert result.protocol_used == "ssh"
    assert len(calls) == 2
    disabled = calls[1]["disabled_algorithms"]
    assert "rsa-sha2-256" in disabled["pubkeys"]
    assert "diffie-hellman-group-exchange-sha1" in disabled["kex"]


def test_legacy_crypto_failure_skips_other_types_then_telnet(handler):
    def fn(**p):
        if p["device_type"].endswith("_telnet"):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
        raise IncompatiblePeer("Incompatible ssh peer (no acceptable kex algorithm)")
    calls = handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    ssh_calls = [c for c in calls if not c["device_type"].endswith("_telnet")]
    assert len(ssh_calls) == 2  # original + one legacy retry, no fallbacks
    assert exc.value.reason == "legacy_crypto"
    assert exc.value.attempts[1]["message"].startswith("legacy algorithms retry")


def test_refused_on_nxos_does_not_try_telnet(handler):
    calls = handler(lambda **p: (_ for _ in ()).throw(_refused()))
    cm = ConnectionManager("192.0.2.10", "cisco_nxos", "u", "p", protocol="auto")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert [c["device_type"] for c in calls] == ["cisco_nxos"]
    telnet = [a for a in exc.value.attempts if a["protocol"] == "telnet"]
    assert telnet[0]["exception_class"] == "Skipped"
    assert exc.value.reason == "refused"


def test_refused_on_c9k_platform_does_not_try_telnet(handler):
    calls = handler(lambda **p: (_ for _ in ()).throw(_refused()))
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto",
                           platform="cisco C9300-48P")
    with pytest.raises(WiremapConnectionError):
        cm.connect()
    assert all(not c["device_type"].endswith("_telnet") for c in calls)


def test_refused_on_classic_ios_still_tries_telnet(handler):
    calls = handler(lambda **p: (_ for _ in ()).throw(_refused()))
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto",
                           platform="cisco WS-C2960X-48FPD-L")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert [c["device_type"] for c in calls] == ["cisco_ios", "cisco_ios_telnet"]
    assert exc.value.attempts[1]["port"] == 23


def test_telnet_auth_failure_reports_auth(handler):
    def fn(**p):
        if p["device_type"].endswith("_telnet"):
            raise NetmikoAuthenticationException("bad login")
        raise NetmikoTimeoutException("timed out")
    handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p", protocol="auto")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    # telnet auth raises straight away with reason auth -- the device was
    # reachable and rejected the credentials
    assert exc.value.reason == "auth"


def test_telnet_only_without_driver_is_no_telnet_driver(handler):
    calls = handler(lambda **p: "never")
    cm = ConnectionManager("192.0.2.10", "cisco_nxos", "u", "p",
                           protocol="telnet", allow_fallback=False)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert calls == []
    assert exc.value.reason == "no_telnet_driver"


def test_ensure_legacy_algorithms_is_idempotent():
    from paramiko.transport import Transport
    before = tuple(Transport._preferred_kex)
    cmod._ensure_legacy_algorithms()
    cmod._ensure_legacy_algorithms()
    assert tuple(Transport._preferred_kex) == before
