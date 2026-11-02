"""Multiple credential sets: parsing, try order, stop rules, recording."""
import gzip
import json
import logging
from unittest.mock import MagicMock

import pytest

import app.connection_manager as cmod
from app.connection_manager import ConnectionManager, ConnectionError as WiremapConnectionError
from app.credentials import (Credential, CredentialChain, MAX_CREDENTIAL_SETS,
                             parse_credential_form)
from app.discovery_engine import DiscoveryEngine

PRIMARY_PW = "Prim4ry-Secret-91"
BACKUP_PW = "B4ckup-Secret-27"
NETOPS = Credential(1, "netops", PRIMARY_PW)
BACKUP = Credential(2, "backup-admin", BACKUP_PW)


class NetmikoAuthenticationException(Exception):
    """Named like netmiko's, which is how app.failures recognises it."""


class _Recorder:
    def __init__(self):
        self.calls = 0

    def acquire(self):
        self.calls += 1
        return 0


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    calls = []

    def install(fn):
        def fake(**params):
            calls.append(params)
            return fn(**params)
        monkeypatch.setattr(cmod, "_connect_handler", fake)
        return calls
    return install


def _accepts(*usernames):
    def fn(**params):
        if params["username"] in usernames:
            conn = MagicMock()
            conn.find_prompt.return_value = "SW-" + params["host"].replace(".", "-") + "#"
            conn.send_command.return_value = ""
            return conn
        raise NetmikoAuthenticationException("Authentication to device failed.")
    return fn


# --- form parsing -----------------------------------------------------------

def test_single_set_from_plain_fields():
    creds = parse_credential_form({"username": " netops ", "password": PRIMARY_PW})
    assert [(c.number, c.username, c.password) for c in creds] == [
        (1, "netops", PRIMARY_PW)]


def test_extra_sets_in_order_and_blank_rows_ignored():
    creds = parse_credential_form({
        "username": "netops", "password": PRIMARY_PW,
        "username_2": "", "password_2": "",
        "username_3": "backup-admin", "password_3": BACKUP_PW,
    })
    assert [(c.number, c.username) for c in creds] == [(1, "netops"), (3, "backup-admin")]


def test_username_without_password_is_rejected():
    with pytest.raises(ValueError, match="set 2: password is required"):
        parse_credential_form({"username": "netops", "password": PRIMARY_PW,
                               "username_2": "backup-admin", "password_2": ""})


def test_password_without_username_is_rejected():
    with pytest.raises(ValueError, match="set 2: username is required"):
        parse_credential_form({"username": "netops", "password": PRIMARY_PW,
                               "password_2": BACKUP_PW})


def test_no_complete_set_is_rejected():
    with pytest.raises(ValueError, match="Username and password are required"):
        parse_credential_form({"username": "", "password": ""})


def test_sets_beyond_the_maximum_are_ignored():
    form = {"username": "netops", "password": PRIMARY_PW}
    for n in range(2, MAX_CREDENTIAL_SETS + 3):
        form[f"username_{n}"] = f"user{n}"
        form[f"password_{n}"] = f"pw{n}"
    assert len(parse_credential_form(form)) == MAX_CREDENTIAL_SETS


def test_exact_duplicate_set_is_dropped():
    creds = parse_credential_form({"username": "netops", "password": PRIMARY_PW,
                                   "username_2": "netops", "password_2": PRIMARY_PW})
    assert len(creds) == 1


def test_credential_repr_hides_password():
    assert PRIMARY_PW not in repr(NETOPS)
    assert PRIMARY_PW not in str([NETOPS])


# --- ordering and stickiness -------------------------------------------------

def test_chain_starts_in_configured_order():
    chain = CredentialChain([NETOPS, BACKUP])
    assert chain.ordered() == [NETOPS, BACKUP]


def test_chain_puts_last_success_first_and_keeps_the_rest_in_order():
    third = Credential(3, "legacy-ro", "x")
    chain = CredentialChain([NETOPS, BACKUP, third])
    chain.mark_success(third)
    assert chain.ordered() == [third, NETOPS, BACKUP]
    chain.mark_success(NETOPS)
    assert chain.ordered() == [NETOPS, BACKUP, third]


def test_chain_ignores_unknown_credential():
    chain = CredentialChain([NETOPS])
    chain.mark_success(Credential(9, "other", "y"))
    chain.mark_success(None)
    assert chain.ordered() == [NETOPS]


# --- connection manager loop ---------------------------------------------------

def test_auth_failure_moves_to_next_set_on_same_driver(handler):
    calls = handler(_accepts("backup-admin"))
    limiter = _Recorder()
    cm = ConnectionManager("192.0.2.10", "cisco_ios", None, None, protocol="ssh",
                           credentials=[NETOPS, BACKUP], login_limiter=limiter)
    result = cm.connect()
    assert result.connection is not None
    assert [(c["username"], c["device_type"]) for c in calls] == [
        ("netops", "cisco_ios"), ("backup-admin", "cisco_ios")]
    assert cm.credential == BACKUP
    assert cm.username == "backup-admin"
    # Every login try goes through the shared limiter.
    assert limiter.calls == 2


def test_all_sets_rejected_raises_auth_without_driver_fallback(handler):
    calls = handler(_accepts())
    limiter = _Recorder()
    cm = ConnectionManager("192.0.2.10", "cisco_ios", None, None, protocol="auto",
                           allow_telnet=True, credentials=[NETOPS, BACKUP],
                           login_limiter=limiter)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert exc.value.reason == "auth"
    assert "all 2 credential sets rejected" in exc.value.message
    # One try per set: no cisco_xe/nxos fallback, no telnet.
    assert len(calls) == 2
    assert limiter.calls == 2
    assert [(a["credential_set"], a["username"]) for a in exc.value.attempts] == [
        (1, "netops"), (2, "backup-admin")]


@pytest.mark.parametrize("error", [
    TimeoutError("timed out"),
    ConnectionRefusedError(111, "Connection refused"),
    Exception("Incompatible ssh peer (no acceptable kex algorithm)"),
])
def test_non_auth_failure_never_tries_other_sets(handler, error):
    def fn(**params):
        raise error
    calls = handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", None, None, protocol="ssh",
                           allow_fallback=False, credentials=[NETOPS, BACKUP])
    with pytest.raises(WiremapConnectionError):
        cm.connect()
    assert {c["username"] for c in calls} == {"netops"}


def test_rejected_set_not_retried_on_driver_fallback(handler):
    """Set 1 rejected, set 2 hits a driver problem: the cisco_xe fallback
    retries set 2 only."""
    def fn(**params):
        if params["username"] == "netops":
            raise NetmikoAuthenticationException("Authentication failed.")
        if params["device_type"] == "cisco_ios":
            raise ValueError("Pattern not detected")
        return MagicMock()
    calls = handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", None, None, protocol="ssh",
                           credentials=[NETOPS, BACKUP])
    cm.connect()
    assert [(c["username"], c["device_type"]) for c in calls] == [
        ("netops", "cisco_ios"), ("backup-admin", "cisco_ios"),
        ("backup-admin", "cisco_xe")]
    assert cm.effective_device_type == "cisco_xe"


def test_legacy_retry_carries_to_next_set(handler):
    def fn(**params):
        if not params.get("disabled_algorithms"):
            raise Exception("Incompatible ssh peer (no acceptable kex algorithm)")
        if params["username"] == "netops":
            raise NetmikoAuthenticationException("Authentication failed.")
        return MagicMock()
    calls = handler(fn)
    cm = ConnectionManager("192.0.2.10", "cisco_ios", None, None, protocol="ssh",
                           allow_fallback=False, credentials=[NETOPS, BACKUP])
    cm.connect()
    assert [(c["username"], bool(c.get("disabled_algorithms"))) for c in calls] == [
        ("netops", False), ("netops", True), ("backup-admin", True)]


def test_single_set_keeps_old_auth_message(handler):
    handler(_accepts())
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "netops", PRIMARY_PW,
                           protocol="ssh")
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert exc.value.message == "Authentication failed to 192.0.2.10"


def test_password_not_in_attempts_or_logs(handler, caplog):
    handler(_accepts())
    cm = ConnectionManager("192.0.2.10", "cisco_ios", None, None, protocol="ssh",
                           credentials=[NETOPS, BACKUP])
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(WiremapConnectionError) as exc:
            cm.connect()
    blob = json.dumps(exc.value.to_record())
    for pw in (PRIMARY_PW, BACKUP_PW):
        assert pw not in blob
        assert pw not in caplog.text


# --- mock mode -------------------------------------------------------------------

def test_mock_device_needing_second_set(monkeypatch):
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    limiter = _Recorder()
    cm = ConnectionManager("10.0.0.1", "cisco_ios", None, None,
                           credentials=[NETOPS, BACKUP], login_limiter=limiter)
    result = cm.connect()
    assert result.protocol_used == "mock"
    assert cm.credential == BACKUP
    assert limiter.calls == 2


def test_mock_device_rejects_when_no_set_matches(monkeypatch):
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    cm = ConnectionManager("10.0.0.1", "cisco_ios", "netops", PRIMARY_PW)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    assert exc.value.reason == "auth"


def test_mock_device_without_restriction_takes_set_one(monkeypatch):
    monkeypatch.setenv("WIREMAP_MOCK", "1")
    cm = ConnectionManager("192.168.1.1", "cisco_nxos", None, None,
                           credentials=[NETOPS, BACKUP])
    cm.connect()
    assert cm.credential == NETOPS


# --- engine: stickiness, recording, no passwords ---------------------------------

def _engine(tmp_path, hosts, creds):
    events = []
    engine = DiscoveryEngine(
        seed_ip=hosts[0], seed_device_type="cisco_ios",
        username=creds[0].username, password=creds[0].password,
        credentials=creds,
        target_hosts=[(h, "cisco_ios") for h in hosts],
        protocol="ssh", inventory_dir=str(tmp_path), max_workers=1,
        progress_callback=events.append,
    )
    return engine, events


def test_engine_sticks_to_the_set_that_worked(tmp_path, handler):
    calls = handler(_accepts("backup-admin"))
    engine, _ = _engine(tmp_path, ["192.0.2.11", "192.0.2.12"], [NETOPS, BACKUP])
    engine.discover()
    order = [(c["host"], c["username"]) for c in calls]
    assert order == [("192.0.2.11", "netops"), ("192.0.2.11", "backup-admin"),
                     ("192.0.2.12", "backup-admin")]


def test_engine_records_login_user_and_never_the_password(tmp_path, handler, caplog):
    def fn(**params):
        if params["host"] == "192.0.2.13":
            raise NetmikoAuthenticationException("Authentication failed.")
        return _accepts("backup-admin")(**params)
    handler(fn)
    engine, events = _engine(tmp_path, ["192.0.2.11", "192.0.2.13"],
                             [NETOPS, BACKUP])
    with caplog.at_level(logging.DEBUG):
        inventory = engine.discover()
    path = inventory.save(str(tmp_path))

    dev = inventory.devices["SW-192-0-2-11"]
    assert dev["login_user"] == "backup-admin"
    assert dev["credential_set"] == 2
    data = inventory.to_dict()
    assert data["params"]["credential_usernames"] == ["netops", "backup-admin"]
    failed = data["scan_summary"]["failed"]["192.0.2.13"]
    assert failed["reason"] == "auth"
    assert {a.get("credential_set") for a in failed["attempts"]} == {1, 2}

    with gzip.open(path, "rt") as f:
        saved = f.read()
    assert "backup-admin" in saved
    for pw in (PRIMARY_PW, BACKUP_PW):
        assert pw not in saved
        assert pw not in caplog.text
        assert pw not in json.dumps(events, default=str)
        assert pw not in json.dumps(data, default=str)


def test_source_ip_learning_uses_the_logged_in_user(tmp_path, handler, monkeypatch):
    import app.discovery_engine as emod
    seen = {}

    def learn(conn, device_type, username=None, local_ip=None, protocol=None):
        seen["username"] = username
        return None, None
    monkeypatch.setattr(emod, "learn_source_ip", learn)
    handler(_accepts("backup-admin"))
    engine, _ = _engine(tmp_path, ["192.0.2.11"], [NETOPS, BACKUP])
    engine.discover()
    assert seen["username"] == "backup-admin"
