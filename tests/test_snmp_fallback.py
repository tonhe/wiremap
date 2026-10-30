"""SNMP fallback after a failed login: when it runs and what it records.

No network: ConnectionManager.connect and the SNMP probe are both replaced.
"""
import logging

import pytest

import app.discovery_engine as mod
from app import failures
from app.connection_manager import ConnectionError as LoginError
from app.discovery_engine import DiscoveryEngine
from app.inventory import DiscoveryInventory
from app.snmp_probe import SnmpCredentials

V2C = SnmpCredentials(version="v2c", community="example-ro")
V3 = SnmpCredentials(version="v3", username="netops", auth_key="authpass1",
                     priv_key="privpass1")


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(mod, "local_source_ip", lambda ip: None)
    monkeypatch.setattr(mod, "snmp_make_walker",
                        lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _fail_login(monkeypatch, reasons):
    """reasons: ip -> failure class raised by connect()."""
    def connect(self):
        reason = reasons[self.host]
        raise LoginError(f"{reason} on {self.host}", "connection", [], reason)
    monkeypatch.setattr(mod.ConnectionManager, "connect", connect)


def _snmp(monkeypatch, outcomes):
    """outcomes: ip -> outcome string. Answers get a synthetic record."""
    calls = []

    def probe(ip, creds):
        calls.append(ip)
        outcome = outcomes[ip]
        if outcome.endswith(" ok"):
            return ({"hostname": f"SNMP-{ip.split('.')[-1]}", "mgmt_ip": ip,
                     "device_type": "cisco_ios", "sys_descr": "Cisco IOS",
                     "discovery_source": "snmp",
                     "login_succeeded": False}, outcome)
        return None, outcome
    monkeypatch.setattr(mod, "snmp_probe_outcome", probe)
    return calls


def _engine(tmp_path, ips, creds, events=None):
    return DiscoveryEngine(
        seed_ip=ips[0], seed_device_type="cisco_ios",
        username="u", password="p",
        target_hosts=[(ip, "cisco_ios") for ip in ips],
        inventory_dir=str(tmp_path),
        snmp_credentials=creds,
        progress_callback=(events.append if events is not None else None),
    )


@pytest.mark.parametrize("reason", [failures.AUTH, failures.REFUSED,
                                    failures.LEGACY_CRYPTO, failures.TIMEOUT])
def test_snmp_is_tried_for_every_login_failure_class(monkeypatch, tmp_path,
                                                      reason):
    _fail_login(monkeypatch, {"192.0.2.10": reason})
    calls = _snmp(monkeypatch, {"192.0.2.10": "v2c ok"})
    inv = _engine(tmp_path, ["192.0.2.10"], V2C).discover()

    assert calls == ["192.0.2.10"]
    summary = inv.to_dict()["scan_summary"]
    assert summary["failed"]["192.0.2.10"]["snmp"] == "v2c ok"
    assert summary["failed"]["192.0.2.10"]["reason"] == reason
    assert inv.devices["SNMP-10"]["discovery_source"] == "snmp"


def test_auth_failed_device_answering_snmp_is_not_counted_as_failed(
        monkeypatch, tmp_path):
    _fail_login(monkeypatch, {"192.0.2.10": failures.AUTH,
                              "192.0.2.11": failures.REFUSED})
    _snmp(monkeypatch, {"192.0.2.10": "v3 ok", "192.0.2.11": "timeout"})
    events = []
    inv = _engine(tmp_path, ["192.0.2.10", "192.0.2.11"], V3,
                  events).discover()

    summary = inv.to_dict()["scan_summary"]
    # Both keep a failure record explaining the missing CLI data ...
    assert set(summary["failed"]) == {"192.0.2.10", "192.0.2.11"}
    # ... but only the one SNMP could not collect counts as failed.
    assert summary["failed_count"] == 1
    assert summary["snmp_collected_count"] == 1
    assert [r["count"] for r in summary["failure_reasons"]] == [1]
    assert summary["failure_reasons"][0]["reason"] == failures.REFUSED
    complete = next(e for e in events if e["event"] == "scan_complete")
    assert complete["failed_count"] == 1
    failed_events = [e for e in events if e["event"] == "device_failed"]
    assert [(e["ip"], e["snmp"]) for e in failed_events] == [
        ("192.0.2.11", "timeout")]
    identified = [e for e in events if e["event"] == "device_snmp_identified"]
    assert identified[0]["snmp"] == "v3 ok"


def test_no_snmp_credentials_records_no_credentials(monkeypatch, tmp_path):
    _fail_login(monkeypatch, {"192.0.2.10": failures.AUTH})
    calls = _snmp(monkeypatch, {"192.0.2.10": "v2c ok"})
    inv = _engine(tmp_path, ["192.0.2.10"], None).discover()

    assert calls == []
    summary = inv.to_dict()["scan_summary"]
    assert summary["failed"]["192.0.2.10"]["snmp"] == "no credentials"
    assert summary["failed_count"] == 1
    assert "snmp_fallback" not in summary


def test_rejected_snmp_is_recorded(monkeypatch, tmp_path):
    _fail_login(monkeypatch, {"192.0.2.10": failures.AUTH})
    _snmp(monkeypatch, {"192.0.2.10": "auth/community rejected"})
    inv = _engine(tmp_path, ["192.0.2.10"], V3).discover()
    record = inv.to_dict()["scan_summary"]["failed"]["192.0.2.10"]
    assert record["snmp"] == "auth/community rejected"


def test_summary_line_counts_each_outcome(monkeypatch, tmp_path, caplog):
    ips = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"]
    _fail_login(monkeypatch, {ip: failures.AUTH for ip in ips})
    _snmp(monkeypatch, {"192.0.2.10": "v2c ok", "192.0.2.11": "v3 ok",
                        "192.0.2.12": "timeout", "192.0.2.13": "timeout"})
    events = []
    with caplog.at_level(logging.INFO, logger="app.discovery_engine"):
        inv = _engine(tmp_path, ips, V2C, events).discover()

    line = ("SNMP fallback: 4 tried, 2 answered (v2c 1, v3 1), "
            "2 no response")
    assert line in caplog.text
    summary_events = [e for e in events
                      if e["event"] == "snmp_fallback_summary"]
    assert summary_events[0]["message"] == line
    stats = inv.to_dict()["scan_summary"]["snmp_fallback"]
    assert stats["tried"] == 4 and stats["no_response"] == 2


def test_summary_line_mentions_rejections_and_errors():
    engine = DiscoveryEngine(seed_ip="192.0.2.1", seed_device_type="cisco_ios",
                             username="u", password="p")
    assert engine.snmp_summary_line() is None
    for outcome in ("auth/community rejected", "error: OSError: boom",
                    "v2c ok"):
        engine._tally_snmp(outcome)
    assert engine.snmp_summary_line() == (
        "SNMP fallback: 3 tried, 1 answered (v2c 1, v3 0), 0 no response, "
        "1 rejected, 1 error")


def test_v2c_timeout_log_says_a_wrong_community_looks_the_same(
        monkeypatch, caplog):
    _snmp(monkeypatch, {"192.0.2.10": "timeout"})
    engine = DiscoveryEngine(seed_ip="192.0.2.1", seed_device_type="cisco_ios",
                             username="u", password="p",
                             snmp_credentials=V2C)
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    with caplog.at_level(logging.INFO, logger="app.discovery_engine"):
        assert engine._snmp_fallback(inv, "192.0.2.10", "auth") == "timeout"
    assert "wrong v2c community" in caplog.text


def test_failure_record_keeps_snmp_outcome():
    record = failures.failure_record({"reason": "auth", "message": "x",
                                      "snmp": "v2c ok"})
    assert record["snmp"] == "v2c ok"
    assert "snmp" not in failures.failure_record({"reason": "auth"})


def test_plain_failures_drops_snmp_collected_devices():
    failed = {"192.0.2.1": {"reason": "auth", "snmp": "v3 ok"},
              "192.0.2.2": {"reason": "auth", "snmp": "timeout"},
              "192.0.2.3": "Authentication failed"}
    assert set(failures.plain_failures(failed)) == {"192.0.2.2", "192.0.2.3"}
    assert failures.reason_counts(failed)[0]["count"] == 2


def test_merged_scans_do_not_count_snmp_collected_devices():
    from app.inventory_merge import merge_inventories
    scan = DiscoveryInventory.create(seed_ip="192.0.2.1")
    scan.set_scan_summary(elapsed=1.0, failed={
        "192.0.2.5": {"reason": "auth", "snmp": "v2c ok"},
        "192.0.2.6": {"reason": "refused"},
    })
    other = DiscoveryInventory.create(seed_ip="192.0.2.2")
    other.set_scan_summary(elapsed=1.0, failed={})
    merged = merge_inventories([scan.to_dict(), other.to_dict()])
    assert merged["scan_summary"]["failed_count"] == 1
    assert len(merged["scan_summary"]["failed"]) == 2
