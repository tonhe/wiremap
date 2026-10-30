"""Engine-side scan diagnostics: per-device timing, the source-host access
check on the seed, the repeated-refusal hint and the login rate limit."""
import errno

import pytest
from netmiko import NetmikoTimeoutException

import app.connection_manager as cmod
import app.discovery_engine as engine_mod
from app.discovery_engine import DiscoveryEngine
from app.scan_timing import collector_ms, summarize

SEED_CONFIG = """\
hostname lab-core1
ip access-list standard MGMT-VTY
 10 permit 192.0.2.0 0.0.0.255
 20 deny   any
line vty 0 4
 access-class MGMT-VTY in
"""


class FakeConn:
    def __init__(self, hostname="lab-core1", config=SEED_CONFIG):
        self.hostname = hostname
        self.config = config
        self.commands = []

    def find_prompt(self):
        return self.hostname + "#"

    def send_command(self, cmd, **kwargs):
        self.commands.append(cmd)
        if cmd == "show running-config":
            return self.config
        return ""

    def disconnect(self):
        pass


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(engine_mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(engine_mod, "snmp_collect_all", lambda walker: {})
    monkeypatch.setattr(engine_mod, "local_source_ip", lambda dest: "198.51.100.50")


def _engine(tmp_path, **kw):
    kw.setdefault("seed_ip", "192.0.2.1")
    kw.setdefault("seed_device_type", "cisco_ios")
    return DiscoveryEngine(username="u", password="p", max_depth=0,
                           inventory_dir=str(tmp_path), **kw)


def test_collector_ms_counts_shared_commands_for_each_collector():
    out = collector_ms({"a": ["show x", "show y"], "b": ["show y"], "c": []},
                       {"show x": 10, "show y": 5})
    assert out == {"a": 15, "b": 5, "c": 0}


def test_summarize_ranks_devices_and_collectors():
    timing = {
        "sw1": {"ip": "192.0.2.1", "total_ms": 900, "connect_ms": 100,
                "collectors_ms": {"config": 300, "arp": 10}},
        "sw2": {"ip": "192.0.2.2", "total_ms": 4000, "connect_ms": 2500,
                "collectors_ms": {"config": 50, "arp": 900}},
        "sw3": {"ip": "192.0.2.3", "total_ms": 100, "connect_ms": 50,
                "collectors_ms": {}},
    }
    s = summarize(timing, top=2)
    assert [d["hostname"] for d in s["devices"]] == ["sw2", "sw1"]
    assert s["collectors"][0] == {"collector": "arp", "total_ms": 910,
                                  "max_ms": 900, "max_device": "sw2",
                                  "devices": 2}
    assert summarize({}) == {"devices": [], "collectors": []}


def test_device_timing_recorded_in_scan_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: FakeConn())
    events = []
    eng = _engine(tmp_path, progress_callback=events.append)
    inv = eng.discover()

    summary = inv.to_dict()["scan_summary"]
    rec = summary["timing"]["lab-core1"]
    assert rec["ip"] == "192.0.2.1"
    for key in ("connect_ms", "login_wait_ms", "batch_ms", "total_ms"):
        assert isinstance(rec[key], int) and rec[key] >= 0
    assert "show version" in rec["commands_ms"]
    # Custom collectors are timed around their own session work.
    assert "config" in rec["collectors_ms"]
    assert "cdp_lldp" in rec["collectors_ms"]
    assert rec["total_ms"] >= rec["connect_ms"]
    assert summary["slowest"]["devices"][0]["hostname"] == "lab-core1"

    done = [e for e in events if e["event"] == "scan_complete"][0]
    assert done["slowest"]["devices"][0]["hostname"] == "lab-core1"
    assert inv.get_summary()["slowest"] == summary["slowest"]


def test_source_ip_reported_at_scan_start(monkeypatch, tmp_path):
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: FakeConn())
    events = []
    inv = _engine(tmp_path, progress_callback=events.append).discover()
    started = [e for e in events if e["event"] == "scan_started"][0]
    assert started["source_ip"] == "198.51.100.50"
    assert inv.to_dict()["scan_summary"]["source_ip"] == "198.51.100.50"


def test_seed_vty_acl_denying_source_is_warned(monkeypatch, tmp_path):
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: FakeConn())
    events = []
    inv = _engine(tmp_path, progress_callback=events.append).discover()

    expected = ("This host (198.51.100.50) is not permitted by vty "
                "access-class MGMT-VTY on lab-core1; expect connection "
                "refused on devices sharing that ACL")
    warnings = inv.to_dict()["scan_summary"]["source_access_warnings"]
    assert [w["message"] for w in warnings] == [expected]
    live = [e for e in events if e["event"] == "source_access_warning"]
    assert live[0]["message"] == expected
    done = [e for e in events if e["event"] == "scan_complete"][0]
    assert done["source_access_warnings"][0]["acl"] == "MGMT-VTY"
    assert inv.get_summary()["source_access_warnings"][0]["acl"] == "MGMT-VTY"


def test_permitted_source_gives_no_warning(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_mod, "local_source_ip", lambda dest: "192.0.2.77")
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: FakeConn())
    inv = _engine(tmp_path).discover()
    assert inv.to_dict()["scan_summary"]["source_access_warnings"] == []


def test_only_the_seed_is_checked(monkeypatch, tmp_path):
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: FakeConn(
        hostname="lab-dist" + p["host"].rsplit(".", 1)[1]))
    eng = _engine(tmp_path, target_hosts=[("192.0.2.5", "cisco_ios"),
                                          ("192.0.2.6", "cisco_ios")],
                  seed_ip="192.0.2.5", max_workers=1)
    inv = eng.discover()
    warnings = inv.to_dict()["scan_summary"]["source_access_warnings"]
    assert [w["device"] for w in warnings] == ["lab-dist5"]


def _refused(**params):
    try:
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
    except ConnectionRefusedError:
        raise NetmikoTimeoutException("TCP connection to device failed.")


def test_repeated_refusals_produce_one_hint(monkeypatch, tmp_path):
    monkeypatch.setattr(cmod, "_connect_handler", _refused)
    events = []
    targets = [(f"192.0.2.{n}", "cisco_xe") for n in (11, 12, 13, 14)]
    inv = _engine(tmp_path, target_hosts=targets, seed_ip="192.0.2.11",
                  progress_callback=events.append, max_workers=1).discover()
    hints = [e for e in events if e["event"] == "refused_hint"]
    assert len(hints) == 1
    assert "198.51.100.50" in hints[0]["message"]
    assert "access-class" in hints[0]["message"]
    summary = inv.to_dict()["scan_summary"]
    assert summary["refused_hint"].startswith("4 devices refused")


def test_two_refusals_give_no_hint(monkeypatch, tmp_path):
    monkeypatch.setattr(cmod, "_connect_handler", _refused)
    events = []
    targets = [("192.0.2.21", "cisco_xe"), ("192.0.2.22", "cisco_xe")]
    inv = _engine(tmp_path, target_hosts=targets, seed_ip="192.0.2.21",
                  progress_callback=events.append).discover()
    assert not [e for e in events if e["event"] == "refused_hint"]
    assert inv.to_dict()["scan_summary"]["refused_hint"] is None


def test_engine_shares_one_limiter_with_every_connection(monkeypatch, tmp_path):
    seen = []

    def handler(**params):
        return FakeConn(hostname="lab-sw" + params["host"].rsplit(".", 1)[1])

    real_init = cmod.ConnectionManager.__init__

    def spy_init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        seen.append(self.login_limiter)

    monkeypatch.setattr(cmod, "_connect_handler", handler)
    monkeypatch.setattr(cmod.ConnectionManager, "__init__", spy_init)
    eng = _engine(tmp_path, target_hosts=[("192.0.2.31", "cisco_ios"),
                                          ("192.0.2.32", "cisco_ios")],
                  seed_ip="192.0.2.31", max_logins_per_minute=600)
    inv = eng.discover()
    assert len(seen) == 2
    assert seen[0] is seen[1] is eng._login_limiter
    assert eng._login_limiter.per_minute == 600
    assert inv.to_dict()["scan_summary"]["max_logins_per_minute"] == 600
