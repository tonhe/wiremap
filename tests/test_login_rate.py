"""Login rate limiting across discovery workers."""
import threading

import pytest

import app.connection_manager as cmod
from app.connection_manager import ConnectionManager, ConnectionError as WiremapConnectionError
from app.login_rate import LoginRateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _limiter(per_minute):
    clock = FakeClock()
    return LoginRateLimiter(per_minute, clock=clock, sleep=clock.sleep), clock


def test_zero_means_unlimited():
    limiter, clock = _limiter(0)
    assert not limiter.enabled
    for _ in range(50):
        assert limiter.acquire() == 0.0
    assert clock.sleeps == []


def test_first_login_is_immediate():
    limiter, clock = _limiter(60)
    assert limiter.acquire() == 0.0
    assert clock.sleeps == []


def test_logins_are_spaced_evenly():
    limiter, clock = _limiter(30)
    starts = []
    for _ in range(4):
        limiter.acquire()
        starts.append(clock.now)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert gaps == pytest.approx([2.0, 2.0, 2.0])


def test_idle_time_does_not_build_a_burst():
    limiter, clock = _limiter(60)
    limiter.acquire()
    clock.now += 600
    assert limiter.acquire() == 0.0
    assert limiter.acquire() == pytest.approx(1.0)


def test_never_exceeds_rate_in_any_minute():
    limiter, clock = _limiter(120)
    starts = []
    for _ in range(300):
        limiter.acquire()
        starts.append(clock.now)
    for i, t in enumerate(starts):
        in_window = [s for s in starts[i:] if s < t + 60]
        assert len(in_window) <= 120


def test_concurrent_workers_get_distinct_slots():
    """Workers reserving at the same instant are queued, not released together."""
    clock = FakeClock()
    reserved = []
    lock = threading.Lock()

    def record_sleep(seconds):
        with lock:
            reserved.append(seconds)

    limiter = LoginRateLimiter(60, clock=clock, sleep=record_sleep)
    threads = [threading.Thread(target=limiter.acquire) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(reserved) == pytest.approx([1.0, 2.0, 3.0, 4.0])


class _Recorder:
    def __init__(self):
        self.calls = 0

    def acquire(self):
        self.calls += 1
        return 0.5


def test_connection_manager_waits_before_every_attempt(monkeypatch):
    """SSH, the legacy-algorithm retry and telnet each count as a login."""
    from paramiko.ssh_exception import IncompatiblePeer

    def fail(**params):
        if params["device_type"].endswith("_telnet"):
            raise OSError("telnet closed")
        raise IncompatiblePeer("no matching key exchange method found")

    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler", fail)
    recorder = _Recorder()
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p",
                           protocol="auto", allow_fallback=False, allow_telnet=True,
                           login_limiter=recorder)
    with pytest.raises(WiremapConnectionError) as exc:
        cm.connect()
    protocols = [a["protocol"] for a in exc.value.attempts]
    assert protocols == ["ssh", "ssh", "telnet"]
    assert recorder.calls == 3
    assert cm.login_wait_ms == 1500


def test_connection_manager_without_limiter_does_not_wait(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: object())
    cm = ConnectionManager("192.0.2.10", "cisco_ios", "u", "p")
    cm.connect()
    assert cm.login_wait_ms == 0
