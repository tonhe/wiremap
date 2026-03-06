"""Tests for per-device log context in parallel discovery."""
import logging
import pytest
from app.discovery_engine import DiscoveryEngine, DeviceLogFilter, _log_context


def test_device_log_filter_adds_ip_prefix():
    """Filter should prepend [device_ip] when context is set."""
    filt = DeviceLogFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="hello world", args=(), exc_info=None,
    )

    _log_context.device_ip = "10.0.0.1"
    try:
        filt.filter(record)
        assert record.msg == "[10.0.0.1] hello world"
    finally:
        _log_context.device_ip = None


def test_device_log_filter_no_prefix_without_context():
    """Filter should leave message unchanged when no context is set."""
    filt = DeviceLogFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="hello world", args=(), exc_info=None,
    )

    _log_context.device_ip = None
    filt.filter(record)
    assert record.msg == "hello world"


def test_discovery_logs_include_device_ip(caplog):
    """Discovery of mock device should produce log lines tagged with IP."""
    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )

    with caplog.at_level(logging.INFO):
        engine.discover()

    # At least one log line should contain the [192.168.1.1] tag
    tagged = [r for r in caplog.records if "[192.168.1.1]" in r.msg]
    assert len(tagged) > 0, (
        f"Expected log lines tagged with [192.168.1.1], got: "
        f"{[r.msg for r in caplog.records]}"
    )


def test_filter_removed_after_discovery():
    """DeviceLogFilter should be removed from handlers after discover()."""
    root = logging.getLogger()

    def count_filters():
        return sum(
            len([f for f in h.filters if isinstance(f, DeviceLogFilter)])
            for h in root.handlers
        )

    before = count_filters()

    engine = DiscoveryEngine(
        seed_ip="192.168.1.1",
        seed_device_type="cisco_nxos",
        username="admin",
        password="admin",
        max_depth=0,
    )
    engine.discover()

    after = count_filters()
    assert after == before, "DeviceLogFilter was not removed after discovery"
