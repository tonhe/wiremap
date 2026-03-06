import json

import pytest
from app.collectors.ntp_logging import NtpLoggingCollector


@pytest.fixture
def collector():
    return NtpLoggingCollector()


def test_attrs(collector):
    assert collector.name == "ntp_logging"
    assert collector.label == "NTP, Logging & SNMP"
    assert collector.enabled_by_default is True


def test_get_commands_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert cmds == [
        "show ntp status",
        "show ntp associations",
        "show logging",
        "show snmp",
        "show aaa sessions",
        "show running-config | section aaa",
    ]


def test_get_commands_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert "show ntp peer-status" in cmds
    assert "show ntp associations" not in cmds


def test_parse_empty(collector):
    raw = {
        "show ntp status": "",
        "show ntp associations": "",
        "show logging": "",
        "show snmp": "",
    }
    result = collector.parse(raw, "cisco_ios")
    assert result["ntp_status"]["synchronized"] is False
    assert result["ntp_peers"] == []
    assert result["logging"]["logging_on"] is False
    assert result["snmp"]["communities_detected"] is False


def test_parse_ntp_status_synced(collector):
    raw = {
        "show ntp status": (
            "Clock is synchronized, stratum 3, reference is 10.1.1.1\n"
            "nominal freq is 250.0000 Hz, actual freq is 250.0000 Hz"
        ),
        "show ntp associations": "",
        "show logging": "",
        "show snmp": "",
    }
    result = collector.parse(raw, "cisco_ios")
    assert result["ntp_status"]["synchronized"] is True
    assert result["ntp_status"]["stratum"] == 3
    assert result["ntp_status"]["reference"] == "10.1.1.1"


def test_parse_ntp_status_unsynced(collector):
    raw = {
        "show ntp status": (
            "Clock is unsynchronized, stratum 16, no reference clock"
        ),
        "show ntp associations": "",
        "show logging": "",
        "show snmp": "",
    }
    result = collector.parse(raw, "cisco_ios")
    assert result["ntp_status"]["synchronized"] is False
    assert result["ntp_status"]["stratum"] == 16


def test_parse_ntp_peers(collector):
    raw = {
        "show ntp status": "",
        "show ntp associations": (
            "  address         ref clock       st   when   poll reach  delay\n"
            "*~10.1.1.1        .GPS.            1     32     64   377  1.234\n"
            " ~10.1.1.2        10.1.1.1         2     16     64   377  2.345\n"
        ),
        "show logging": "",
        "show snmp": "",
    }
    result = collector.parse(raw, "cisco_ios")
    assert len(result["ntp_peers"]) >= 1
    peer = result["ntp_peers"][0]
    assert "remote" in peer
    assert "stratum" in peer


def test_parse_logging(collector):
    raw = {
        "show ntp status": "",
        "show ntp associations": "",
        "show logging": (
            "Syslog logging: enabled (0 messages dropped, 0 flushes)\n"
            "    Logging is on\n"
            "    Buffer logging:  level debugging, 42 messages logged, xml disabled,\n"
            "                     filtering disabled, 4096 bytes\n"
            "    Logging to 10.2.2.2\n"
            "    Logging to 10.2.2.3\n"
            "    Trap logging: level informational, 100 message lines logged\n"
        ),
        "show snmp": "",
    }
    result = collector.parse(raw, "cisco_ios")
    log = result["logging"]
    assert log["logging_on"] is True
    assert "4096" in log["buffer_size"]
    assert "10.2.2.2" in log["hosts"]
    assert "10.2.2.3" in log["hosts"]
    assert log["trap_level"] == "informational"


def test_snmp_no_secrets(collector):
    """SECURITY: community strings must never appear in serialized output."""
    raw = {
        "show ntp status": "",
        "show ntp associations": "",
        "show logging": "",
        "show snmp": (
            "SNMP community: SuperSecret123 (RO)\n"
            "SNMP community: WritePass456 (RW)\n"
            "Contact: admin@example.com\n"
            "Location: DC1-Row5-Rack12\n"
        ),
    }
    result = collector.parse(raw, "cisco_ios")
    serialized = json.dumps(result)

    # Community strings must not appear anywhere in the parsed output
    assert "SuperSecret123" not in serialized
    assert "WritePass456" not in serialized

    # But the flag should indicate communities were found
    assert result["snmp"]["communities_detected"] is True
    assert result["snmp"]["contact"] == "admin@example.com"
    assert result["snmp"]["location"] == "DC1-Row5-Rack12"
