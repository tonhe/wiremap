"""Switch-only commands are kept off routers (ASR/ISR are cisco_xe too)."""
from unittest.mock import MagicMock, patch

import pytest

from app.collectors.switchport import SwitchportCollector, _parse_switchport_regex
from app.connection_manager import ConnectionResult
from app.device_role import (
    is_router_model, is_switchless_router, model_from_show_version,
)
from app.discovery_engine import DiscoveryEngine

INVALID = "                ^\n% Invalid input detected at '^' marker.\n"

ASR_SHOW_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], ASR1000 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.4a, RELEASE SOFTWARE (fc3)

RTR-A uptime is 1 year, 2 weeks, 3 days, 4 hours, 5 minutes
System image file is "bootflash:asr1001x-universalk9.17.09.04a.SPA.bin"

cisco ASR1001-X (1NG) processor (revision 1NG) with 3730415K/6147K bytes of memory.
Processor board ID FXS000000AA
6 Gigabit Ethernet interfaces
"""

C9300_SHOW_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a
cisco C9300-48P (X86) processor with 1419044K/6147K bytes of memory.
Processor board ID FOC0000X0AA
"""

ISR_G2_SHOW_VERSION = """\
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.7(3)M8
Cisco CISCO2911/K9 (revision 1.0) with 479232K/45056K bytes of memory.
"""

SWITCHING_CMDS = {
    "show interfaces switchport", "show port-security",
    "show port-security address", "show errdisable recovery",
    "show storm-control", "show mac address-table", "show vlan brief",
    "show vtp status", "show spanning-tree", "show spanning-tree root",
    "show spanning-tree detail", "show interfaces status",
}


@pytest.mark.parametrize("text,model", [
    (ASR_SHOW_VERSION, "ASR1001-X"),
    (C9300_SHOW_VERSION, "C9300-48P"),
    (ISR_G2_SHOW_VERSION, "CISCO2911/K9"),
    ("", ""),
    (INVALID, ""),
])
def test_model_from_show_version(text, model):
    assert model_from_show_version(text) == model


@pytest.mark.parametrize("model", [
    "ASR1001-X", "ASR-920-24SZ-M", "ISR4431/K9", "C8300-1N1S-6T",
    "C8500-12X4QC", "C8000V", "CSR1000V", "C1121X",
    "CISCO2911/K9", "cisco ASR1002-HX",
])
def test_router_models(model):
    assert is_router_model(model)


@pytest.mark.parametrize("model", [
    "C9300-48P", "WS-C3850-48P", "C1000-24P-4G-L", "N9K-C93180YC-FX",
    "C1111-8P", "C1121X-8P", "", "Linux",
])
def test_non_router_models(model):
    assert not is_router_model(model)


def test_unknown_device_is_not_treated_as_router():
    assert is_switchless_router() is False


def test_category_used_only_without_a_model():
    assert is_switchless_router(category="router") is True
    assert is_switchless_router(show_version=C9300_SHOW_VERSION,
                                category="router") is False


def test_show_version_beats_neighbour_platform():
    assert is_switchless_router(show_version=ASR_SHOW_VERSION,
                                platform="cisco WS-C3850-48P") is True


@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _discover(hostname, show_version):
    sent = []

    def send_command(cmd, **kwargs):
        sent.append(cmd)
        if cmd == "show version":
            return show_version
        return ""

    engine = DiscoveryEngine(
        seed_ip="192.0.2.1", seed_device_type="cisco_xe",
        username="admin", password="admin", max_depth=0,
        protocol="ssh", inventory_dir=None, max_workers=1,
    )
    conn = MagicMock()
    conn.find_prompt.return_value = f"{hostname}#"
    conn.send_command.side_effect = send_command
    result = ConnectionResult(connection=conn, protocol_used="ssh",
                              fallback_occurred=False)
    with patch("app.connection_manager.ConnectionManager.connect",
               return_value=result):
        inventory = engine.discover()
    return inventory, sent


def test_router_is_not_sent_switching_commands():
    inventory, sent = _discover("RTR-A", ASR_SHOW_VERSION)
    assert not SWITCHING_CMDS & set(sent)
    # The rest of the collection still ran
    assert "show ip interface brief" in sent
    cdata = inventory.devices["RTR-A"]["collector_data"]
    for cname in ("switchport", "mac_table", "stp_vlan", "stp_detail"):
        assert cdata[cname]["parsed"]["not_applicable"] is True
    assert "show interfaces status" not in cdata["interfaces"]["raw"]


def test_switch_still_gets_switching_commands():
    _, sent = _discover("SW1", C9300_SHOW_VERSION)
    assert SWITCHING_CMDS <= set(sent)


def test_unknown_model_still_gets_switching_commands():
    _, sent = _discover("SW1", "")
    assert "show interfaces switchport" in sent


def test_switchport_regex_ignores_error_block():
    assert _parse_switchport_regex(INVALID) == []


def test_switchport_regex_still_parses_real_blocks():
    output = (
        "Name: Gi1/0/1\n"
        "Switchport: Enabled\n"
        "Administrative Mode: static access\n"
        "Access Mode VLAN: 10 (USERS)\n"
        "\n"
        "Name: Gi1/0/2\n"
        "Administrative Mode: trunk\n"
        "Trunking Native Mode VLAN: 1 (default)\n"
    )
    entries = _parse_switchport_regex(output)
    assert [e["interface"] for e in entries] == ["Gi1/0/1", "Gi1/0/2"]


def test_port_security_error_text_not_fed_to_ntc():
    collector = SwitchportCollector()
    raw = {c: INVALID for c in collector.get_commands("cisco_xe")}
    # parse() directly, bypassing the error detection in parse_collected
    parsed = collector.parse(raw, "cisco_xe")
    assert parsed["switchports"] == []
    assert parsed["port_security"] == []
    assert parsed["port_security_addresses"] == []
    assert parsed["errdisable_recovery"] == []
    assert parsed["storm_control"] == []



HEALTH_SWITCHING_CMDS = {"show power inline", "show vstack config",
                         "show switch stack-ports", "show switch stack-ring speed"}
HEALTH_GENERAL_CMDS = {"show environment all", "show redundancy", "show ip ssh",
                       "show interfaces", "show processes cpu history",
                       "show processes memory sorted"}


def test_router_skips_switch_only_health_commands():
    inventory, sent = _discover("RTR-B", ASR_SHOW_VERSION)
    assert not HEALTH_SWITCHING_CMDS & set(sent)
    assert HEALTH_GENERAL_CMDS <= set(sent)
    cdata = inventory.devices["RTR-B"]["collector_data"]
    assert "show power inline" not in cdata["environment"]["raw"]
    assert "show vstack config" not in cdata["mgmt_security"]["raw"]


def test_switch_gets_all_health_commands():
    _, sent = _discover("SW2", C9300_SHOW_VERSION)
    assert (HEALTH_SWITCHING_CMDS | HEALTH_GENERAL_CMDS) <= set(sent)
