"""The engine logs into ASAs on the ASA driver, keeps both units of a failover
pair, and sends them only the collectors written for ASAs."""
from unittest.mock import MagicMock, patch

import pytest

from app.asa_identity import (ASA_PROBE, FAILOVER_PROBE, asa_hostname, base_hostname,
                              is_asa, parse_unit, unit_key)
from app.connection_manager import ConnectionManager, ConnectionResult
from app.discovery_engine import DiscoveryEngine

ASA_VERSION_LINE = "Cisco Adaptive Security Appliance Software Version 9.16(4)\n"

FAILOVER_ACTIVE = """\
Failover On
        This host: Primary - Active
"""
FAILOVER_STANDBY = """\
Failover On
        This host: Secondary - Standby Ready
"""


@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


class _Device:
    """One reachable address: what each driver sees when it logs in."""

    def __init__(self, prompt, failover="Failover Off\n", ios_probe=ASA_VERSION_LINE):
        self.prompt = prompt
        self.failover = failover
        self.ios_probe = ios_probe
        self.sent = {}

    def connection(self, device_type):
        sent = self.sent.setdefault(device_type, [])
        conn = MagicMock()
        conn.find_prompt.return_value = self.prompt

        def send_command(cmd, **kwargs):
            sent.append(cmd)
            if cmd == ASA_PROBE:
                return self.ios_probe
            if cmd == FAILOVER_PROBE:
                return self.failover
            if cmd == "show version":
                return ASA_VERSION_LINE
            return ""
        conn.send_command.side_effect = send_command
        return conn


def _discover(devices, seed_type=None, targets=None):
    """devices: {ip: _Device}. Returns (inventory, {ip: [device types tried]})."""
    tried = {}

    def connect(self):
        tried.setdefault(self.host, []).append(self.device_type)
        self.effective_device_type = self.device_type
        self.credential = self.credentials[0]
        return ConnectionResult(
            connection=devices[self.host].connection(self.device_type),
            protocol_used="ssh", fallback_occurred=False)

    ips = list(devices)
    engine = DiscoveryEngine(
        seed_ip=ips[0], seed_device_type=seed_type,
        username="admin", password="admin", max_depth=0,
        protocol="ssh", inventory_dir=None, max_workers=1,
        target_hosts=targets)
    with patch.object(ConnectionManager, "connect", autospec=True, side_effect=connect):
        inventory = engine.discover()
    return inventory, tried


def test_untyped_asa_is_reopened_on_the_asa_driver():
    fw = _Device("LAB-FW-01#")
    inventory, tried = _discover({"192.0.2.10": fw})
    assert tried["192.0.2.10"][-1] == "cisco_asa"
    dev = inventory.devices["LAB-FW-01"]
    assert dev["device_type"] == "cisco_asa"
    assert dev["asa_unit"]["role"] == "standalone"
    # Nothing written for IOS reaches the firewall.
    asa_sent = fw.sent["cisco_asa"]
    assert "show cdp neighbors detail" not in asa_sent
    assert "show interfaces" not in asa_sent
    cd = dev["collector_data"]
    assert cd["cdp_lldp"]["parsed"]["not_applicable"] is True
    assert cd["qos"]["parsed"]["not_applicable"] is True
    assert "show version" in cd["device_inventory"]["raw"]


def test_typed_asa_is_not_probed():
    fw = _Device("LAB-FW-01#")
    _, tried = _discover({"192.0.2.10": fw}, seed_type="cisco_asa")
    assert tried["192.0.2.10"] == ["cisco_asa"]
    assert ASA_PROBE not in fw.sent["cisco_asa"]


def test_ios_device_is_not_reopened():
    sw = _Device("LAB-SW-01#", ios_probe="")
    inventory, tried = _discover({"192.0.2.20": sw}, seed_type="cisco_ios")
    assert tried["192.0.2.20"] == ["cisco_ios"]
    assert "asa_unit" not in inventory.devices["LAB-SW-01"]


def test_both_units_of_a_pair_are_kept():
    active = _Device("LAB-FW-01#", failover=FAILOVER_ACTIVE)
    standby = _Device("LAB-FW-01#", failover=FAILOVER_STANDBY)
    targets = [("192.0.2.10", "cisco_asa"), ("192.0.2.11", "cisco_asa")]
    inventory, _ = _discover({"192.0.2.10": active, "192.0.2.11": standby},
                             seed_type="cisco_asa", targets=targets)
    assert {"LAB-FW-01", "LAB-FW-01/stby"} <= set(inventory.devices)
    act = inventory.devices["LAB-FW-01"]
    stby = inventory.devices["LAB-FW-01/stby"]
    assert act["ha_state"] == "active" and stby["ha_state"] == "standby"
    assert stby["asa_unit"] == {"hostname": "LAB-FW-01", "role": "standby",
                                "failover_role": "secondary",
                                "failover_state": "Standby Ready"}


def test_prompt_decorations_are_not_part_of_the_hostname():
    fw = _Device("LAB-FW-01/pri/act#", failover=FAILOVER_ACTIVE)
    inventory, _ = _discover({"192.0.2.10": fw}, seed_type="cisco_asa")
    assert "LAB-FW-01" in inventory.devices


@pytest.mark.parametrize("output,role,frole,state", [
    ("Failover Off\n", "standalone", "", ""),
    ("", "standalone", "", ""),
    (FAILOVER_ACTIVE, "active", "primary", "Active"),
    (FAILOVER_STANDBY, "standby", "secondary", "Standby Ready"),
    ("Failover On\n  This host: Secondary - Failed\n", "standby", "secondary", "Failed"),
])
def test_parse_unit(output, role, frole, state):
    assert parse_unit(output) == {"role": role, "failover_role": frole,
                                  "failover_state": state}


def test_hostname_helpers():
    assert asa_hostname("LAB-FW-01/pri/stby") == "LAB-FW-01"
    assert asa_hostname("LAB-FW-01/admin") == "LAB-FW-01"
    assert unit_key("LAB-FW-01", "standby") == "LAB-FW-01/stby"
    assert unit_key("LAB-FW-01", "active") == "LAB-FW-01"
    assert base_hostname("LAB-FW-01/stby") == "LAB-FW-01"
    assert is_asa(ASA_VERSION_LINE) and not is_asa("Cisco IOS Software")
