"""The engine pages AireOS sessions and names controllers by System Name."""
from unittest.mock import MagicMock, patch

import pytest

from app.connection_manager import ConnectionManager, ConnectionResult
from app.discovery_engine import DiscoveryEngine
from app.wlc_session import SYSINFO, WlcConnection, prompt_name

SYSINFO_OUT = ("Product Version.................................. 8.10.185.0\n"
               "System Name...................................... lab-wlc-01\n")


@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _discover(prompt, sysinfo=SYSINFO_OUT, wrapped=None):
    sent = []
    conn = MagicMock()
    conn.find_prompt.return_value = prompt

    def send_command(cmd, **kwargs):
        sent.append(cmd)
        return sysinfo if cmd == SYSINFO else ""
    conn.send_command.side_effect = send_command

    def connect(self):
        self.effective_device_type = self.device_type
        self.credential = self.credentials[0]
        return ConnectionResult(connection=conn, protocol_used="ssh", fallback_occurred=False)

    def wrap(c):
        wrapped.append(c)
        return c

    engine = DiscoveryEngine(
        seed_ip="192.0.2.30", seed_device_type="cisco_wlc", username="admin",
        password="admin", max_depth=0, protocol="ssh", inventory_dir=None, max_workers=1)
    with patch.object(ConnectionManager, "connect", autospec=True, side_effect=connect), \
            patch("app.discovery_engine.WlcConnection", side_effect=wrap):
        inventory = engine.discover()
    return inventory, sent


def test_default_prompt_is_replaced_by_system_name():
    wrapped = []
    inventory, sent = _discover("(Cisco Controller) >", wrapped=wrapped)
    assert "lab-wlc-01" in inventory.devices
    assert inventory.devices["lab-wlc-01"]["device_type"] == "cisco_wlc"
    assert sent[0] == SYSINFO
    assert len(wrapped) == 1


def test_no_system_name_falls_back_to_the_prompt_then_the_address():
    inventory, _ = _discover("(lab-wlc-02) >", sysinfo="", wrapped=[])
    assert "lab-wlc-02" in inventory.devices
    inventory, _ = _discover("(Cisco Controller) >", sysinfo="", wrapped=[])
    assert "192.0.2.30" in inventory.devices


def test_wrapper_routes_send_command_through_paging():
    raw = MagicMock()
    with patch("app.wlc_session.send_paged", return_value="out") as paged:
        assert WlcConnection(raw).send_command("show ap summary", read_timeout=30) == "out"
    paged.assert_called_once_with(raw, "show ap summary", 120)
    raw.send_command.assert_not_called()


def test_prompt_name():
    assert prompt_name("(lab-wlc-01) >") == "lab-wlc-01"
    assert prompt_name("(Cisco Controller) >") == ""
    assert prompt_name("") == ""
