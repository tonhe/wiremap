"""The engine hands the QoS collector its device context, and optional
collectors can be left out of a scan."""
from unittest.mock import MagicMock, patch

import pytest

from app.collectors.qos import MLS_QOS, POLICY_MAP_INTERFACE, QFP_QOS_GLOBAL
from app.connection_manager import ConnectionResult
from app.discovery_engine import DiscoveryEngine

ASR_SHOW_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a
RTR-A uptime is 1 year, 2 weeks, 3 days, 4 hours, 5 minutes
cisco ASR1001-HX (1NG) processor (revision 1NG) with 3730415K/6147K bytes of memory.
"""

C2960_SHOW_VERSION = """\
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8
cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision B0) with 524288K bytes of memory.
"""

CDP_PHONE = """\
-------------------------
Device ID: SEP00005E005301
Entry address(es):
  IP address: 192.0.2.50
Platform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Port 1
Holdtime : 150 sec
"""


@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _discover(hostname, show_version, outputs=None, **engine_kwargs):
    sent = []
    outputs = outputs or {}

    def send_command(cmd, **kwargs):
        sent.append(cmd)
        if cmd == "show version":
            return show_version
        return outputs.get(cmd, "")

    engine = DiscoveryEngine(
        seed_ip="192.0.2.1", seed_device_type="cisco_xe",
        username="admin", password="admin", max_depth=0,
        protocol="ssh", inventory_dir=None, max_workers=1, **engine_kwargs)
    conn = MagicMock()
    conn.find_prompt.return_value = f"{hostname}#"
    conn.send_command.side_effect = send_command
    result = ConnectionResult(connection=conn, protocol_used="ssh",
                              fallback_occurred=False)
    with patch("app.connection_manager.ConnectionManager.connect",
               return_value=result):
        inventory = engine.discover()
    return inventory, sent


def test_router_gets_router_qos_commands():
    inventory, sent = _discover("RTR-A", ASR_SHOW_VERSION)
    assert POLICY_MAP_INTERFACE in sent and QFP_QOS_GLOBAL in sent
    assert MLS_QOS not in sent
    qos = inventory.devices["RTR-A"]["collector_data"]["qos"]["parsed"]
    assert qos["qos_global"]["platform_family"] == "router-qfp"


def test_classic_switch_gets_neighbours_from_cdp():
    inventory, sent = _discover(
        "SW-A", C2960_SHOW_VERSION,
        outputs={"show cdp neighbors detail": CDP_PHONE,
                 MLS_QOS: "QoS is enabled\n"})
    assert MLS_QOS in sent
    qos = inventory.devices["SW-A"]["collector_data"]["qos"]["parsed"]
    assert qos["qos_global"]["platform_family"] == "classic"
    assert qos["qos_global"]["mls_qos_enabled"] is True
    ports = {i["interface"]: i for i in qos["interfaces"]}
    assert ports["GigabitEthernet1/0/5"]["neighbor_class"] == "phone"


def test_every_collector_runs():
    inventory, _ = _discover("SW-A", C2960_SHOW_VERSION)
    params = inventory.to_dict()["params"]
    assert "collectors_skipped" not in params
    assert {"qos", "asa", "wlc"} <= set(params["collectors_enabled"])
