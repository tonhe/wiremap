"""Device identity after login: NAME(SERIAL) neighbour IDs, OS type, category
and a management address chosen by rule rather than crawl order."""
from unittest.mock import MagicMock, patch

import pytest

from app.connection_manager import ConnectionManager, ConnectionResult
from app.device_role import (
    category_for_model, device_type_from_show_version, is_switchless_router,
    is_voice_gateway_model, skips_routing,
)
from app.discovery_engine import DiscoveryEngine
from app.neighbors import CrawlScope
from app.identity import (
    collected_serial, resolve_mgmt_ip, split_device_id,
)
from app.inventory import DiscoveryInventory
from app.inventory_merge import merge_inventories
from app.parsers import parse_cdp_neighbors_detail, parse_lldp_neighbors_detail


# --- split_device_id ---------------------------------------------------------

@pytest.mark.parametrize("raw,name,serial", [
    ("MDS-A(JPG00000000)", "MDS-A", "JPG00000000"),
    ("HOST-02(FOC0000X00X)", "HOST-02", "FOC0000X00X"),
    ("MDS-A(JPG00000000).example.com", "MDS-A.example.com", "JPG00000000"),
    ("MDS-A.example.com(JPG00000000)", "MDS-A.example.com", "JPG00000000"),
    ("RTR-A", "RTR-A", None),
    # Not serials: lowercase, too short, no digit, too long
    ("EDGE(backup)", "EDGE(backup)", None),
    ("EDGE(A1)", "EDGE(A1)", None),
    ("EDGE(BACKUPLINK)", "EDGE(BACKUPLINK)", None),
    ("EDGE(ABCDEFGHIJ12345)", "EDGE(ABCDEFGHIJ12345)", None),
    ("", "", None),
    (None, None, None),
])
def test_split_device_id(raw, name, serial):
    assert split_device_id(raw) == (name, serial)


IOS_CDP = """\
-------------------------
Device ID: MDS-A(JPG00000000)
Entry address(es):
  IP address: 192.0.2.20
Platform: cisco DS-C9148S-K9,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): mgmt0
Holdtime : 150 sec

Version :
Cisco Nexus Operating System (NX-OS) Software, Version 8.4(2c)

Management address(es):
  IP address: 192.0.2.20
"""

NXOS_CDP = """\
----------------------------------------
Device ID:RTR-A
System Name: RTR-A

Interface address(es):
    IPv4 Address: 203.0.113.9
Platform: cisco ISR4351/K9, Capabilities: Router Switch IGMP
Interface: Ethernet1/1, Port ID (outgoing port): GigabitEthernet0/0/1
Holdtime: 170 sec

Mgmt address(es):
    IPv4 Address: 198.51.100.1
"""


def test_cdp_parser_splits_serial_from_device_id():
    [n] = parse_cdp_neighbors_detail(IOS_CDP)
    assert n["remote_device"] == "MDS-A"
    assert n["remote_serial"] == "JPG00000000"


def test_cdp_parser_separates_management_address():
    [n] = parse_cdp_neighbors_detail(NXOS_CDP)
    assert n["remote_mgmt_ip"] == "198.51.100.1"
    assert "remote_serial" not in n


def test_cdp_parser_entry_address_alone_is_not_management():
    text = IOS_CDP.split("Management address")[0]
    [n] = parse_cdp_neighbors_detail(text)
    assert n["remote_ip"] == "192.0.2.20"
    assert "remote_mgmt_ip" not in n


def test_lldp_parser_splits_serial_from_system_name():
    text = (
        "Local Intf: Gi1/0/1\n"
        "Chassis id: 0000.5e00.5301\n"
        "Port id: Eth1/1\n"
        "System Name: HOST-02(FOC0000X00X)\n"
        "Management Addresses:\n"
        "    IP: 192.0.2.30\n"
    )
    [n] = parse_lldp_neighbors_detail(text)
    assert n["remote_device"] == "HOST-02"
    assert n["remote_serial"] == "FOC0000X00X"
    assert n["remote_mgmt_ip"] == "192.0.2.30"


def test_old_scan_neighbour_record_is_split_on_extract():
    from app.neighbors.sources import CdpLldpSource
    device = {"collector_data": {"cdp_lldp": {"parsed": {"neighbors": [
        {"remote_device": "MDS-A(JPG00000000)", "remote_ip": "192.0.2.20"},
    ]}}}}
    [ref] = CdpLldpSource().extract(device)
    assert ref["remote_device"] == "MDS-A"
    assert ref["remote_serial"] == "JPG00000000"


# --- device_role -------------------------------------------------------------

@pytest.mark.parametrize("model,category", [
    ("ISR4351/K9", "router"),
    ("ASR1001-HX", "router"),
    ("C8300-1N1S-6T", "router"),
    ("C1121X", "router"),
    ("C1111-8P", None),            # integrated switch, not a plain router
    ("VG310", "voice-gateway"),
    ("VG204XM", "voice-gateway"),
    ("VG450", "voice-gateway"),
    ("C9300-48P", "switch"),
    ("WS-C3850-48P", "switch"),
    ("N9K-C93180YC-FX", "switch"),
    ("C93180YC-EX", "switch"),
    ("C9800-40-K9", None),         # wireless controller
    ("", None),
])
def test_category_for_model(model, category):
    assert category_for_model(model) == category


def test_voice_gateway_skips_switching_and_routing():
    vg = "Cisco IOS Software, VG3x0 Software\ncisco VG310 (revision 1.0) with 1000K/1000K bytes of memory.\n"
    assert is_voice_gateway_model("cisco VG310")
    assert is_switchless_router(show_version=vg)
    assert skips_routing(show_version=vg)
    assert not skips_routing(model="ISR4351/K9")
    assert skips_routing(category="voice-gateway")


XE_VERSION = ("Cisco IOS XE Software, Version 17.09.04a\n"
              "Cisco IOS Software [Cupertino], ASR1000 Software, Version 17.9.4a\n"
              "cisco ASR1001-HX (2KP) processor (revision 2KP) with 1K/1K bytes of memory.\n")
XE3_VERSION = "Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software\n"
IOS_VERSION = ("Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), "
               "Version 15.7(3)M8\n")
NXOS_VERSION = "Cisco Nexus Operating System (NX-OS) Software\n"


@pytest.mark.parametrize("text,current,expected", [
    (XE_VERSION, "cisco_ios", "cisco_xe"),
    (XE_VERSION, None, "cisco_xe"),
    (XE3_VERSION, "cisco_ios", "cisco_xe"),
    (IOS_VERSION, "cisco_xe", "cisco_ios"),
    (NXOS_VERSION, "cisco_ios", "cisco_nxos"),
    ("Cisco IOS XR Software, Version 7.3.2\n", "cisco_ios", "cisco_ios"),
    ("", "cisco_ios", "cisco_ios"),
    (XE_VERSION, "juniper_junos", "juniper_junos"),
    ("% Invalid input", None, None),
])
def test_device_type_from_show_version(text, current, expected):
    assert device_type_from_show_version(text, current) == expected


# --- engine ------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _conn(hostname, outputs, sent):
    def send_command(cmd, **kwargs):
        sent.append((hostname, cmd))
        return outputs.get(cmd, "")

    conn = MagicMock()
    conn.find_prompt.return_value = f"{hostname}#"
    conn.send_command.side_effect = send_command
    return ConnectionResult(connection=conn, protocol_used="ssh",
                            fallback_occurred=False)


def _run(devices, seed="192.0.2.1", seed_type="cisco_ios", depth=1):
    """devices maps ip -> (hostname, {command: output})."""
    sent = []
    results = {ip: _conn(name, out, sent) for ip, (name, out) in devices.items()}

    def connect(self):
        return results[self.host]

    engine = DiscoveryEngine(
        seed_ip=seed, seed_device_type=seed_type,
        username="admin", password="admin", max_depth=depth,
        protocol="ssh", inventory_dir=None, max_workers=1,
        crawl_scope=CrawlScope(rfc1918_only=False),
    )
    with patch.object(ConnectionManager, "connect", autospec=True,
                      side_effect=connect):
        inventory = engine.discover()
    return inventory, sent


def test_cdp_name_with_serial_and_ssh_login_are_one_device():
    inventory, _ = _run({
        "192.0.2.1": ("RTR-A", {"show version": IOS_VERSION,
                                "show cdp neighbors detail": IOS_CDP}),
        "192.0.2.20": ("MDS-A", {"show version": NXOS_VERSION}),
    })
    assert "MDS-A" in inventory.devices
    assert not [n for n in inventory.devices if "(" in n]
    mds = inventory.devices["MDS-A"]
    assert mds["login_succeeded"] is True
    assert mds["cdp_serial"] == "JPG00000000"
    assert mds["device_type"] == "cisco_nxos"
    # Link and topology reports read the neighbour name from here
    [n] = (inventory.devices["RTR-A"]["collector_data"]["cdp_lldp"]
           ["parsed"]["neighbors"])
    assert n["remote_device"] == "MDS-A"


def test_device_type_comes_from_show_version_not_the_neighbour():
    inventory, sent = _run({
        "192.0.2.1": ("RTR-A", {"show version": XE_VERSION}),
    }, depth=0)
    dev = inventory.devices["RTR-A"]
    assert dev["device_type"] == "cisco_xe"
    # Commands were chosen for the proven type: the IOS-XE map
    assert ("RTR-A", "show stackwise-virtual") in sent
    # show version is not sent twice
    assert [c for _, c in sent].count("show version") == 1


def test_identical_routers_get_identical_types():
    a, _ = _run({"192.0.2.1": ("RTR-A", {"show version": XE_VERSION})},
                seed_type="cisco_ios", depth=0)
    b, _ = _run({"192.0.2.2": ("RTR-B", {"show version": XE_VERSION})},
                seed="192.0.2.2", seed_type="cisco_xe", depth=0)
    assert a.devices["RTR-A"]["device_type"] == \
        b.devices["RTR-B"]["device_type"] == "cisco_xe"


def test_router_with_switch_capability_categorised_from_model():
    isr = ("Cisco IOS XE Software, Version 17.09.04a\n"
           "cisco ISR4351/K9 (2RU) processor with 1K/1K bytes of memory.\n")
    inventory, _ = _run({"192.0.2.1": ("RTR-A", {"show version": isr})},
                        depth=0)
    assert inventory.devices["RTR-A"]["device_category"] == "router"


def test_category_overrides_neighbour_guess():
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("RTR-A", device_category="switch", device_type="cisco_ios")
    inv.set_collected_role("RTR-A", device_type="cisco_xe",
                           device_category="router")
    assert inv.devices["RTR-A"]["device_type"] == "cisco_xe"
    assert inv.devices["RTR-A"]["device_category"] == "router"


def test_voice_gateway_skips_switching_and_routing_collectors():
    vg = ("Cisco IOS Software, VG3x0 Software (VG3X0-UNIVERSALK9-M), "
          "Version 15.7(3)M8\n"
          "cisco VG310 (revision 1.0) with 1K/1K bytes of memory.\n")
    inventory, sent = _run({"192.0.2.1": ("VG-A", {"show version": vg})},
                           depth=0)
    dev = inventory.devices["VG-A"]
    assert dev["device_category"] == "voice-gateway"
    cmds = {c for _, c in sent}
    assert "show ip route" not in cmds
    assert "show ip protocols" not in cmds
    assert "show interfaces switchport" not in cmds
    for cname in ("l3_routing", "routing_detail", "switchport", "mac_table"):
        assert dev["collector_data"][cname]["parsed"]["not_applicable"] is True
    # General collection still ran
    assert "show ip interface brief" in cmds


# --- management address ------------------------------------------------------

BRIEF = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   203.0.113.1     YES NVRAM  up                    up
GigabitEthernet0/0/1   203.0.113.9     YES NVRAM  up                    up
Loopback0              198.51.100.1    YES NVRAM  up                    up
"""


def _logged_in(reached, evidence=(), loopback=True):
    rows = [{"interface": "GigabitEthernet0/0/0", "ip_address": "203.0.113.1"},
            {"interface": "GigabitEthernet0/0/1", "ip_address": "203.0.113.9"},
            {"interface": "Loopback0", "ip_address": "198.51.100.1"}]
    if not loopback:
        rows = rows[:2]
    return {
        "hostname": "RTR-A", "mgmt_ip": reached, "reached_ip": reached,
        "login_succeeded": True, "evidence": list(evidence),
        "collector_data": {"interfaces": {"parsed": {"ip_interfaces": rows}}},
    }


def test_loopback_beats_reached_address():
    assert resolve_mgmt_ip(_logged_in("203.0.113.1")) == \
        ("198.51.100.1", "loopback")


def test_reached_address_when_nothing_better():
    assert resolve_mgmt_ip(_logged_in("203.0.113.1", loopback=False)) == \
        ("203.0.113.1", "reached")


def test_advertised_address_owned_by_device_wins():
    dev = _logged_in("198.51.100.1", evidence=[
        {"source": "cdp_lldp", "seen_from": "SW-A",
         "remote_port": "Gi0/0/0", "mgmt_address": "203.0.113.9"},
    ])
    assert resolve_mgmt_ip(dev) == ("203.0.113.9", "advertised")


def test_advertised_link_address_is_not_a_management_address():
    # Each neighbour on a link sees that link's own address advertised.
    dev = _logged_in("203.0.113.1", evidence=[
        {"source": "cdp_lldp", "seen_from": "PE-A",
         "remote_port": "GigabitEthernet0/0/1", "mgmt_address": "203.0.113.9"},
    ])
    assert resolve_mgmt_ip(dev) == ("198.51.100.1", "loopback")


def test_advertised_address_not_owned_is_ignored():
    dev = _logged_in("203.0.113.1", evidence=[
        {"source": "cdp_lldp", "seen_from": "SW-A", "remote_port": "Gi0/0/0",
         "mgmt_address": "192.0.2.99"},
    ])
    assert resolve_mgmt_ip(dev) == ("198.51.100.1", "loopback")


def test_mgmt_ip_independent_of_arrival_order():
    sightings = [
        {"source": "cdp_lldp", "seen_from": "PE-A",
         "remote_port": "Gi0/0/1", "mgmt_address": "203.0.113.9"},
        {"source": "cdp_lldp", "seen_from": "PE-B",
         "remote_port": "Gi0/0/0", "mgmt_address": "203.0.113.1"},
    ]
    a = resolve_mgmt_ip(_logged_in("203.0.113.1", sightings))
    b = resolve_mgmt_ip(_logged_in("203.0.113.9", list(reversed(sightings))))
    assert a == b == ("198.51.100.1", "loopback")


def test_engine_records_loopback_as_mgmt_ip():
    inventory, _ = _run({"192.0.2.1": ("RTR-A", {
        "show version": XE_VERSION, "show ip interface brief": BRIEF})},
        depth=0)
    dev = inventory.devices["RTR-A"]
    assert dev["mgmt_ip"] == "198.51.100.1"
    assert dev["mgmt_ip_source"] == "loopback"
    assert dev["reached_ip"] == "192.0.2.1"
    assert inventory.collected_ips() >= {"192.0.2.1", "198.51.100.1"}


def test_scan_merge_picks_mgmt_ip_by_rule():
    def inv(ts, reached):
        dev = _logged_in(reached)
        return {"discovery_id": ts, "seed_ip": reached, "timestamp": ts,
                "devices": {"RTR-A": dev}}

    one = merge_inventories([inv("2026-01-01T00:00:00+00:00", "203.0.113.1"),
                             inv("2026-01-02T00:00:00+00:00", "203.0.113.9")])
    two = merge_inventories([inv("2026-01-02T00:00:00+00:00", "203.0.113.9"),
                             inv("2026-01-01T00:00:00+00:00", "203.0.113.1")])
    assert one["devices"]["RTR-A"]["mgmt_ip"] == \
        two["devices"]["RTR-A"]["mgmt_ip"] == "198.51.100.1"


# --- serial handling ---------------------------------------------------------

def test_neighbour_serial_fills_serial_and_keeps_cdp_serial():
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("MDS-A", mgmt_ip="192.0.2.20")
    inv.set_neighbour_serial("MDS-A", "JPG00000000")
    dev = inv.devices["MDS-A"]
    assert dev["serial"] == "JPG00000000"
    assert dev["cdp_serial"] == "JPG00000000"
    inv.mark_login_succeeded("MDS-A", serial="JPG11111111")
    assert dev["serial"] == "JPG11111111"
    assert dev["cdp_serial"] == "JPG00000000"


def test_existing_serial_is_not_replaced_by_cdp():
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("MDS-A")
    inv.mark_login_succeeded("MDS-A", serial="JPG11111111")
    inv.set_neighbour_serial("MDS-A", "JPG00000000")
    assert inv.devices["MDS-A"]["serial"] == "JPG11111111"
    assert inv.devices["MDS-A"]["cdp_serial"] == "JPG00000000"


def test_cdp_serial_does_not_block_merge_with_collected_twin():
    # NX-OS may advertise the chassis serial while show version reports the
    # supervisor's; the two records are still one device.
    inv = DiscoveryInventory.create(seed_ip="192.0.2.1")
    inv.add_device("mds-a", mgmt_ip="192.0.2.20")
    inv.set_neighbour_serial("mds-a", "JPG00000000")
    inv.add_device("MDS-A", mgmt_ip="192.0.2.20")
    inv.mark_login_succeeded("MDS-A", serial="JPG11111111")
    assert inv.merge_duplicates() == 1
    assert list(inv.devices) == ["MDS-A"]


def test_collected_serial_ignores_cdp_only_serial():
    assert collected_serial({"serial": "JPG00000000",
                             "cdp_serial": "JPG00000000"}) == ""
    assert collected_serial({"serial": "JPG00000000",
                             "cdp_serial": "JPG00000000",
                             "login_succeeded": True}) == "JPG00000000"
    assert collected_serial({"serial": "JPG11111111"}) == "JPG11111111"
