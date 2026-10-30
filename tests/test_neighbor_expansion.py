"""Gating of non-CDP/LLDP neighbour addresses and discovered_via recording."""
import pytest

from app.discovery_engine import DiscoveryEngine
from app.inventory import DiscoveryInventory
from app.neighbors import expansion

CISCO_MAC = "00:00:0c:aa:bb:01"
JUNIPER_MAC = "0005.85aa.bb02"
VMWARE_MAC = "00:50:56:aa:bb:03"

ROUTERS = {"include_routers": True, "include_switches": True}


# --- OUI table and decision rules -------------------------------------------

def test_vendor_for_mac_accepts_colon_and_dotted_forms():
    assert expansion.vendor_for_mac(CISCO_MAC) == "cisco"
    assert expansion.vendor_for_mac(JUNIPER_MAC) == "juniper"
    assert expansion.vendor_for_mac("00-1C-73-01-02-03") == "arista"


def test_vendor_for_mac_rejects_unknown_and_garbage():
    assert expansion.vendor_for_mac(VMWARE_MAC) is None
    assert expansion.vendor_for_mac("") is None
    assert expansion.vendor_for_mac("incomplete") is None


def test_every_listed_prefix_is_a_well_formed_oui():
    for vendor, prefixes in expansion.NETWORK_VENDOR_OUIS.items():
        for prefix in prefixes:
            assert expansion._oui(prefix + ":00:00:00") == prefix, (vendor, prefix)


@pytest.mark.parametrize("state,multi", [
    ("FULL/DR", True), ("FULL/BDR", True), ("FULL/DROTHER", True),
    ("FULL/-", False), ("FULL/  -", False), ("FULL", False), (None, False),
])
def test_ospf_multiaccess_detection(state, multi):
    ref = {"protocol": "OSPF", "state": state}
    assert (expansion.kind_of(ref) == "ospf_multiaccess") is multi


def test_bgp_peer_needs_cdp_even_with_vendor_mac():
    ref = {"protocol": "BGP"}
    assert expansion.decide(ref, False, mac=CISCO_MAC) == (
        False, expansion.REASON_BGP)
    assert expansion.decide(ref, True, mac=None) == (True, None)
    assert expansion.decide(ref, False, mac=None, expand=True) == (True, None)


def test_multiaccess_ospf_needs_cdp_even_with_vendor_mac():
    ref = {"protocol": "OSPF", "state": "FULL/DR"}
    assert expansion.decide(ref, False, mac=CISCO_MAC) == (
        False, expansion.REASON_OSPF_MULTIACCESS)


def test_p2p_adjacency_and_next_hop_follow_the_oui_rule():
    for ref in ({"protocol": "OSPF", "state": "FULL/-"},
                {"protocol": "EIGRP"},
                {"source": "next_hop"},
                {"source": "hsrp_vrrp"}):
        assert expansion.decide(ref, False, mac=CISCO_MAC) == (True, None)
        assert expansion.decide(ref, False, mac=VMWARE_MAC) == (
            False, expansion.REASON_NON_VENDOR_MAC)
        assert expansion.decide(ref, False, mac=None) == (
            False, expansion.REASON_NO_ARP)


def test_arp_map_skips_incomplete_entries():
    devices = {"RTR-A": {"collector_data": {"arp": {"parsed": {"entries": [
        {"ip": "10.0.0.5", "mac": CISCO_MAC, "incomplete": False},
        {"ip": "10.0.0.6", "mac": "", "incomplete": True},
    ]}}}}}
    assert expansion.arp_map(devices) == {"10.0.0.5": CISCO_MAC}


def test_discovered_via_labels():
    label = expansion.discovered_via_label
    assert label({"source": "cdp_lldp", "protocols": ["CDP", "LLDP"]}) == "cdp"
    assert label({"source": "cdp_lldp", "protocols": ["LLDP"]}) == "lldp"
    assert label({"source": "routing_adjacency"}) == "routing"
    assert label({"source": "next_hop"}) == "next_hop"
    assert label({"source": "hsrp_vrrp"}) == "hsrp_vrrp"


# --- engine -----------------------------------------------------------------

def _cdp(name, ip, platform, caps, protocols=("CDP",)):
    return {"remote_device": name, "remote_ip": ip, "remote_platform": platform,
            "remote_capabilities": caps, "local_intf": "Gi0/1",
            "remote_intf": "Gi0/1", "protocols": list(protocols)}


# hostname, then per-collector parsed data, keyed by management address.
TOPOLOGY = {
    "10.0.0.1": ("RTR-A", {
        "cdp_lldp": {"neighbors": [
            _cdp("SW1", "10.0.0.2", "cisco WS-C3850-48P", "Switch IGMP"),
        ]},
        "l3_routing": {"neighbors": [
            {"remote_ip": "10.9.0.1", "protocol": "BGP", "state": "Established"},
            {"remote_ip": "10.9.0.2", "protocol": "OSPF", "state": "FULL/DR"},
            {"remote_ip": "10.0.0.3", "protocol": "OSPF", "state": "FULL/-"},
            {"remote_ip": "10.9.0.4", "protocol": "EIGRP", "state": "UP"},
            {"remote_ip": "10.9.0.5", "protocol": "EIGRP", "state": "UP"},
            # Multi-access, but SW1 sees it over CDP one layer later.
            {"remote_ip": "10.0.0.6", "protocol": "OSPF", "state": "FULL/BDR"},
        ]},
        "arp": {"entries": [
            {"ip": "10.9.0.1", "mac": CISCO_MAC, "incomplete": False},
            {"ip": "10.0.0.3", "mac": JUNIPER_MAC, "incomplete": False},
            {"ip": "10.9.0.5", "mac": VMWARE_MAC, "incomplete": False},
        ]},
    }),
    "10.0.0.2": ("SW1", {
        "cdp_lldp": {"neighbors": [
            _cdp("RTR-B", "10.0.0.6", "cisco ISR4451-X/K9", "Router",
                 protocols=("LLDP",)),
        ]},
    }),
    "10.0.0.3": ("RTR-C", {}),
    "10.0.0.6": ("RTR-B", {}),
    "10.9.0.1": ("PE-1", {}),
}


def _engine(monkeypatch, tmp_path, **kwargs):
    events = []
    kwargs.setdefault("max_depth", 2)
    engine = DiscoveryEngine(
        seed_ip="10.0.0.1", seed_device_type="cisco_ios",
        username="u", password="p", filters=dict(ROUTERS),
        inventory_dir=str(tmp_path), max_workers=1,
        progress_callback=events.append, **kwargs)
    attempted = []

    def fake_discover(ip, device_type, depth, inventory):
        attempted.append(ip)
        hostname, collectors = TOPOLOGY[ip]
        inventory.add_device(hostname, mgmt_ip=ip, device_type="cisco_ios",
                             discovery_source="login")
        inventory.mark_login_succeeded(hostname)
        for name, parsed in collectors.items():
            inventory.set_collector_data(hostname, name, raw={}, parsed=parsed)
        return engine._extract_neighbors(inventory, hostname, ip,
                                         "cisco_ios", depth)

    monkeypatch.setattr(engine, "_discover_device", fake_discover)
    return engine, events, attempted


def test_non_cdp_addresses_are_gated_and_recorded(monkeypatch, tmp_path):
    engine, events, attempted = _engine(monkeypatch, tmp_path)
    inv = engine.discover()
    summary = inv.to_dict()["scan_summary"]

    assert sorted(attempted) == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.6"]
    not_attempted = summary["not_attempted"]
    assert {ip: r["reason"] for ip, r in not_attempted.items()} == {
        "10.9.0.1": expansion.REASON_BGP,
        "10.9.0.2": expansion.REASON_OSPF_MULTIACCESS,
        "10.9.0.4": expansion.REASON_NO_ARP,
        "10.9.0.5": expansion.REASON_NON_VENDOR_MAC,
    }
    assert not_attempted["10.9.0.1"]["source"] == "routing_adjacency"
    assert not_attempted["10.9.0.1"]["seen_on"] == "RTR-A"
    assert not_attempted["10.9.0.1"]["protocol"] == "BGP"
    assert summary["not_attempted_count"] == 4

    complete = [e for e in events if e["event"] == "scan_complete"][0]
    assert complete["not_attempted_count"] == 4


def test_expand_setting_attempts_every_in_scope_address(monkeypatch, tmp_path):
    engine, _, attempted = _engine(monkeypatch, tmp_path,
                                   expand_non_cdp_neighbors=True)
    monkeypatch.setitem(TOPOLOGY, "10.9.0.2", ("FW-1", {}))
    monkeypatch.setitem(TOPOLOGY, "10.9.0.4", ("RTR-D", {}))
    monkeypatch.setitem(TOPOLOGY, "10.9.0.5", ("HOST-1", {}))
    inv = engine.discover()
    assert "10.9.0.1" in attempted
    assert inv.to_dict()["scan_summary"]["not_attempted"] == {}
    assert inv.to_dict()["params"]["expand_non_cdp_neighbors"] is True


def test_scope_guard_still_applies_before_the_gate(monkeypatch, tmp_path):
    engine, _, attempted = _engine(monkeypatch, tmp_path,
                                   expand_non_cdp_neighbors=True)
    monkeypatch.setitem(TOPOLOGY, "10.0.0.1", ("RTR-A", {"l3_routing": {
        "neighbors": [{"remote_ip": "198.51.100.1", "protocol": "BGP"}]}}))
    inv = engine.discover()
    assert attempted == ["10.0.0.1"]
    summary = inv.to_dict()["scan_summary"]
    assert "198.51.100.1" in summary["out_of_scope"]
    assert summary["not_attempted"] == {}


def test_depth_limit_is_not_reported_as_not_attempted(monkeypatch, tmp_path):
    engine, _, attempted = _engine(monkeypatch, tmp_path, max_depth=0)
    inv = engine.discover()
    assert attempted == ["10.0.0.1"]
    assert inv.to_dict()["scan_summary"]["not_attempted"] == {}


def test_discovered_via_is_recorded_per_device(monkeypatch, tmp_path):
    engine, _, _ = _engine(monkeypatch, tmp_path)
    devices = engine.discover().devices
    assert devices["RTR-A"]["discovered_via"] == "seed"
    assert devices["SW1"]["discovered_via"] == "cdp"
    assert devices["RTR-B"]["discovered_via"] == "lldp"
    assert devices["RTR-C"]["discovered_via"] == "routing"


def test_targeted_scan_records_target_params(monkeypatch, tmp_path):
    engine, _, _ = _engine(
        monkeypatch, tmp_path,
        target_hosts=[("10.0.0.1", "cisco_ios"), ("10.0.0.2", None)],
        target_resolution={"targets": [], "unresolved": [],
                           "targets_file": "hosts.csv"})
    inv = engine.discover()
    params = inv.to_dict()["params"]
    assert params["targets_file"] == "hosts.csv"
    assert params["targets_count"] == 2
    assert params["target_hints"] == {"10.0.0.1": "cisco_ios"}
    assert inv.devices["RTR-A"]["discovered_via"] == "target"
    assert inv.devices["SW1"]["discovered_via"] == "target"


def test_device_inventory_column_uses_discovered_via():
    from app.reports.device_inventory import _discovered_via
    device = {"discovery_source": "login", "mgmt_ip": "10.0.0.3",
              "discovered_via": "next_hop"}
    assert _discovered_via("RTR-C", device, {"params": {}}) == "next_hop"
