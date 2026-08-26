from app.neighbors import get_registry, extract_all


def _device(collector_data):
    return {"hostname": "CORE1", "collector_data": collector_data}


def test_registry_has_expected_sources():
    names = set(get_registry())
    assert {"cdp_lldp", "routing_adjacency", "next_hop", "hsrp_vrrp"} <= names


def test_cdp_lldp_source_passes_neighbours_through():
    dev = _device({"cdp_lldp": {"parsed": {"neighbors": [
        {"remote_device": "SW2", "remote_ip": "10.0.0.2",
         "remote_platform": "cisco WS-C3850", "remote_capabilities": "Switch",
         "remote_intf": "Gi1/0/1"},
    ]}}})
    refs = get_registry()["cdp_lldp"].extract(dev)
    assert len(refs) == 1
    assert refs[0]["remote_ip"] == "10.0.0.2"
    assert refs[0]["source"] == "cdp_lldp"


def test_routing_adjacency_yields_protocol_peers():
    dev = _device({"l3_routing": {"parsed": {"neighbors": [
        {"remote_ip": "10.0.0.5", "protocol": "OSPF",
         "remote_capabilities": "Router", "state": "FULL"},
        {"remote_ip": "10.0.0.6", "protocol": "BGP",
         "remote_capabilities": "Router"},
    ]}}})
    refs = get_registry()["routing_adjacency"].extract(dev)
    ips = {r["remote_ip"] for r in refs}
    assert ips == {"10.0.0.5", "10.0.0.6"}
    assert all(r["source"] == "routing_adjacency" for r in refs)


def test_next_hop_source_extracts_gateways():
    dev = _device({"l3_routing": {"parsed": {"routes": [
        {"network": "10.5.0.0", "nexthop_ip": "10.0.0.9"},
        {"network": "10.6.0.0", "next_hop": "10.0.0.10"},
        {"network": "10.7.0.0", "nexthop_ip": ""},
    ]}}})
    refs = get_registry()["next_hop"].extract(dev)
    ips = {r["remote_ip"] for r in refs}
    assert ips == {"10.0.0.9", "10.0.0.10"}


def test_next_hop_deduplicates_repeated_gateways():
    """A default gateway appears on hundreds of routes."""
    routes = [{"network": f"10.{i}.0.0", "nexthop_ip": "10.0.0.1"}
              for i in range(200)]
    dev = _device({"l3_routing": {"parsed": {"routes": routes}}})
    refs = get_registry()["next_hop"].extract(dev)
    assert len(refs) == 1


def test_hsrp_source_yields_peers():
    dev = _device({"hsrp": {"parsed": {"entries": [
        {"group": "10", "active_ip": "10.0.0.2", "standby_ip": "10.0.0.3"},
    ]}}})
    refs = get_registry()["hsrp_vrrp"].extract(dev)
    ips = {r["remote_ip"] for r in refs}
    assert "10.0.0.2" in ips
    assert "10.0.0.3" in ips


def test_failed_collector_yields_nothing():
    dev = _device({"l3_routing": {"parsed": {"collector_failed": True}}})
    assert get_registry()["routing_adjacency"].extract(dev) == []
    assert get_registry()["next_hop"].extract(dev) == []


def test_missing_collector_yields_nothing():
    dev = _device({})
    for source in get_registry().values():
        assert source.extract(dev) == []


def test_extract_all_merges_and_dedupes_by_ip():
    dev = _device({
        "cdp_lldp": {"parsed": {"neighbors": [
            {"remote_device": "SW2", "remote_ip": "10.0.0.2",
             "remote_capabilities": "Switch"}]}},
        "l3_routing": {"parsed": {
            "neighbors": [{"remote_ip": "10.0.0.2", "protocol": "OSPF"}],
            "routes": [{"network": "0.0.0.0", "nexthop_ip": "10.0.0.9"}],
        }},
    })
    refs = extract_all(dev, enabled={"cdp_lldp", "routing_adjacency", "next_hop"})
    ips = [r["remote_ip"] for r in refs]
    assert ips.count("10.0.0.2") == 1, "same peer seen twice must merge"
    assert "10.0.0.9" in ips


def test_next_hop_is_off_by_default():
    """A routing table names far more gateways than a site owns, and each
    costs a login attempt -- so next-hop crawling is opt-in."""
    from app.neighbors import default_enabled
    enabled = default_enabled()
    assert "next_hop" not in enabled
    assert {"cdp_lldp", "routing_adjacency", "hsrp_vrrp"} <= enabled


def test_merged_ref_records_every_sighting():
    dev = _device({
        "cdp_lldp": {"parsed": {"neighbors": [
            {"remote_device": "SW2", "remote_ip": "10.0.0.2"}]}},
        "l3_routing": {"parsed": {
            "neighbors": [{"remote_ip": "10.0.0.2", "protocol": "OSPF"}]}},
    })
    ref = [r for r in extract_all(dev) if r["remote_ip"] == "10.0.0.2"][0]
    assert set(ref["seen_via"]) == {"cdp_lldp", "routing_adjacency"}


def test_extract_all_prefers_the_named_sighting():
    """CDP knows the hostname; OSPF only knows an address. Keep the name."""
    dev = _device({
        "cdp_lldp": {"parsed": {"neighbors": [
            {"remote_device": "SW2", "remote_ip": "10.0.0.2"}]}},
        "l3_routing": {"parsed": {
            "neighbors": [{"remote_ip": "10.0.0.2", "protocol": "OSPF"}]}},
    })
    ref = [r for r in extract_all(dev) if r["remote_ip"] == "10.0.0.2"][0]
    assert ref["remote_device"] == "SW2"


def test_disabled_sources_are_skipped():
    dev = _device({"l3_routing": {"parsed": {
        "routes": [{"network": "0.0.0.0", "nexthop_ip": "10.0.0.9"}]}}})
    refs = extract_all(dev, enabled={"cdp_lldp"})
    assert refs == []
