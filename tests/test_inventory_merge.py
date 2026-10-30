from app.inventory_merge import merge_inventories, pick_winner


def _device(**kw):
    base = {
        "hostname": kw.get("hostname", "SW1"),
        "mgmt_ip": None, "device_type": None, "device_category": None,
        "platform": None, "discovery_source": None, "login_succeeded": False,
        "login_error": None, "serial": None, "model": None,
        "software_version": None, "evidence": [], "collector_data": {},
    }
    base.update(kw)
    return base


def _inv(discovery_id, devices, timestamp="2026-08-26T10:00:00+00:00", seed="10.0.0.1"):
    return {
        "discovery_id": discovery_id,
        "seed_ip": seed,
        "timestamp": timestamp,
        "params": {},
        "devices": {d["hostname"]: d for d in devices},
    }


def test_merge_requires_at_least_two():
    import pytest
    with pytest.raises(ValueError):
        merge_inventories([_inv("a", [])])


def test_devices_from_both_files_are_present():
    a = _inv("a", [_device(hostname="SW1", mgmt_ip="10.0.0.1")])
    b = _inv("b", [_device(hostname="SW2", mgmt_ip="10.0.0.2")])
    merged = merge_inventories([a, b])
    assert set(merged["devices"]) == {"SW1", "SW2"}


def test_merged_records_its_sources():
    a = _inv("scan-a", [])
    b = _inv("scan-b", [])
    merged = merge_inventories([a, b])
    assert [m["discovery_id"] for m in merged["merged_from"]] == ["scan-a", "scan-b"]
    assert merged["discovery_id"] not in ("scan-a", "scan-b")


def test_collected_record_beats_neighbour_record():
    """A device logged into must never be replaced by a neighbour sighting."""
    a = _inv("a", [_device(hostname="SW1", mgmt_ip="10.0.0.1",
                           login_succeeded=True, serial="FOC1",
                           discovery_source="login",
                           collector_data={"arp": {"parsed": {}}})])
    b = _inv("b", [_device(hostname="SW1", discovery_source="cdp_lldp")],
             timestamp="2026-08-27T10:00:00+00:00")
    merged = merge_inventories([a, b])
    sw1 = merged["devices"]["SW1"]
    assert sw1["login_succeeded"] is True
    assert sw1["serial"] == "FOC1"


def test_newer_wins_between_two_collected_records():
    a = _inv("a", [_device(hostname="SW1", login_succeeded=True,
                           software_version="15.0")],
             timestamp="2026-08-25T10:00:00+00:00")
    b = _inv("b", [_device(hostname="SW1", login_succeeded=True,
                           software_version="16.9")],
             timestamp="2026-08-27T10:00:00+00:00")
    assert merge_inventories([a, b])["devices"]["SW1"]["software_version"] == "16.9"


def test_loser_fills_fields_the_winner_lacks():
    """Nothing known should be thrown away just because it lost."""
    a = _inv("a", [_device(hostname="SW1", login_succeeded=True,
                           serial="FOC1", model=None)],
             timestamp="2026-08-27T10:00:00+00:00")
    b = _inv("b", [_device(hostname="SW1", model="WS-C3850",
                           discovery_source="cdp_lldp")])
    sw1 = merge_inventories([a, b])["devices"]["SW1"]
    assert sw1["serial"] == "FOC1"
    assert sw1["model"] == "WS-C3850"


def test_collector_data_is_unioned():
    a = _inv("a", [_device(hostname="SW1", login_succeeded=True,
                           collector_data={"arp": {"parsed": {"entries": [1]}}})])
    b = _inv("b", [_device(hostname="SW1", login_succeeded=True,
                           collector_data={"interfaces": {"parsed": {}}})])
    cd = merge_inventories([a, b])["devices"]["SW1"]["collector_data"]
    assert set(cd) == {"arp", "interfaces"}


def test_winner_collector_data_is_not_overwritten():
    a = _inv("a", [_device(hostname="SW1", login_succeeded=True,
                           collector_data={"arp": {"parsed": {"entries": [1, 2]}}})],
             timestamp="2026-08-27T10:00:00+00:00")
    b = _inv("b", [_device(hostname="SW1", login_succeeded=True,
                           collector_data={"arp": {"parsed": {"entries": []}}})])
    cd = merge_inventories([a, b])["devices"]["SW1"]["collector_data"]
    assert cd["arp"]["parsed"]["entries"] == [1, 2]


def test_evidence_accumulates_across_files():
    a = _inv("a", [_device(hostname="SW1",
                           evidence=[{"source": "cdp_lldp", "seen_from": "CORE1"}])])
    b = _inv("b", [_device(hostname="SW1",
                           evidence=[{"source": "lldp", "seen_from": "CORE2"}])])
    ev = merge_inventories([a, b])["devices"]["SW1"]["evidence"]
    assert len(ev) == 2


def test_duplicate_evidence_is_not_repeated():
    entry = {"source": "cdp_lldp", "seen_from": "CORE1", "remote_port": "Gi1/0/1"}
    a = _inv("a", [_device(hostname="SW1", evidence=[entry])])
    b = _inv("b", [_device(hostname="SW1", evidence=[dict(entry)])])
    assert len(merge_inventories([a, b])["devices"]["SW1"]["evidence"]) == 1


def test_hostname_variants_are_merged():
    """The NX-OS hostname(serial).domain form must fold into one device."""
    a = _inv("a", [_device(hostname="N5K-A", mgmt_ip="172.21.0.27",
                           login_succeeded=True, serial="FOC1")])
    b = _inv("b", [_device(hostname="N5K-A(SSI1).example.net",
                           discovery_source="cdp_lldp")])
    merged = merge_inventories([a, b])
    assert len(merged["devices"]) == 1
    assert merged["devices"]["N5K-A"]["login_succeeded"] is True


def test_different_serials_are_different_devices():
    a = _inv("a", [_device(hostname="SW1", login_succeeded=True, serial="AAA")])
    b = _inv("b", [_device(hostname="SW1", login_succeeded=True, serial="BBB")])
    assert len(merge_inventories([a, b])["devices"]) == 2


def test_three_files_merge():
    invs = [_inv(f"s{i}", [_device(hostname=f"SW{i}")]) for i in range(3)]
    merged = merge_inventories(invs)
    assert len(merged["devices"]) == 3
    assert len(merged["merged_from"]) == 3


def test_failures_are_carried_forward():
    a = dict(_inv("a", []), scan_summary={"failed": {"10.0.0.9": "timeout"},
                                          "elapsed": 1.0, "failed_count": 1})
    b = dict(_inv("b", []), scan_summary={"failed": {"10.0.0.8": "auth"},
                                          "elapsed": 1.0, "failed_count": 1})
    merged = merge_inventories([a, b])
    failed = merged["scan_summary"]["failed"]
    assert set(failed) == {"10.0.0.9", "10.0.0.8"}


def test_device_collected_in_one_file_clears_its_failure_elsewhere():
    """If a device was reached in any file, it is not a failure any more."""
    a = dict(_inv("a", []), scan_summary={"failed": {"10.0.0.1": "timeout"},
                                          "elapsed": 1.0, "failed_count": 1})
    b = _inv("b", [_device(hostname="SW1", mgmt_ip="10.0.0.1",
                           login_succeeded=True)])
    merged = merge_inventories([a, b])
    assert "10.0.0.1" not in merged["scan_summary"]["failed"]


def test_sources_do_not_mutate():
    a = _inv("a", [_device(hostname="SW1", login_succeeded=True)])
    b = _inv("b", [_device(hostname="SW1", model="WS-C3850")])
    before = a["devices"]["SW1"]["model"]
    merge_inventories([a, b])
    assert a["devices"]["SW1"]["model"] == before


def test_pick_winner_prefers_collected():
    collected = _device(hostname="SW1", login_succeeded=True)
    seen = _device(hostname="SW1", discovery_source="cdp_lldp")
    assert pick_winner(seen, "2026-08-27", collected, "2026-08-25") is collected


def test_pick_winner_prefers_more_collector_data():
    thin = _device(hostname="SW1", login_succeeded=True,
                   collector_data={"arp": {}})
    rich = _device(hostname="SW1", login_succeeded=True,
                   collector_data={"arp": {}, "interfaces": {}})
    assert pick_winner(thin, "2026-08-27", rich, "2026-08-25") is rich


def test_merged_from_carries_structured_detail():
    """A bare list of ids does not say much six weeks later."""
    a = _inv("scan-a", [_device(hostname="SW1")], seed="10.0.0.1",
             timestamp="2026-08-25T10:00:00+00:00")
    b = _inv("scan-b", [_device(hostname="SW2")], seed="10.1.0.1")
    merged = merge_inventories([a, b], filenames=["a.json", "b.json"])
    first = merged["merged_from"][0]
    assert first["discovery_id"] == "scan-a"
    assert first["filename"] == "a.json"
    assert first["device_count"] == 1
    assert first["seed_ip"] == "10.0.0.1"
    assert first["timestamp"].startswith("2026-08-25")


def test_merged_from_works_without_filenames():
    a = _inv("scan-a", [])
    b = _inv("scan-b", [])
    merged = merge_inventories([a, b])
    assert [m["discovery_id"] for m in merged["merged_from"]] == ["scan-a", "scan-b"]


def test_each_device_records_which_scan_it_came_from():
    a = _inv("scan-a", [_device(hostname="SW1", login_succeeded=True)])
    b = _inv("scan-b", [_device(hostname="SW2", login_succeeded=True)])
    merged = merge_inventories([a, b])
    assert merged["devices"]["SW1"]["source_scan"] == "scan-a"
    assert merged["devices"]["SW2"]["source_scan"] == "scan-b"


def test_conflicts_are_recorded_with_a_reason():
    """A merge that silently picks a winner should say what it dropped."""
    a = _inv("scan-a", [_device(hostname="SW1", login_succeeded=True,
                                serial="FOC1")])
    b = _inv("scan-b", [_device(hostname="SW1", discovery_source="cdp_lldp")],
             timestamp="2026-08-27T10:00:00+00:00")
    merged = merge_inventories([a, b])
    conflicts = merged["merge_conflicts"]
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["hostname"] == "SW1"
    assert c["kept_from"] == "scan-a"
    assert c["discarded_from"] == "scan-b"
    assert "neighbour" in c["reason"].lower()


def test_conflict_reason_names_the_deciding_rule():
    a = _inv("scan-a", [_device(hostname="SW1", login_succeeded=True,
                                collector_data={"arp": {}, "interfaces": {}})])
    b = _inv("scan-b", [_device(hostname="SW1", login_succeeded=True,
                                collector_data={"arp": {}})],
             timestamp="2026-08-27T10:00:00+00:00")
    reason = merge_inventories([a, b])["merge_conflicts"][0]["reason"]
    assert "collector" in reason.lower() or "data" in reason.lower()


def test_newer_wins_reason():
    a = _inv("scan-a", [_device(hostname="SW1", login_succeeded=True)],
             timestamp="2026-08-25T10:00:00+00:00")
    b = _inv("scan-b", [_device(hostname="SW1", login_succeeded=True)],
             timestamp="2026-08-27T10:00:00+00:00")
    merged = merge_inventories([a, b])
    assert merged["merge_conflicts"][0]["kept_from"] == "scan-b"
    assert "newer" in merged["merge_conflicts"][0]["reason"].lower()


def test_no_conflicts_when_nothing_overlaps():
    a = _inv("scan-a", [_device(hostname="SW1")])
    b = _inv("scan-b", [_device(hostname="SW2")])
    assert merge_inventories([a, b])["merge_conflicts"] == []


def test_merged_inventory_is_flagged():
    merged = merge_inventories([_inv("a", []), _inv("b", [])])
    assert merged["params"]["merged"] is True
