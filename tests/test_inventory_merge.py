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


def _ab_scans():
    a = _inv("scan-a", [
        _device(hostname="SW1", mgmt_ip="192.0.2.1", login_succeeded=True),
        _device(hostname="SW2", mgmt_ip="192.0.2.2", login_succeeded=True),
    ], timestamp="2026-08-25T10:00:00+00:00", seed="192.0.2.1")
    b = _inv("scan-b", [
        _device(hostname="SW1", mgmt_ip="192.0.2.1", login_succeeded=True),
        _device(hostname="SW3", mgmt_ip="192.0.2.3", login_succeeded=True),
    ], timestamp="2026-08-27T10:00:00+00:00", seed="192.0.2.3")
    return a, b


def test_remerge_lists_original_scans_not_the_merge_file():
    a, b = _ab_scans()
    first = merge_inventories([a, b])
    again = merge_inventories([first, b])
    assert [m["discovery_id"] for m in again["merged_from"]] == ["scan-a", "scan-b"]
    assert all(m["via"] == first["discovery_id"] for m in again["merged_from"])


def test_remerge_adds_no_conflicts_for_records_from_the_same_scan():
    a, b = _ab_scans()
    first = merge_inventories([a, b])
    assert len(first["merge_conflicts"]) == 1
    again = merge_inventories([first, b])
    assert again["merge_conflicts"] == first["merge_conflicts"]


def test_remerge_keeps_per_device_source_scan():
    a, b = _ab_scans()
    first = merge_inventories([a, b])
    again = merge_inventories([first, b])
    assert again["devices"]["SW1"]["source_scan"] == "scan-b"
    assert again["devices"]["SW2"]["source_scan"] == "scan-a"
    assert again["devices"]["SW3"]["source_scan"] == "scan-b"


def test_merging_two_merges_lists_each_original_once():
    a, b = _ab_scans()
    c = _inv("scan-c", [_device(hostname="SW4", login_succeeded=True)])
    ab = merge_inventories([a, b])
    bc = merge_inventories([b, c])
    both = merge_inventories([ab, bc])
    assert [m["discovery_id"] for m in both["merged_from"]] == [
        "scan-a", "scan-b", "scan-c"]


def test_remerge_conflict_names_the_original_scan():
    a, b = _ab_scans()
    first = merge_inventories([a, b])
    c = _inv("scan-c", [_device(hostname="SW1", mgmt_ip="192.0.2.1",
                                login_succeeded=True)],
             timestamp="2026-08-28T10:00:00+00:00")
    again = merge_inventories([first, c])
    new = [x for x in again["merge_conflicts"] if x["kept_from"] == "scan-c"]
    assert len(new) == 1
    assert new[0]["discarded_from"] == "scan-b"


def test_record_from_earlier_merge_ranks_by_its_own_scan_time():
    """A merge file is stamped with the merge time; its records are not
    that new, so a later scan still wins the newer-scan rule."""
    a, b = _ab_scans()
    first = merge_inventories([a, b])
    c = _inv("scan-c", [_device(hostname="SW1", mgmt_ip="192.0.2.1",
                                login_succeeded=True)],
             timestamp="2026-08-28T10:00:00+00:00")
    again = merge_inventories([first, c])
    assert again["devices"]["SW1"]["source_scan"] == "scan-c"


def test_continued_scan_owns_its_records_even_if_tagged():
    """A continuation of a merge copies tagged records but has no
    merged_from, so its records belong to the continuation."""
    tagged = _device(hostname="SW9", login_succeeded=True, source_scan="scan-old")
    cont = _inv("scan-cont", [tagged])
    other = _inv("scan-x", [_device(hostname="SW8", login_succeeded=True)])
    merged = merge_inventories([cont, other])
    assert merged["devices"]["SW9"]["source_scan"] == "scan-cont"


def _targeted(discovery_id, devices, summary, timestamp="2026-08-26T10:00:00+00:00"):
    inv = _inv(discovery_id, devices, timestamp=timestamp, seed="192.0.2.1")
    inv["scan_summary"] = summary
    return inv


def _target(host, ip, outcome, **kw):
    t = {"input": host, "resolved_ip": ip, "outcome": outcome}
    t.update(kw)
    return t


def _two_targeted_scans():
    a = _targeted("scan-a", [
        _device(hostname="SW1", mgmt_ip="192.0.2.1", login_succeeded=True),
    ], {
        "elapsed": 30.0,
        "failed": {"192.0.2.2": {"reason": "timeout", "hostname": "SW2"}},
        "targets": [
            _target("sw1.example.net", "192.0.2.1", "collected", hostname="SW1"),
            _target("sw2.example.net", "192.0.2.2", "failed", reason="timeout"),
            {"input": "sw9.example.net", "resolved_ip": None,
             "outcome": "unresolved", "reason": "no such name"},
            {"input": "sw4.example.net", "resolved_ip": None,
             "outcome": "unresolved", "reason": "no such name"},
        ],
        "unresolved": [{"input": "sw9.example.net", "error": "no such name"},
                       {"input": "sw4.example.net", "error": "no such name"}],
        "not_attempted": {"198.51.100.5": {"reason": "route next-hop"},
                          "198.51.100.6": {"reason": "route next-hop"}},
        "not_attempted_count": 2,
        "source_ip": "203.0.113.10",
        "source_ip_method": "show users",
        "source_access_line": "source 203.0.113.10 permitted",
        "source_access_warnings": [{"acl": "MGMT-VTY", "service": "ssh"}],
        "timing": {"SW1": {"total": 30.0}},
        "slowest": {"devices": [["SW1", 30.0]], "collectors": []},
        "max_logins_per_minute": 30,
    })
    b = _targeted("scan-b", [
        _device(hostname="SW2", mgmt_ip="192.0.2.2", login_succeeded=True),
        _device(hostname="SW6", mgmt_ip="198.51.100.6", login_succeeded=True),
    ], {
        "elapsed": 12.5,
        "failed": {},
        "targets": [
            _target("SW2.example.net", "192.0.2.2", "collected", hostname="SW2"),
            _target("sw3.example.net", "192.0.2.3", "not_attempted",
                    reason="scan cancelled"),
            _target("sw4.example.net", "192.0.2.4", "not_attempted",
                    reason="scan cancelled"),
        ],
        "unresolved": [],
        "not_attempted": {"198.51.100.7": {"reason": "fhrp"}},
        "source_ip": "203.0.113.20",
        "source_ip_method": "show users",
        "source_access_warnings": [{"acl": "MGMT-VTY", "service": "ssh"},
                                   {"acl": "SNMP-RO", "service": "snmp"}],
        "slowest": {"devices": [["SW2", 12.5]], "collectors": []},
        "max_logins_per_minute": 30,
    }, timestamp="2026-08-27T10:00:00+00:00")
    return a, b


def test_merged_targets_are_a_union_by_host():
    merged = merge_inventories(list(_two_targeted_scans()))
    hosts = sorted(t["input"].lower() for t in merged["scan_summary"]["targets"])
    assert hosts == ["sw1.example.net", "sw2.example.net", "sw3.example.net",
                     "sw4.example.net", "sw9.example.net"]


def test_target_failed_in_one_scan_collected_in_another_is_collected():
    merged = merge_inventories(list(_two_targeted_scans()))
    by_host = {t["input"].lower(): t for t in merged["scan_summary"]["targets"]}
    sw2 = by_host["sw2.example.net"]
    assert sw2["outcome"] == "collected"
    assert sw2["hostname"] == "SW2"
    assert "reason" not in sw2


def test_target_prefers_best_outcome_across_scans():
    merged = merge_inventories(list(_two_targeted_scans()))
    by_host = {t["input"].lower(): t for t in merged["scan_summary"]["targets"]}
    assert by_host["sw1.example.net"]["outcome"] == "collected"
    assert by_host["sw9.example.net"]["outcome"] == "unresolved"
    assert by_host["sw3.example.net"]["outcome"] == "not_attempted"


def test_name_resolved_in_any_scan_is_not_unresolved():
    """Unresolved in one scan, resolved but cancelled before it was tried
    in another: the name resolves, so it is not attempted, not unresolved."""
    summary = merge_inventories(list(_two_targeted_scans()))["scan_summary"]
    by_host = {t["input"].lower(): t for t in summary["targets"]}
    assert by_host["sw4.example.net"]["outcome"] == "not_attempted"
    assert by_host["sw4.example.net"]["resolved_ip"] == "192.0.2.4"
    assert [u["input"] for u in summary["unresolved"]] == ["sw9.example.net"]


def test_merged_target_failed_is_rechecked_against_merged_devices():
    a = _targeted("scan-a", [], {
        "failed": {"192.0.2.2": {"reason": "timeout"}},
        "targets": [_target("192.0.2.2", "192.0.2.2", "failed", reason="timeout")],
    })
    b = _targeted("scan-b", [
        _device(hostname="SW2", mgmt_ip="192.0.2.2", login_succeeded=True)], {})
    merged = merge_inventories([a, b])
    target = merged["scan_summary"]["targets"][0]
    assert target["outcome"] == "collected"
    assert target["hostname"] == "SW2"


def test_merged_target_outcome_counts_are_recomputed():
    counts = merge_inventories(list(_two_targeted_scans()))[
        "scan_summary"]["target_outcomes"]
    assert counts["collected"] == 2
    assert counts["failed"] == 0
    assert counts["unresolved"] == 1
    assert counts["not_attempted"] == 2


def test_unresolved_drops_names_that_resolved_elsewhere():
    a = _targeted("scan-a", [], {
        "targets": [{"input": "sw5.example.net", "resolved_ip": None,
                     "outcome": "unresolved"},
                    {"input": "sw9.example.net", "resolved_ip": None,
                     "outcome": "unresolved"}],
        "unresolved": [{"input": "sw5.example.net", "error": "timeout"},
                       {"input": "sw9.example.net", "error": "timeout"}],
    })
    b = _targeted("scan-b", [
        _device(hostname="SW5", mgmt_ip="192.0.2.5", login_succeeded=True)], {
        "targets": [_target("sw5.example.net", "192.0.2.5", "collected",
                            hostname="SW5")],
    })
    summary = merge_inventories([a, b])["scan_summary"]
    assert [u["input"] for u in summary["unresolved"]] == ["sw9.example.net"]


def test_not_attempted_union_minus_reached():
    summary = merge_inventories(list(_two_targeted_scans()))["scan_summary"]
    assert set(summary["not_attempted"]) == {"198.51.100.5", "198.51.100.7"}
    assert summary["not_attempted_count"] == 2


def test_not_attempted_accepts_a_list():
    a = _targeted("scan-a", [], {"not_attempted": ["198.51.100.8",
                                                  {"ip": "198.51.100.9"}]})
    b = _targeted("scan-b", [], {})
    summary = merge_inventories([a, b])["scan_summary"]
    assert set(summary["not_attempted"]) == {"198.51.100.8", "198.51.100.9"}


def test_no_targets_key_for_untargeted_scans():
    a = _inv("scan-a", [])
    b = _inv("scan-b", [])
    summary = merge_inventories([a, b])["scan_summary"]
    assert "targets" not in summary
    assert summary["not_attempted"] == {}


def test_per_source_run_details_move_to_merged_from():
    merged = merge_inventories(list(_two_targeted_scans()))
    a, b = merged["merged_from"]
    assert a["source_ip"] == "203.0.113.10"
    assert a["source_ip_method"] == "show users"
    assert a["source_access_line"] == "source 203.0.113.10 permitted"
    assert a["source_access_warnings"] == [{"acl": "MGMT-VTY", "service": "ssh"}]
    assert a["elapsed"] == 30.0
    assert a["slowest"]["devices"] == [["SW1", 30.0]]
    assert b["source_ip"] == "203.0.113.20"
    assert b["elapsed"] == 12.5


def test_top_level_keeps_only_what_every_source_agrees_on():
    summary = merge_inventories(list(_two_targeted_scans()))["scan_summary"]
    assert "source_ip" not in summary
    assert "source_access_line" not in summary
    assert summary["source_ip_method"] == "show users"
    assert summary["max_logins_per_minute"] == 30
    assert "timing" not in summary
    assert "slowest" not in summary


def test_source_ip_kept_when_sources_agree():
    a, b = _two_targeted_scans()
    b["scan_summary"]["source_ip"] = "203.0.113.10"
    summary = merge_inventories([a, b])["scan_summary"]
    assert summary["source_ip"] == "203.0.113.10"


def test_access_warnings_are_concatenated_without_repeats():
    summary = merge_inventories(list(_two_targeted_scans()))["scan_summary"]
    assert summary["source_access_warnings"] == [
        {"acl": "MGMT-VTY", "service": "ssh"},
        {"acl": "SNMP-RO", "service": "snmp"},
    ]


def test_elapsed_is_summed_and_says_so():
    summary = merge_inventories(list(_two_targeted_scans()))["scan_summary"]
    assert summary["elapsed"] == 42.5
    assert summary["elapsed_summed"] is True


def test_refused_hint_recomputed_from_merged_failures():
    failed = {f"192.0.2.{n}": {"reason": "refused"} for n in (11, 12, 13)}
    a = _targeted("scan-a", [], {"failed": failed, "source_ip": "203.0.113.10"})
    b = _targeted("scan-b", [], {"source_ip": "203.0.113.10"})
    summary = merge_inventories([a, b])["scan_summary"]
    assert "203.0.113.10" in summary["refused_hint"]


def test_merged_summary_reads_back_through_get_summary():
    from app.inventory import DiscoveryInventory
    merged = merge_inventories(list(_two_targeted_scans()))
    s = DiscoveryInventory(merged).get_summary()
    assert s["elapsed_summed"] is True
    assert s["source_ip_method"] == "show users"
    assert len(s["source_access_warnings"]) == 2


def test_merged_inventory_renders_targets_sheet():
    import io
    from openpyxl import load_workbook
    from app.reports.device_inventory import DeviceInventoryReport
    merged = merge_inventories(list(_two_targeted_scans()))
    wb = load_workbook(io.BytesIO(DeviceInventoryReport().generate(merged, "xlsx")))
    assert "Targets" in wb.sheetnames
    rows = list(wb["Targets"].iter_rows(min_row=2, values_only=True))
    assert len(rows) == 5
    by_host = {r[0].lower(): r for r in rows}
    assert by_host["sw2.example.net"][2] == "Collected"
    assert "Not Collected" in wb.sheetnames


def test_remerge_keeps_per_source_run_details_and_targets():
    a, b = _two_targeted_scans()
    first = merge_inventories([a, b])
    again = merge_inventories([first, b])
    assert [m["source_ip"] for m in again["merged_from"]] == [
        "203.0.113.10", "203.0.113.20"]
    assert again["scan_summary"]["target_outcomes"] == \
        first["scan_summary"]["target_outcomes"]
