"""Voice & QoS report: posture, voice ports, uplinks/WAN, catalogs, findings."""
import io

import pytest
from openpyxl import load_workbook

from app.collectors.qos import DEFAULT_DSCP_OUTPUT_Q
from app.reports import get_registry
from app.reports.voice_qos import VoiceQosReport, analyze, build_tabular


def _intf(name, **kw):
    base = {"interface": name, "trust_state": "", "trust_mode": "", "trust_device": "",
            "auto_qos_macro": "", "queue_set": None, "expedite_queue": None,
            "ingress_policy": "", "egress_policy": "", "neighbor": "",
            "neighbor_platform": "", "neighbor_class": "none", "voice_vlan": "",
            "is_trunk": False, "is_uplink": False}
    base.update(kw)
    return base


def _phone_port(name, trust="trust cos", **kw):
    return _intf(name, neighbor="SEP00005E005301", neighbor_class="phone",
                 voice_vlan="110", trust_state=trust, **kw)


def _uplink(name, **kw):
    return _intf(name, neighbor="LAB-DIST-01", neighbor_class="switch",
                 is_trunk=True, is_uplink=True, **kw)


def _policy_def(name, actions="set dscp ef", hash_="aaaa"):
    return {"name": name, "hash": hash_,
            "classes": [{"name": "LAB-VOICE", "actions": [actions]}]}


def _device(qos, uptime="2 weeks, 1 day", counters=(), model="WS-C2960X-48FPD-L",
            edge=None):
    cd = {
        "qos": {"raw": {}, "parsed": qos},
        "device_inventory": {"parsed": {"version_details": {
            "model": model, "uptime": uptime}}},
        "interface_counters": {"parsed": {"interfaces": list(counters)}},
    }
    if edge is not None:
        cd["edge_services"] = {"parsed": {"access_lists": edge}}
    return {"collector_data": cd, "model": model}


def _classic(interfaces, mls=True, queues=(), dscp=(), dmap=None, policies=(),
             policy_defs=(), class_defs=(), **glob):
    return {
        "qos_global": dict({"platform_family": "classic", "mls_qos_enabled": mls,
                            "auto_qos_applied": any(i["auto_qos_macro"] for i in interfaces),
                            "queue_set_tuned": False}, **glob),
        "interfaces": list(interfaces), "queues": list(queues),
        "dscp_counters": list(dscp), "policies": list(policies),
        "policy_definitions": list(policy_defs), "class_definitions": list(class_defs),
        "maps": {"dscp_output_q": dmap if dmap is not None else dict(DEFAULT_DSCP_OUTPUT_Q),
                 "cos_output_q": {}},
    }


def _router(policies, interfaces=(), family="router-qfp"):
    return {"qos_global": {"platform_family": family, "mls_qos_enabled": None},
            "interfaces": list(interfaces), "queues": [], "dscp_counters": [],
            "policies": list(policies), "policy_definitions": [],
            "class_definitions": [], "maps": {}}


def _out_policy(interface, name, classes):
    return {"interface": interface, "direction": "output", "policy_name": name,
            "parent_policy": None, "parent_class": None, "classes": classes,
            "priority_queue": {}}


def _class(name, **kw):
    base = {"class_name": name, "set": [], "is_priority": False, "drops": None,
            "priority_drops": None, "priority_percent": None, "priority_kbps": None}
    base.update(kw)
    return base


def _up(name, **kw):
    row = {"interface": name, "status": "up", "protocol": "up",
           "counters_cleared": "never", "output_drops": 0}
    row.update(kw)
    return row


def _inv(**devices):
    return {"devices": devices, "params": {}}


def _findings(inv, ftype=None):
    found = analyze(inv)["findings"]
    return [f for f in found if ftype is None or f["type"] == ftype]


def _sheets(inv):
    return build_tabular(inv, analyze(inv))


def _rows(sheets, name):
    headers, rows = sheets[name]
    return [dict(zip(headers, r)) for r in rows]


# --- registry -------------------------------------------------------------

def test_registered_and_needs_qos_data():
    report = get_registry()["voice_qos"]
    assert report.required_collectors == ["qos"]
    assert not report.can_generate(_inv(SW=_device({"not_applicable": True})))
    assert report.can_generate(_inv(SW=_device(_classic([_phone_port("Gi1/0/5")]))))


def test_old_scan_without_qos_cannot_generate():
    assert not VoiceQosReport().can_generate(
        {"devices": {"SW": {"collector_data": {"cdp_lldp": {"parsed": {}}}}}})


# --- QoS off: per-port commands not run --------------------------------------

def test_qos_off_switch_shows_qos_off_and_why_commands_were_not_run():
    qos = _classic([_phone_port("GigabitEthernet1/0/5", trust="")], mls=False,
                   dmap={}, queue_set_tuned=None,
                   deep_skipped="QoS is disabled globally")
    qos["skipped_commands"] = ["show mls qos interface", "show mls qos queue-set"]
    sheets = _sheets(_inv(SW1=_device(qos)))
    [row] = _rows(sheets, "Switch QoS Posture")
    assert row["mls qos"] == "Off"
    assert (row["Queue-Set"], row["DSCP-to-Queue Map"], row["EF Queue"]) == (
        "QoS off", "QoS off", "QoS off")
    [err] = _rows(sheets, "Collection Errors")
    assert err["Command"] == "2 per-port QoS commands"
    assert err["Error"] == "not run: QoS is disabled globally" and err["Kind"] == "skipped"


# --- findings ---------------------------------------------------------------

def test_mls_qos_disabled_with_voice_endpoints():
    inv = _inv(SW1=_device(_classic([_phone_port("GigabitEthernet1/0/5")], mls=False)))
    [f] = _findings(inv, "qos:mls_disabled")
    assert f["severity"] == "Critical" and f["hostname"] == "SW1"


def test_mls_qos_disabled_without_voice_is_quiet():
    inv = _inv(SW1=_device(_classic([_intf("GigabitEthernet1/0/5")], mls=False)))
    assert not _findings(inv, "qos:mls_disabled")


def test_untrusted_voice_port_without_marking():
    inv = _inv(SW1=_device(_classic([
        _phone_port("GigabitEthernet1/0/5"),
        _phone_port("GigabitEthernet1/0/6", trust="not trusted")])))
    [f] = _findings(inv, "qos:voice_untrusted")
    assert "GigabitEthernet1/0/6" in f["description"]
    assert "GigabitEthernet1/0/5" not in f["description"]


def test_untrusted_port_with_marking_policy_is_fine():
    policy = {"interface": "GigabitEthernet1/0/6", "direction": "input",
              "policy_name": "LAB-PHONE-IN", "parent_policy": None,
              "classes": [_class("LAB-VOICE", set=["dscp ef"])]}
    inv = _inv(SW1=_device(_classic(
        [_phone_port("GigabitEthernet1/0/6", trust="not trusted",
                     ingress_policy="LAB-PHONE-IN")], policies=[policy])))
    assert not _findings(inv, "qos:voice_untrusted")


def test_cat9k_voice_port_trusts_by_default():
    qos = _classic([_phone_port("GigabitEthernet1/0/6", trust="")], mls=None,
                   platform_family="cat9k")
    inv = _inv(SW1=_device(qos, model="C9300-48P"))
    assert not _findings(inv, "qos:voice_untrusted")
    [row] = _rows(_sheets(inv), "Voice Ports")
    assert row["QoS Status"] == "Trusted (platform default)"


def test_ef_mapped_outside_priority_queue():
    dmap = dict(DEFAULT_DSCP_OUTPUT_Q, **{"46": "02-01"})
    inv = _inv(SW1=_device(_classic([_phone_port("GigabitEthernet1/0/5")], dmap=dmap)))
    [f] = _findings(inv, "qos:ef_queue")
    assert f["severity"] == "Critical" and "02-01" in f["description"]
    posture = _rows(_sheets(inv), "Switch QoS Posture")[0]
    assert posture["DSCP-to-Queue Map"] == "Modified"
    assert posture["EF Queue"] == "02-01"


def test_classic_uplink_without_expedite_queue():
    inv = _inv(SW1=_device(_classic([
        _uplink("GigabitEthernet1/0/49", expedite_queue=False),
        _uplink("GigabitEthernet1/0/50", expedite_queue=True)])))
    [f] = _findings(inv, "qos:uplink_no_priority")
    assert f["interface"] == "GigabitEthernet1/0/49"
    rows = {r["Interface"]: r for r in _rows(_sheets(inv), "Uplinks and WAN")}
    assert rows["GigabitEthernet1/0/49"]["Flag"] == "No egress policy"
    assert rows["GigabitEthernet1/0/50"]["Egress Policy"] == "srr expedite queue"
    assert rows["GigabitEthernet1/0/50"]["Flag"] == ""


def test_wan_interface_without_llq_and_lan_interface_left_alone():
    shape_only = _out_policy("GigabitEthernet0/0/1", "LAB-SHAPE",
                             [_class("class-default", drops=5)])
    qos = _router([shape_only], interfaces=[
        _intf("GigabitEthernet0/0/2", neighbor="LAB-DIST-01", neighbor_class="switch")])
    inv = _inv(RTR1=_device(qos, model="ASR1001-HX", counters=[
        _up("GigabitEthernet0/0/1", description="LAB MPLS circuit"),
        _up("GigabitEthernet0/0/2"), _up("Loopback0"), _up("GigabitEthernet0")]))
    [f] = _findings(inv, "qos:wan_no_llq")
    assert f["interface"] == "GigabitEthernet0/0/1"
    assert "without a priority class" in f["description"]
    rows = {r["Interface"]: r for r in _rows(_sheets(inv), "Uplinks and WAN")}
    assert set(rows) == {"GigabitEthernet0/0/1", "GigabitEthernet0/0/2"}
    assert rows["GigabitEthernet0/0/1"]["Role"] == "Router WAN/DCI"
    assert rows["GigabitEthernet0/0/1"]["WAN Evidence"] == "description (MPLS)"
    assert rows["GigabitEthernet0/0/1"]["Flag"] == "No priority class"
    assert rows["GigabitEthernet0/0/2"]["Role"] == "Router LAN (to switch)"
    assert rows["GigabitEthernet0/0/2"]["Flag"] == ""


def test_subinterface_covered_by_parent_policy():
    llq = _out_policy("GigabitEthernet0/0/1", "LAB-WAN",
                      [_class("LAB-RT", is_priority=True, priority_percent=20)])
    inv = _inv(RTR1=_device(_router([llq]), model="ISR4351/K9", counters=[
        _up("GigabitEthernet0/0/1", description="LAB-WAN-1"),
        _up("GigabitEthernet0/0/1.100")]))
    assert not _findings(inv, "qos:wan_no_llq")
    rows = {r["Interface"]: r for r in _rows(_sheets(inv), "Uplinks and WAN")}
    assert rows["GigabitEthernet0/0/1.100"]["Role"] == "Router WAN/DCI"
    assert rows["GigabitEthernet0/0/1.100"]["Priority Class"] == "LAB-RT"


def test_voice_gateway_is_not_flagged_for_wan_llq():
    inv = _inv(VG1=_device(_router([], family="router"), model="VG310",
                           counters=[_up("GigabitEthernet0/0")]))
    assert not _findings(inv, "qos:wan_no_llq")


def _router_device(counters, **collectors):
    dev = _device(_router([]), model="ASR1001-HX", counters=counters)
    for name, parsed in collectors.items():
        dev["collector_data"][name] = {"parsed": parsed}
    return dev


def _ip_intf(name, ip, prefix):
    return {"interface": name, "ip_address": [ip], "prefix_length": [prefix]}


def _uplink_roles(inv):
    return {r["Interface"]: (r["Role"], r["WAN Evidence"])
            for r in _rows(_sheets(inv), "Uplinks and WAN")}


def test_port_channel_subinterfaces_without_evidence_are_lan():
    names = ["Port-channel51", "Port-channel51.996", "Port-channel52.993"]
    inv = _inv(RTR1=_router_device([_up(n) for n in names] + [_up("GigabitEthernet0/0/3")]))
    roles = _uplink_roles(inv)
    for n in names:
        assert roles[n] == ("Router LAN (no CDP neighbour)", "")
    assert roles["GigabitEthernet0/0/3"] == ("Router, unclassified (no CDP neighbour)", "")
    assert not _findings(inv, "qos:wan_no_llq")


def test_wan_from_public_address_bgp_peer_and_nat_outside():
    inv = _inv(RTR1=_router_device(
        [_up("GigabitEthernet0/0/0"), _up("GigabitEthernet0/0/1"),
         _up("GigabitEthernet0/0/2"), _up("Port-channel10"), _up("Port-channel10.20")],
        interfaces={"ip_interfaces_full": [
            _ip_intf("GigabitEthernet0/0/0", "198.51.100.2", "30"),
            _ip_intf("GigabitEthernet0/0/1", "10.255.0.1", "30"),
            _ip_intf("Port-channel10.20", "10.20.0.1", "24")]},
        routing_detail={"bgp_summary": [
            {"neighbor": "10.255.0.2", "asn": "65010"},
            {"neighbor": "10.99.0.1", "asn": "65010"}]},
        config={"config": ("interface GigabitEthernet0/0/2\n"
                           " ip nat outside\n"
                           "!\n"
                           "interface Port-channel10\n"
                           " ip nat inside\n")}))
    roles = _uplink_roles(inv)
    assert roles["GigabitEthernet0/0/0"] == ("Router WAN/DCI", "public address 198.51.100.2")
    assert roles["GigabitEthernet0/0/1"] == ("Router WAN/DCI", "BGP peer 10.255.0.2")
    assert roles["GigabitEthernet0/0/2"] == ("Router WAN/DCI", "ip nat outside")
    assert roles["Port-channel10"][0] == "Router LAN (no CDP neighbour)"
    assert roles["Port-channel10.20"][0] == "Router LAN (no CDP neighbour)"
    assert {f["interface"] for f in _findings(inv, "qos:wan_no_llq")} == {
        "GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "GigabitEthernet0/0/2"}


def test_subinterface_inherits_parent_wan_evidence_and_neighbour():
    qos = _router([], interfaces=[
        _intf("Port-channel1", neighbor="LAB-DIST-01", neighbor_class="switch")])
    dev = _device(qos, model="ASR1001-HX", counters=[
        _up("Port-channel1"), _up("Port-channel1.10"),
        _up("GigabitEthernet0/0/1", description="to LAB-ISP"),
        _up("GigabitEthernet0/0/1.200")])
    roles = _uplink_roles(_inv(RTR1=dev))
    assert roles["Port-channel1.10"][0] == "Router LAN (to switch)"
    assert roles["GigabitEthernet0/0/1.200"] == ("Router WAN/DCI", "description (ISP)")


def test_priority_drops_with_counter_window():
    llq = _out_policy("GigabitEthernet0/0/1", "LAB-WAN", [
        _class("LAB-RT", is_priority=True, priority_percent=20, priority_drops=12),
        _class("class-default", drops=288)])
    inv = _inv(RTR1=_device(_router([llq]), model="ASR1001-HX",
                            uptime="36 weeks, 2 days, 4 hours",
                            counters=[_up("GigabitEthernet0/0/1", output_drops=300)]))
    [f] = _findings(inv, "qos:pq_drops")
    assert f["severity"] == "Warning"
    assert "12 priority-queue drops" in f["description"]
    assert "since boot (36 weeks, 2 days, 4 hours)" in f["description"]
    [stale] = _findings(inv, "qos:stale_counters")
    assert stale["severity"] == "Info"
    [row] = _rows(_sheets(inv), "Uplinks and WAN")
    assert row["Priority Class"] == "LAB-RT" and row["Priority Rate"] == "20%"
    assert row["Priority Drops"] == 12 and row["Queue Drops"] == 300
    assert row["Counters"].startswith("since boot")


def test_priority_drops_reported_twice_are_counted_once():
    llq = _out_policy("GigabitEthernet0/0/1", "LAB-WAN", [
        _class("LAB-RT", is_priority=True, priority_drops=12, drops=12)])
    inv = _inv(RTR1=_device(_router([llq]), model="ASR1001-HX",
                            counters=[_up("GigabitEthernet0/0/1")]))
    [row] = _rows(_sheets(inv), "Uplinks and WAN")
    assert row["Priority Drops"] == 12 and row["Queue Drops"] == 12


def test_cleared_counters_are_not_stale():
    llq = _out_policy("GigabitEthernet0/0/1", "LAB-WAN", [
        _class("LAB-RT", is_priority=True, priority_drops=3)])
    inv = _inv(RTR1=_device(_router([llq]), model="ASR1001-HX", uptime="2 years",
                            counters=[_up("GigabitEthernet0/0/1",
                                          counters_cleared="1d02h")]))
    [f] = _findings(inv, "qos:pq_drops")
    assert "cleared 1d02h ago" in f["description"]
    assert not _findings(inv, "qos:stale_counters")


def test_classic_expedite_queue_drops():
    queues = [{"interface": "GigabitEthernet1/0/49", "queue_id": 1, "enqueued": 10,
               "dropped": 7, "is_priority": True, "unit": "packets"},
              {"interface": "GigabitEthernet1/0/49", "queue_id": 2, "enqueued": 10,
               "dropped": 1, "is_priority": False, "unit": "packets"}]
    inv = _inv(SW1=_device(_classic(
        [_uplink("GigabitEthernet1/0/49", expedite_queue=True)], queues=queues)))
    [f] = _findings(inv, "qos:pq_drops")
    assert "7 priority-queue drops" in f["description"]
    [row] = _rows(_sheets(inv), "Uplinks and WAN")
    assert row["Queue Drops"] == 8


def test_ef_lost_between_access_and_uplink():
    dscp = [{"interface": "GigabitEthernet1/0/5", "direction": "in",
             "dscp": {"46": 1500}, "cos": {}},
            {"interface": "GigabitEthernet1/0/49", "direction": "out",
             "dscp": {"0": 90000}, "cos": {}}]
    ports = [_phone_port("GigabitEthernet1/0/5"),
             _uplink("GigabitEthernet1/0/49", expedite_queue=True)]
    inv = _inv(SW1=_device(_classic(ports, dscp=dscp)))
    [f] = _findings(inv, "qos:ef_lost")
    assert "1500 EF packets" in f["description"]
    [row] = _rows(_sheets(inv), "Voice Ports")
    assert row["Ingress EF (pkts)"] == 1500
    dscp[1]["dscp"]["46"] = 1400
    assert not _findings(_inv(SW1=_device(_classic(ports, dscp=dscp))), "qos:ef_lost")


def test_auto_qos_on_some_phone_ports_only():
    inv = _inv(SW1=_device(_classic([
        _phone_port("GigabitEthernet1/0/5", auto_qos_macro="auto qos voip cisco-phone"),
        _phone_port("GigabitEthernet1/0/6")])))
    [f] = _findings(inv, "qos:auto_partial")
    assert f["severity"] == "Info" and "1 of 2" in f["description"]


def test_policy_map_versions_across_fleet():
    inv = _inv(
        SW1=_device(_classic([], policy_defs=[_policy_def("LAB-MARK", hash_="aaaa")])),
        SW2=_device(_classic([], policy_defs=[_policy_def("LAB-MARK", hash_="aaaa")])),
        SW3=_device(_classic([], policy_defs=[_policy_def(
            "LAB-MARK", actions="set dscp cs5", hash_="bbbb")])))
    found = _findings(inv, "qos:policy_drift")
    assert sorted(f["hostname"] for f in found) == ["SW1", "SW2", "SW3"]
    assert all(f["severity"] == "Warning" for f in found)
    sw3 = next(f for f in found if f["hostname"] == "SW3")
    assert "version 2 of 2" in sw3["description"]
    [agg] = [r for r in _rows(_sheets(inv), "Findings")
             if r["Finding"] == "Policy-map has multiple versions"]
    assert "LAB-MARK exists in 2 versions" in agg["Details"]
    assert agg["Device count"] == 3
    assert agg["Devices"] == "SW1, SW2, SW3"
    assert not _findings(inv, "meta:overfire")
    rows = _rows(_sheets(inv), "Policy Catalog")
    assert [(r["Version"], r["Device Count"]) for r in rows] == [("1 of 2", 2), ("2 of 2", 1)]
    assert rows[1]["Classes and Actions"] == "LAB-VOICE: set dscp cs5"


def test_class_catalog_flags_missing_acl_and_unused():
    classes = [{"name": "LAB-SIG", "match_type": "match-all",
                "match": ["access-group name LAB-SIP-ACL"], "acls": ["LAB-SIP-ACL"],
                "hash": "cccc"},
               {"name": "LAB-OLD", "match_type": "match-any", "match": ["dscp af41"],
                "acls": [], "hash": "dddd"},
               {"name": "class-default", "match_type": "match-any", "match": ["any"],
                "acls": [], "hash": "eeee"}]
    policy = {"name": "LAB-MARK", "hash": "ffff",
              "classes": [{"name": "LAB-SIG", "actions": ["set dscp cs3"]}]}
    inv = _inv(SW1=_device(_classic([], policy_defs=[policy], class_defs=classes),
                           edge=[{"name": "LAB-OTHER-ACL"}]))
    rows = {r["Class Map"]: r for r in _rows(_sheets(inv), "Class Catalog")}
    assert "class-default" not in rows
    assert rows["LAB-SIG"]["Flags"] == "ACL missing on SW1"
    assert rows["LAB-OLD"]["Flags"] == "Unused on SW1"


def test_acl_check_skipped_without_acl_data():
    classes = [{"name": "LAB-SIG", "match_type": "match-all", "match": [],
                "acls": ["LAB-SIP-ACL"], "hash": "cccc"}]
    inv = _inv(SW1=_device(_classic([], class_defs=classes)))
    [row] = _rows(_sheets(inv), "Class Catalog")
    assert "ACL missing" not in row["Flags"]


# --- sheets -----------------------------------------------------------------

def test_posture_row():
    inv = _inv(SW1=_device(_classic([
        _phone_port("GigabitEthernet1/0/5", ingress_policy="LAB-PHONE-IN",
                    auto_qos_macro="auto qos voip cisco-phone"),
        _phone_port("GigabitEthernet1/0/6", trust="not trusted"),
        _intf("GigabitEthernet1/0/7", neighbor_class="ap", trust_state="trust dscp"),
        _uplink("GigabitEthernet1/0/49", expedite_queue=True)])))
    [row] = _rows(_sheets(inv), "Switch QoS Posture")
    assert row["mls qos"] == "On"
    assert row["Auto-QoS"] == "Yes: auto qos voip cisco-phone"
    assert (row["Phone Ports"], row["AP Ports"], row["VG Ports"]) == (2, 1, 0)
    assert row["Voice Ports Trusted"] == "2 of 3"
    assert row["Access Policies"] == "LAB-PHONE-IN"
    assert row["Uplink Egress"] == "srr expedite queue"
    assert row["Queue-Set"] == "Default"
    assert row["DSCP-to-Queue Map"] == "Default"
    assert row["EF Queue"] == "01-01"


def test_summary_counts():
    inv = _inv(
        SW1=_device(_classic([_phone_port("GigabitEthernet1/0/5")], mls=False)),
        SW2=_device(_classic([_uplink("GigabitEthernet1/0/49", expedite_queue=False)])))
    summary = dict(_sheets(inv)["Summary"][1])
    assert summary["Devices with QoS data"] == 2
    assert summary["Switches with mls qos off"] == 1
    assert summary["Switches with voice endpoints and no trust"] == 1
    assert summary["Uplinks with no egress priority"] == 1


def test_collection_errors_list_real_failures_and_capping():
    qos = _classic([_phone_port("GigabitEthernet1/0/5")])
    qos.update({
        "failed_commands": ["show mls qos maps cos-output-q", "show auto qos"],
        "command_errors": {"show mls qos maps cos-output-q": "% Invalid input detected",
                           "show auto qos": "% Authorization failed"},
        "command_error_kinds": {"show mls qos maps cos-output-q": "not_applicable",
                                "show auto qos": "unauthorized"},
        "queue_stats_ports": {"selected": ["Gi1/0/1"], "eligible": 31, "cap": 24,
                              "capped": True,
                              "skipped": ["GigabitEthernet1/0/5", "GigabitEthernet1/0/7"]},
    })
    rows = _rows(_sheets(_inv(SW1=_device(qos))), "Collection Errors")
    assert [r["Command"] for r in rows] == ["show auto qos", "per-port queue counters"]
    assert "capped at 24 of 31" in rows[1]["Error"]
    assert ("2 skipped, no uplinks among them: GigabitEthernet1/0/5, "
            "GigabitEthernet1/0/7") in rows[1]["Error"]


def test_capped_queue_ports_name_skipped_uplinks():
    qos = _classic([_uplink("GigabitEthernet1/0/49")])
    qos["queue_stats_ports"] = {"selected": [], "eligible": 25, "cap": 24,
                                "capped": True, "skipped": ["GigabitEthernet1/0/49"]}
    [row] = _rows(_sheets(_inv(SW1=_device(qos))), "Collection Errors")
    assert "including uplinks GigabitEthernet1/0/49" in row["Error"]


def test_posture_notes_device_with_no_policies_attached():
    sheets = _sheets(_inv(SW1=_device(_classic([_phone_port("GigabitEthernet1/0/5")]))))
    [row] = _rows(sheets, "Switch QoS Posture")
    assert row["Access Policies"] == "No policies attached"


def test_no_collection_errors_sheet_when_clean():
    sheets = _sheets(_inv(SW1=_device(_classic([_phone_port("GigabitEthernet1/0/5")]))))
    assert "Collection Errors" not in sheets


def test_collector_output_feeds_the_report():
    """Real parser output, not hand-built dicts, drives every sheet."""
    from app.collectors.qos import QosCollector, MLS_STATISTICS
    from tests.test_collectors.test_qos import (
        FakeConn, _classic_outputs, _context, _phone, _switch, SHOW_MLS_STATISTICS)
    outputs = _classic_outputs()
    # The uplink sent 50 packets out, none of them EF.
    outputs[MLS_STATISTICS] = SHOW_MLS_STATISTICS + SHOW_MLS_STATISTICS.replace(
        "GigabitEthernet1/0/5 (All", "GigabitEthernet1/0/49 (All").replace(
        " 45 - 49 :           0         1500", " 45 - 49 :           0            0")
    ctx = _context(neighbors=[_phone("Gi1/0/5"), _phone("Gi1/0/6"),
                              _switch("Gi1/0/49")],
                   switchports=[{"interface": "Gi1/0/49", "operational_mode": "trunk"}])
    result = QosCollector().collect(FakeConn(outputs), "cisco_ios", context=ctx)
    inv = _inv(SW1={"collector_data": {"qos": result}})
    sheets = _sheets(inv)
    voice = {r["Interface"]: r for r in _rows(sheets, "Voice Ports")}
    assert voice["GigabitEthernet1/0/5"]["QoS Status"] == "Trusted"
    assert voice["GigabitEthernet1/0/5"]["Ingress EF (pkts)"] == 1500
    assert voice["GigabitEthernet1/0/6"]["QoS Status"] == "Not trusted"
    [uplink] = _rows(sheets, "Uplinks and WAN")
    assert uplink["Interface"] == "GigabitEthernet1/0/49"
    assert uplink["Flag"] == "No egress policy"
    types = {f["type"] for f in analyze(inv)["findings"]}
    assert {"qos:voice_untrusted", "qos:uplink_no_priority", "qos:ef_lost"} <= types
    catalog = {r["Policy Map"] for r in _rows(sheets, "Policy Catalog")}
    assert catalog == {"LAB-PHONE-IN", "LAB-WAN-CHILD"}


@pytest.mark.parametrize("fmt", ["xlsx", "json", "csv", "xml"])
def test_generates_every_format(fmt):
    inv = _inv(SW1=_device(_classic([_phone_port("GigabitEthernet1/0/5"),
                                     _uplink("GigabitEthernet1/0/49")])))
    data = VoiceQosReport().generate(inv, fmt)
    assert data
    if fmt == "xlsx":
        wb = load_workbook(io.BytesIO(data))
        assert wb.sheetnames[:7] == ["Summary", "Switch QoS Posture", "Voice Ports",
                                     "Uplinks and WAN", "Policy Catalog",
                                     "Class Catalog", "Findings"]
