import io
import json

from openpyxl import load_workbook

from app.collectors.hsrp import HsrpCollector
from app.neighbors.sources import HsrpVrrpSource
from app.reports.fhrp import (
    FHRP_HEADERS,
    NOT_COLLECTED,
    configured_fhrp,
    device_fhrp_entries,
    has_fhrp_data,
)
from app.reports.internet_edge import InternetEdgeReport
from app.reports.routing_summary import RoutingSummaryReport

GLBP_BRIEF = """\
Interface   Grp  Fwd Pri State    Address         Active router   Standby router
Vl10        10   -   110 Active   192.0.2.1       local           192.0.2.3
Vl10        10   1   -   Active   0007.b400.0a01  local           -
Vl20        20   -   100 Speak    198.51.100.1    198.51.100.3    unknown
"""

CONFIG = """\
hostname RTR-A
!
interface Vlan10
 ip address 192.0.2.2 255.255.255.0
 glbp 10 ip 192.0.2.1
 glbp 10 priority 110
 glbp 10 authentication text <REDACTED>
!
interface Vlan20
 ip address 198.51.100.2 255.255.255.0
 glbp 20 ip 198.51.100.1
!
interface Vlan30
 standby version 2
 standby 30 ip 203.0.113.1
 standby 30 priority 110
!
interface Vlan40
 vrrp 40 address-family ipv4
  address 203.0.113.65 primary
!
interface Vlan50
 standby ip 203.0.113.129
!
interface GigabitEthernet0/0/1
 description uplink
!
router ospf 1
 vrrp 99 ip 192.0.2.250
"""


def test_configured_fhrp_from_interfaces():
    got = [(g["interface"], g["protocol"], g["group"], g["virtual_ip"])
           for g in configured_fhrp(CONFIG)]
    assert got == [
        ("Vlan10", "GLBP", "10", "192.0.2.1"),
        ("Vlan20", "GLBP", "20", "198.51.100.1"),
        ("Vlan30", "HSRP", "30", "203.0.113.1"),
        ("Vlan40", "VRRP", "40", ""),
        ("Vlan50", "HSRP", "0", "203.0.113.129"),
    ]


def test_configured_fhrp_nxos_blocks():
    cfg = ("interface Vlan10\n"
           "  hsrp version 2\n"
           "  hsrp 10\n"
           "    ip 192.0.2.1\n"
           "  vrrpv3 11 address-family ipv4\n"
           "interface Vlan12\n"
           "  vrrp 12\n"
           "    address 192.0.2.65\n")
    got = [(g["interface"], g["protocol"], g["group"]) for g in configured_fhrp(cfg)]
    assert got == [("Vlan10", "HSRP", "10"), ("Vlan10", "VRRP", "11"),
                   ("Vlan12", "VRRP", "12")]


def _device(hsrp_parsed, config=None):
    cd = {"hsrp": {"raw": {}, "parsed": hsrp_parsed}}
    if config is not None:
        cd["config"] = {"raw": {}, "parsed": {"config": config, "redacted": True}}
    return {"collector_data": cd}


def test_config_only_groups_marked_not_collected():
    parsed = HsrpCollector().parse_collected({
        "show standby brief": "",
        "show glbp brief": GLBP_BRIEF,
        "show vrrp brief": "% Invalid input detected at '^' marker.\n",
    }, "cisco_xe")
    entries = device_fhrp_entries(_device(parsed, CONFIG))
    by_key = {(e["interface"], e["protocol"], e["group"]): e for e in entries}
    assert by_key[("Vlan10", "GLBP", "10")]["state"] == "Active"
    assert by_key[("Vlan20", "GLBP", "20")]["state"] == "Speak"
    assert by_key[("Vlan30", "HSRP", "30")]["state"] == NOT_COLLECTED
    assert by_key[("Vlan40", "VRRP", "40")]["state"] == NOT_COLLECTED
    assert len(entries) == 5


def test_glbp_only_from_config_when_collector_failed():
    dev = _device({"collector_failed": True, "collector_error": "timeout"},
                  "interface Vlan10\n glbp 10 ip 192.0.2.1\n")
    inv = {"devices": {"RTR-A": dev}}
    assert has_fhrp_data(inv)
    entries = device_fhrp_entries(dev)
    assert [(e["protocol"], e["state"], e["virtual_ip"]) for e in entries] == [
        ("GLBP", NOT_COLLECTED, "192.0.2.1")]


def test_has_fhrp_data_false_without_entries_or_config():
    assert not has_fhrp_data({"devices": {"SW1": _device({"entries": []})}})


def _glbp_inventory(sample_inventory):
    parsed = HsrpCollector().parse({"show glbp brief": GLBP_BRIEF}, "cisco_xe")
    cd = sample_inventory["devices"]["SW2"]["collector_data"]
    cd["hsrp"] = {"raw": {}, "parsed": parsed}
    cd["config"] = {"raw": {}, "parsed": {"config": CONFIG, "redacted": True}}
    return sample_inventory


def _sheet_rows(ws):
    return [[c.value for c in row] for row in ws.iter_rows(min_row=1)]


def test_routing_summary_fhrp_sheet_lists_glbp(sample_inventory):
    inv = _glbp_inventory(sample_inventory)
    wb = load_workbook(io.BytesIO(RoutingSummaryReport().generate(inv)))
    rows = _sheet_rows(wb["FHRP Status"])
    assert rows[0] == FHRP_HEADERS
    sw2 = [r for r in rows if r[0] == "SW2"]
    assert ["SW2", "Vlan10", "GLBP", "10", "110", "Active", "192.0.2.1"] == \
        [sw2[0][0]] + sw2[0][2:]
    assert any(r[3] == "HSRP" and r[6] == NOT_COLLECTED for r in sw2)
    # Pre-existing HSRP entry without a protocol tag still reports as HSRP.
    assert any(r[0] == "SW1" and r[3] == "HSRP" for r in rows)


def test_routing_summary_glbp_bad_state_finding(sample_inventory):
    inv = _glbp_inventory(sample_inventory)
    data = json.loads(RoutingSummaryReport().generate(inv, fmt="json"))
    text = json.dumps(data)
    assert "FHRP group in unexpected state" in text
    assert "Vlan20 GLBP group 20" in text
    # Healthy states and config-only rows raise nothing.
    assert "Vlan10 GLBP group 10" not in text
    assert f"state: {NOT_COLLECTED}" not in text


def test_internet_edge_fhrp_sheet_lists_glbp(sample_inventory):
    inv = _glbp_inventory(sample_inventory)
    wb = load_workbook(io.BytesIO(InternetEdgeReport().generate(inv)))
    rows = _sheet_rows(wb["FHRP Status"])
    assert rows[0] == FHRP_HEADERS
    assert any(r[0] == "SW2" and r[3] == "GLBP" and r[6] == "Active" for r in rows)


def test_vrrp_master_backup_not_flagged():
    from app.reports.fhrp import fhrp_state_findings
    dev = _device({"entries": [
        {"protocol": "VRRP", "interface": "Vlan30", "group": "30", "state": "Master"},
        {"protocol": "VRRP", "interface": "Vlan31", "group": "31", "state": "Backup"},
        {"protocol": "GLBP", "interface": "Vlan32", "group": "32", "state": "Listen"},
        {"protocol": "VRRP", "interface": "Vlan33", "group": "33", "state": "Init"},
    ]})
    found = fhrp_state_findings("RTR-A", dev, lambda *a: a, "warning")
    assert len(found) == 1
    assert "Vlan33 VRRP group 33" in found[0][3]


def test_glbp_peers_feed_neighbor_source():
    parsed = HsrpCollector().parse({"show glbp brief": GLBP_BRIEF}, "cisco_xe")
    refs = HsrpVrrpSource().extract({"collector_data": {"hsrp": {"parsed": parsed}}})
    assert {r["remote_ip"] for r in refs} == {"192.0.2.3", "198.51.100.3"}


def test_redundancy_names_the_fhrp():
    from app.reports.device_inventory import _redundancy
    glbp = _device({"entries": [{"protocol": "GLBP", "state": "Listen"}]})
    vrrp = _device({"entries": [{"protocol": "VRRP", "state": "Backup"}]})
    hsrp = _device({"entries": [{"state": "Active"}]})
    assert _redundancy(glbp) == "glbp-pair"
    assert _redundancy(vrrp) == "vrrp-pair"
    assert _redundancy(hsrp) == "hsrp-pair"
