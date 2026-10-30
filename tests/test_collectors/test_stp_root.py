"""'show spanning-tree root' on IOS / IOS-XE (no ntc template exists)."""
from app.collectors.stp_detail import StpDetailCollector, parse_ios_stp_root
from app.collectors.stp_vlan import StpVlanCollector
from app.reports.l2_discovery import L2DiscoveryReport

# IOS-XE 17.x, rapid-PVST+. SW1 is root for VLAN 1 and 10, SW2 for VLAN 20.
SW1_ROOT = """\

                                        Root    Hello Max Fwd
Vlan                   Root ID          Cost    Time  Age Dly  Root Port
---------------- -------------------- --------- ----- --- ---  ------------
VLAN0001          24577 aabb.cc00.0100         0    2   20  15
VLAN0010          24586 aabb.cc00.0100         0    2   20  15
VLAN0020          24596 aabb.cc00.0200         4    2   20  15  Te1/1/1
"""

SW2_ROOT = """\

                                        Root    Hello Max Fwd
Vlan                   Root ID          Cost    Time  Age Dly  Root Port
---------------- -------------------- --------- ----- --- ---  ------------
VLAN0001          24577 aabb.cc00.0100         4    2   20  15  Te1/1/1
VLAN0010          24586 aabb.cc00.0100         4    2   20  15  Te1/1/1
VLAN0020          24596 aabb.cc00.0200         0    2   20  15
"""

VLAN_BRIEF = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/1
10   USERS                            active    Gi1/0/2
20   VOICE                            active    Gi1/0/3
"""


def test_parses_root_and_non_root_lines():
    entries = parse_ios_stp_root(SW1_ROOT)
    assert [e["vlan_id"] for e in entries] == ["1", "10", "20"]
    assert entries[0] == {
        "vlan_id": "1", "root_priority": "24577",
        "root_address": "aabb.cc00.0100", "root_cost": "0", "root_port": "",
        "hello_time": "2", "max_age": "20", "fwd_delay": "15",
    }
    assert entries[2]["root_port"] == "Te1/1/1"
    assert entries[2]["root_cost"] == "4"


def test_root_bridge_line_has_no_port():
    """Forward delay "15" used to be read as the root port."""
    summary = StpDetailCollector().parse(
        {"show spanning-tree root": SW1_ROOT}, "cisco_xe")["stp_root_summary"]
    assert summary[0]["port"] == ""
    assert summary[2]["port"] == "Te1/1/1"
    assert summary[2]["priority"] == 24596


def test_error_output_yields_nothing():
    assert parse_ios_stp_root("% Invalid input detected at '^' marker.") == []


def test_stp_vlan_populates_spanning_tree_root_on_ios_xe():
    parsed = StpVlanCollector().parse(
        {"show spanning-tree root": SW1_ROOT}, "cisco_xe")
    roots = parsed["spanning_tree_root"]
    assert len(roots) == 3
    assert roots[1]["root_address"] == "aabb.cc00.0100"
    assert roots[1]["root_priority"] == "24586"


def _device(hostname, root_raw, store_parsed=True):
    collector = StpVlanCollector()
    raw = {"show spanning-tree root": root_raw, "show vlan brief": VLAN_BRIEF}
    parsed = collector.parse(raw, "cisco_xe")
    if not store_parsed:
        parsed["spanning_tree_root"] = []
    return {"hostname": hostname, "device_type": "cisco_xe",
            "collector_data": {"stp_vlan": {"raw": raw, "parsed": parsed}}}


def _report(store_parsed=True):
    inventory = {"devices": {
        "SW1": _device("SW1", SW1_ROOT, store_parsed),
        "SW2": _device("SW2", SW2_ROOT, store_parsed),
    }}
    return L2DiscoveryReport().generate_tabular_data(inventory)


def _check(sheets):
    _, rb_rows = sheets["Root Bridge IDs"]
    assert ["SW1", "aabb.cc00.0100"] == [rb_rows[0][0], rb_rows[0][2]]
    assert ["SW2", "aabb.cc00.0200"] == [rb_rows[1][0], rb_rows[1][2]]

    headers, rows = sheets["VLAN Documentation"]
    root_col = headers.index("STP Root Bridge")
    prio_col = headers.index("Root Priority")
    by_vid = {str(r[0]): r for r in rows}
    assert "SW1" in str(by_vid["10"][root_col])
    assert "24586" in str(by_vid["10"][prio_col])
    assert "SW2" in str(by_vid["20"][root_col])


def test_l2_discovery_root_columns_populate():
    _check(_report())


def test_l2_discovery_reparses_raw_for_older_inventories():
    _check(_report(store_parsed=False))
