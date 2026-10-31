from app.collectors.routing_detail import (
    RoutingDetailCollector,
    _parse_eigrp_topology_summary,
    _parse_ospf_db_summary,
)

IOS_XE_OSPF_DB_SUMMARY = """\

            OSPF Router with ID (192.0.2.1) (Process ID 1)

Area 0 database summary
  LSA Type      Count    Delete   Maxage
  Router        3        0        0
  Network       1        0        0
  Summary Net   4        0        0
  Summary ASBR  0        0        0
  Type-7 Ext    0        0        0
      Prefixes redistributed in Type-7  0
  Opaque Link   0        0        0
  Opaque Area   0        0        0
  Subtotal      8        0        0

Area 10 database summary
  LSA Type      Count    Delete   Maxage
  Router        2        0        0
  Network       0        0        0
  Summary Net   7        0        0
  Summary ASBR  1        0        0
  Type-7 Ext    0        0        0
      Prefixes redistributed in Type-7  0
  Opaque Link   0        0        0
  Opaque Area   0        0        0
  Subtotal      10       0        0

Process 1 database summary
  LSA Type      Count    Delete   Maxage
  Router        5        0        0
  Network       1        0        0
  Summary Net   11       0        0
  Summary ASBR  1        0        0
  Type-7 Ext    0        0        0
  Opaque Link   0        0        0
  Opaque Area   0        0        0
  Type-5 Ext    12       0        0
      Prefixes redistributed in Type-5  12
  Opaque AS     0        0        0
  Non-self      24       0        0
  Total         30       0        0

"""

NXOS_OSPF_DB_SUMMARY = """\
        OSPF Router with ID (192.0.2.11) (Process ID 10 VRF default)

 Area 0.0.0.0 database summary
   LSA Type      Count
   Opaque Link   0
   Router        4
   Network       2
   Summary Network 3
   Summary Asbr  0
   Type-7 AS External 0
   Opaque Area   0
   Total         9

 Process 10 database summary
   LSA Type      Count
   Opaque Link   0
   Router        4
   Network       2
   Summary Network 3
   Summary Asbr  0
   Type-7 AS External 0
   Opaque Area   0
   Type-5 AS External 5
   Opaque AS     0
   Total         14

        OSPF Router with ID (192.0.2.12) (Process ID 20 VRF TENANT-A)

 Area 0.0.0.1 database summary
   LSA Type      Count
   Router        2
   Network       1
   Total         3

"""

IOS_XE_EIGRP_TOPO_SUMMARY = """\
EIGRP-IPv4 Topology Table for AS(100)/ID(192.0.2.1)
Head serial 1, next serial 37
12 routes, 0 pending replies, 0 dummies
EIGRP-IPv4(100) enabled on 4 interfaces, 2 neighbors present on 2 interfaces
Quiescent interfaces:  Gi0/0/1 Gi0/0/2

EIGRP-IPv4 VR(OVERLAY) Topology Table for AS(200)/ID(192.0.2.1)
Head serial 1, next serial 9
4 routes, 1 pending replies, 0 dummies
EIGRP-IPv4 VR(OVERLAY) Address-Family(200) enabled on 1 interfaces, 1 neighbors present on 1 interfaces
"""


def test_ospf_db_summary_ios_xe_areas_and_process():
    entries = _parse_ospf_db_summary(IOS_XE_OSPF_DB_SUMMARY)
    assert [(e["scope"], e["area"]) for e in entries] == [
        ("area", "0"), ("area", "10"), ("process", "")]
    area0 = entries[0]
    assert area0["process_id"] == "1"
    assert area0["router_id"] == "192.0.2.1"
    assert area0["vrf"] == "default"
    assert area0["total"] == 8
    assert area0["counts"]["Router"] == 3
    assert area0["counts"]["Summary Net"] == 4
    # The "Prefixes redistributed" line is commentary, not an LSA type.
    assert not any(k.startswith("Prefixes") for k in area0["counts"])
    process = entries[2]
    assert process["total"] == 30
    assert process["counts"]["Type-5 Ext"] == 12


def test_ospf_db_summary_nxos_vrf_all():
    entries = _parse_ospf_db_summary(NXOS_OSPF_DB_SUMMARY)
    assert len(entries) == 3
    assert entries[0]["area"] == "0.0.0.0"
    assert entries[0]["total"] == 9
    assert entries[0]["counts"]["Summary Network"] == 3
    assert entries[1]["scope"] == "process"
    assert entries[1]["total"] == 14
    assert entries[1]["counts"]["Type-5 AS External"] == 5
    assert entries[2]["vrf"] == "TENANT-A"
    assert entries[2]["process_id"] == "20"
    assert entries[2]["total"] == 3


def test_ospf_db_summary_empty():
    assert _parse_ospf_db_summary("") == []


def test_eigrp_topology_summary_classic_and_named():
    entries = _parse_eigrp_topology_summary(IOS_XE_EIGRP_TOPO_SUMMARY)
    assert len(entries) == 2
    first, named = entries
    assert first["as_number"] == "100"
    assert first["router_id"] == "192.0.2.1"
    assert first["routes"] == 12
    assert first["pending_replies"] == 0
    assert first["interfaces"] == 4
    assert first["neighbors"] == 2
    assert named["as_number"] == "200"
    assert named["routes"] == 4
    assert named["pending_replies"] == 1


def test_eigrp_topology_summary_empty():
    assert _parse_eigrp_topology_summary("") == []


def test_collector_parses_scale_commands():
    c = RoutingDetailCollector()
    raw = {cmd: "" for cmd in c.get_commands("cisco_xe")}
    raw["show ip ospf database database-summary"] = IOS_XE_OSPF_DB_SUMMARY
    raw["show ip eigrp topology summary"] = IOS_XE_EIGRP_TOPO_SUMMARY
    result = c.parse(raw, "cisco_xe")
    assert len(result["ospf_db_summary"]) == 3
    assert len(result["eigrp_topology_summary"]) == 2


def test_collector_nxos_uses_vrf_all_form():
    c = RoutingDetailCollector()
    cmds = c.get_commands("cisco_nxos")
    assert "show ip ospf database database-summary vrf all" in cmds
    raw = {cmd: "" for cmd in cmds}
    raw["show ip ospf database database-summary vrf all"] = NXOS_OSPF_DB_SUMMARY
    result = c.parse(raw, "cisco_nxos")
    assert {e["vrf"] for e in result["ospf_db_summary"]} == {"default", "TENANT-A"}


def test_collector_rejected_scale_commands_yield_empty_lists():
    c = RoutingDetailCollector()
    raw = {cmd: "" for cmd in c.get_commands("cisco_xe")}
    raw["show ip route summary"] = "IP routing table name is default (0x0)"
    raw["show ip eigrp topology summary"] = "% Invalid input detected at '^' marker."
    result = c.parse_collected(raw, "cisco_xe")
    assert result["eigrp_topology_summary"] == []
    assert result["ospf_db_summary"] == []


def test_unknown_platform_skips_scale_commands():
    cmds = RoutingDetailCollector().get_commands("some_unknown_os")
    assert "show ip ospf database database-summary" not in cmds
    assert "show ip eigrp topology summary" not in cmds
