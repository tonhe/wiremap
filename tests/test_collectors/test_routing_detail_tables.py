"""show ip route summary and show ip ospf interface brief, as printed by
IOS 15, IOS-XE 16/17 and NX-OS."""
import pytest

from app.collectors.routing_detail import (
    RoutingDetailCollector, normalize_route_summary)


@pytest.fixture
def collector():
    return RoutingDetailCollector()


# IOS-XE 16/17: Replicates column, an "internal" row, an NSSA line.
XE_ROUTE_SUMMARY = """IP routing table name is default (0x0)
IP routing table maximum-paths is 32
Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
application     0           0           0           0           0
connected       0           12          0           1152        3648
static          1           3           0           384         1216
ospf 100        112         1340        0           139392      440968
  Intra-area: 1300 Inter-area: 140 External-1: 0 External-2: 12
  NSSA External-1: 0 NSSA External-2: 0
bgp 64512       4           20          0           2304        7296
  External: 20 Internal: 4 Local: 0
internal        8                                               54064
Total           125         1375        0           143232      506592
"""

# IOS 15: no Replicates column.
IOS15_ROUTE_SUMMARY = """IP routing table name is default (0x0)
IP routing table maximum-paths is 32
Route Source    Networks    Subnets     Overhead    Memory (bytes)
connected       0           6           432         1080
static          1           2           216         540
eigrp 10        3           40          3096        7740
  External: 5 Internal: 38 Local: 0
internal        5                                   5860
Total           9           48          3744        15220
"""

NXOS_ROUTE_SUMMARY = """IP Route Table for VRF "default"
Total number of routes: 9
Total number of paths:  9

Best paths per protocol:      Backup paths per protocol:
  am             : 1            None
  local          : 3
  direct         : 3
  ospf-1         : 2

Number of routes per mask-length:
  /24: 3   /32: 6
"""


def _counts(summary):
    return {e["source"]: e["count"] for e in summary}


def test_route_summary_iosxe_counts_networks_plus_subnets(collector):
    result = collector.parse({"show ip route summary": XE_ROUTE_SUMMARY}, "cisco_xe")
    counts = _counts(result["route_summary"])
    assert counts["connected"] == 12
    assert counts["static"] == 4
    assert counts["ospf 100"] == 1452
    assert counts["bgp 64512"] == 24
    # Bookkeeping rows are not route sources
    assert "Total" not in counts
    assert "internal" not in counts


def test_route_summary_ios15_layout(collector):
    result = collector.parse({"show ip route summary": IOS15_ROUTE_SUMMARY}, "cisco_ios")
    counts = _counts(result["route_summary"])
    assert counts == {"connected": 6, "static": 3, "eigrp 10": 43}


def test_route_summary_regex_fallback_handles_both_layouts():
    from app.collectors.routing_detail import _parse_route_summary_regex
    xe = _counts(_parse_route_summary_regex(XE_ROUTE_SUMMARY))
    ios = _counts(_parse_route_summary_regex(IOS15_ROUTE_SUMMARY))
    assert xe["ospf 100"] == 1452
    assert xe["connected"] == 12
    assert "internal" not in xe and "Total" not in xe
    assert ios == {"connected": 6, "static": 3, "eigrp 10": 43}


def test_route_summary_nxos_default_table(collector):
    result = collector.parse({"show ip route summary": NXOS_ROUTE_SUMMARY}, "cisco_nxos")
    counts = _counts(result["route_summary"])
    assert counts["direct"] == 3
    assert counts["ospf-1"] == 2


def test_normalize_route_summary_accepts_ntc_rows():
    rows = [{"route_source": "ospf 1", "networks": "2", "subnets": "5"},
            {"route_source": "Total", "networks": "2", "subnets": "5"},
            {"source": "static", "count": 3}]
    assert normalize_route_summary(rows) == [
        {"source": "ospf 1", "count": 7}, {"source": "static", "count": 3}]


def test_route_summary_report_rows_not_zero(collector):
    """The Route Summary sheet read zero for every protocol on IOS-XE."""
    from app.reports.routing_summary import _route_summary_rows
    parsed = collector.parse({"show ip route summary": XE_ROUTE_SUMMARY}, "cisco_xe")
    inv = {"devices": {"RTR-A": {"collector_data": {
        "routing_detail": {"raw": {}, "parsed": parsed}}}}}
    rows = _route_summary_rows(inv)
    assert len(rows) == 1
    # Device, Site, VRF, Connected, Static, OSPF, EIGRP, BGP, Other, Total
    assert rows[0][2:] == ["default", 12, 4, 1452, 0, 24, 0, 1492]


def test_route_summary_report_reads_stored_ntc_rows():
    """Scans saved before the fix stored the raw ntc field names."""
    from app.reports.routing_summary import _route_summary_rows
    stored = [{"route_source": "connected", "networks": "0", "subnets": "4"},
              {"route_source": "ospf 1", "networks": "1", "subnets": "9"},
              {"route_source": "Total", "networks": "1", "subnets": "13"}]
    inv = {"devices": {"RTR-A": {"collector_data": {
        "routing_detail": {"raw": {}, "parsed": {"route_summary": stored}}}}}}
    row = _route_summary_rows(inv)[0]
    assert row[3] == 4
    assert row[5] == 10
    assert row[9] == 14


# IOS-XE brief with dotted areas; the ntc IOS template drops these rows.
XE_OSPF_BRIEF = """Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C
Lo4          100   0.0.0.0         10.0.0.4/32        1     LOOP  0/0
Vl100        100   0.0.0.0         10.0.1.1/24        1     DR    0/0
Te1/1/1      100   0.0.0.0         10.0.2.1/30        10    P2P   1/1
Gi1/0/1      110   0.0.0.10        10.0.3.1/24        10    DROTH 2/4
"""

# Decimal areas, which ntc does parse.
IOS_OSPF_BRIEF_DECIMAL = """Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C
Gi0/0        1     0               192.0.2.1/30       1     P2P   1/1
Gi0/1        1     10              198.51.100.1/24    10    BDR   1/2
"""

NXOS_OSPF_BRIEF = """ OSPF Process ID 1 VRF default
 Total number of interface: 2
 Interface               ID     Area            Cost   State    Neighbors Status
 Vlan10                  1      0.0.0.0         40     DR       0         up
 Eth1/1                  2      0.0.0.0         40     P2P      1         up
 OSPF Process ID 2 VRF CUST-A
 Total number of interface: 1
 Interface               ID     Area            Cost   State    Neighbors Status
 Vlan20                  3      0.0.0.1         40     BDR      1         up
"""


def test_ospf_brief_iosxe_dotted_area_columns(collector):
    result = collector.parse({"show ip ospf interface brief": XE_OSPF_BRIEF}, "cisco_xe")
    intfs = {i["interface"]: i for i in result["ospf_interfaces"]}
    assert set(intfs) == {"Lo4", "Vl100", "Te1/1/1", "Gi1/0/1"}
    lo = intfs["Lo4"]
    assert lo["process"] == "100"
    assert lo["area"] == "0.0.0.0"
    assert lo["ip_address"] == "10.0.0.4/32"
    assert lo["cost"] == "1"
    assert lo["state"] == "LOOP"
    assert lo["neighbors"] == "0"
    gi = intfs["Gi1/0/1"]
    assert (gi["process"], gi["area"], gi["state"], gi["neighbors"],
            gi["neighbors_total"]) == ("110", "0.0.0.10", "DROTH", "2", "4")


def test_ospf_brief_ios_decimal_area(collector):
    result = collector.parse({"show ip ospf interface brief": IOS_OSPF_BRIEF_DECIMAL},
                             "cisco_ios")
    rows = result["ospf_interfaces"]
    assert [(r["interface"], r["area"], r["cost"], r["state"], r["neighbors"])
            for r in rows] == [("Gi0/0", "0", "1", "P2P", "1"),
                               ("Gi0/1", "10", "10", "BDR", "1")]


def test_ospf_brief_nxos_carries_process_and_vrf(collector):
    result = collector.parse({"show ip ospf interface brief": NXOS_OSPF_BRIEF},
                             "cisco_nxos")
    intfs = {i["interface"]: i for i in result["ospf_interfaces"]}
    assert intfs["Eth1/1"]["area"] == "0.0.0.0"
    assert intfs["Eth1/1"]["cost"] == "40"
    assert intfs["Eth1/1"]["state"] == "P2P"
    assert intfs["Eth1/1"]["neighbors"] == "1"
    assert intfs["Eth1/1"]["process"] == "1"
    assert intfs["Vlan20"]["process"] == "2"
    assert intfs["Vlan20"]["vrf"] == "CUST-A"


def _ospf_device(raw_brief, parsed_intfs=None):
    return {"collector_data": {"routing_detail": {
        "raw": {"show ip ospf interface brief": raw_brief} if raw_brief else {},
        "parsed": {
            "ospf_processes": [
                {"process_id": "100", "router_id": "10.0.0.4", "areas": ["0.0.0.0"]},
                {"process_id": "110", "router_id": "10.0.0.5", "areas": ["0.0.0.10"]},
            ],
            "ospf_interfaces": parsed_intfs if parsed_intfs is not None else
            RoutingDetailCollector().parse(
                {"show ip ospf interface brief": raw_brief}, "cisco_xe")["ospf_interfaces"],
        }}}}


def test_ospf_topology_sheet_columns_line_up():
    from app.reports.routing_summary import RoutingSummaryReport
    inv = {"devices": {"RTR-A": _ospf_device(XE_OSPF_BRIEF)}}
    headers, rows = RoutingSummaryReport().generate_tabular_data(inv)["OSPF Topology"]
    assert headers[2:] == ["Process ID", "Router ID", "Area", "Interface",
                           "Cost", "State", "Neighbors"]
    by_intf = {r[5]: r for r in rows}
    assert by_intf["Lo4"][2:] == ["100", "10.0.0.4", "0.0.0.0", "Lo4", "1", "LOOP", "0"]
    # Process and router ID follow the interface, not the first process
    assert by_intf["Gi1/0/1"][2:5] == ["110", "10.0.0.5", "0.0.0.10"]


def test_ospf_topology_repairs_rows_stored_shifted():
    """Old scans stored positional rows; the raw output is re-read."""
    from app.reports.routing_summary import _ospf_topology_rows
    shifted = [{"interface": "Lo4", "area": "100", "cost": "0.0.0.0",
                "state": "10.0.0.4/32", "neighbors": "1"}]
    inv = {"devices": {"RTR-A": _ospf_device(XE_OSPF_BRIEF, shifted)}}
    row = {r[5]: r for r in _ospf_topology_rows(inv)}["Lo4"]
    assert row[4] == "0.0.0.0"
    assert row[6] == "1"
    assert row[7] == "LOOP"
