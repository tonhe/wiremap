import io

from openpyxl import load_workbook

from app.collectors.l3_routing import parse_ip_protocols
from app.reports.routing_summary import (
    RoutingSummaryReport,
    _analyze_l3,
    _config_redistribution,
)

MUTUAL_NO_ROUTE_MAP = """\
Routing Protocol is "ospf 1"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Router ID 192.0.2.1
 Redistributing External Routes from,
    eigrp 100 with metric mapped to 20, includes subnets in redistribution
  Maximum path: 4
  Routing for Networks:
    192.0.2.0 0.0.0.255 area 0
  Distance: (default is 110)

Routing Protocol is "eigrp 100"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Redistributing: ospf 1, static
  Maximum path: 4
  Routing for Networks:
    198.51.100.0/24
  Distance: internal 90 external 170
"""

MUTUAL_OSPF_SIDE_FILTERED = MUTUAL_NO_ROUTE_MAP.replace(
    "includes subnets in redistribution",
    "includes subnets in redistribution, route-map EIGRP-TO-OSPF")

ONE_WAY = """\
Routing Protocol is "ospf 1"
  Router ID 192.0.2.1
 Redistributing External Routes from,
    static, includes subnets in redistribution
    eigrp 100, includes subnets in redistribution
  Distance: (default is 110)

Routing Protocol is "eigrp 100"
  Redistributing: connected
  Distance: internal 90 external 170
"""

CONFIG_WITH_ROUTE_MAPS = """\
!
router eigrp CAMPUS
 !
 address-family ipv4 unicast autonomous-system 100
  !
  topology base
   redistribute ospf 1 metric 100000 10 255 1 1500 route-map OSPF-TO-EIGRP
  exit-af-topology
  network 198.51.100.0
 exit-address-family
!
router ospf 1
 router-id 192.0.2.1
 redistribute eigrp 100 subnets route-map EIGRP-TO-OSPF
 redistribute static subnets
!
router bgp 65001
 address-family ipv4
  redistribute connected
 exit-address-family
!
"""


def _inventory(protocols_raw, config=None, scale=None):
    cd = {"l3_routing": {"parsed": {
        "neighbors": [], "routes": [],
        "ip_protocols_raw": protocols_raw,
        "ip_protocols": parse_ip_protocols(protocols_raw),
    }}}
    if config is not None:
        cd["config"] = {"parsed": {"config": config, "redacted": True}}
    if scale is not None:
        cd["routing_detail"] = {"parsed": scale}
    return {"devices": {"EDGE-RTR-01": {"collector_data": cd}}}


def _mutual(findings):
    return [f for f in findings
            if f["type"] == "Mutual redistribution without route-map"]


def test_mutual_redistribution_without_route_map_warns():
    found = _mutual(_analyze_l3(_inventory(MUTUAL_NO_ROUTE_MAP))["findings"])
    assert len(found) == 1
    f = found[0]
    assert f["severity"] == "Warning"
    assert f["hostname"] == "EDGE-RTR-01"
    assert "eigrp 100" in f["description"] and "ospf 1" in f["description"]
    # Without running-config the reader is told EIGRP route-maps are invisible.
    assert "running-config" in f["description"]


def test_route_map_on_one_direction_suppresses_finding():
    findings = _analyze_l3(_inventory(MUTUAL_OSPF_SIDE_FILTERED))["findings"]
    assert _mutual(findings) == []


def test_one_way_redistribution_no_finding():
    assert _mutual(_analyze_l3(_inventory(ONE_WAY))["findings"]) == []


def test_running_config_route_maps_suppress_finding():
    inv = _inventory(MUTUAL_NO_ROUTE_MAP, config=CONFIG_WITH_ROUTE_MAPS)
    assert _mutual(_analyze_l3(inv)["findings"]) == []


def test_config_redistribution_parser():
    red = _config_redistribution(CONFIG_WITH_ROUTE_MAPS)
    assert red[("eigrp 100", "ospf 1")] == "OSPF-TO-EIGRP"
    assert red[("ospf 1", "eigrp 100")] == "EIGRP-TO-OSPF"
    assert red[("ospf 1", "static")] == ""
    assert red[("bgp 65001", "connected")] == ""


def test_redistribution_sheet_rows():
    inv = _inventory(MUTUAL_NO_ROUTE_MAP, config=CONFIG_WITH_ROUTE_MAPS)
    sheets = RoutingSummaryReport().generate_tabular_data(inv)
    headers, rows = sheets["Redistribution"]
    assert headers[:5] == ["Device", "Site/Location", "Into Protocol",
                           "From Protocol", "Route-Map"]
    by_pair = {(r[2], r[3]): r for r in rows}
    assert set(by_pair) == {("ospf 1", "eigrp 100"), ("eigrp 100", "ospf 1"),
                            ("eigrp 100", "static")}
    assert by_pair[("eigrp 100", "ospf 1")][4] == "OSPF-TO-EIGRP"
    assert by_pair[("ospf 1", "eigrp 100")][5] == "20"


def test_routing_processes_sheet():
    sheets = RoutingSummaryReport().generate_tabular_data(
        _inventory(MUTUAL_NO_ROUTE_MAP))
    _, rows = sheets["Routing Processes"]
    ospf = next(r for r in rows if r[2] == "ospf")
    assert ospf[3] == "1"
    assert ospf[4] == "192.0.2.1"
    assert ospf[7] == "110"
    assert ospf[9] == "eigrp 100"


def test_xlsx_has_new_sheets():
    scale = {
        "ospf_db_summary": [
            {"process_id": "1", "router_id": "192.0.2.1", "vrf": "default",
             "scope": "area", "area": "0",
             "counts": {"Router": 3, "Network": 1, "Summary Net": 0},
             "total": 4},
            {"process_id": "1", "router_id": "192.0.2.1", "vrf": "default",
             "scope": "process", "area": "", "counts": {"Type-5 Ext": 12},
             "total": 16},
        ],
        "eigrp_topology_summary": [
            {"as_number": "100", "router_id": "192.0.2.1", "vrf": "default",
             "routes": 12, "pending_replies": 0, "interfaces": 4,
             "neighbors": 2},
        ],
    }
    inv = _inventory(MUTUAL_NO_ROUTE_MAP, scale=scale)
    wb = load_workbook(io.BytesIO(RoutingSummaryReport().generate(inv)))
    for name in ("Routing Scale", "Routing Processes", "Redistribution"):
        assert name in wb.sheetnames
    ws = wb["Routing Scale"]
    rows = [[c.value for c in r] for r in ws.iter_rows(min_row=2)]
    area = next(r for r in rows if r[5] == "Area 0")
    assert area[7] == 4
    # Zero counts are left out of the detail column.
    assert area[8] == "Router 3, Network 1"
    eigrp = next(r for r in rows if r[2] == "EIGRP topology")
    assert eigrp[7] == 12
    assert eigrp[8] == "2 neighbor(s) on 4 interface(s)"


def test_sheets_absent_without_data():
    inv = {"devices": {"SW-01": {"collector_data": {"l3_routing": {"parsed": {
        "neighbors": [], "routes": [], "ip_protocols_raw": ""}}}}}}
    sheets = RoutingSummaryReport().generate_tabular_data(inv)
    assert "Redistribution" not in sheets
    assert "Routing Scale" not in sheets
