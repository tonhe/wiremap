import io
from openpyxl import load_workbook
from app.reports.routing_summary import RoutingSummaryReport


def test_report_attrs():
    r = RoutingSummaryReport()
    assert r.name == "routing_summary"
    assert "l3_routing" in r.required_collectors


def test_generate_xlsx(sample_inventory):
    r = RoutingSummaryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "Summary" in wb.sheetnames
    assert "Protocol Neighbors" in wb.sheetnames
    assert "Routes" in wb.sheetnames
    assert "Routed Interfaces" in wb.sheetnames
    assert "Findings" in wb.sheetnames

    # Protocol Neighbors: Device, Site/Location, Protocol, ...
    ws = wb["Protocol Neighbors"]
    assert ws.cell(row=2, column=1).value == "SW1"
    assert ws.cell(row=2, column=3).value == "ospf"


def test_generate_xlsx_with_routing_detail(sample_inventory):
    """Verify Route Summary and OSPF Topology tabs appear when routing_detail has data."""
    # Add some routing_detail data
    dev = sample_inventory["devices"]["SW1"]["collector_data"]["routing_detail"]
    dev["parsed"] = {
        "route_summary": [
            {"source": "connected", "count": 5},
            {"source": "ospf 1", "count": 10},
        ],
        "ospf_processes": [
            {"process_id": "1", "router_id": "10.0.0.1", "areas": ["0"]},
        ],
        "ospf_interfaces": [
            {"interface": "Gi0/1", "area": "0", "cost": "1", "state": "DR", "neighbors": "1"},
        ],
        "bgp_summary": [],
        "eigrp_topology": [],
        "eigrp_neighbors": [],
    }

    r = RoutingSummaryReport()
    data = r.generate(sample_inventory)
    wb = load_workbook(io.BytesIO(data))
    assert "Route Summary" in wb.sheetnames
    assert "OSPF Topology" in wb.sheetnames

    ws = wb["Route Summary"]
    assert ws.cell(row=2, column=1).value == "SW1"

    ws2 = wb["OSPF Topology"]
    assert ws2.cell(row=2, column=3).value == "1"  # Process ID


def test_collect_collector_errors_finds_failures():
    from app.reports.routing_summary import _collect_collector_errors
    inventory = {
        "devices": {
            "SW1": {
                "hostname": "SW1",
                "collector_data": {
                    "routing_detail": {
                        "parsed": {
                            "collector_failed": True,
                            "collector_error": "% Invalid input detected",
                        }
                    }
                },
            },
            "SW2": {
                "hostname": "SW2",
                "collector_data": {
                    "routing_detail": {"parsed": {"ospf_processes": []}}
                },
            },
        }
    }
    errors = _collect_collector_errors(inventory)
    assert ("SW1", "routing_detail", "% Invalid input detected") in errors
    assert len(errors) == 1


def test_collect_collector_errors_empty_when_clean():
    from app.reports.routing_summary import _collect_collector_errors
    inventory = {"devices": {"SW1": {"collector_data": {}}}}
    assert _collect_collector_errors(inventory) == []


def test_failed_collector_produces_no_ospf_rows():
    """Regression: error text was tokenised into Area/Interface/Cost columns."""
    from app.reports.routing_summary import _build_ospf_topology_sheet
    from openpyxl import Workbook
    wb = Workbook()
    wb.remove(wb.active)
    inventory = {
        "devices": {
            "TRMH-DR-Top-Core2": {
                "collector_data": {
                    "routing_detail": {
                        "parsed": {
                            "collector_failed": True,
                            "collector_error": "% Invalid input detected",
                        }
                    }
                },
            }
        }
    }
    _build_ospf_topology_sheet(wb, inventory)
    ws = wb["OSPF Topology"]
    assert ws.max_row == 1


def _rs_device(hostname, rd=None, vrf_routes=None):
    return {"hostname": hostname, "collector_data": {
        "routing_detail": {"raw": {}, "parsed": rd or {}},
        "vrf": {"raw": {}, "parsed": {"vrfs": [], "vrf_interfaces": [],
                                       "vrf_routes": vrf_routes or {}}},
    }}


def test_route_summary_rows_per_vrf():
    from app.reports.routing_summary import _route_summary_rows
    inv = {"devices": {
        "RTR-A": _rs_device("RTR-A", rd={
            "route_summary": [{"source": "connected", "count": 4}],
        }, vrf_routes={"CUST-A": [
            {"protocol": "C", "network": "10.1.0.0/24"},
            {"protocol": "L", "network": "10.1.0.1/32"},
            {"protocol": "B", "network": "10.2.0.0/16"},
            {"protocol": "S*", "network": "0.0.0.0/0"},
        ]}),
        "RTR-B": _rs_device("RTR-B", rd={
            "route_summary": [],
            "vrf_route_summary": {
                "default": [{"source": "direct", "count": 3}],
                "INET": [{"source": "direct", "count": 1},
                         {"source": "bgp-64500", "count": 4},
                         {"source": "am", "count": 2}],
            },
        }),
    }}
    rows = {(r[0], r[2]): r for r in _route_summary_rows(inv)}
    assert rows[("RTR-A", "default")][3] == 4
    cust = rows[("RTR-A", "CUST-A")]
    # Connected, Static, OSPF, EIGRP, BGP, Other, Total
    assert cust[3:] == [2, 1, 0, 0, 1, 0, 4]
    inet = rows[("RTR-B", "INET")]
    assert inet[3:] == [1, 0, 0, 0, 4, 2, 7]
    # NX-OS default VRF duplicates the global summary, so it is not repeated
    assert ("RTR-B", "default") not in rows


def test_route_summary_tab_has_vrf_column(sample_inventory):
    sheets = RoutingSummaryReport().generate_tabular_data(sample_inventory)
    assert sheets["Route Summary"][0][2] == "VRF"


def test_bgp_down_finding_names_vrf():
    from app.reports.routing_summary import _analyze_l3
    inv = {"devices": {"RTR-A": _rs_device("RTR-A", rd={"bgp_summary": [
        {"neighbor": "192.0.2.1", "asn": "64496", "state": "Idle", "vrf": "INET"},
    ]})}}
    findings = _analyze_l3(inv)["findings"]
    assert findings[0]["title"] == "BGP peer not Established"
    assert "VRF INET" in findings[0]["description"]
    assert findings[0]["type"] == "BGP peer not Established"


def test_l3_overfire_note():
    from app.reports.findings import OVERFIRE_TYPE
    from app.reports.routing_summary import _analyze_l3
    peer_down = {"bgp_summary": [{"neighbor": "192.0.2.1", "asn": "64496",
                                  "state": "Active"}]}
    inv = {"devices": {h: _rs_device(h, rd=peer_down)
                       for h in ("RTR-A", "RTR-B", "RTR-C", "RTR-D")}}
    meta = [f for f in _analyze_l3(inv)["findings"] if f["type"] == OVERFIRE_TYPE]
    assert len(meta) == 1
    assert meta[0]["about"] == "BGP peer not Established"
