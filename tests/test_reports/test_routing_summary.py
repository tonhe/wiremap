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
