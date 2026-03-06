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
    assert "Protocol Neighbors" in wb.sheetnames
    assert "Routes" in wb.sheetnames
    assert "Routed Interfaces" in wb.sheetnames
    ws = wb["Protocol Neighbors"]
    assert ws.cell(row=2, column=1).value == "SW1"
    assert ws.cell(row=2, column=2).value == "ospf"
