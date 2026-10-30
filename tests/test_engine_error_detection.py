"""CLI error detection on the engine's batch path and the custom collectors."""
import io
from unittest.mock import MagicMock, patch

import pytest
from openpyxl import load_workbook

from app.collectors.ntp_logging import NtpLoggingCollector
from app.collectors.vrf import VrfCollector
from app.connection_manager import ConnectionResult
from app.discovery_engine import DiscoveryEngine
from app.reports.routing_summary import RoutingSummaryReport

INVALID = "                ^\n% Invalid input detected at '^' marker.\n"


@pytest.fixture(autouse=True)
def _no_snmp_network(monkeypatch):
    import app.discovery_engine as mod
    monkeypatch.setattr(mod, "snmp_make_walker", lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(mod, "snmp_collect_all", lambda walker: {})


def _discover(send_command):
    engine = DiscoveryEngine(
        seed_ip="192.0.2.10",
        seed_device_type="cisco_xe",
        username="admin",
        password="admin",
        max_depth=0,
        protocol="ssh",
        inventory_dir=None,
        max_workers=1,
    )
    conn = MagicMock()
    conn.find_prompt.return_value = "RTR-A#"
    conn.send_command.side_effect = send_command
    result = ConnectionResult(connection=conn, protocol_used="ssh",
                              fallback_occurred=False)
    with patch("app.connection_manager.ConnectionManager.connect",
               return_value=result):
        return engine.discover()


def _switchport_rejected(cmd, **kwargs):
    if cmd == "show interfaces switchport":
        return INVALID
    return ""


def test_batch_path_marks_wholly_rejected_collector_failed():
    inventory = _discover(lambda cmd, **kw: INVALID)
    parsed = inventory.devices["RTR-A"]["collector_data"]["switchport"]["parsed"]
    assert parsed["collector_failed"] is True
    assert "Invalid input" in parsed["collector_error"]
    assert "show interfaces switchport" in parsed["failed_commands"]


def test_batch_path_does_not_parse_error_caret_as_interface():
    inventory = _discover(_switchport_rejected)
    cdata = inventory.devices["RTR-A"]["collector_data"]["switchport"]
    parsed = cdata["parsed"]
    assert parsed.get("collector_failed") is not True
    assert parsed["switchports"] == []
    assert parsed["command_errors"] == {
        "show interfaces switchport": "% Invalid input detected at '^' marker."}
    # raw keeps the device's answer for diagnosis
    assert "Invalid input" in cdata["raw"]["show interfaces switchport"]


def test_collection_errors_sheet_populated_from_scan():
    inventory = _discover(_switchport_rejected)
    data = RoutingSummaryReport().generate(inventory.to_dict())
    wb = load_workbook(io.BytesIO(data))
    assert "Collection Errors" in wb.sheetnames
    ws = wb["Collection Errors"]
    rows = [[c.value for c in r] for r in ws.iter_rows(min_row=2)]
    assert any(r[0] == "RTR-A" and r[2] == "switchport"
               and "show interfaces switchport" in r[3]
               and "Invalid input" in r[3] for r in rows)


class _Conn:
    def __init__(self, outputs):
        self._outputs = outputs

    def send_command(self, cmd):
        return self._outputs.get(cmd, "")


def test_vrf_collect_does_not_turn_error_into_vrfs():
    conn = _Conn({"show ip vrf": INVALID, "show ip vrf interfaces": INVALID})
    result = VrfCollector().collect(conn, "cisco_xe")
    assert result["parsed"]["collector_failed"] is True
    # No phase-2 commands were invented from the error text
    assert set(result["raw"]) == {"show ip vrf", "show ip vrf interfaces"}


def test_vrf_collect_partial_failure_recorded():
    vrf_out = (
        "  Name                             Default RD            Protocols   Interfaces\n"
        "  BLUE                             64500:1               ipv4        Gi0/0/1\n"
    )
    conn = _Conn({"show ip vrf": vrf_out,
                  "show ip vrf interfaces": INVALID,
                  "show ip route vrf BLUE": "",
                  "show ip arp vrf BLUE": ""})
    parsed = VrfCollector().collect(conn, "cisco_xe")["parsed"]
    assert parsed.get("collector_failed") is not True
    assert parsed["failed_commands"] == ["show ip vrf interfaces"]
    assert parsed["vrf_interfaces"] == []


def test_vrf_collect_honours_unsupported_platforms():
    result = VrfCollector().collect(_Conn({}), "cisco_wlc")
    assert result["parsed"]["not_applicable"] is True


def test_ntp_logging_collect_detects_errors_and_still_redacts():
    collector = NtpLoggingCollector()
    cmds = collector.get_commands("cisco_xe")
    outputs = {c: "" for c in cmds}
    outputs["show ntp status"] = INVALID
    outputs["show snmp"] = "Chassis: X\n"
    result = collector.collect(_Conn(outputs), "cisco_xe")
    assert result["parsed"]["failed_commands"] == ["show ntp status"]
    assert result["raw"]["show snmp"] == "<REDACTED>"
