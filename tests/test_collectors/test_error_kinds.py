"""Rejected commands are classified: not applicable, unauthorized or failed.

Regression for Collection Status reporting partial:vrf on 2960-X LAN Base
switches (show ip vrf does not exist there) and partial:mac_table,switchport
on routers: a syntax rejection means the feature is absent, not that data
was lost.
"""
from unittest.mock import MagicMock

import pytest

from app.collectors.base import (
    BaseCollector, collector_has_failures, command_error_kinds)
from app.collectors.errors import (
    FAILED, NOT_APPLICABLE, UNAUTHORIZED, classify_error, error_kind,
    send_failure_output)
from app.collectors.vrf import VrfCollector
from app.connection_manager import ConnectionManager
from app.reports.device_inventory import _collection_status
from app.reports.routing_summary import _collect_collector_errors

# 2960-X LAN Base answering show ip vrf
C2960X_VRF = "show ip vrf\n            ^\n% Invalid input detected at '^' marker.\n\n"
# ISR answering show interfaces switchport
ROUTER_SWITCHPORT = ("show interfaces switchport\n"
                     "                     ^\n"
                     "% Invalid input detected at '^' marker.\n")
# TACACS command authorization refusing a command
AUTHZ = "Command authorization failed.\n"


@pytest.mark.parametrize("text", [
    "% Invalid input detected at '^' marker.",
    "% Incomplete command.",
    '% Ambiguous command:  "show ip"',
    "% Unknown command or computer name, or unable to find computer address",
    "% Invalid command at '^' marker.",
    "Invalid command at '^' marker.",
    "Syntax error while parsing 'show ip vrf'",
    C2960X_VRF,
    # ASA rejecting a command its platform lacks.
    "show cluster info\n             ^\nERROR: % Invalid input detected at '^' marker.\n",
    "ERROR: % Incomplete command",
    ROUTER_SWITCHPORT,
])
def test_syntax_rejections_are_not_applicable(text):
    assert error_kind(text) == NOT_APPLICABLE


@pytest.mark.parametrize("text", [
    "% Permission denied",
    "% Authorization failed.",
    AUTHZ,
])
def test_aaa_refusals_are_unauthorized(text):
    assert error_kind(text) == UNAUTHORIZED


def test_send_failure_marker_is_failed():
    out = send_failure_output(TimeoutError("Pattern not detected: 'SW-STK-1#'"))
    assert error_kind(out) == FAILED
    assert "TimeoutError" in classify_error(out)[0]


def test_send_failure_marker_keeps_one_short_line():
    out = send_failure_output(RuntimeError("line one\nline two " + "x" * 500))
    assert "\n" not in out
    assert "line two" not in out


def test_clean_output_has_no_kind():
    assert error_kind("Gi0/1 up up") is None
    assert error_kind("") is None


def test_run_commands_marks_send_exceptions():
    conn = MagicMock()

    def send(cmd, read_timeout=30):
        if cmd == "show ip vrf":
            raise TimeoutError("read timed out")
        return ""
    conn.send_command.side_effect = send
    out = ConnectionManager.run_commands(conn, ["show ip vrf", "show clock"])
    assert error_kind(out["show ip vrf"]) == FAILED
    # A command that legitimately printed nothing stays empty
    assert out["show clock"] == ""


class _Two(BaseCollector):
    name = "two"

    def get_commands(self, device_type):
        return ["a", "b"]

    def parse(self, raw_outputs, device_type):
        return {"a": raw_outputs["a"], "b": raw_outputs["b"]}


def test_all_syntax_rejected_is_not_applicable():
    parsed = _Two().parse_collected({"a": C2960X_VRF, "b": C2960X_VRF}, "cisco_ios")
    assert parsed["not_applicable"] is True
    assert not parsed.get("collector_failed")
    assert parsed["command_error_kinds"] == {"a": NOT_APPLICABLE,
                                             "b": NOT_APPLICABLE}
    assert not collector_has_failures(parsed)


def test_all_rejected_with_one_unauthorized_is_failed():
    parsed = _Two().parse_collected({"a": C2960X_VRF, "b": AUTHZ}, "cisco_ios")
    assert parsed["collector_failed"] is True
    assert "authorization" in parsed["collector_error"].lower()
    assert collector_has_failures(parsed)


def test_partial_syntax_rejection_parses_rest_and_is_not_a_failure():
    parsed = _Two().parse_collected({"a": "data", "b": C2960X_VRF}, "cisco_ios")
    assert parsed["a"] == "data"
    assert parsed["b"] == ""
    assert not collector_has_failures(parsed)


def test_partial_unauthorized_is_a_failure():
    parsed = _Two().parse_collected({"a": "data", "b": AUTHZ}, "cisco_ios")
    assert parsed["a"] == "data"
    assert parsed["command_error_kinds"] == {"b": UNAUTHORIZED}
    assert collector_has_failures(parsed)


class _Conn:
    def __init__(self, outputs):
        self._outputs = outputs

    def send_command(self, cmd):
        out = self._outputs.get(cmd, "")
        if isinstance(out, Exception):
            raise out
        return out


def test_collect_records_send_exception_as_failed():
    conn = _Conn({"a": "data", "b": TimeoutError("timed out")})
    result = _Two().collect(conn, "cisco_ios")
    assert result["parsed"]["command_error_kinds"] == {"b": FAILED}
    # The marker never reaches the parser
    assert result["parsed"]["b"] == ""
    assert collector_has_failures(result["parsed"])


def test_vrf_collect_on_lan_base_is_not_applicable():
    conn = _Conn({"show ip vrf": C2960X_VRF, "show ip vrf interfaces": C2960X_VRF})
    parsed = VrfCollector().collect(conn, "cisco_ios")["parsed"]
    assert parsed["not_applicable"] is True
    assert not collector_has_failures(parsed)


def test_old_scan_kinds_reclassified_from_error_text():
    parsed = {"failed_commands": ["a", "b"],
              "command_errors": {"a": "% Invalid input detected",
                                 "b": "% Permission denied"}}
    assert command_error_kinds(parsed) == {"a": NOT_APPLICABLE, "b": UNAUTHORIZED}


def test_old_scan_collector_failed_on_syntax_is_not_a_failure():
    assert not collector_has_failures({"collector_failed": True,
                                       "collector_error": "% Invalid input detected"})
    assert collector_has_failures({"collector_failed": True,
                                   "collector_error": "% Permission denied"})
    assert collector_has_failures({"collector_failed": True})


def _logged_in(collector_data):
    return {"hostname": "SW-STK-1", "mgmt_ip": "192.0.2.10",
            "login_succeeded": True, "collector_data": collector_data}


def _cd(parsed):
    return {"raw": {}, "parsed": parsed}


def test_status_collected_for_lan_base_and_router_rejections():
    vrf = VrfCollector().parse_collected(
        {"show ip vrf": C2960X_VRF, "show ip vrf interfaces": C2960X_VRF},
        "cisco_ios")
    switchport = {"not_applicable": True,
                  "command_error_kinds": {"show interfaces switchport":
                                          NOT_APPLICABLE},
                  "command_errors": {"show interfaces switchport":
                                     "% Invalid input detected at '^' marker."}}
    device = _logged_in({"vrf": _cd(vrf), "switchport": _cd(switchport)})
    assert _collection_status(device, {}) == "collected"


def test_status_partial_lists_only_real_failures():
    hsrp = _Two().parse_collected({"a": "data", "b": AUTHZ}, "cisco_ios")
    timed_out = _Two().parse_collected(
        {"a": send_failure_output(TimeoutError("x")),
         "b": send_failure_output(TimeoutError("x"))}, "cisco_ios")
    vrf = _Two().parse_collected({"a": C2960X_VRF, "b": C2960X_VRF}, "cisco_ios")
    device = _logged_in({"hsrp": _cd(hsrp), "mac_table": _cd(timed_out),
                         "vrf": _cd(vrf)})
    assert _collection_status(device, {}) == "partial:hsrp,mac_table"


def test_collection_errors_kind_column_and_failures_first():
    inventory = {"devices": {
        "SW-STK-1": {"collector_data": {
            "vrf": _cd(_Two().parse_collected(
                {"a": C2960X_VRF, "b": C2960X_VRF}, "cisco_ios")),
        }},
        "SW-STK-2": {"collector_data": {
            "hsrp": _cd(_Two().parse_collected({"a": "data", "b": AUTHZ},
                                               "cisco_ios")),
            "mac_table": _cd(_Two().parse_collected(
                {"a": "data", "b": send_failure_output(TimeoutError("x"))},
                "cisco_ios")),
        }},
    }}
    rows = _collect_collector_errors(inventory)
    kinds = [r[2] for r in rows]
    assert kinds == ["unauthorized", "failed", "not applicable", "not applicable"]
    assert rows[0][:2] == ("SW-STK-2", "hsrp")
    assert rows[0][3].startswith("b: ")
