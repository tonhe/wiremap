"""AireOS collector: command scope, per-item commands, reuse, redaction and
client scrubbing."""
import json

import pytest

import app.collectors.wlc as mod
from app.collectors.wlc import WlcCollector
from tests.test_collectors import wlc_fixtures as fx


class FakeConn:
    def __init__(self, outputs, fail=()):
        self.outputs = outputs
        self.fail = set(fail)
        self.sent = []

    def send_command(self, cmd, **kwargs):
        self.sent.append(cmd)
        if cmd in self.fail:
            raise OSError("socket closed")
        return self.outputs.get(cmd, "")


@pytest.fixture(autouse=True)
def _redact_on(monkeypatch):
    monkeypatch.setattr(mod, "redact_secrets_enabled", lambda: True)


def _collect(outputs=None, context=None, fail=()):
    conn = FakeConn(fx.CONTROLLER if outputs is None else outputs, fail)
    return WlcCollector().collect(conn, "cisco_wlc", context=context), conn


def test_only_cisco_wlc():
    c = WlcCollector()
    assert c.applies_to("cisco_wlc") and not c.applies_to("cisco_ios")
    assert c.collect(FakeConn({}), "cisco_ios")["parsed"]["not_applicable"]
    assert "show sysinfo" in c.get_commands("cisco_wlc") and c.get_commands("cisco_xe") == []


def test_every_controller_command_then_items_with_aps_last():
    result, conn = _collect()
    sent = conn.sent
    for cmd in mod.CONTROLLER_COMMANDS:
        assert cmd in sent
    assert len(sent) == len(set(sent))
    items = sent[len(mod.CONTROLLER_COMMANDS):]
    assert items[:5] == ["show interface detailed lab-guest", "show interface detailed lab-voice",
                         "show interface detailed management",
                         "show interface detailed redundancy-management",
                         "show interface detailed virtual"]
    assert ["show wlan 1", "show wlan 2", "show wlan 3"] == [c for c in items
                                                            if c.startswith("show wlan ")]
    assert "show rf-profile details lab-rf-5g" in items
    assert "show acl detailed lab-preauth" in items
    assert "show flexconnect group detail lab-flex-01" in items
    assert "show stats port detailed 1" in items and "show stats port detailed 2" in items
    assert "show ap join stats detailed 00:11:22:aa:00:03" in items
    assert not any("00:11:22:aa:00:01" in c for c in items)
    assert items[-6:] == ["show ap config general lab-ap-01", "show ap config 802.11a lab-ap-01",
                          "show ap config 802.11b lab-ap-01", "show ap config general lab-ap-02",
                          "show ap config 802.11a lab-ap-02", "show ap config 802.11b lab-ap-02"]
    parsed = result["parsed"]
    assert parsed["system_name"] == "lab-wlc-01"
    assert parsed["counts"] == {"aps": 2, "wlans": 3, "interfaces": 5}
    assert parsed["per_item"]["ap"] == {"planned": 6, "run": 6}


def test_nothing_secret_or_client_identifying_is_stored():
    result, _ = _collect()
    stored = json.dumps(result)
    for value in fx.SECRETS + fx.CLIENT_IDS:
        assert value not in stored, value
    raw = result["raw"]
    # Counts survive: rows stay, identifiers go.
    assert raw["show client summary"].count(mod.CLIENT_MAC) == 2
    assert "802.11ac(5 GHz)" in raw["show client summary"]
    # AP MACs in logs are not clients and stay.
    assert "00:11:22:aa:00:02" in raw["show traplog"]
    assert mod.CLIENT_IP in raw["show traplog"]
    # Guest names become a stable pseudonym in every output.
    token = mod.pseudonym("lab-guest-user")
    assert token in raw["show netuser summary"] and token in raw["show run-config commands"]
    # Default communities are recorded before masking.
    assert result["parsed"]["snmp_default_communities"] == ["public"]
    assert result["parsed"]["snmp_communities"] == 2


def test_client_scrub_holds_with_redaction_off(monkeypatch):
    monkeypatch.setattr(mod, "redact_secrets_enabled", lambda: False)
    result, _ = _collect()
    stored = json.dumps(result["raw"])
    for value in fx.CLIENT_IDS:
        assert value not in stored, value
    assert "LabRadiusKey1" in stored


def test_reuses_output_other_collectors_stored():
    context = {"collector_data": {
        "config": {"raw": {"show run-config commands": fx.RUN_CONFIG}},
        "device_inventory": {"raw": {"show sysinfo": fx.SYSINFO,
                                     "show inventory": "Incorrect usage."}}}}
    result, conn = _collect(context=context)
    assert "show run-config commands" not in conn.sent and "show sysinfo" not in conn.sent
    # An error another collector got is asked again.
    assert "show inventory" in conn.sent
    assert "LabRadiusKey1" not in result["raw"]["show run-config commands"]


def test_rejections_and_send_failures_are_recorded():
    result, _ = _collect(fail={"show ap summary"})
    parsed = result["parsed"]
    kinds = parsed["command_error_kinds"]
    assert kinds["config paging disable"] == "not_applicable"
    assert kinds["show flexconnect acl summary"] == "not_applicable"
    assert kinds["show ap summary"] == "failed"
    assert parsed["per_item"].get("ap") is None


@pytest.mark.parametrize("text,expected", [
    (fx.JOIN_SUMMARY, ["00:11:22:aa:00:03"]),
    (fx.JOIN_SUMMARY_RULED, ["00:11:22:aa:00:03"]),
    ("", []),
])
def test_join_failures_with_and_without_a_rule(text, expected):
    assert mod.join_failure_macs(text) == expected


def test_item_lists():
    assert mod.flex_group_names(fx.FLEX_GROUP_SUMMARY) == ["lab-flex-01"]
    assert mod.acl_names(fx.ACL_SUMMARY) == ["lab-preauth"]
    assert mod.port_numbers(fx.PORT_SUMMARY) == ["1", "2"]
    assert mod.snmp_communities(fx.SNMPCOMMUNITY) == ["public", "lab-ro-comm"]
