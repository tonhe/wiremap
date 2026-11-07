"""ASA collector: command scope per unit role and context mode, redaction,
and parsing from stored raw output."""
import pytest

from app.collectors import get_registry
from app.collectors.asa import (
    AsaCollector, BLOCK_ASAV, BLOCK_SYSTEM, CONTEXT_COMMANDS, LONG_TIMEOUT, SHORT_TIMEOUT,
    TRAFFIC_COMMANDS, UNIT_COMMANDS, context_key, read_timeout, split_raw,
)
from tests.test_collectors import asa_fixtures as fx


@pytest.fixture(autouse=True)
def _redaction_on(monkeypatch):
    import app.collectors.asa as mod
    monkeypatch.setattr(mod, "redact_secrets_enabled", lambda: True)


def _collect(fake, role="active"):
    return AsaCollector().collect(fake, "cisco_asa",
                                  context={"asa_unit": {"role": role}})


def test_registered_and_only_for_asa():
    c = get_registry()["asa"]
    assert c.optional and c.serves_asa and c.needs_custom_collect
    assert c.applies_to("cisco_asa") and not c.applies_to("cisco_ios")
    assert c.get_commands("cisco_ios") == []
    assert AsaCollector().collect(fx.FakeAsa({}), "cisco_ios")["parsed"]["not_applicable"]


def test_single_mode_active_runs_every_block():
    fake = fx.FakeAsa(fx.single_mode_outputs(fx.FAILOVER_ACTIVE))
    result = _collect(fake)
    sent = [cmd for _, cmd, _ in fake.sent]
    assert sent[0] == "show mode"
    for cmd in UNIT_COMMANDS + TRAFFIC_COMMANDS:
        assert cmd in sent, cmd
    assert len(sent) == len(set(sent))
    assert not any(c.startswith("changeto") for c in sent)
    assert not set(BLOCK_ASAV) - set(UNIT_COMMANDS + TRAFFIC_COMMANDS) & set(sent)
    parsed = result["parsed"]
    ctx = parsed["contexts"][""]
    assert parsed["version"]["model"] == "FPR-2130"
    assert parsed["failover"]["this_host"]["state"] == "Active"
    assert parsed["failover_key_set"] is True
    assert parsed["config_saved"] is False
    assert parsed["health"]["conns"] == {"in_use": 80000, "peak": 95000, "limit": 100000}
    assert ctx["counts"]["interfaces_up"] == 4 and ctx["counts"]["acl_elements"] == 15
    assert ctx["counts"]["anyconnect_active"] == 12 and ctx["counts"]["s2s_up"] == 1
    intf = {r["interface"]: r for r in ctx["interfaces"]}
    assert intf["GigabitEthernet0/0"]["standby_ip"] == "198.51.100.3"
    assert intf["GigabitEthernet0/0"]["monitored"] is True
    assert intf["GigabitEthernet0/1"]["channel_group"] == 1
    assert intf["Port-channel1.10"]["security_level"] == 100
    assert ctx["certificates"][0]["used_by"] == ["ssl outside", "tunnel-group LAB-RA"]
    assert ctx["enable_password_set"] is True
    # Rejected commands are recorded, not parsed.
    assert "show cluster info" in parsed["failed_commands"]


def test_standby_unit_gets_platform_ha_and_config_only():
    fake = fx.FakeAsa(fx.single_mode_outputs(fx.FAILOVER_ACTIVE))
    result = _collect(fake, role="standby")
    sent = {cmd for _, cmd, _ in fake.sent}
    assert set(UNIT_COMMANDS) <= sent
    assert "show access-list" not in sent and "show vpn-sessiondb summary" not in sent
    # Config-derived data still comes from its running-config.
    ctx = result["parsed"]["contexts"][""]
    assert ctx["mgmt"]["telnet"] and ctx["counts"]["acl_elements"] is None


def test_asav_block_runs_on_asav():
    outputs = fx.single_mode_outputs()
    outputs["show version"] = fx.VERSION_ASAV
    fake = fx.FakeAsa(outputs)
    _collect(fake)
    sent = [cmd for _, cmd, _ in fake.sent]
    assert "show vm" in sent and "show license platform" in sent


def test_multiple_context_visits_each_context():
    system = fx.single_mode_outputs(fx.FAILOVER_ACTIVE)
    system["show mode"] = fx.MODE_MULTIPLE
    system["show context"] = fx.CONTEXTS
    ctx_a = {"show running-config": fx.CONTEXT_CONFIG, "show interface ip brief": fx.IP_BRIEF}
    fake = fx.FakeAsa(system, contexts={"admin": {}, "lab-ctx-a": ctx_a})
    result = _collect(fake)
    sent = [(ctx, cmd) for ctx, cmd, _ in fake.sent]
    assert sent[1] == (None, "changeto system")
    assert (None, "show resource allocation") in sent
    assert ("lab-ctx-a", "show running-config") in sent
    assert ("lab-ctx-a", "show access-list") in sent
    # A context the account cannot switch to is skipped, not collected as system.
    assert not any(c == "lab-ctx-b" for c, _ in sent)
    assert sent[-1][1] == "changeto system" and fake.current is None
    raw = result["raw"]
    assert context_key("lab-ctx-a", "show running-config") in raw
    assert "changeto context lab-ctx-b" in result["parsed"]["failed_commands"]
    parsed = result["parsed"]
    assert set(parsed["contexts"]) == {"admin", "lab-ctx-a"}
    assert [c["name"] for c in parsed["system"]["contexts"]] == ["admin", "lab-ctx-a",
                                                                 "lab-ctx-b"]
    a = parsed["contexts"]["lab-ctx-a"]
    assert a["mgmt"]["telnet"][0]["nameif"] == "outside"
    assert a["counts"]["interfaces_total"] == 5


def test_multiple_context_standby_skips_contexts():
    system = fx.single_mode_outputs(fx.FAILOVER_ACTIVE)
    system["show mode"] = fx.MODE_MULTIPLE
    system["show context"] = fx.CONTEXTS
    fake = fx.FakeAsa(system, contexts={"lab-ctx-a": {}})
    _collect(fake, role="standby")
    assert not any(cmd.startswith("changeto context") for _, cmd, _ in fake.sent)


def test_context_config_is_redacted_and_masked_values_kept():
    system = fx.single_mode_outputs()
    system["show mode"] = fx.MODE_MULTIPLE
    system["show context"] = fx.CONTEXTS
    fake = fx.FakeAsa(system, contexts={"lab-ctx-a": {
        "show running-config": fx.CONTEXT_CONFIG}})
    raw = _collect(fake)["raw"]
    text = raw[context_key("lab-ctx-a", "show running-config")]
    assert "Plain-ctx-secret" not in text
    assert "snmp-server community <REDACTED>" in text
    assert "failover key *****" in raw["show running-config"]


def test_long_outputs_get_long_timeouts():
    assert read_timeout("show running-config") == LONG_TIMEOUT
    assert read_timeout("show access-list") == LONG_TIMEOUT
    assert read_timeout("show clock") == SHORT_TIMEOUT
    fake = fx.FakeAsa(fx.single_mode_outputs())
    _collect(fake)
    timeouts = {cmd: t for _, cmd, t in fake.sent}
    assert timeouts["show route"] == LONG_TIMEOUT and timeouts["show cpu usage"] == SHORT_TIMEOUT


def test_parse_from_stored_raw_matches_collection():
    fake = fx.FakeAsa(fx.single_mode_outputs(fx.FAILOVER_ACTIVE))
    result = _collect(fake)
    again = AsaCollector().parse_collected(result["raw"], "cisco_asa")
    assert again == result["parsed"]


def test_split_raw():
    unit, ctx = split_raw({"show version": "v", context_key("c1", "show nameif"): "n"})
    assert unit == {"show version": "v"} and ctx == {"c1": {"show nameif": "n"}}


def test_command_lists_cover_the_blocks():
    assert "show running-config" in CONTEXT_COMMANDS
    assert "show context" in BLOCK_SYSTEM
    assert "show startup-config | include Cryptochecksum" in UNIT_COMMANDS
    assert len(set(TRAFFIC_COMMANDS)) == len(TRAFFIC_COMMANDS)
