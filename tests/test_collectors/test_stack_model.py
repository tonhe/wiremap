"""Model fallback chain for stacks whose show version has no usable model.

Regression: collected 2960-X and C9200/3850 stacks had platform None and an
empty Platform column because the main show version block carried no
"Model number" line and nothing else was tried.
"""
import time

import pytest

from app.collectors.device_inventory import (
    DeviceInventoryCollector, _parse_version_details,
    _parse_version_switch_table)
from app.device_facts import extract_device_facts

from tests.test_collectors.stack_fixtures import (
    C2960X_STACK_INVENTORY, C2960X_STACK_VERSION, C9200L_PROCESSOR_ONLY_VERSION,
    C9300_MIXED_STACK_INVENTORY, C9300_MIXED_STACK_VERSION, big_stack_version)


def test_classic_ios_switch_table_without_mode_column():
    rows = _parse_version_switch_table(C2960X_STACK_VERSION)
    assert [(r["switch"], r["model"], r["local"]) for r in rows] == [
        ("1", "WS-C2960X-48FPD-L", True),
        ("2", "WS-C2960X-48FPD-L", False),
        ("3", "WS-C2960X-24PD-L", False),
    ]
    assert rows[0]["sw_image"] == "C2960X-UNIVERSALK9-M"


def test_iosxe_switch_table_with_mode_column():
    rows = _parse_version_switch_table(C9300_MIXED_STACK_VERSION)
    assert [(r["switch"], r["model"], r["local"]) for r in rows] == [
        ("1", "C9300-48P", False),
        ("2", "C9300-48P", True),
        ("3", "C9300-24T", False),
    ]


def test_no_switch_table_reads_nothing():
    assert _parse_version_switch_table(C9200L_PROCESSOR_ONLY_VERSION) == []


def test_version_model_is_active_stack_member():
    assert _parse_version_details(C9300_MIXED_STACK_VERSION)["model"] == "C9300-48P"
    assert (_parse_version_details(C2960X_STACK_VERSION)["model"]
            == "WS-C2960X-48FPD-L")


def test_version_model_from_processor_line():
    assert (_parse_version_details(C9200L_PROCESSOR_ONLY_VERSION)["model"]
            == "C9200L-48P-4X")
    ios15 = ("cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision B0) "
             "with 524288K bytes of memory.\n")
    assert _parse_version_details(ios15)["model"] == "WS-C2960X-48FPD-L"


def test_version_model_from_model_number_line():
    text = ("SW-STK-1 uptime is 1 week\n"
            "Model Number                       : C9300-48P\n")
    assert _parse_version_details(text)["model"] == "C9300-48P"
    text = "Model number                    : WS-C3850-48P\n"
    assert _parse_version_details(text)["model"] == "WS-C3850-48P"


@pytest.mark.parametrize("version, inventory, model", [
    (C2960X_STACK_VERSION, C2960X_STACK_INVENTORY, "WS-C2960X-48FPD-L"),
    (C9300_MIXED_STACK_VERSION, C9300_MIXED_STACK_INVENTORY, "C9300-48P"),
])
@pytest.mark.parametrize("device_type", ["cisco_ios", "cisco_xe"])
def test_collected_stack_has_a_model(version, inventory, model, device_type):
    parsed = DeviceInventoryCollector().parse(
        {"show version": version, "show inventory": inventory}, device_type)
    facts = extract_device_facts(parsed)
    assert facts["model"].split(",")[0].strip() == model


def test_model_from_version_details_when_template_found_nothing():
    parsed = {"version": [], "inventory": [],
              "version_details": {"model": "C9200L-48P-4X"}}
    assert extract_device_facts(parsed)["model"] == "C9200L-48P-4X"


def test_model_from_inventory_when_show_version_gave_nothing():
    parsed = DeviceInventoryCollector().parse(
        {"show version": "", "show inventory": C2960X_STACK_INVENTORY},
        "cisco_ios")
    assert extract_device_facts(parsed)["model"] == "WS-C2960X-48FPD-L"
    parsed = DeviceInventoryCollector().parse(
        {"show version": "", "show inventory": C9300_MIXED_STACK_INVENTORY},
        "cisco_xe")
    assert extract_device_facts(parsed)["model"] == "C9300-48P"


@pytest.mark.parametrize("inventory, model", [
    ([{"name": "Chassis", "descr": "ISR4331", "pid": "ISR4331/K9"},
      {"name": "module 0", "pid": "ISR4331/K9"}], "ISR4331/K9"),
    ([{"name": "Power Supply 1", "pid": "PWR-C1-715WAC"},
      {"name": "Switch 1", "pid": "C9300-48P"}], "C9300-48P"),
    ([{"name": "c38xx Stack", "pid": "WS-C3850-48P"},
      {"name": "Switch 2 - Power Supply A", "pid": "PWR-C1-715WAC"}],
     "WS-C3850-48P"),
    ([{"name": "Slot 0", "pid": ""},
      {"name": "Fan Tray", "pid": "FAN-T1"}], "FAN-T1"),
])
def test_inventory_pid_preference(inventory, model):
    parsed = {"version": [], "inventory": inventory}
    assert extract_device_facts(parsed)["model"] == model


def test_model_from_discovery_platform_as_last_resort():
    facts = extract_device_facts({"version": [], "inventory": []},
                                 platform_hint="cisco WS-C2960X-48FPD-L")
    assert facts["model"] == "WS-C2960X-48FPD-L"
    facts = extract_device_facts({}, platform_hint="C9200L-48P-4X")
    assert facts["model"] == "C9200L-48P-4X"


def test_collected_model_beats_discovery_platform():
    parsed = {"version": [], "version_details": {"model": "C9300-24T"}}
    facts = extract_device_facts(parsed, platform_hint="cisco C9300-48P")
    assert facts["model"] == "C9300-24T"


def test_no_hint_no_model():
    assert extract_device_facts({"version": [], "inventory": []})["model"] == ""


def test_long_stack_output_parses_fast():
    """The slowest device of a field run was a large stack: one pass only."""
    text = big_stack_version(10)
    started = time.perf_counter()
    details = _parse_version_details(text)
    elapsed = time.perf_counter() - started
    assert len(details["switches"]) == 10
    assert details["model"] == "C9300-48P"
    assert elapsed < 0.05


def test_pathological_lines_stay_linear():
    """Long whitespace runs under the table header must not backtrack."""
    text = ("Switch Ports Model  SW Version  SW Image\n"
            "------ ----- -----  ----------  --------\n"
            "*    1 " + " " * 50000 + "x\n"
            + "\t" * 50000 + "1 52 C9300-48P\n"
            + "cisco " + " " * 50000 + "\n")
    started = time.perf_counter()
    _parse_version_details(text)
    assert time.perf_counter() - started < 0.5
