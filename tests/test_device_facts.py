from app.device_facts import extract_device_facts, extract_version_details


def test_version_details_prefer_collector_reading():
    parsed = {
        "version": [{"uptime": "2 weeks", "running_image": "packages.conf"}],
        "version_details": {"uptime": "1 year, 2 weeks",
                            "image": "flash:packages.conf",
                            "license": "network-advantage"},
    }
    d = extract_version_details(parsed)
    assert d["uptime"] == "1 year, 2 weeks"
    assert d["image"] == "flash:packages.conf"
    assert d["license"] == "network-advantage"


def test_version_details_fall_back_to_ntc_fields_on_old_scans():
    nxos = {"version": [{"UPTIME": "120 day(s), 3 hour(s)",
                         "LAST_REBOOT_REASON": "Reset Requested by CLI command reload",
                         "BOOT_IMAGE": "bootflash:///nxos.9.3.10.bin",
                         "PLATFORM": "C93180YC"}]}
    d = extract_version_details(nxos)
    assert d["uptime"] == "120 day(s), 3 hour(s)"
    assert d["reload_reason"].startswith("Reset Requested")
    assert d["image"] == "bootflash:///nxos.9.3.10.bin"
    assert d["platform_description"] == "C93180YC"


def test_platform_description_from_inventory_chassis():
    parsed = {"inventory": [
        {"NAME": "Chassis", "DESCR": "Cisco ISR9999 Chassis", "PID": "ISR9999"},
        {"NAME": "module 0", "DESCR": "Built-In NIM", "PID": "ISR9999-X"},
    ]}
    assert extract_version_details(parsed)["platform_description"] == \
        "Cisco ISR9999 Chassis"


def test_version_details_empty_when_collector_failed():
    d = extract_version_details({"collector_failed": True})
    assert set(d.values()) == {""}
    assert set(extract_version_details(None).values()) == {""}


def test_extracts_from_version_list():
    parsed = {"version": [{"serial": "FOC1234", "version": "16.9.4",
                           "hardware": "WS-C3850-48P"}]}
    facts = extract_device_facts(parsed)
    assert facts["serial"] == "FOC1234"
    assert facts["software_version"] == "16.9.4"
    assert facts["model"] == "WS-C3850-48P"


def test_falls_back_to_inventory_for_serial():
    parsed = {"version": [{"version": "16.9.4"}],
              "inventory": [{"sn": "FOC9999"}]}
    assert extract_device_facts(parsed)["serial"] == "FOC9999"


def test_handles_alternate_key_spellings():
    parsed = {"version": [{"serial_number": "ABC1", "os_version": "9.3"}]}
    facts = extract_device_facts(parsed)
    assert facts["serial"] == "ABC1"
    assert facts["software_version"] == "9.3"


def test_handles_uppercase_keys():
    parsed = {"version": [{"SERIAL": "ABC1", "VERSION": "9.3"}]}
    facts = extract_device_facts(parsed)
    assert facts["serial"] == "ABC1"
    assert facts["software_version"] == "9.3"


def test_joins_list_values():
    parsed = {"version": [{"serial": ["A", "B"], "version": "1.0"}]}
    assert extract_device_facts(parsed)["serial"] == "A, B"


def test_empty_parsed_returns_empty_strings():
    facts = extract_device_facts({})
    assert facts == {"serial": "", "software_version": "", "model": ""}


def test_none_parsed_returns_empty_strings():
    facts = extract_device_facts(None)
    assert facts == {"serial": "", "software_version": "", "model": ""}


def test_failed_collector_returns_empty():
    facts = extract_device_facts({"collector_failed": True})
    assert facts["serial"] == ""
    assert facts["model"] == ""
