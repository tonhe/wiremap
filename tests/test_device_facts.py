from app.device_facts import extract_device_facts


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
