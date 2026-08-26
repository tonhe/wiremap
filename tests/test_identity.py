from app.identity import normalize_hostname, device_key, looks_like_mac


def test_strips_serial_suffix():
    assert normalize_hostname("SW1(FOC1234ABCD)") == "sw1"


def test_strips_domain():
    assert normalize_hostname("SW1.example.local") == "sw1"


def test_casefolds():
    assert normalize_hostname("Core-SW-01") == "core-sw-01"


def test_strips_whitespace():
    assert normalize_hostname("  SW1  ") == "sw1"


def test_handles_empty():
    assert normalize_hostname("") == ""
    assert normalize_hostname(None) == ""


def test_serial_and_domain_together():
    assert normalize_hostname("SW1.example.local(FOC1234)") == "sw1"


def test_device_key_prefers_serial():
    assert device_key("SW1", "FOC1234") == "serial:FOC1234"


def test_device_key_falls_back_to_hostname():
    assert device_key("SW1(FOC1234)", None) == "host:sw1"


def test_device_key_ignores_blank_serial():
    assert device_key("SW1", "   ") == "host:sw1"


def test_looks_like_mac_cisco_dotted():
    assert looks_like_mac("009a.d2d4.9700") is True


def test_looks_like_mac_colon():
    assert looks_like_mac("00:9a:d2:d4:97:00") is True


def test_looks_like_mac_hyphen():
    assert looks_like_mac("00-9a-d2-d4-97-00") is True


def test_looks_like_mac_bare_hex():
    assert looks_like_mac("009ad2d49700") is True


def test_platform_string_is_not_a_mac():
    assert looks_like_mac("cisco Nexus9000 N9K-C93180YC-EX") is False
    assert looks_like_mac("WS-C3850-48P") is False
    assert looks_like_mac("") is False
    assert looks_like_mac(None) is False


def test_nexus_hostname_pair_normalizes_equal():
    """The 28 duplicate pairs were hostname vs hostname(SERIAL)."""
    assert normalize_hostname("TRMH-DR-Top-Core2") == \
        normalize_hostname("TRMH-DR-Top-Core2(FOC1948R0MB)")
