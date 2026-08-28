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


def test_serial_suffix_before_domain():
    """NX-OS CDP reports device IDs as hostname(serial).domain. Stripping the
    suffix only at end-of-string left it attached, so the CDP sighting never
    grouped with the login record and survived merge as a duplicate."""
    assert normalize_hostname("DCN5K-5A(SSI16421TNJ).trmc.us") == "dcn5k-5a"


def test_serial_suffix_after_domain():
    assert normalize_hostname("DCN5K-5A.trmc.us(SSI16421TNJ)") == "dcn5k-5a"


def test_all_nexus_cdp_forms_agree():
    forms = [
        "DCN5K-5A",
        "DCN5K-5A.trmc.us",
        "DCN5K-5A(SSI16421TNJ)",
        "DCN5K-5A(SSI16421TNJ).trmc.us",
        "DCN5K-5A.trmc.us(SSI16421TNJ)",
    ]
    assert len({normalize_hostname(f) for f in forms}) == 1


def test_detects_hpe_broadcom_ocp_adapter():
    from app.identity import looks_like_host_nic
    assert looks_like_host_nic(
        "10/25Gb 2-port SFP28 BCM57414 OCP3 Adapter fw_version:AFW_228") is True


def test_detects_broadcom_netxtreme_adapter():
    from app.identity import looks_like_host_nic
    assert looks_like_host_nic(
        "Broadcom P225p NetXtreme-E Dual-port 10Gb/25Gb Ethernet Adapter") is True


def test_detects_hpe_flr_adptr():
    from app.identity import looks_like_host_nic
    assert looks_like_host_nic(
        "HPE Eth 10/25Gb 2p 631FLR-SFP28 Adptr fw_version:AFW_100") is True


def test_detects_intel_and_mellanox_nics():
    from app.identity import looks_like_host_nic
    assert looks_like_host_nic("Intel(R) Ethernet Converged Network Adapter X710") is True
    assert looks_like_host_nic("Mellanox ConnectX-5 Ex") is True


def test_real_switches_are_not_flagged():
    from app.identity import looks_like_host_nic
    for name in [
        "DCN5K-5A",
        "Cisco Nexus9000 N9K-C93180YC-EX",
        "cisco WS-C3850-48P",
        "Arista DCS-7280SR-48C6",
        "Palo Alto Networks PA-3220",
        "ANES-Cart-SW25",
        "AP-1-DC-Row2",
    ]:
        assert looks_like_host_nic(name) is False, name


def test_host_nic_handles_empty():
    from app.identity import looks_like_host_nic
    assert looks_like_host_nic(None) is False
    assert looks_like_host_nic("") is False


def test_host_nic_checks_all_supplied_fields():
    from app.identity import looks_like_host_nic
    assert looks_like_host_nic("server01", "Broadcom NetXtreme-E Adapter") is True


def test_parse_prompt_plain_cisco():
    from app.identity import parse_device_prompt
    assert parse_device_prompt("SW-CORE-01#") == {"hostname": "SW-CORE-01", "ha_state": None}
    assert parse_device_prompt("SW-CORE-01>") == {"hostname": "SW-CORE-01", "ha_state": None}


def test_parse_prompt_panos_active():
    """PAN-OS prompts are user@host(state). All three parts matter."""
    from app.identity import parse_device_prompt
    got = parse_device_prompt("admin@pa-as18-ex-fw01(active)>")
    assert got["hostname"] == "pa-as18-ex-fw01"
    assert got["ha_state"] == "active"


def test_parse_prompt_panos_passive():
    from app.identity import parse_device_prompt
    got = parse_device_prompt("admin@pa-as09-ex-fw02(passive)>")
    assert got["hostname"] == "pa-as09-ex-fw02"
    assert got["ha_state"] == "passive"


def test_parse_prompt_panos_standalone():
    from app.identity import parse_device_prompt
    got = parse_device_prompt("admin@pa-standalone>")
    assert got["hostname"] == "pa-standalone"
    assert got["ha_state"] is None


def test_parse_prompt_ignores_config_mode():
    """A config-mode prompt must not have (config) read as an HA state."""
    from app.identity import parse_device_prompt
    got = parse_device_prompt("SW1(config)#")
    assert got["hostname"] == "SW1"
    assert got["ha_state"] is None


def test_parse_prompt_handles_empty():
    from app.identity import parse_device_prompt
    assert parse_device_prompt("") == {"hostname": "", "ha_state": None}
    assert parse_device_prompt(None) == {"hostname": "", "ha_state": None}
