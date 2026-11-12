"""AireOS wireless parsers: WLANs, AP groups, RF, RF profiles, radios, APs,
joins, clients and exclusions."""
import json

import pytest

from app.collectors import wlc_wireless as w
from tests.test_collectors import wlc_fixtures as base
from tests.test_collectors import wlc_wireless_fixtures as fx


SINGLE_ARG = [
    w.parse_wlan_summary, w.parse_wlan, w.parse_apgroups, w.parse_band, w.parse_channel,
    w.parse_txpower, w.parse_coverage, w.parse_group, w.parse_monitor,
    w.parse_profile_global, w.parse_cleanair, w.parse_fra, w.parse_dot11h,
    w.parse_rf_profile_summary, w.parse_rf_profile, w.parse_radio_summary,
    w.parse_ap_summary, w.parse_ap_inventory, w.parse_ap_cdp, w.parse_ap_image,
    w.parse_ap_uptime, w.parse_join_summary, w.parse_join_detail,
    w.parse_ap_config_general, w.parse_ap_radio_config, w.parse_link_encryption,
    w.parse_ap_ethernet, w.parse_tcp_mss, w.parse_retransmit, w.parse_ap_max_count,
    w.parse_air_quality, w.parse_client_summary, w.parse_exclusionlist,
]


@pytest.mark.parametrize("parser", SINGLE_ARG, ids=lambda p: p.__name__)
@pytest.mark.parametrize("text", [None, "", "   \n", fx.CLI_ERROR])
def test_empty_or_error_output_is_none(parser, text):
    assert parser(text) is None


@pytest.mark.parametrize("parser", SINGLE_ARG, ids=lambda p: p.__name__)
def test_unrelated_output_does_not_raise(parser):
    parser(base.SYSINFO)
    parser(fx.AP_RADIO_A)


# --- WLANs ------------------------------------------------------------------

def test_wlan_summary():
    rows = w.parse_wlan_summary(base.WLAN_SUMMARY)
    assert rows == [
        {"id": 1, "profile": "lab-corp", "ssid": "lab-corp", "status": "Enabled",
         "interface": "management"},
        {"id": 2, "profile": "lab-guest", "ssid": "lab-guest", "status": "Enabled",
         "interface": "lab-guest"},
        {"id": 3, "profile": "lab-voice", "ssid": "lab-voice", "status": "Disabled",
         "interface": "lab-voice"},
    ]


def test_wlan_corp_enterprise():
    d = w.parse_wlan(fx.WLAN_CORP)
    assert d["id"] == 1 and d["profile"] == "lab-corp" and d["ssid"] == "lab-corp"
    assert d["status"] == "Enabled" and d["broadcast_ssid"] is True
    assert d["radio_policy"] == "All" and d["interface"] == "management"
    assert d["interface_group"] is None
    assert d["l2_security"] == "WPA2"
    assert d["encryption"] == ["AES"]
    assert d["akm"] == ["802.1X", "FT-802.1X"]
    assert d["psk_set"] is False
    assert d["pmf"] == "optional"
    assert d["ft"] is True and d["ft_mode"] == "enabled" and d["ft_over_ds"] is False
    assert d["dot11k"] is True and d["dot11v"] is True
    assert d["l3_security"] == "none"
    assert d["mac_filtering"] is False
    assert d["auth_servers"] == ["192.0.2.50:1812", "192.0.2.51:1812"]
    assert d["acct_servers"] == ["192.0.2.50:1813"]
    assert d["auth_global"] is False
    assert d["aaa_override"] is True
    assert d["session_timeout_s"] == 1800 and d["idle_timeout_s"] == 300
    assert d["exclusion"] is True and d["exclusion_timeout_s"] == 60
    assert d["max_clients"] == 0
    assert d["p2p_blocking"] == "disabled"
    assert d["dhcp_required"] is False
    assert d["qos_profile"] == "Silver" and d["wmm"] == "Allowed"
    assert d["avc"] is False and d["netflow_monitor"] is None
    assert d["mobility_anchors"] == []
    assert d["flex_local_switching"] is False and d["flex_local_auth"] is False
    assert d["mdns_snooping"] is False and d["mdns_profile"] is None
    assert d["multicast_vlan"] is None
    assert d["dtim_a"] == 1 and d["dtim_b"] == 1
    assert d["band_select"] is False and d["load_balancing"] is False
    assert d["clients"] == 30
    assert d["dot11_auth"] == "Open System"


def test_wlan_guest_web_auth_anchored():
    d = w.parse_wlan(fx.WLAN_GUEST)
    assert d["l2_security"] == "None"
    assert d["encryption"] == [] and d["akm"] == [] and d["psk_set"] is False
    assert d["l3_security"] == "web auth"
    assert d["pmf"] == "disabled"
    assert d["auth_servers"] == [] and d["acct_servers"] == []
    assert d["mobility_anchors"] == [{"ip": "198.51.100.20", "status": "Up"},
                                     {"ip": "198.51.100.21", "status": "Up"}]
    assert d["qos_profile"] == "Bronze"
    assert d["p2p_blocking"] == "drop"
    assert d["dhcp_required"] is True
    assert d["max_clients"] == 150
    assert d["idle_timeout_s"] == 0
    assert d["session_timeout_s"] == 28800
    assert d["avc"] is True and d["avc_profile"] == "lab-avc"
    assert d["netflow_monitor"] == "lab-flow"
    assert d["band_select"] is True and d["load_balancing"] is True
    assert d["dot11k"] is False and d["ft"] is False


def test_wlan_legacy_wpa_tkip_psk():
    d = w.parse_wlan(fx.WLAN_LEGACY)
    assert d["l2_security"] == "WPA"
    assert d["encryption"] == ["TKIP"]
    assert d["akm"] == ["PSK"]
    assert d["psk_set"] is True
    assert d["broadcast_ssid"] is False and d["mac_filtering"] is True
    assert d["exclusion"] is False and d["exclusion_timeout_s"] is None
    assert d["session_timeout_s"] == 0
    assert d["auth_servers"] == [] and d["auth_global"] is True
    assert d["acct_global"] is True
    assert d["interface_group"] == "lab-scan-grp"
    assert d["multicast_vlan"] == "lab-scan"
    assert d["radio_policy"] == "802.11b/g only"
    assert d["wmm"] == "Disabled"
    assert d["ft_over_ds"] is True
    assert d["flex_local_switching"] is True and d["flex_local_auth"] is True
    # 8.5 output without 802.11k/v lines or a mobility anchor section.
    assert d["dot11k"] is None and d["dot11v"] is None
    assert d["mobility_anchors"] == []
    assert d["dtim_b"] == 3


def test_wlan_wpa3_sae_without_pmf_required():
    d = w.parse_wlan(fx.WLAN_WPA3)
    assert d["l2_security"] == "WPA3"
    assert d["akm"] == ["SAE"]
    assert d["psk_set"] is True
    assert d["pmf"] == "optional"
    assert d["ft"] is True and d["ft_mode"] == "adaptive"
    assert d["mdns_snooping"] is True and d["mdns_profile"] == "default-mdns-profile"
    assert d["wmm"] == "Required"
    assert d["exclusion_timeout_s"] == 120


def test_wlan_open_minimal():
    d = w.parse_wlan(fx.WLAN_OPEN)
    assert d["status"] == "Disabled"
    assert d["l2_security"] == "None" and d["l3_security"] == "none"
    assert d["akm"] == [] and d["encryption"] == []
    assert d["pmf"] is None and d["exclusion"] is None
    assert d["auth_servers"] == [] and d["mobility_anchors"] == []
    assert d["clients"] == 0


def test_wlan_static_wep_and_passthrough():
    d = w.parse_wlan(fx.WLAN_WEP)
    assert d["l2_security"] == "Static WEP"
    assert d["encryption"] == ["WEP"]
    assert d["l3_security"] == "web passthrough"
    assert d["dot11_auth"] == "Shared Key"


def test_wlan_dynamic_wep():
    text = fx.WLAN_OPEN.replace("   802.1X........................................ Disabled",
                                "   802.1X........................................ Enabled")
    assert w.parse_wlan(text)["l2_security"] == "WEP"


def test_wlan_wpa2_wpa3_transition():
    text = fx.WLAN_WPA3.replace("WPA2 (RSN IE).............................. Disabled",
                                "WPA2 (RSN IE).............................. Enabled")
    text = text.replace("            PSK.................................. Disabled",
                        "            PSK.................................. Enabled")
    d = w.parse_wlan(text)
    assert d["l2_security"] == "WPA2+WPA3"
    assert d["akm"] == ["PSK", "SAE"]


def test_wlan_never_returns_a_key():
    text = base.SHOW_WLAN_2
    d = w.parse_wlan(text)
    assert d["profile"] == "lab-guest"
    assert "LabPskValue9" not in json.dumps(d)


def test_wlan_without_identifier_is_none():
    assert w.parse_wlan(base.SYSINFO) is None


def test_apgroups():
    groups = w.parse_apgroups(fx.APGROUPS, wlans=w.parse_wlan_summary(base.WLAN_SUMMARY))
    assert [g["name"] for g in groups] == ["lab-site-a", "default-group"]
    a, default = groups
    assert a["description"] == "lab floor 1"
    assert a["rf_profile_a"] == "lab-rf-5g" and a["rf_profile_b"] == "lab-rf-24g"
    assert a["wlans"] == [
        {"id": 1, "ssid": "lab-corp", "interface": "management", "radio_policy": "All"},
        {"id": 2, "ssid": "lab-guest", "interface": "lab-guest", "radio_policy": "All"},
    ]
    assert a["aps"] == ["lab-ap-01", "lab-ap-02"]
    assert default["description"] is None
    assert default["rf_profile_a"] is None and default["rf_profile_b"] is None
    assert [x["id"] for x in default["wlans"]] == [1, 3]
    assert default["aps"] == ["lab-ap-03"]


def test_apgroups_without_wlan_summary_leaves_ssid_empty():
    groups = w.parse_apgroups(fx.APGROUPS)
    assert groups[0]["wlans"][0]["ssid"] is None


# --- RF global -------------------------------------------------------------

def test_band_a():
    d = w.parse_band(fx.BAND_A)
    assert d["network_enabled"] is True
    assert d["n_enabled"] is True and d["ac_enabled"] is True and d["ax_enabled"] is True
    assert d["mandatory_rates"] == ["12", "24"]
    assert d["supported_rates"] == ["18", "36", "48", "54"]
    assert d["disabled_rates"] == ["6", "9"]
    assert d["beacon_interval"] == 100 and d["fragmentation"] == 2346
    assert d["dtim"] is None
    assert d["dtpc"] is True and d["rssi_threshold"] == -80


def test_band_b_low_rates_on():
    d = w.parse_band(fx.BAND_B)
    assert d["network_enabled"] is True and d["g_enabled"] is True
    assert d["mandatory_rates"] == ["1", "2", "5.5", "11"]
    assert d["disabled_rates"] == []
    assert d["ax_enabled"] is None and d["ac_enabled"] is None
    assert d["short_preamble"] is True


def test_channel_a():
    d = w.parse_channel(fx.CHANNEL_A)
    assert d["dca_mode"] == "auto" and d["interval_s"] == 600 and d["anchor_hour"] == 0
    assert d["sensitivity"] == "medium" and d["sensitivity_db"] == 15
    assert d["width"] == "40 MHz" and d["width_mhz"] == 40
    assert d["leader"] == {"name": "lab-wlc-01", "ip": "192.0.2.40"}
    assert d["edrrm"] is True
    assert d["channels"] == [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132,
                             136, 140, 149, 153, 157, 161]
    assert d["unused_channels"] == [120, 124, 128, 144, 165]
    assert d["dfs_channels_in_list"] == [52, 56, 60, 64, 100, 104, 108, 112, 116, 132,
                                         136, 140]


def test_channel_b():
    d = w.parse_channel(fx.CHANNEL_B)
    assert d["interval_s"] == 12 * 3600
    assert d["sensitivity"] == "low" and d["width_mhz"] == 20
    assert d["channels"] == [1, 6, 11] and d["dfs_channels_in_list"] == []
    assert d["edrrm"] is False


def test_txpower():
    d = w.parse_txpower(fx.TXPOWER_A)
    assert d["tpc_mode"] == "auto"
    assert d["threshold_dbm"] == -70 and d["min_dbm"] == -10 and d["max_dbm"] == 30
    assert d["tpc_version"] == "Version 1 (Coverage Optimal Mode)"
    assert d["neighbor_count"] == 3 and d["interval_s"] == 600
    old = w.parse_txpower(fx.TXPOWER_B_OLD)
    assert old["tpc_mode"] == "on demand" and old["tpc_version"] is None
    assert old["leader"] == {"name": "lab-wlc-02", "ip": None}


def test_coverage():
    assert w.parse_coverage(fx.COVERAGE_A) == {
        "enabled": True, "voice_packet_count": 100, "voice_packet_pct": 50,
        "voice_rssi_dbm": -80, "data_packet_count": 50, "data_packet_pct": 50,
        "data_rssi_dbm": -80, "exception_level_pct": 25, "min_clients": 3,
    }


def test_group():
    d = w.parse_group(fx.GROUP_A)
    assert d["mode"] == "auto" and d["interval_s"] == 600
    assert d["leader"] == {"name": "lab-wlc-01", "ip": "192.0.2.40"}
    assert d["members"] == [{"name": "lab-wlc-01", "ip": "192.0.2.40"},
                            {"name": "lab-wlc-02", "ip": "192.0.2.42"}]
    assert d["group_name"] is None


def test_monitor_and_profile_global():
    m = w.parse_monitor(fx.MONITOR_A)
    assert m["enabled"] is True and m["channels"] == "Country channels"
    assert m["coverage_interval_s"] == 90 and m["report_interval_s"] == 180
    p = w.parse_profile_global(fx.PROFILE_GLOBAL_A)
    assert p == {"interference_pct": 10, "noise_dbm": -70, "utilization_pct": 80,
                 "throughput_bps": 1000000, "clients": 12}


def test_cleanair():
    assert w.parse_cleanair(fx.CLEANAIR_A) == {
        "enabled": True, "aq_reporting": True, "edrrm": True, "edrrm_sensitivity": "medium",
        "persistent_devices": False}
    off = w.parse_cleanair(fx.CLEANAIR_B_OFF)
    assert off["enabled"] is False and off["edrrm"] is False


def test_fra_and_dot11h():
    assert w.parse_fra(fx.FRA) == {"enabled": True, "sensitivity": "medium",
                                   "interval_s": 3600, "priority": "coverage",
                                   "client_aware": False}
    assert w.parse_dot11h(fx.DOT11H) == {"power_constraint": 3, "channel_switch": True,
                                         "channel_switch_mode": 1, "smart_dfs": True}


# --- RF profiles -------------------------------------------------------------

def test_rf_profile_summary():
    assert w.parse_rf_profile_summary(base.RF_PROFILE_SUMMARY) == [
        {"name": "lab-rf-5g", "band": "5", "description": None, "applied": True}]
    two = w.parse_rf_profile_summary(fx.RF_PROFILE_SUMMARY_TWO)
    assert [(r["name"], r["band"], r["description"], r["applied"]) for r in two] == [
        ("lab-rf-24g", "2.4", "lab 2.4 GHz", True), ("lab-rf-5g", "5", None, False)]


def test_rf_profile_details():
    d = w.parse_rf_profile(fx.RF_PROFILE_5G, name="lab-rf-5g")
    assert d["name"] == "lab-rf-5g" and d["band"] == "5"
    assert d["description"] == "lab 5 GHz high density"
    assert d["ap_group"] == "lab-site-a"
    assert d["tpc_min"] == 5 and d["tpc_max"] == 17
    assert d["tpc_threshold"] == -65 and d["tpc_threshold_v2"] == -67
    assert d["mandatory_rates"] == ["12", "24"] and d["disabled_rates"] == ["6", "9"]
    assert d["channels"][:3] == [36, 40, 44] and d["channels"][-1] == 161
    assert len(d["channels"]) == 20
    assert d["width"] == "80" and d["width_mhz"] == 80
    assert d["load_balancing"] == {"window": 5, "denial": 3}
    assert d["coverage"] == {"data_rssi_dbm": -80, "voice_rssi_dbm": -80,
                             "min_clients": 3, "exception_pct": 25}
    assert d["trap_thresholds"]["clients"] == 12
    assert d["max_clients"] == 200


# --- radios ----------------------------------------------------------------

def test_radio_summary_810():
    rows = w.parse_radio_summary(fx.RADIO_SUMMARY_A)
    assert rows[0] == {"ap_name": "lab-ap-01", "mac": "00:11:22:aa:00:01", "slot": 1,
                       "admin": "Enabled", "oper": "Up", "channel": 36, "width": 40,
                       "channel_rrm": True, "tx_power_level": 1, "tx_power_levels": 6,
                       "tx_power_dbm": 17}
    assert rows[1]["channel"] == 100 and rows[1]["width"] == 80
    assert rows[2]["admin"] == "Disabled" and rows[2]["oper"] == "Down"
    assert rows[2]["channel_rrm"] is False and rows[2]["width"] == 20


def test_radio_summary_85():
    rows = w.parse_radio_summary(fx.RADIO_SUMMARY_B)
    assert rows[0]["channel"] == 6 and rows[0]["slot"] == 0
    assert rows[0]["tx_power_level"] == 3 and rows[0]["tx_power_dbm"] is None
    assert rows[1]["tx_power_dbm"] == 20


# --- access points -----------------------------------------------------------

def test_ap_summary():
    rows = w.parse_ap_summary(base.AP_SUMMARY)
    assert rows[0] == {"name": "lab-ap-01", "slots": 2, "model": "AIR-AP2802I-B-K9",
                       "ethernet_mac": "00:11:22:00:00:01", "location": "floor 1",
                       "country": "US", "ip": "10.1.1.10", "clients": 30}
    assert len(rows) == 2


def test_ap_inventory_takes_the_ap_not_its_module():
    inv = w.parse_ap_inventory(fx.AP_INVENTORY)
    assert inv["lab-ap-01"] == {"name": "AP2800",
                                "descr": "Cisco Aironet 2800 Series (IEEE 802.11ac) Access Point",
                                "pid": "AIR-AP2802I-B-K9", "vid": "01", "sn": "FCW0000A001"}
    assert inv["lab-ap-02"]["pid"] == "AIR-CAP2602I-A-K9"
    assert inv["lab-ap-02"]["sn"] == "FCW0000A002"


def test_ap_cdp():
    rows = w.parse_ap_cdp(fx.AP_CDP)
    assert rows[0] == {"ap_name": "lab-ap-01", "ap_ip": "10.1.1.10",
                       "neighbor": "lab-sw-01.lab.example", "neighbor_ip": "10.1.1.2",
                       "port": "GigabitEthernet1/0/10"}
    assert rows[1]["port"] == "GigabitEthernet1/0/11"


def test_ap_image():
    d = w.parse_ap_image(fx.AP_IMAGE)
    assert d["lab-ap-01"] == {"primary": "8.10.185.0", "backup": "8.10.162.0",
                              "predownload_status": None}
    assert d["lab-ap-02"]["primary"] == "8.5.182.0"


def test_ap_uptime():
    d = w.parse_ap_uptime(fx.AP_UPTIME)
    assert d["lab-ap-01"]["uptime"] == "41 days, 03 h 10 m 05 s"
    assert d["lab-ap-01"]["uptime_s"] == 41 * 86400 + 3 * 3600 + 10 * 60 + 5
    assert d["lab-ap-02"]["join_uptime_s"] == 12 * 60 + 30
    assert d["lab-ap-02"]["ethernet_mac"] == "00:11:22:00:00:02"


def test_uptime_seconds_variants():
    assert w.uptime_seconds("2 days 3 hrs 4 mins 5 secs") == 2 * 86400 + 3 * 3600 + 245
    assert w.uptime_seconds("") is None


@pytest.mark.parametrize("text", [base.JOIN_SUMMARY, base.JOIN_SUMMARY_RULED])
def test_join_summary_with_and_without_rule(text):
    rows = w.parse_join_summary(text)
    assert len(rows) == 3
    assert rows[0] == {"base_mac": "00:11:22:aa:00:01", "ethernet_mac": "00:11:22:00:00:01",
                       "name": "lab-ap-01", "ip": "10.1.1.10", "status": "Joined"}
    assert rows[2]["status"] == "Not Joined"


def test_join_detail():
    d = w.parse_join_detail(fx.JOIN_DETAIL)
    assert d["last_join_attempt"] == "Nov 10 09:00:05.430"
    assert d["last_success"] is None
    assert d["last_error_type"] == "Join"
    assert d["last_error"] == "Regulatory domain check failed"
    assert d["failure_reason"] == "Regulatory domain check failed"
    assert d["attempts"] == 3 and d["failures"] == 3
    assert d["ethernet_mac"] == "00:11:22:00:00:03" and d["ip"] == "10.1.1.12"
    assert d["disconnect_reason"] is None


def test_ap_config_general():
    d = w.parse_ap_config_general(fx.AP_GENERAL)
    assert d["name"] == "lab-ap-01"
    assert d["ethernet_mac"] == "00:11:22:00:00:01"
    assert d["model"] == "AIR-AP2802I-B-K9" and d["serial"] == "FCW0000A001"
    assert (d["ip"], d["mask"], d["gateway"]) == ("10.1.1.10", "255.255.255.0", "10.1.1.1")
    assert d["ip_mode"] == "DHCP"
    assert d["mode"] == "Local" and d["ap_group"] == "lab-site-a" and d["flex_group"] is None
    assert d["location"] == "floor 1"
    assert d["primary_controller"] == {"name": "lab-wlc-01", "ip": "192.0.2.40"}
    assert d["secondary_controller"] == {"name": "lab-wlc-02", "ip": "192.0.2.42"}
    assert d["tertiary_controller"] is None
    assert d["sw_version"] == "8.10.185.0" and d["boot_version"] == "1.1.2.4"
    assert d["uptime_s"] == 41 * 86400 + 3 * 3600 + 10 * 60 + 5
    assert d["join_uptime"] == "41 days, 02 h 58 m 44 s"
    assert d["join_date"] == "Thu Oct 01 07:01:20 2026"
    assert d["last_reboot_reason"] == "Reload command"
    assert d["last_disconnect_reason"] == "AP Message Timeout"
    assert d["power"] == "PoE full"
    assert d["admin_state"] == "Enabled" and d["oper_state"] == "Registered"
    assert d["country"] == "US" and d["led_state"] is True
    assert d["tcp_mss"] == 1250


def test_ap_config_general_flex_low_power_static():
    d = w.parse_ap_config_general(fx.AP_GENERAL_FLEX)
    assert d["ip_mode"] == "Static"
    assert d["mode"] == "FlexConnect" and d["flex_group"] == "lab-flex-01"
    assert d["ap_group"] == "default-group"
    assert d["power"] == "PoE low power"
    assert d["secondary_controller"] is None
    assert d["led_state"] is False
    assert d["last_reboot_reason"] is None and d["join_date"] is None


@pytest.mark.parametrize("raw,want", [
    ("PoE/Full Power", "PoE full"), ("PoE/Low Power (degraded mode)", "PoE low power"),
    ("Power Injector / Normal mode", "injector"), ("PoE/Medium Power", "PoE medium power"),
])
def test_power_normalised(raw, want):
    text = fx.AP_GENERAL.replace("PoE/Full Power", raw)
    assert w.parse_ap_config_general(text)["power"] == want


def test_ap_radio_config_a():
    radios = w.parse_ap_radio_config(fx.AP_RADIO_A)
    assert len(radios) == 1
    r = radios[0]
    assert r["slot"] == 1 and r["band"] == "5" and r["radio_type"] == "RADIO_TYPE_80211ac-5"
    assert r["admin"] == "Enabled" and r["oper"] == "Up"
    assert r["channel"] == 36 and r["width"] == 40
    assert r["tx_power_level"] == 2 and r["tx_power_dbm"] == 14
    assert r["tx_power_assigned_by"] == "DCA"
    assert r["cleanair_capable"] is True and r["cleanair_enabled"] is False
    assert r["utilization"] is None and r["clients"] is None


def test_ap_radio_config_dual_5ghz():
    radios = w.parse_ap_radio_config(fx.AP_RADIO_A_DUAL)
    assert [(r["slot"], r["band"], r["channel"], r["tx_power_dbm"]) for r in radios] == [
        (0, "5", 52, 20), (1, "5", 149, 14)]


def test_ap_radio_config_b():
    r = w.parse_ap_radio_config(fx.AP_RADIO_B)[0]
    assert r["slot"] == 0 and r["band"] == "2.4"
    assert r["admin"] == "Disabled" and r["oper"] == "Down"
    assert r["channel"] == 11 and r["width"] is None
    assert r["tx_power_dbm"] == 20
    assert r["cleanair_capable"] is False and r["cleanair_enabled"] is None


def test_link_encryption():
    assert w.parse_link_encryption(fx.LINK_ENCRYPTION) == {"lab-ap-01": True,
                                                           "lab-ap-02": False}


def test_ap_ethernet_uses_the_interface_that_is_up():
    d = w.parse_ap_ethernet(fx.AP_ETHERNET)
    assert d["lab-ap-01"] == {"interface": "GigabitEthernet0", "status": "UP",
                              "speed_mbps": 1000, "duplex": "full"}
    assert d["lab-ap-02"]["speed_mbps"] == 100 and d["lab-ap-02"]["duplex"] == "half"


def test_ap_ethernet_older_columns():
    d = w.parse_ap_ethernet(fx.AP_ETHERNET_OLD)
    assert d["lab-ap-04"]["speed_mbps"] == 2500 and d["lab-ap-04"]["duplex"] is None


def test_tcp_mss_and_retransmit():
    assert w.parse_tcp_mss(fx.TCP_MSS) == {"lab-ap-01": {"enabled": True, "mss": 1250},
                                           "lab-ap-02": {"enabled": False, "mss": None}}
    assert w.parse_retransmit(fx.RETRANSMIT) == {"lab-ap-01": {"interval": 3, "count": 5},
                                                 "lab-ap-02": {"interval": 5, "count": 8}}


def test_ap_max_count():
    assert w.parse_ap_max_count(fx.MAX_COUNT) == 1500


def test_air_quality():
    d = w.parse_air_quality(fx.AIR_QUALITY_A, slot=1)
    assert d[("lab-ap-01", 1)] == {"channel": 36, "avg": 99, "min": 98, "interferers": 0}
    assert d[("lab-ap-02", 1)]["avg"] == 87


# --- clients -----------------------------------------------------------------

def test_client_summary_scrubbed():
    rows = w.parse_client_summary(fx.CLIENT_SUMMARY_SCRUBBED)
    assert len(rows) == 5
    assert rows[0] == {"ap": "lab-ap-01", "slot": 1, "status": "Associated", "wlan": 1,
                       "auth": True, "protocol": "ac", "band": "5", "wired": False}
    assert rows[2]["band"] == "2.4" and rows[2]["protocol"] == "n"
    assert rows[3]["protocol"] == "ax"
    assert rows[4]["protocol"] == "g" and rows[4]["band"] == "2.4"
    assert "xx:xx" not in json.dumps(rows)


def test_client_summary_never_returns_a_mac():
    rows = w.parse_client_summary(base.CLIENT_SUMMARY)
    dumped = json.dumps(rows)
    for ident in base.CLIENT_IDS:
        assert ident not in dumped
    assert rows[0]["band"] == "5" and rows[1]["band"] == "2.4"


def test_client_counts():
    c = w.client_counts(w.parse_client_summary(fx.CLIENT_SUMMARY_SCRUBBED))
    assert c["total"] == 5 and c["5"] == 3 and c["2.4"] == 2 and c["6"] == 0
    assert c["by_wlan"] == {1: 3, 2: 2}
    assert {"wlan": 1, "band": "5", "protocol": "ac", "count": 2} in c["groups"]
    assert sum(g["count"] for g in c["groups"]) == 5
    assert w.client_counts(None)["total"] == 0


def test_exclusionlist():
    assert w.parse_exclusionlist(fx.EXCLUSION_SCRUBBED) == {
        "count": 3, "reasons": {"802.1X Failure": 2, "Web Auth Failure": 1}}
    assert w.parse_exclusionlist(fx.EXCLUSION_EMPTY) == {"count": 0, "reasons": {}}
    raw = w.parse_exclusionlist(base.EXCLUSION)
    assert raw == {"count": 1, "reasons": {"802.1X Failure": 1}}
    assert "a4:5e" not in json.dumps(raw)
