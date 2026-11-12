"""AireOS service parsers: AAA, ACLs, WIPS, mobility, FlexConnect, QoS,
services, management plane and certificates."""
import pytest

from app.collectors import wlc_services as s
from tests.test_collectors import wlc_fixtures as base
from tests.test_collectors import wlc_services_fixtures as f

ALL_PARSERS = [
    s.parse_radius_summary, s.parse_radius_stats, s.parse_rfc3576_stats,
    s.parse_tacacs_summary, s.parse_tacacs_stats, s.parse_aaa_auth,
    s.parse_local_auth_config, s.parse_local_auth_stats, s.parse_netuser, s.parse_mgmtuser,
    s.parse_acl_summary, s.parse_acl_detail, s.parse_acl_cpu, s.parse_flex_acl_summary,
    s.parse_flex_acl_detail, s.parse_wps_summary, s.parse_mfp, s.parse_signatures,
    s.parse_ap_auth, s.parse_rogue_ap_summary, s.parse_rogue_client_summary,
    s.parse_rogue_adhoc_summary, s.parse_rogue_rules, s.parse_auto_contain,
    s.parse_mobility_summary, s.parse_mobility_stats, s.parse_mobility_anchor,
    s.parse_mobility_ap_list, s.parse_flex_group_detail, s.parse_qos_profile,
    s.parse_qos_map, s.parse_avc_profiles, s.parse_flow_exporters, s.parse_flow_monitors,
    s.parse_mdns_summary, s.parse_mdns_services, s.parse_mdns_profiles,
    s.parse_nmsp_status, s.parse_nmsp_subscription, s.parse_mgid,
    s.parse_network_summary, s.parse_snmpversion, s.parse_snmpcommunity,
    s.parse_snmpv3user, s.parse_snmptrap, s.parse_logging, s.parse_certificates,
]


@pytest.mark.parametrize("parser", ALL_PARSERS, ids=lambda p: p.__name__)
@pytest.mark.parametrize("text", [None, "", "   \n", f.ERROR])
def test_empty_or_error_output_is_none(parser, text):
    assert parser(text) is None


GARBAGE = "some unexpected\ntext ...... with\n---- ----\nodd rows 1 2 3\n"


@pytest.mark.parametrize("parser", ALL_PARSERS, ids=lambda p: p.__name__)
def test_unexpected_text_never_raises(parser):
    parser(GARBAGE)


# --- AAA --------------------------------------------------------------------

def test_radius_summary_servers():
    r = s.parse_radius_summary(f.RADIUS_SUMMARY)
    auth = [x for x in r["servers"] if x["use"] == "auth"]
    acct = [x for x in r["servers"] if x["use"] == "acct"]
    assert len(auth) == 2 and len(acct) == 1
    one = auth[0]
    assert one == {"use": "auth", "index": 1, "ip": "192.0.2.50", "port": 1812,
                   "admin": "Enabled", "network_user": True, "management": True,
                   "timeout_s": 5, "mgmt_timeout_s": 5, "retransmit": None,
                   "keywrap": False, "rfc3576": True, "ipsec": False, "active": False}
    two = auth[1]
    assert two["admin"] == "Disabled"
    assert two["network_user"] is True and two["management"] is False
    assert two["timeout_s"] == 2 and two["rfc3576"] is False
    assert acct[0]["port"] == 1813 and acct[0]["rfc3576"] is False
    assert acct[0]["mgmt_timeout_s"] is None


def test_radius_summary_globals():
    r = s.parse_radius_summary(f.RADIUS_SUMMARY)
    assert r["fallback_mode"] == "Passive"
    assert r["mac_delimiter"] == "hyphen"
    assert r["mac_delimiter_acct"] == "hyphen"
    assert r["aggressive_failover"] is True
    assert r["keywrap"] is False
    assert r["framed_mtu"] == 1300


def test_radius_summary_old_layout_without_type_column():
    r = s.parse_radius_summary(f.RADIUS_SUMMARY_OLD)
    assert len(r["servers"]) == 1
    one = r["servers"][0]
    assert one["ip"] == "10.20.0.5" and one["timeout_s"] == 2
    assert one["network_user"] is None and one["management"] is None
    assert r["fallback_mode"] is None and r["keywrap"] is None


def test_radius_auth_stats():
    r = s.parse_radius_stats(f.RADIUS_AUTH_STATS)
    assert set(r) == {1, 2}
    one = r[1]
    assert one["server"] == "192.0.2.50"
    assert (one["requests"], one["retransmissions"], one["accepts"], one["rejects"],
            one["challenges"], one["timeouts"]) == (1000, 40, 800, 120, 60, 30)
    assert one["bad_authenticators"] == 2 and one["malformed"] == 0
    assert one["dropped"] == 1 and one["round_trip_ms"] == 3
    assert one["last_error"] is None
    assert r[2]["requests"] == 0


def test_radius_acct_stats_use_accounting_responses():
    r = s.parse_radius_stats(f.RADIUS_ACCT_STATS)
    assert r[1]["accepts"] == 4990 and r[1]["rejects"] is None
    assert r[1]["timeouts"] == 10


def test_rfc3576_stats():
    r = s.parse_rfc3576_stats(f.RFC3576_STATS)
    assert r["totals"]["total_coa_requests"] == 7
    assert r["totals"]["total_disconnect_requests"] == 4
    assert r["servers"][1]["server"] == "192.0.2.50"
    assert r["servers"][1]["coa_naks"] == 1


def test_tacacs_summary():
    r = s.parse_tacacs_summary(f.TACACS_SUMMARY)
    uses = [x["use"] for x in r["servers"]]
    assert uses == ["auth", "auth", "acct", "athr"]
    assert r["servers"][1] == {"use": "auth", "index": 2, "ip": "192.0.2.61", "port": 49,
                               "admin": "Enabled", "timeout_s": 5, "mgmt_timeout_s": 5}
    assert r["servers"][3]["admin"] == "Disabled"


def test_tacacs_stats():
    r = s.parse_tacacs_stats(f.TACACS_AUTH_STATS)
    assert r[1]["requests"] == 25 and r[1]["accepts"] == 24 and r[1]["rejects"] == 1
    assert r[1]["errors"] == 0


def test_aaa_auth_order():
    assert s.parse_aaa_auth(f.AAA_AUTH)["management_order"] == ["local", "tacacs"]
    assert s.parse_aaa_auth(f.AAA_AUTH)["has_tacacs"] is True
    local = s.parse_aaa_auth(f.AAA_AUTH_LOCAL)
    assert local["local_only"] is True and local["has_tacacs"] is False
    assert s.parse_aaa_auth(f.AAA_AUTH_ONE_LINE)["management_order"] == ["local", "radius"]


def test_local_auth_config():
    r = s.parse_local_auth_config(f.LOCAL_AUTH_CONFIG)
    assert r["enabled"] is True
    assert r["database_order"] == ["Local DB"]
    assert r["active_timeout_s"] == 300
    assert r["profiles"] == [{"name": "lab-eap-prof", "methods": ["peap", "eap-fast"],
                              "wlans": [3, 4], "certificate_issuer": "cisco"}]
    assert r["pac_ttl"] == 10 and r["anonymous_provisioning"] is True


def test_local_auth_config_without_profiles():
    r = s.parse_local_auth_config(f.LOCAL_AUTH_CONFIG_UNUSED)
    assert r["enabled"] is False and r["profiles"] == []
    assert r["active_timeout_s"] is None


def test_local_auth_stats():
    r = s.parse_local_auth_stats(f.LOCAL_AUTH_STATS)
    assert r["requests"] == 14 and r["dropped"] == 1 and r["timeouts"] == 2
    assert r["methods"]["PEAP"] == {"success": 10, "fail": 0}
    assert r["methods"]["EAP-FAST"] == {"success": 3, "fail": 1}


def test_netuser_counts_and_keeps_pseudonyms():
    r = s.parse_netuser(f.NETUSER)
    assert r["count"] == 3 and r["no_expiry"] == 2
    assert [u["name"] for u in r["users"]] == ["user-0a1b2c3d4e", "user-5f6a7b8c9d",
                                               "user-1122334455"]
    assert r["users"][0] == {"name": "user-0a1b2c3d4e", "wlan": 2, "type": "Guest",
                             "lifetime": "Unlimited"}
    assert r["users"][2]["wlan"] is None


def test_netuser_existing_fixture():
    r = s.parse_netuser(base.NETUSER)
    assert r["count"] == 1 and r["no_expiry"] == 1


def test_mgmtuser():
    r = s.parse_mgmtuser(f.MGMTUSER)
    assert [(u["name"], u["access"]) for u in r] == [
        ("lab-admin", "ReadWrite"), ("lab-ro", "ReadOnly"), ("lab-lobby", "LobbyAdmin")]
    assert r[0]["description"] is None and r[1]["description"] == "lab read only"
    assert r[2]["password_strength"] == "Weak" and r[1]["telnet"] is False


# --- ACLs -------------------------------------------------------------------

def test_acl_summary_both_families():
    r = s.parse_acl_summary(f.ACL_SUMMARY)
    assert r == [{"name": "lab-preauth", "applied": True, "family": "IPv4"},
                 {"name": "lab-guest-acl", "applied": False, "family": "IPv4"},
                 {"name": "lab-v6-acl", "applied": False, "family": "IPv6"}]
    assert s.parse_acl_counters(f.ACL_SUMMARY) is True


def test_acl_summary_existing_fixture():
    assert s.parse_acl_summary(base.ACL_SUMMARY) == [
        {"name": "lab-preauth", "applied": True, "family": "IPv4"}]
    assert s.parse_acl_counters(base.ACL_SUMMARY) is False


def test_acl_detail_8x_layout():
    r = s.parse_acl_detail(f.ACL_DETAIL, "lab-preauth")
    assert r["name"] == "lab-preauth"
    assert r["counters_enabled"] is True and r["deny_hits"] == 3
    assert len(r["rules"]) == 3
    assert r["rules"][0] == {"seq": 1, "action": "Permit", "direction": "In", "protocol": "17",
                             "source": "10.0.0.0", "src_mask": "255.0.0.0",
                             "destination": "192.0.2.53", "dst_mask": "255.255.255.255",
                             "src_ports": "0-65535", "dst_ports": "53-53", "dscp": "Any",
                             "hits": 42}
    assert r["rules"][2]["action"] == "Deny" and r["rules"][2]["direction"] == "Any"
    assert r["rules"][2]["protocol"] == "Any"


def test_acl_detail_old_layout_direction_after_dscp():
    r = s.parse_acl_detail(f.ACL_DETAIL_OLD)
    assert r["name"] is None and r["counters_enabled"] is False
    assert [(x["seq"], x["direction"], x["action"], x["hits"]) for x in r["rules"]] == [
        (1, "Any", "Permit", None), (2, "In", "Deny", None)]
    assert r["rules"][0]["destination"] == "198.51.100.10"
    assert r["rules"][0]["dst_ports"] == "443-443" and r["rules"][0]["protocol"] == "6"


def test_acl_cpu():
    assert s.parse_acl_cpu(f.ACL_CPU) == {"acl": "lab-cpu-acl", "mode": "wired+wireless",
                                         "wired": True, "wireless": True}
    none = s.parse_acl_cpu(f.ACL_CPU_NONE)
    assert none["acl"] is None and none["mode"] is None


def test_flex_acl_summary():
    r = s.parse_flex_acl_summary(f.FLEX_ACL_SUMMARY)
    assert [(a["name"], a["applied"], a["status"]) for a in r] == [
        ("lab-flex-acl", True, "Applied"), ("lab-flex-split", False, "Modified")]


def test_flex_acl_detail_has_no_direction():
    r = s.parse_flex_acl_detail(f.FLEX_ACL_DETAIL, "lab-flex-acl")
    assert r["name"] == "lab-flex-acl" and len(r["rules"]) == 2
    one = r["rules"][0]
    assert one["direction"] is None and one["hits"] is None
    assert (one["source"], one["src_mask"], one["destination"], one["protocol"],
            one["dst_ports"], one["action"]) == (
        "10.30.0.0", "255.255.0.0", "203.0.113.10", "6", "443-443", "Permit")


# --- WIPS and rogues --------------------------------------------------------------

def test_wps_summary():
    r = s.parse_wps_summary(f.WPS_SUMMARY)
    assert r["auto_immune"] is False
    assert r["client_exclusion"]["IP-theft"] is False
    assert r["client_exclusion"]["Excessive 802.1x-authentication"] is True
    assert r["max_8021x_failures"] == 3
    assert r["signature_processing"] is True
    assert r["infrastructure_mfp"] is True
    assert r["sections"]["Trusted AP Policy"]["Trusted AP timeout"] == "120"


def test_mfp():
    r = s.parse_mfp(f.MFP_SUMMARY)
    assert r["infrastructure_mfp"] is True and r["time_source_valid"] is False
    assert r["client_mfp"] == {"required": 1, "optional": 1, "disabled": 1}
    assert r["wlans"][1]["client_protection"].startswith("Optional but inactive")
    off = s.parse_mfp(f.MFP_SUMMARY_OFF)
    assert off["infrastructure_mfp"] is False and off["client_mfp"] is None


def test_signatures():
    r = s.parse_signatures(f.SIGNATURES)
    assert (r["total"], r["standard"], r["custom"]) == (3, 2, 1)
    assert r["standard_enabled"] == 1 and r["custom_enabled"] == 1
    assert r["signatures"][2]["name"] == "lab-custom-sig"


def test_ap_auth():
    assert s.parse_ap_auth(f.AP_AUTH_OFF) == {"enabled": False, "alarm_threshold": None}
    assert s.parse_ap_auth(f.AP_AUTH_ON) == {"enabled": True, "alarm_threshold": 1}


def _no_macs(value):
    text = repr(value).lower()
    assert "00:11:22:f" not in text


def test_rogue_ap_summary_counts_only():
    r = s.parse_rogue_ap_summary(f.ROGUE_AP_SUMMARY)
    assert r["total"] == 5
    assert r["by_class"] == {"Malicious": 1, "Friendly": 1, "Unclassified": 2, "Custom": 1}
    assert r["by_state"] == {"Contained": 1, "Internal": 1, "Alert": 3}
    assert r["contained"] == 1 and r["on_wire"] == 1
    assert r["classified_reported"] == 4
    _no_macs(r)


def test_rogue_client_and_adhoc_counts():
    c = s.parse_rogue_client_summary(f.ROGUE_CLIENT_SUMMARY)
    assert c["total"] == 2 and c["by_state"] == {"Alert": 1, "Contained": 1}
    _no_macs(c)
    a = s.parse_rogue_adhoc_summary(f.ROGUE_ADHOC_SUMMARY)
    assert a["total"] == 0 and a["settings"]["Auto-contain Ad-Hoc"] == "Disabled"


def test_rogue_rules():
    r = s.parse_rogue_rules(f.ROGUE_RULES)
    assert r[0] == {"priority": 1, "name": "lab-rule-ssid", "class": "Malicious",
                    "enabled": True, "action": "Contain", "notify": "Global", "match": "Any",
                    "hits": 3, "conditions": None}
    assert r[1]["enabled"] is False
    old = s.parse_rogue_rules(f.ROGUE_RULES_OLD)
    assert old[0]["enabled"] is True and old[0]["action"] is None
    assert old[0]["class"] == "Malicious" and old[0]["hits"] == 9


def test_auto_contain():
    on = s.parse_auto_contain(f.AUTO_CONTAIN)
    assert on["any_enabled"] is True and on["level"] == 3
    assert on["enabled_settings"] == ["Rogue on wire Auto-Contain"]
    off = s.parse_auto_contain(f.AUTO_CONTAIN_OFF)
    assert off["any_enabled"] is False and off["enabled_settings"] == []


def test_auto_contain_from_wps_policy_action():
    r = s.parse_auto_contain(f.WPS_SUMMARY)
    assert r["any_enabled"] is True
    assert r["enabled_settings"] == ["Detect trusted clients on rogue APs"]


def test_auto_contain_from_rogue_summary_is_off():
    assert s.parse_auto_contain(f.ROGUE_AP_SUMMARY)["any_enabled"] is False


# --- Mobility ------------------------------------------------------------------

def test_mobility_summary():
    r = s.parse_mobility_summary(f.MOBILITY_SUMMARY)
    assert r["group_name"] == "lab-mob-grp"
    assert r["multicast_mode"] == "Disabled" and r["dtls"] is True
    assert r["members_configured"] == 4
    paths = [(p["ip"], p["control_up"], p["data_up"]) for p in r["peers"]]
    assert paths == [("192.0.2.10", True, True), ("192.0.2.11", True, False),
                     ("198.51.100.10", False, False), ("198.51.100.11", False, True)]
    assert r["peers"][2]["group"] == "lab-mob-dmz"
    assert r["peers"][2]["status"] == "Control and Data Paths Down"
    assert r["peers"][0]["mac"] == "00:11:22:00:aa:01"


def test_mobility_summary_public_ip_column():
    r = s.parse_mobility_summary(f.MOBILITY_SUMMARY_PUBLIC)
    assert r["multicast_ip"] == "239.10.10.10"
    peer = r["peers"][0]
    assert peer["multicast_ip"] == "239.10.10.10" and peer["public_ip"] == "192.0.2.10"
    assert peer["status"] == "Up" and peer["control_up"] is True


def test_mobility_stats():
    r = s.parse_mobility_stats(f.MOBILITY_STATS)
    assert r["handoffs"] == {"requests_sent": 10, "requests_received": 12,
                             "as_local": 9, "as_foreign": 5}
    assert r["failures"] == 4


def test_mobility_anchor():
    r = s.parse_mobility_anchor(f.MOBILITY_ANCHOR)
    assert r == [
        {"wlan": 2, "kind": "wlan", "anchor_ip": "198.51.100.10", "status": "Up",
         "priority": 1},
        {"wlan": 2, "kind": "wlan", "anchor_ip": "198.51.100.11",
         "status": "Control and Data Paths Down", "priority": 2}]


def test_mobility_ap_list_count():
    assert s.parse_mobility_ap_list(f.MOBILITY_AP_LIST) == 3


# --- FlexConnect --------------------------------------------------------------

def test_flex_group_detail():
    r = s.parse_flex_group_detail(f.FLEX_GROUP_DETAIL, "lab-flex-01")
    assert r["name"] == "lab-flex-01" and r["ap_count"] == 2
    assert [a["name"] for a in r["aps"]] == ["lab-ap-01", "lab-ap-02"]
    assert r["aps"][0]["mac"] == "00:11:22:aa:00:01"
    assert r["local_auth"] is True
    assert r["radius_servers"] == ["192.0.2.50"]
    assert r["vlan_mode"] is True and r["native_vlan"] == 100
    assert r["wlan_vlan_mappings"] == [{"wlan": 1, "vlan": 110}, {"wlan": 3, "vlan": 130}]
    assert r["acl_mappings"] == [
        {"kind": "local-split", "wlan": 1, "acl": "lab-flex-split"},
        {"kind": "webauth", "wlan": 2, "acl": "lab-flex-acl"}]
    assert r["vlan_mappings"] == [{"vlan": 110, "ingress": "lab-flex-acl",
                                   "egress": "lab-flex-acl"}]
    assert r["efficient_upgrade"] is True and r["master_ap"] == "lab-ap-01"
    assert "<REDACTED>" not in repr(r)


def test_flex_group_detail_minimal():
    r = s.parse_flex_group_detail(f.FLEX_GROUP_DETAIL_MIN)
    assert r["ap_count"] == 0 and r["aps"] == []
    assert r["radius_servers"] == [] and r["local_auth"] is False
    assert r["efficient_upgrade"] is False and r["master_ap"] is None


# --- QoS, AVC, NetFlow, mDNS, NMSP, multicast -----------------------------------------

def test_qos_profile_8x():
    r = s.parse_qos_profile(f.QOS_PLATINUM, "platinum")
    assert r["name"] == "platinum" and r["description"] == "For Voice Applications"
    assert r["max_priority"] == "voice" and r["unicast_default_priority"] == "voice"
    assert r["multicast_default_priority"] == "voice"
    assert r["per_user_rate_limits"]["average_data"] == {"upstream": 2000, "downstream": 4000}
    assert r["per_ssid_rate_limits"]["burst_realtime"] == {"upstream": 0, "downstream": 0}
    assert r["dot1p_tag"] == 6 and r["wired_protocol"] == "dot1p"


def test_qos_profile_older_single_rate():
    r = s.parse_qos_profile(f.QOS_BRONZE_OLD)
    assert r["per_user_rate_limits"]["average_data"] == {"upstream": None, "downstream": 512}
    assert r["per_ssid_rate_limits"] == {}
    assert r["dot1p_tag"] == 1 and r["wired_protocol"] == "none"


def test_qos_map():
    r = s.parse_qos_map(f.QOS_MAP)
    assert r["enabled"] is True and r["trust_dscp_upstream"] is False
    assert r["map"][2] == {"up": 6, "dscp_default": 46, "dscp_start": 46, "dscp_end": 47}
    assert len(r["map"]) == 4
    assert r["exceptions"] == [{"dscp": 48, "up": 6}]
    off = s.parse_qos_map(f.QOS_MAP_OFF)
    assert off["enabled"] is False and off["map"] == []


def test_avc_and_flow():
    assert s.parse_avc_profiles(f.AVC_PROFILES) == [
        {"name": "lab-avc-prof", "rules": 2}, {"name": "lab-avc-guest", "rules": 5}]
    assert s.parse_flow_exporters(f.FLOW_EXPORTERS) == [
        {"name": "lab-prime", "ip": "192.0.2.70", "port": 9995}]
    assert s.parse_flow_monitors(f.FLOW_MONITORS) == [
        {"name": "lab-mon", "exporter": "lab-prime", "exporter_ip": "192.0.2.70",
         "port": 9995, "record": "ipv4_client_app_flow_record"}]


def test_mdns():
    r = s.parse_mdns_summary(f.MDNS_SUMMARY)
    assert r["enabled"] is True and r["query_interval_min"] == 15 and r["services"] == 3
    svc = s.parse_mdns_services(f.MDNS_SERVICES)
    assert [x["name"] for x in svc] == ["AirPrint", "AppleTV"]
    assert svc[1]["lss"] is True and svc[1]["providers"] == 2
    assert svc[0]["service_string"] == "_ipp._tcp.local."
    prof = s.parse_mdns_profiles(f.MDNS_PROFILES)
    assert prof == [{"name": "default-mdns-profile", "interfaces": 2, "interface_groups": 0,
                     "wlans": 1, "ap_groups": 0}]


def test_nmsp_status_both_layouts():
    assert s.parse_nmsp_status(f.NMSP_STATUS) == [
        {"ip": "192.0.2.80", "local_ip": "192.0.2.10", "tx_echo": 1200, "rx_echo": 1200,
         "tx_data": 340, "rx_data": 12, "transport": "TLS"}]
    old = s.parse_nmsp_status(f.NMSP_STATUS_OLD)
    assert old[0]["ip"] == "192.0.2.81" and old[0]["tx_echo"] == 500
    assert old[0]["local_ip"] is None


def test_nmsp_subscription_wrapped_services():
    assert s.parse_nmsp_subscription(f.NMSP_SUBSCRIPTION) == [
        {"ip": "192.0.2.80",
         "services": ["RSSI", "Info", "Statistics", "AP Monitor", "AP Info"]}]


def test_mgid():
    r = s.parse_mgid(f.MGID)
    assert r["layer2_count"] == 2 and r["layer3_count"] == 2
    assert r["layer2"][1] == {"interface": "lab-guest", "vlan": 20, "mgid": 1}


# --- Management plane -----------------------------------------------------------

def test_network_summary():
    r = s.parse_network_summary(f.NETWORK_SUMMARY)
    assert r["telnet"] is True and r["ssh"] is True
    assert r["http"] is False and r["https"] is True
    assert r["secure_web_cipher_high"] is False
    assert r["web_auth_secure"] is True
    assert r["mgmt_via_wireless"] is True and r["mgmt_via_dynamic_interface"] is False
    assert r["multicast_mode"] == "Multicast" and r["multicast_group"] == "239.1.1.1"
    assert r["ipv6_multicast_mode"] == "Unicast"
    assert r["igmp_snooping"] is True and r["mld_snooping"] is False
    assert r["fast_ssid_change"] is False
    assert r["user_idle_timeout_s"] == 300


def test_network_summary_older_wording():
    r = s.parse_network_summary(f.NETWORK_SUMMARY_OLD)
    assert r["http"] is True and r["telnet"] is False
    assert r["multicast_mode"] == "Unicast" and r["multicast_group"] is None
    assert r["mld_snooping"] is None


def test_snmpversion():
    assert s.parse_snmpversion(f.SNMPVERSION) == {"v1": False, "v2c": True, "v3": True}


def test_snmpcommunity_names_stay_masked():
    r = s.parse_snmpcommunity(f.SNMPCOMMUNITY_MASKED)
    assert r == [
        {"name": "<REDACTED>", "ip": "0.0.0.0", "mask": "0.0.0.0", "access": "RO",
         "enabled": True},
        {"name": "<REDACTED>", "ip": "192.0.2.0", "mask": "255.255.255.0", "access": "RW",
         "enabled": False}]


def test_snmpcommunity_existing_fixture_shape():
    r = s.parse_snmpcommunity(base.SNMPCOMMUNITY)
    assert [c["access"] for c in r] == ["RO", "RO"]


def test_snmpv3user():
    r = s.parse_snmpv3user(f.SNMPV3USER)
    assert r[0] == {"name": "default", "access": "RW", "auth_protocol": "HMAC-SHA",
                    "priv_protocol": "CFB-AES"}
    assert r[2]["auth_protocol"] == "HMAC-MD5" and r[2]["priv_protocol"] == "None"


def test_snmptrap():
    assert s.parse_snmptrap(f.SNMPTRAP) == [
        {"name": "lab-prime", "ip": "192.0.2.70", "enabled": True},
        {"name": "lab-old-nms", "ip": "198.51.100.70", "enabled": False}]


def test_logging():
    r = s.parse_logging(f.LOGGING)
    assert r["syslog_hosts"] == ["192.0.2.90", "192.0.2.91"]
    assert r["syslog_host_count"] == 2
    assert r["syslog_level"] == "notifications"
    assert r["facility"] == "local0"
    assert r["buffered_level"] == "errors" and r["console_level"] == "disabled"
    assert r["syslog_tls"] is False


def test_logging_without_hosts():
    r = s.parse_logging(f.LOGGING_NO_HOSTS)
    assert r["syslog_hosts"] == [] and r["syslog_host_count"] == 0


# --- Certificates ------------------------------------------------------------------

def test_certificate_summary_uses():
    r = s.parse_certificates(f.CERT_SUMMARY)
    assert [(c["use"], c["source"], c["self_signed"]) for c in r] == [
        ("web-admin", "Locally Generated", True), ("web-auth", "3rd Party", False)]
    assert r[0]["subject"] is None and r[0]["valid_to"] is None


def test_certificate_lsc():
    assert s.parse_certificates(f.CERT_LSC_OFF) == []
    r = s.parse_certificates(f.CERT_LSC_ON)
    assert len(r) == 1
    assert r[0]["use"] == "lsc-ca"
    assert r[0]["subject"] == "C=US, O=lab, CN=lab-issuing-ca"
    assert (r[0]["valid_from"], r[0]["valid_to"]) == ("2024-01-10", "2029-01-10")


def test_certificate_local_auth():
    r = s.parse_certificates(f.LOCAL_AUTH_CERTS)
    assert [c["use"] for c in r] == ["local-eap-ca", "local-eap-device", "local-eap-device"]
    assert r[1]["valid_to"] == "2026-03-29" and r[1]["self_signed"] is False
    assert r[1]["source"] == "cisco"
    assert r[2]["self_signed"] is True and r[2]["valid_from"] == "2025-02-01"
    for c in r:
        assert set(c) == {"use", "source", "subject", "issuer", "valid_from", "valid_to",
                          "key_size", "signature_algorithm", "self_signed"}
