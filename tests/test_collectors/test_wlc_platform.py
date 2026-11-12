"""AireOS platform parsers: system, licence, HA, interfaces, ports, CDP,
time and health."""
import pytest

from app.collectors import wlc_platform as p
from tests.test_collectors import wlc_fixtures as base
from tests.test_collectors import wlc_platform_fixtures as fx


SINGLE_ARG = [
    p.parse_sysinfo, p.parse_inventory, p.parse_boot, p.parse_cpu, p.parse_memory,
    p.parse_redundancy_summary, p.parse_redundancy_detail, p.parse_redundancy_statistics,
    p.parse_redundancy_timers, p.parse_peer_route, p.parse_interface_summary,
    p.parse_interface_detail, p.parse_interface_groups, p.parse_port_summary, p.parse_lag,
    p.parse_port_stats, p.parse_cdp_neighbors, p.parse_time, p.parse_coredumps,
    p.parse_ap_crash_files, p.parse_switchconfig, p.parse_stats_switch, p.parse_serial,
    p.parse_sessions, p.parse_loginsession,
]


@pytest.mark.parametrize("parser", SINGLE_ARG, ids=lambda f: f.__name__)
@pytest.mark.parametrize("text", [None, "", "  \n", fx.INCORRECT])
def test_empty_or_error_output_is_none(parser, text):
    assert parser(text) is None


@pytest.mark.parametrize("parser", SINGLE_ARG, ids=lambda f: f.__name__)
def test_unrelated_output_does_not_raise(parser):
    parser("some unexpected banner\n----\nwith ... dots ... and = signs\n")


def test_license_all_empty_is_none():
    assert p.parse_license(None, "", fx.INCORRECT) is None


# --- sysinfo / inventory / boot -------------------------------------------

def test_sysinfo_810():
    s = p.parse_sysinfo(base.SYSINFO)
    assert s["system_name"] == "lab-wlc-01"
    assert s["version"] == "8.10.185.0"
    assert s["field_recovery"] == "7.6.101.1"
    assert s["emergency_image"] == "8.10.185.0"
    assert s["uptime"] == "41 days 3 hrs 12 mins 9 secs"
    assert s["uptime_days"] == 41
    assert s["last_reset"] == "Software reset"
    assert s["max_aps"] == 1500
    assert s["location"] == "Lab/Building 1/Floor 2"
    assert s["contact"] == "lab-noc"
    assert s["ip"] == "192.0.2.40"
    assert s["redundancy_mode"] == "SSO"
    assert s["country"] == "US"
    assert s["temperature_c"] == 23
    assert s["temp_alarm_limits"] == "10 to 38 C"
    assert s["fan_status"] == "OK"
    assert s["power_supplies"] == ["1: Present, OK", "2: Present, OK"]
    assert s["clients"] == 42
    assert s["wlans"] == 3
    assert s["cpu_current"] == 4
    assert s["memory_current"] == 39
    assert s["burned_in_mac"] == "00:a0:c9:00:00:01"
    assert s["licensing_type"] == "RTU"


def test_sysinfo_85_missing_fields():
    s = p.parse_sysinfo(fx.SYSINFO_85)
    assert s["version"] == "8.5.182.0"
    assert s["field_recovery"] == ""
    assert s["licensing_type"] == ""
    assert s["uptime_days"] == 0
    assert s["country"] == "GB"
    assert s["temperature_c"] == 38
    assert s["power_supplies"] == ["1: Absent", "2: Present, OK"]
    assert s["cpu_current"] is None
    assert s["memory_current"] is None
    assert s["redundancy_mode"] == "Disabled"


def test_inventory_5520():
    inv = p.parse_inventory(fx.INVENTORY_5520)
    assert inv["model"] == "AIR-CT5520-K9"
    assert inv["serial"] == "FCW0000A001"
    assert inv["description"] == "Cisco 5520 Wireless Controller"
    assert inv["max_aps"] == 1500
    assert inv["burned_in_mac"] == "00:a0:c9:00:00:01"
    assert inv["power_supplies"] == ["1: Present, OK", "2: Present, OK"]
    assert len(inv["entries"]) == 2
    assert inv["entries"][1] == {"name": "NIC Card 1", "descr": "Intel X710 10G NIC",
                                 "pid": "AIR-CT5520-NIC", "vid": "V01", "sn": "FCW0000A101"}


def test_inventory_5508():
    inv = p.parse_inventory(fx.INVENTORY_5508)
    assert inv["model"] == "AIR-CT5508-K9"
    assert inv["serial"] == "FCW0000A002"
    assert inv["entries"][0]["vid"] == "V02"
    assert inv["power_supplies"][0] == "1: Absent"


def test_inventory_without_entries():
    inv = p.parse_inventory("Maximum number of APs supported.................. 50\n")
    assert inv["model"] == "" and inv["entries"] == [] and inv["max_aps"] == 50


def test_boot():
    assert p.parse_boot(fx.BOOT) == {"primary": "8.10.185.0", "backup": "8.10.181.0",
                                     "default": "8.10.185.0", "active": "8.10.185.0"}
    b = p.parse_boot(fx.BOOT_BACKUP_ACTIVE)
    assert b["default"] == "8.5.182.0"
    assert b["active"] == "8.5.171.0"


# --- licences ---------------------------------------------------------------

def test_license_capacity_table_wins():
    lic = p.parse_license(fx.LICENSE_SUMMARY_RTU, fx.LICENSE_CAPACITY, None)
    assert lic == {"licensed_aps": 500, "type": "RTU", "in_use": 120}


def test_license_rtu_feature_block():
    lic = p.parse_license(fx.LICENSE_SUMMARY_RTU, None, None)
    assert lic["licensed_aps"] == 500
    assert lic["type"] == "RTU"
    assert lic["in_use"] is None


def test_license_5508_sums_active_ap_counts():
    lic = p.parse_license(None, fx.INCORRECT, fx.LICENSE_ALL_5508)
    assert lic["licensed_aps"] == 75
    assert lic["type"] == "Permanent"


def test_license_evaluation_only():
    text = ("Index 1   Feature: ap_count\n        License Type: Evaluation\n"
            "        License State: Active, In Use\n        License Count: 100/0/0\n")
    lic = p.parse_license(text, None, None)
    assert lic["type"] == "Evaluation"
    assert lic["licensed_aps"] == 100


def test_license_dotted_and_smart():
    assert p.parse_license(fx.LICENSE_DOTTED, None, None)["licensed_aps"] == 250
    lic = p.parse_license(fx.LICENSE_SMART, None, None)
    assert lic["type"] == "Smart"
    assert lic["licensed_aps"] is None


# --- cpu / memory ------------------------------------------------------------

def test_cpu():
    c = p.parse_cpu(fx.CPU)
    assert c["current_pct"] == 4
    assert c["cores"] == [2, 6, 4, 8]
    assert c["avg_pct"] == 5


def test_cpu_cores_only_falls_back_to_average():
    assert p.parse_cpu(fx.CPU_CORES_ONLY)["current_pct"] == 10


def test_memory_bytes():
    m = p.parse_memory(fx.MEMORY_BYTES)
    assert m["total_kb"] == 3851260
    assert m["free_kb"] == 2310756
    assert m["free_pct"] == 60.0


def test_memory_one_line_kb():
    m = p.parse_memory(fx.MEMORY_KB_ONELINE)
    assert m == {"total_kb": 3851260, "free_kb": 1925630, "free_pct": 50.0}


def test_memory_free_from_used():
    m = p.parse_memory(fx.MEMORY_USED_ONLY)
    assert m["free_kb"] == 1500000
    assert m["free_pct"] == 75.0


# --- redundancy --------------------------------------------------------------

def test_redundancy_summary_sso():
    r = p.parse_redundancy_summary(fx.REDUNDANCY_SUMMARY_SSO)
    assert r["mode"] == "SSO"
    assert r["local_state"] == "ACTIVE"
    assert r["peer_state"] == "STANDBY HOT"
    assert r["unit"] == "Primary"
    assert r["ha_sku"] is False
    assert r["unit_id"] == "00:a0:c9:00:00:01"
    assert r["redundancy_state"] == "SSO"
    assert r["mobility_mac"] == "00:a0:c9:00:00:01"
    assert r["bulk_sync_status"] == "Complete"
    assert r["peer_latency_us"] == 412
    assert r["gateway_latency_us"] == 1120


def test_redundancy_summary_disabled_ha_sku():
    r = p.parse_redundancy_summary(fx.REDUNDANCY_SUMMARY_OFF)
    assert r["mode"] == "Disabled"
    assert r["peer_state"] == "N/A"
    assert r["unit"] == "Secondary"
    assert r["ha_sku"] is True


def test_redundancy_detail():
    d = p.parse_redundancy_detail(fx.REDUNDANCY_DETAIL)
    assert d == {"redundancy_mgmt_ip": "192.0.2.41", "peer_redundancy_mgmt_ip": "192.0.2.42",
                 "redundancy_port_ip": "198.51.100.41",
                 "peer_redundancy_port_ip": "198.51.100.42",
                 "peer_service_port_ip": "10.0.0.42", "redundancy_port_state": "UP"}


def test_redundancy_detail_unset_addresses_blank():
    d = p.parse_redundancy_detail(fx.REDUNDANCY_DETAIL_OFF)
    assert d["redundancy_mgmt_ip"] == ""
    assert d["peer_service_port_ip"] == ""
    assert d["redundancy_port_state"] == ""


def test_redundancy_statistics():
    s = p.parse_redundancy_statistics(fx.REDUNDANCY_STATISTICS)
    assert s["switchovers"] == 2
    assert s["last_switchover_time"] == "Thu Oct  1 08:12:44 2026"
    assert s["last_switchover_reason"] == "Active unit reload"
    assert s["keep_alive_request_sent"] == "1209344"


def test_redundancy_timers():
    r = p.parse_redundancy_timers(fx.REDUNDANCY_TIMERS)
    assert r["keepalive_ms"] == 100
    assert r["peer_search_s"] == 120
    assert r["keepalive_retries"] == 3
    assert r["management_gateway_failover"] == "Enabled"
    r = p.parse_redundancy_timers(fx.REDUNDANCY_TIMERS_SECONDS)
    assert r["keepalive_ms"] == 1000
    assert r["peer_search_s"] == 120


def test_peer_route():
    assert p.parse_peer_route(fx.PEER_ROUTE) == [
        {"network": "10.10.0.0", "mask": "255.255.0.0", "gateway": "192.0.2.1"},
        {"network": "203.0.113.0", "mask": "255.255.255.0", "gateway": "192.0.2.1"},
    ]
    assert p.parse_peer_route("Peer Network Routes:\n") == []


# --- interfaces ----------------------------------------------------------------

def test_interface_summary():
    rows = p.parse_interface_summary(base.INTERFACE_SUMMARY)
    assert [r["name"] for r in rows] == ["lab-guest", "lab-voice", "management",
                                         "redundancy-management", "virtual"]
    mgmt = rows[2]
    assert mgmt == {"name": "management", "port": "LAG", "vlan": "untagged",
                    "ip": "192.0.2.40", "type": "Static", "ap_manager": True, "guest": False}
    assert rows[0]["type"] == "Dynamic" and rows[0]["vlan"] == "20"


def test_interface_detail_810_management():
    d = p.parse_interface_detail(fx.INTERFACE_DETAIL_MGMT)
    assert d["name"] == "management"
    assert d["mac"] == "00:a0:c9:00:00:01"
    assert (d["ip"], d["mask"], d["gateway"]) == ("192.0.2.40", "255.255.255.0", "192.0.2.1")
    assert d["vlan"] == "untagged"
    assert d["port"] == "LAG" and d["active_port"] == "LAG" and d["backup_port"] == ""
    assert d["dhcp_primary"] == "192.0.2.10" and d["dhcp_secondary"] == ""
    assert d["dhcp_proxy"] == "Global"
    assert d["acl"] == ""
    assert d["ipv6"] == ""
    assert d["nas_id"] == "lab-wlc-01"
    assert d["ap_manager"] is True
    assert d["guest_lan"] is False
    assert d["quarantine"] is False


def test_interface_detail_85_dynamic():
    d = p.parse_interface_detail(fx.INTERFACE_DETAIL_DYN_85)
    assert d["port"] == "2" and d["active_port"] == "2"
    assert d["vlan"] == "40"
    assert d["acl"] == "lab-acl-in"
    assert d["ipv6"] == "2001:db8:40::5/64"
    assert d["nas_id"] == ""
    assert d["guest_lan"] is True
    assert d["quarantine"] is True and d["quarantine_vlan"] == 41
    assert d["ap_manager"] is False
    assert d["dhcp_secondary"] == "10.40.0.3"


def test_interface_groups():
    g = p.parse_interface_groups(fx.INTERFACE_GROUPS)
    assert g == [
        {"name": "lab-ifg-users", "interface_count": 2, "wlan_count": 1, "ap_group_count": 0,
         "quarantine": False},
        {"name": "lab-ifg-quar", "interface_count": 1, "wlan_count": 0, "ap_group_count": 1,
         "quarantine": True},
    ]
    assert p.interface_group_members(fx.RUN_CONFIG_IFG) == {
        "lab-ifg-users": ["lab-guest", "lab-voice"], "lab-ifg-quar": ["lab-quarantine"]}
    assert p.interface_group_members(None) == {}


# --- ports -------------------------------------------------------------------

def test_port_summary_810():
    rows = p.parse_port_summary(base.PORT_SUMMARY)
    assert rows[0] == {"port": 1, "type": "Normal", "stp": "Forw", "admin": "Enable",
                       "phys_mode": "Auto", "phys_status": "10000 Full", "speed_mbps": 10000,
                       "duplex": "Full", "link": "Up", "link_trap": "Enable", "poe": "N/A",
                       "media": "10GBase-SR"}
    assert rows[1]["speed_mbps"] is None
    assert rows[1]["duplex"] == ""
    assert rows[1]["link"] == "Down"
    assert rows[1]["media"] == "Not Present"


def test_port_summary_85():
    rows = p.parse_port_summary(fx.PORT_SUMMARY_85)
    assert [r["port"] for r in rows] == [1, 2, 3]
    assert rows[1]["admin"] == "Disable"
    assert rows[2]["phys_mode"] == "1000 Full"
    assert rows[2]["speed_mbps"] == 1000
    assert rows[2]["link_trap"] == "Disable"
    assert rows[2]["media"] == "1000BaseT"


def test_lag():
    assert p.parse_lag(fx.LAG_ON) == {"enabled": True}
    assert p.parse_lag(fx.LAG_OFF) == {"enabled": False}
    assert p.parse_lag("something else") == {"enabled": None}


def test_port_stats_totals():
    s = p.parse_port_stats(fx.PORT_STATS)
    assert s["input_errors"] == 17
    assert s["output_errors"] == 3
    assert s["input_drops"] == 40
    assert s["output_drops"] == 5
    assert s["crc"] == 12
    assert s["counters"]["rx_fcs_errors"] == 12
    assert s["counters"]["tx_fcs_errors"] == 1


def test_port_stats_summed_when_no_totals():
    s = p.parse_port_stats(fx.PORT_STATS_NO_TOTALS)
    assert s["input_errors"] == 7
    assert s["output_errors"] == 3
    assert s["input_drops"] is None
    assert s["crc"] == 4


def test_cdp_neighbors():
    n = p.parse_cdp_neighbors(fx.CDP_NEIGHBORS)
    assert len(n) == 2
    assert n[0] == {"local_port": "1", "device_id": "lab-sw-01.lab.example", "ip": "192.0.2.2",
                    "platform": "cisco C9300-48P", "remote_port": "TenGigabitEthernet1/0/1",
                    "capabilities": "Router Switch IGMP",
                    "version": "Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software "
                               "(CAT9K_IOSXE), Version 17.3.4, RELEASE SOFTWARE (fc3)"}
    assert n[1]["local_port"] == "2"
    assert n[1]["version"] == ""
    assert p.parse_cdp_neighbors("No CDP neighbors found\n") == []


# --- time ----------------------------------------------------------------

def test_time_810():
    tm = p.parse_time(fx.TIME_810)
    assert tm["time"] == "Thu Nov 12 10:00:00 2026"
    assert tm["timezone"] == "(GMT) London, Lisbon, Dublin, Edinburgh"
    assert tm["timezone_delta"] == "0:0"
    assert tm["ntp_servers"] == [
        {"index": 1, "server": "192.0.2.123", "status": "In Sync", "key_index": 0},
        {"index": 2, "server": "192.0.2.124", "status": "Not Synced", "key_index": 1},
    ]
    assert tm["ntp_synced"] is True
    assert tm["ntp_version"] == 3
    assert tm["polling_interval"] == 3600


def test_time_not_synced_hostname_server():
    tm = p.parse_time(fx.TIME_NOT_SYNCED)
    assert tm["ntp_servers"][0]["server"] == "lab-ntp-01"
    assert tm["ntp_synced"] is False
    assert tm["timezone"] == "0:0"


def test_time_without_status_column():
    tm = p.parse_time(fx.TIME_NO_STATUS)
    assert tm["ntp_servers"] == [{"index": 1, "server": "192.0.2.123", "status": "",
                                  "key_index": 0}]
    assert tm["ntp_synced"] is None


def test_time_dotted_servers_and_none():
    tm = p.parse_time(fx.TIME_DOTTED_NTP)
    assert [s["server"] for s in tm["ntp_servers"]] == ["192.0.2.123"]
    tm = p.parse_time(fx.TIME_NO_NTP)
    assert tm["ntp_servers"] == [] and tm["ntp_synced"] is None


# --- crash data ------------------------------------------------------------

def test_coredumps():
    assert p.parse_coredumps(fx.COREDUMP_NONE) == {"present": False, "files": [],
                                                   "enabled": True}
    c = p.parse_coredumps(fx.COREDUMP_PRESENT)
    assert c["present"] is True
    assert c["files"] == ["core_lab-wlc-01.gz"]
    assert c["enabled"] is False


def test_ap_crash_files():
    assert p.parse_ap_crash_files(fx.AP_CRASH) == ["lrad_lab-ap-01.rdump0",
                                                   "lab-ap-02_crash_20261001"]
    assert p.parse_ap_crash_files(fx.AP_CRASH_NONE) == []


# --- management plane ------------------------------------------------------

def test_switchconfig():
    s = p.parse_switchconfig(fx.SWITCHCONFIG)
    assert s["802_3x_flow_control_mode"] == "Disabled"
    assert s["fips_prerequisite_features"] == "Disabled"
    assert s["secret_obfuscation"] == "Enabled"
    assert s["strong_password_case_check"] == "Enabled"
    assert s["strong_password_position_check"] == "Disabled"
    assert s["min_password_length"] == "8"
    assert s["mgmt_user_password_lockout"] == "Enabled"
    assert s["snmpv3_user_password_lockout"] == "Disabled"
    assert s["mgmt_user_lockout_timeout_mins"] == "5"


def test_stats_switch():
    s = p.parse_stats_switch(fx.STATS_SWITCH)
    assert s == {"rx_packets": 51234567, "rx_errors": 4, "tx_packets": 41234567,
                 "tx_errors": 0, "since_cleared": "41 day 3 hr 12 min 9 sec"}


def test_serial_sessions_loginsession():
    assert p.parse_serial(fx.SERIAL) == {"console_timeout_min": 15, "baud_rate": 9600}
    assert p.parse_sessions(fx.SESSIONS) == {"cli_timeout_min": 5, "max_sessions": 5}
    sessions = p.parse_loginsession(fx.LOGINSESSION)
    assert sessions == {"count": 2}
    assert "lab-admin" not in str(sessions)
