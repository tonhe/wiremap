"""ASA / ASAv output parsers."""
from app.collectors import asa_parsers as p
from tests.test_collectors import asa_fixtures as fx


def test_asa_time_only_converts_utc():
    assert p.asa_time("10:15:22 UTC Oct 1 2026") == "2026-10-01T10:15:22Z"
    assert p.asa_time("14:22:31.123 UTC Fri Nov 7 2026") == "2026-11-07T14:22:31Z"
    assert p.asa_time("10:15:22 CST Oct 1 2026") is None
    assert p.asa_time("") is None


def test_version_firepower_running_asa():
    v = p.parse_version(fx.VERSION_ASA)
    assert v["asa_version"] == "9.16(4)" and v["asdm_version"] == "7.18(1)"
    assert v["boot_image"] == "disk0:/asa9-16-4-smp-k8.bin"
    assert v["uptime"] == "120 days 3 hours"
    assert v["failover_uptime"] == "200 days 4 hours"
    assert v["model"] == "FPR-2130" and v["ram_mb"] == 13703
    assert v["serial"] == "JAD00000AAA"
    assert v["licence_tier"] == "FPR-2130 Security Plus"
    assert v["features"]["Security Contexts"] == "2"
    assert v["features"]["AnyConnect Premium Peers"] == "250"
    assert v["features"]["Encryption-3DES-AES"] == "Enabled"
    assert v["platform_type"] == "Firepower running ASA"
    assert v["last_modified"].startswith("10:00:00.000 UTC")


def test_version_asav_smart_licensing():
    v = p.parse_version(fx.VERSION_ASAV)
    assert v["platform_type"] == "ASAv"
    assert v["model_id"] == "ASAv30"
    assert v["licence_mode"] == "Smart Licensing"
    assert v["uptime"] == "30 days 2 hours"
    assert p.parse_version("") is None


def test_inventory_and_chassis():
    items = p.parse_inventory(fx.INVENTORY)
    assert [i["pid"] for i in items] == ["FPR-2130", "FPR2K-PWR-AC-400"]
    assert p.chassis(items)["sn"] == "JAD00000AAA"
    assert p.chassis([]) == {}


def test_platform_health_parsers():
    assert p.parse_mode(fx.MODE_MULTIPLE) == "multiple"
    assert p.parse_cpu(fx.CPU) == {"5s": 12, "1m": 75, "5m": 72}
    mem = p.parse_memory(fx.MEMORY)
    assert mem["used_pct"] == 80.0 and mem["free"] == 1717986918
    assert p.parse_disk(fx.DISK)["used_pct"] == 75.0
    assert p.parse_bootvar(fx.BOOTVAR) == "disk0:/asa9-16-4-smp-k8.bin"
    top = p.parse_processes(fx.PROCESSES)
    assert [r["process"] for r in top] == ["DATAPATH-0-1825", "Logger", "SSH"]
    assert p.parse_blocks(fx.BLOCKS) == [1550]
    drops = p.parse_asp_drop(fx.ASP_DROP)
    assert drops[0] == {"reason": "Flow is denied by configured rule (acl-drop)",
                        "count": 12345}
    assert len(drops) == 4
    assert p.parse_in_use(fx.CONN_COUNT) == {"in_use": 80000, "peak": 95000}
    rows = p.parse_resource_usage(fx.RESOURCE_USAGE)
    assert p.resource(rows, "Conns")["limit"] == 100000
    assert p.resource(rows, "Xlates")["limit"] is None
    crash = p.parse_crashinfo(fx.CRASHINFO)
    assert crash == {"present": True, "thread": "DATAPATH-1-1826",
                     "time": "2026-03-01T10:00:00Z"}
    assert p.parse_crashinfo("")["present"] is False
    assert p.parse_ntp_status(fx.NTP_SYNCED) == {"synced": True, "stratum": 3}
    assert p.parse_ntp_status(fx.NTP_UNSYNCED)["synced"] is False
    logs = p.parse_critical_logs(fx.CRITICAL_LOGS)
    assert logs["count"] == 2 and "%ASA-1-105005" in logs["last"][-1]


def test_config_saved_compares_checksums():
    assert p.config_saved(fx.CHECKSUM, fx.STARTUP_SAME) is True
    assert p.config_saved(fx.CHECKSUM, fx.STARTUP_DIFFERENT) is False
    assert p.config_saved(fx.CHECKSUM, "") is None


def test_failover_detail():
    fo = p.parse_failover(fx.FAILOVER_ACTIVE)
    assert fo["enabled"] and fo["unit"] == "primary"
    assert fo["failover_link"] == {"name": "FOLINK", "interface": "GigabitEthernet0/3",
                                   "state": "up"}
    assert fo["stateful_link"]["state"] == "down"
    assert fo["poll"] == {"unit": "1 seconds", "unit_hold": "15 seconds",
                          "interface": "5 seconds", "interface_hold": "25 seconds"}
    assert fo["monitored"] == 3
    assert fo["version"] == {"ours": "9.16(4)", "mate": "9.16(3)"}
    assert fo["serial"]["mate"] == "JAD00000AAB"
    assert fo["this_host"]["state"] == "Active"
    assert fo["other_host"]["failover_role"] == "secondary"
    dmz = fo["this_host"]["interfaces"][2]
    assert dmz == {"nameif": "dmz", "ip": "10.1.0.1", "status": "Failed", "monitor": "Waiting"}
    off = p.parse_failover(fx.FAILOVER_OFF)
    assert off["enabled"] is False and off["failover_link"] is None
    assert p.parse_failover("") is None


def test_failover_history_and_monitor():
    hist = p.parse_failover_history(fx.FAILOVER_HISTORY)
    assert hist[-1] == {"time": "10:15:22 UTC Oct 1 2026", "from": "Negotiation",
                        "to": "Just Active", "reason": "No Active unit found"}
    assert len(hist) == 2
    mon = p.parse_monitor_interface(fx.MONITOR_INTERFACE)
    assert mon == {"outside": "Normal (Monitored)", "inside": "Normal (Monitored)",
                   "dmz": "Failed (Waiting)"}
    assert p.is_monitored("Normal (Monitored)") and p.is_monitored("Failed (Waiting)")
    assert not p.is_monitored("Normal (Not-Monitored)") and not p.is_monitored(None)


def test_config_interfaces_and_mode():
    intf = p.parse_config_interfaces(fx.RUNNING_CONFIG)
    assert intf["GigabitEthernet0/0"]["standby_ip"] == "198.51.100.3"
    assert intf["GigabitEthernet0/1"]["channel_group"] == 1
    assert intf["Port-channel1.10"]["vlan"] == 10
    assert intf["Management0/0"]["management_only"] is True
    assert p.firewall_mode(fx.RUNNING_CONFIG) == "Routed"
    assert p.firewall_mode("firewall transparent\n") == "Transparent"
    assert p.firewall_mode(None) is None
    assert p.same_security(fx.RUNNING_CONFIG) == {"inter": True, "intra": False}


def test_show_interface():
    rows = {r["interface"]: r for r in p.parse_show_interface(fx.SHOW_INTERFACE)}
    out = rows["GigabitEthernet0/0"]
    assert out["nameif"] == "outside" and out["admin"] == "up" and out["line"] == "up"
    assert out["duplex"] == "Full-duplex" and out["speed"] == "1000 Mbps"
    assert out["mtu"] == 1500 and out["description"] == "LAB uplink"
    assert (out["input_errors"], out["crc"], out["overruns"], out["underruns"]) == (500, 200, 3, 4)
    assert out["input_packets"] == 100000 and out["output_drops"] == 12
    assert out["in_rate_bps"] == 320000 and out["out_rate_bps"] == 360000
    assert rows["Port-channel1.10"]["vlan"] == 10
    assert rows["GigabitEthernet0/5"]["admin"] == "down"
    assert rows["Management0/0"]["management_only"] is True
    assert p.parse_nameif(fx.NAMEIF)["Port-channel1.10"] == ("inside", 100)
    brief = p.parse_ip_brief(fx.IP_BRIEF)
    assert sum(1 for r in brief if r["status"] == "up" and r["protocol"] == "up") == 4
    assert len(brief) == 5


def test_certificates_and_users():
    certs = p.parse_certificates(fx.CERTIFICATES)
    ident, ca = certs
    assert ident["type"] == "identity" and ident["subject_cn"] == "vpn.lab.example"
    assert ident["issuer_cn"] == "LAB-CA" and ident["key_size"] == 2048
    assert ident["valid_to"] == "2026-12-01T10:00:00Z"
    assert ident["self_signed"] is False
    assert ca["type"] == "ca" and ca["self_signed"] is True
    users = p.trustpoint_users(fx.RUNNING_CONFIG)
    assert users["LAB-TP"] == ["ssl outside", "tunnel-group LAB-RA"]


def test_management_plane():
    m = p.parse_management(fx.RUNNING_CONFIG)
    assert {"net": "0.0.0.0", "mask": "0.0.0.0", "nameif": "outside"} in m["ssh"]
    assert m["telnet"] == [{"net": "10.0.0.0", "mask": "255.0.0.0", "nameif": "inside"}]
    assert m["http_server"] and m["http"][0]["nameif"] == "outside"
    assert m["ssh_version"] == "2" and m["ssh_kex"] == "dh-group14-sha256"
    assert m["icmp"] == [{"action": "permit", "from": "any", "nameif": "outside"}]
    assert m["aaa_auth"]["ssh"] == "LOCAL"
    assert m["aaa_auth"]["http"] == "LAB-TACACS LOCAL"
    assert m["aaa_cmd_authz"] is False and m["aaa_accounting"] == []
    assert m["aaa_servers"] == [{"group": "LAB-TACACS", "nameif": "inside",
                                 "host": "10.0.0.20"}]
    assert m["aaa_server_groups"] == {"LAB-TACACS": "tacacs+"}
    assert m["max_fail"] == 5
    assert m["local_users"] == [{"username": "lab-admin", "privilege": 15},
                                {"username": "lab-ro", "privilege": 5}]
    assert m["snmp"]["communities"] == 1
    assert [(h["host"], h["version"], h["kind"]) for h in m["snmp"]["hosts"]] == [
        ("10.0.0.30", "2c", "poll+trap"), ("10.0.0.31", "1", "poll")]
    assert m["snmp"]["users"] == [{"user": "lab-snmp", "group": "LAB-GRP", "auth": "sha",
                                   "priv": "aes 256"}]
    assert m["syslog_hosts"] == [
        {"nameif": "inside", "host": "10.0.0.40", "protocol": "udp", "port": 514},
        {"nameif": "inside", "host": "10.0.0.41", "protocol": "tcp", "port": 1470}]
    assert m["logging"] == {"enabled": True, "timestamp": True,
                            "buffered": "informational", "trap": "debugging"}
    assert m["flow_export"] == [{"nameif": "inside", "host": "10.0.0.50", "port": 2055}]
    assert m["ntp_servers"] == [{"host": "10.0.0.60", "key": True}]
    assert m["dns_servers"] == ["10.0.0.53"] and m["domain_name"] == "lab.example"
    assert m["banners"] == ["motd"] and m["management_access"] == "inside"
    assert m["call_home"] and m["smart_licensing"]
    assert p.enable_password_set(m) is True
    assert p.enable_password_set({"enable_password": p.BLANK_ENABLE_HASH}) is False
    assert p.enable_password_set({"enable_password": None}) is False
    assert p.parse_management(None) is None


def test_aaa_status_and_counts():
    assert p.parse_aaa_server_status(fx.AAA_SERVER) == [
        {"group": "LAB-TACACS", "protocol": "tacacs+", "host": "10.0.0.20",
         "status": "FAILED"}]
    assert p.acl_elements(fx.ACCESS_LIST) == 15
    assert p.nat_rule_count(fx.NAT_DETAIL) == 2
    assert p.s2s_configured(fx.RUNNING_CONFIG) == 2
    assert p.l2l_sessions(fx.L2L) == 1
    vpn = p.parse_vpn_summary(fx.VPN_SUMMARY)
    assert vpn["anyconnect client"] == {"active": 12, "cumulative": 3456, "peak": 45}
    assert vpn["site-to-site vpn"]["active"] == 1
    assert vpn["capacity"] == 7500 and vpn["load_pct"] == 1


def test_contexts():
    ctx = p.parse_contexts(fx.CONTEXTS)
    assert [c["name"] for c in ctx] == ["admin", "lab-ctx-a", "lab-ctx-b"]
    assert ctx[0]["admin"] and ctx[2]["mode"] == "Transparent"
