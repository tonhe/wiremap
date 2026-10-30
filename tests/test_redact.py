import pytest

from app.redact import REDACTED, redact_config, redact_line

R = REDACTED


@pytest.mark.parametrize("line,expected", [
    # SNMP communities: community replaced, view/RO/RW/ACL kept
    ("snmp-server community s3cr3tComm RO", f"snmp-server community {R} RO"),
    ("snmp-server community s3cr3tComm RO 10", f"snmp-server community {R} RO 10"),
    ("snmp-server community s3cr3tComm view V1 RW SNMP-ACL",
     f"snmp-server community {R} view V1 RW SNMP-ACL"),
    ("snmp-server community s3cr3tComm group network-operator",
     f"snmp-server community {R} group network-operator"),
    # snmp-server host (positional community)
    ("snmp-server host 192.0.2.10 s3cr3tComm", f"snmp-server host 192.0.2.10 {R}"),
    ("snmp-server host 192.0.2.10 version 2c s3cr3tComm",
     f"snmp-server host 192.0.2.10 version 2c {R}"),
    ("snmp-server host 192.0.2.10 informs version 2c s3cr3tComm udp-port 162",
     f"snmp-server host 192.0.2.10 informs version 2c {R} udp-port 162"),
    ("snmp-server host 192.0.2.10 vrf MGMT traps version 1 s3cr3tComm",
     f"snmp-server host 192.0.2.10 vrf MGMT traps version 1 {R}"),
    ("snmp-server host 192.0.2.10 traps version 2c s3cr3tComm",
     f"snmp-server host 192.0.2.10 traps version 2c {R}"),
    ("snmp-server host inside 192.0.2.10 community s3cr3tComm version 2c",
     f"snmp-server host inside 192.0.2.10 community {R} version 2c"),
    # snmp-server user auth/priv keys
    ("snmp-server user u1 G1 v3 auth sha AuthKey123 priv aes 128 PrivKey456",
     f"snmp-server user u1 G1 v3 auth sha {R} priv aes 128 {R}"),
    ("snmp-server user u1 G1 v3 auth md5 AuthKey123 priv des PrivKey456 access 99",
     f"snmp-server user u1 G1 v3 auth md5 {R} priv des {R} access 99"),
    ("snmp-server user admin network-admin auth md5 0xabc123 priv 0xdef456 localizedkey",
     f"snmp-server user admin network-admin auth md5 {R} priv {R} localizedkey"),
    ("snmp-server user admin network-admin auth sha AuthKey123 priv aes-128 PrivKey456",
     f"snmp-server user admin network-admin auth sha {R} priv aes-128 {R}"),
    ("snmp-server user u1 G1 v3 auth sha encrypted 0A1B priv aes 128 encrypted 0C2D",
     f"snmp-server user u1 G1 v3 auth sha encrypted {R} priv aes 128 encrypted {R}"),
    # enable / username
    ("enable secret 5 $1$abcd$efghijklmn", f"enable secret 5 {R}"),
    ("enable secret 9 $9$abcdefgh", f"enable secret 9 {R}"),
    ("enable password Plain123", f"enable password {R}"),
    ("enable secret level 15 5 $1$abcd", f"enable secret level 15 5 {R}"),
    ("enable algorithm-type scrypt secret Plain123",
     f"enable algorithm-type scrypt secret {R}"),
    ("username admin privilege 15 secret 9 $9$abcdefgh",
     f"username admin privilege 15 secret 9 {R}"),
    ("username admin password 7 0822455D0A16", f"username admin password 7 {R}"),
    ("username bob privilege 15 password 0 Plain123",
     f"username bob privilege 15 password 0 {R}"),
    ("username admin password 5 $5$abcdef role network-admin",
     f"username admin password 5 {R} role network-admin"),
    ("username admin secret sha512 $6$abcdef", f"username admin secret sha512 {R}"),
    (" secret 10 $6$abcdef", f" secret 10 {R}"),
    # line vty/con
    (" password 7 0822455D0A16", f" password 7 {R}"),
    (" password Plain123", f" password {R}"),
    ("passwd 2KFQnbNIdI.2KYOU encrypted", f"passwd {R} encrypted"),
    ("key config-key password-encrypt MasterKey1",
     f"key config-key password-encrypt {R}"),
    # AAA
    ("tacacs-server key 7 0822455D0A16", f"tacacs-server key 7 {R}"),
    ("tacacs-server host 192.0.2.5 key Plain123", f"tacacs-server host 192.0.2.5 key {R}"),
    ('tacacs-server host 192.0.2.5 key 7 "0822455D0A16"',
     f"tacacs-server host 192.0.2.5 key 7 {R}"),
    ("radius-server key Plain123", f"radius-server key {R}"),
    ("radius-server host 192.0.2.6 auth-port 1812 acct-port 1813 key 7 0822455D",
     f"radius-server host 192.0.2.6 auth-port 1812 acct-port 1813 key 7 {R}"),
    (" key 7 0822455D0A16", f" key 7 {R}"),
    (" key 0 Plain123", f" key 0 {R}"),
    (" key 6 ABCdef123", f" key 6 {R}"),
    (" key Plain123", f" key {R}"),
    (" server-private 192.0.2.5 key 7 0822455D0A16",
     f" server-private 192.0.2.5 key 7 {R}"),
    (" server-private 192.0.2.5 timeout 5 key Plain123",
     f" server-private 192.0.2.5 timeout 5 key {R}"),
    # key chains / routing protocols
    ("  key-string 7 0822455D0A16", f"  key-string 7 {R}"),
    ("  key-string Plain123", f"  key-string {R}"),
    ("  key-string password 0822455D0A16", f"  key-string password {R}"),
    (" neighbor 192.0.2.1 password 7 0822455D0A16",
     f" neighbor 192.0.2.1 password 7 {R}"),
    (" neighbor 192.0.2.1 password Plain123", f" neighbor 192.0.2.1 password {R}"),
    (" ip ospf message-digest-key 1 md5 7 0822455D0A16",
     f" ip ospf message-digest-key 1 md5 7 {R}"),
    (" ip ospf message-digest-key 1 md5 Plain123",
     f" ip ospf message-digest-key 1 md5 {R}"),
    (" ip ospf authentication-key 7 0822455D0A16",
     f" ip ospf authentication-key 7 {R}"),
    (" ip ospf authentication-key Plain123", f" ip ospf authentication-key {R}"),
    ("  authentication-key encrypted 0822455D", f"  authentication-key encrypted {R}"),
    (" area-password Plain123", f" area-password {R}"),
    (" isis password Plain123", f" isis password {R}"),
    ("ntp authentication-key 1 md5 104D000A0618 7",
     f"ntp authentication-key 1 md5 {R} 7"),
    ("ntp authentication-key 2 md5 Plain123", f"ntp authentication-key 2 md5 {R}"),
    # FHRP
    (" standby 1 authentication Plain123", f" standby 1 authentication {R}"),
    (" standby 1 authentication text Plain123", f" standby 1 authentication text {R}"),
    (" standby 1 authentication md5 key-string 7 0822455D",
     f" standby 1 authentication md5 key-string 7 {R}"),
    (" vrrp 1 authentication text Plain123", f" vrrp 1 authentication text {R}"),
    ("    authentication text Plain123", f"    authentication text {R}"),
    # VPN
    ("crypto isakmp key Plain123 address 192.0.2.1",
     f"crypto isakmp key {R} address 192.0.2.1"),
    ("crypto isakmp key 6 ABCdef address 192.0.2.1",
     f"crypto isakmp key 6 {R} address 192.0.2.1"),
    (" pre-shared-key address 192.0.2.1 key Plain123",
     f" pre-shared-key address 192.0.2.1 key {R}"),
    (" pre-shared-key address 192.0.2.0 255.255.255.0 key Plain123",
     f" pre-shared-key address 192.0.2.0 255.255.255.0 key {R}"),
    ("  pre-shared-key local Plain123", f"  pre-shared-key local {R}"),
    ("  pre-shared-key remote 6 ABCdef", f"  pre-shared-key remote 6 {R}"),
    ("  pre-shared-key Plain123", f"  pre-shared-key {R}"),
    (" ikev1 pre-shared-key Plain123", f" ikev1 pre-shared-key {R}"),
    (" ikev2 remote-authentication pre-shared-key Plain123",
     f" ikev2 remote-authentication pre-shared-key {R}"),
    (" authentication local pre-share key Plain123",
     f" authentication local pre-share key {R}"),
    (" tunnel key 12345", f" tunnel key {R}"),
    # Wireless
    (" wpa-psk ascii 0 Plain123", f" wpa-psk ascii 0 {R}"),
    ("config wlan security wpa akm psk set-key ascii Plain123 1",
     f"config wlan security wpa akm psk set-key ascii {R} 1"),
    ("config snmp community create s3cr3tComm",
     f"config snmp community create {R}"),
    ("config radius auth add 1 192.0.2.5 1812 ascii Plain123",
     f"config radius auth add 1 192.0.2.5 1812 ascii {R}"),
    # PAN-OS / VyOS set format, brace format, Junos
    ("set mgt-config users admin phash $1$abcdefgh",
     f"set mgt-config users admin phash {R}"),
    ("set deviceconfig system snmp-setting access-setting version v2c "
     "snmp-community-string s3cr3tComm",
     "set deviceconfig system snmp-setting access-setting version v2c "
     f"snmp-community-string {R}"),
    ("set network ike gateway GW1 authentication pre-shared-key key Plain123",
     f"set network ike gateway GW1 authentication pre-shared-key key {R}"),
    ("set service snmp community s3cr3tComm authorization ro",
     f"set service snmp community {R} authorization ro"),
    ("set system login user ops authentication encrypted-password '$6$abcdef'",
     f"set system login user ops authentication encrypted-password {R}"),
    ("        phash $1$abcdefgh;", f"        phash {R};"),
    ("    key Plain123;", f"    key {R};"),
    ('    encrypted-password "$6$abcdef"; ## SECRET-DATA',
     f"    encrypted-password {R}; ## SECRET-DATA"),
    ('    secret "$9$abcdef"; ## SECRET-DATA', f"    secret {R}; ## SECRET-DATA"),
])
def test_redacts_secret(line, expected):
    assert redact_line(line) == expected


@pytest.mark.parametrize("line", [
    "service password-encryption",
    "password encryption aes",
    "password strength-check",
    "no password strength-check",
    "key chain OSPF-KEYS",
    " key 1",
    " key 10",
    "ip authentication key-chain eigrp 100 EIGRP-KEYS",
    " ip authentication key-chain eigrp 100 EIGRP-KEYS",
    " ip authentication mode eigrp 100 md5",
    " standby 1 authentication md5 key-chain HSRP-KEYS",
    "snmp-server host 192.0.2.10 use-vrf management",
    "snmp-server host 192.0.2.10 source-interface mgmt0",
    "snmp-server host 192.0.2.10 informs version 3 priv v3user",
    "snmp-server host inside 192.0.2.10 poll",
    "snmp-server group G1 v3 priv",
    "snmp-server enable traps",
    "snmp-server location Lab Rack 4",
    "hostname SW1",
    "interface GigabitEthernet0/1",
    " ip address 192.0.2.1 255.255.255.0",
    "aaa authentication login default group tacacs+ local",
    "aaa group server tacacs+ TACS",
    "tacacs server TAC1",
    " address ipv4 192.0.2.5",
    "crypto key generate rsa modulus 2048",
    "security passwords min-length 8",
    "ip ssh version 2",
    " login local",
    "ntp server 192.0.2.123 key 1",
    "ntp authenticate",
    "ntp trusted-key 1",
    " route-map RM permit 10",
    " set community 65000:100",
    "set protocols bgp 65000 neighbor 192.0.2.1 remote-as 65001",
    "    members 65000:100;",
    "!",
    "",
])
def test_leaves_non_secret_lines(line):
    assert redact_line(line) == line


def test_redact_config_keeps_every_line():
    config = (
        "!\n"
        "hostname SW1\n"
        "enable secret 9 $9$abcdefgh\n"
        "username admin privilege 15 secret 9 $9$ijklmnop\n"
        "snmp-server community s3cr3tComm RO 10\n"
        "key chain OSPF-KEYS\n"
        " key 1\n"
        "  key-string 7 0822455D0A16\n"
        "line vty 0 4\n"
        " password 7 0822455D0A16\n"
        " login\n"
        "end\n"
    )
    out = redact_config(config)
    assert out.count("\n") == config.count("\n")
    assert "$9$" not in out
    assert "s3cr3tComm" not in out
    assert "0822455D0A16" not in out
    assert "key chain OSPF-KEYS\n key 1\n" in out
    assert "snmp-server community <REDACTED> RO 10\n" in out


def test_redact_config_crlf_and_idempotent():
    config = "enable secret 5 $1$abc\r\nhostname R1\r\n"
    once = redact_config(config)
    assert once == "enable secret 5 <REDACTED>\r\nhostname R1\r\n"
    assert redact_config(once) == once


def test_redact_config_empty():
    assert redact_config("") == ""
    assert redact_config(None) is None
