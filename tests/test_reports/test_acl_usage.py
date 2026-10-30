from app.reports.acl_usage import (
    parse_acl_references, classify_acls,
    INTERFACE, MANAGEMENT, QOS, ROUTING, NAT, CRYPTO, OTHER,
    UNREFERENCED, UNKNOWN,
)

CONFIG = """hostname RTR-A
!
class-map match-any CM-VOICE
 match access-group name ACL-QOS-VOICE
class-map match-all CM-BULK
 match access-group 120
!
crypto map VPN-MAP 10 ipsec-isakmp
 set peer 203.0.113.2
 match address ACL-VPN-TRAFFIC
!
interface GigabitEthernet0/0
 description WAN
 ip address 198.51.100.2 255.255.255.252
 ip access-group OUTSIDE-IN in
 ip access-group 110 out
 ip nat outside
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 ip nat inside
 ip multicast boundary ACL-MCAST
!
router bgp 64500
 address-family ipv4 vrf INET
  neighbor 192.0.2.1 distribute-list ACL-BGP-IN in
  neighbor 192.0.2.1 prefix-list PL-IN in
!
ip nat inside source list ACL-NAT interface GigabitEthernet0/0 overload
!
ip access-list extended OUTSIDE-IN
 permit tcp any any established
 remark match access-group name NOT-A-REF
ip access-list extended UNUSED-ACL
 permit ip any any
access-list 110 permit ip any any
access-list 99 permit 10.0.0.0 0.0.0.255
!
route-map RM-EXPORT permit 10
 match ip address ACL-RM-1 ACL-RM-2
route-map RM-PL permit 10
 match ip address prefix-list PL-OUT
!
ip http access-class ipv4 ACL-HTTP
ntp access-group peer ACL-NTP
snmp-server community REDACTED RO MGMT-ONLY
snmp-server community REDACTED2 view V1 RO
!
line vty 0 4
 access-class 99 in
 transport input ssh
!
end
"""


def _cats(refs, name):
    return [c for c, _ in refs.get(name, [])]


def test_reference_categories():
    refs = parse_acl_references(CONFIG)
    assert _cats(refs, "OUTSIDE-IN") == [INTERFACE]
    assert refs["OUTSIDE-IN"][0][1] == "GigabitEthernet0/0 in"
    assert _cats(refs, "110") == [INTERFACE]
    assert _cats(refs, "ACL-QOS-VOICE") == [QOS]
    assert _cats(refs, "120") == [QOS]
    assert _cats(refs, "ACL-VPN-TRAFFIC") == [CRYPTO]
    assert _cats(refs, "ACL-NAT") == [NAT]
    assert _cats(refs, "ACL-BGP-IN") == [ROUTING]
    assert _cats(refs, "ACL-RM-1") == [ROUTING]
    assert _cats(refs, "ACL-RM-2") == [ROUTING]
    assert _cats(refs, "99") == [MANAGEMENT]
    assert _cats(refs, "MGMT-ONLY") == [MANAGEMENT]
    assert _cats(refs, "ACL-HTTP") == [MANAGEMENT]
    assert _cats(refs, "ACL-NTP") == [MANAGEMENT]
    assert _cats(refs, "ACL-MCAST") == [OTHER]


def test_prefix_lists_and_acl_bodies_are_not_references():
    refs = parse_acl_references(CONFIG)
    assert "PL-OUT" not in refs
    assert "PL-IN" not in refs
    assert "prefix-list" not in refs
    assert "NOT-A-REF" not in refs
    assert "UNUSED-ACL" not in refs
    # snmp community without an ACL does not pick up the RO keyword
    assert "RO" not in refs


def test_classify_with_config():
    result = classify_acls(["OUTSIDE-IN", "UNUSED-ACL", "ACL-QOS-VOICE"], CONFIG)
    assert result["OUTSIDE-IN"] == [INTERFACE]
    assert result["UNUSED-ACL"] == [UNREFERENCED]
    assert result["ACL-QOS-VOICE"] == [QOS]


def test_classify_without_config_uses_show_ip_interface():
    ifaces = [{"interface": "Gi0/0", "acl_in": "OUTSIDE-IN", "acl_out": ""}]
    result = classify_acls(["OUTSIDE-IN", "ACL-QOS-VOICE"], None, ifaces)
    assert result["OUTSIDE-IN"] == [INTERFACE]
    assert result["ACL-QOS-VOICE"] == [UNKNOWN]


def test_classify_multiple_uses():
    cfg = ("interface Gi0/0\n ip access-group ACL-X in\n!\n"
           "class-map CM\n match access-group name ACL-X\n")
    assert classify_acls(["ACL-X"], cfg)["ACL-X"] == [INTERFACE, QOS]


def test_nxos_snmp_use_acl():
    cfg = ("snmp-server community REDACTED group network-operator\n"
           "snmp-server community REDACTED use-acl MGMT-ONLY\n")
    refs = parse_acl_references(cfg)
    assert _cats(refs, "MGMT-ONLY") == [MANAGEMENT]
    assert "network-operator" not in refs
