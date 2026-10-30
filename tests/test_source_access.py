"""Source-host access check against the seed's vty and SNMP ACLs."""
from app import source_access as sa

IOS_CONFIG = """\
hostname lab-core1
!
ip access-list standard MGMT-VTY
 10 permit 192.0.2.0 0.0.0.255
 20 permit host 198.51.100.7
 30 deny   any log
ip access-list extended VTY-EXT
 10 remark management stations
 20 permit tcp 203.0.113.0 0.0.0.15 any eq 22
 30 permit tcp host 198.51.100.9 any eq www
 40 deny   ip any any log
!
access-list 15 permit 192.0.2.64 0.0.0.63
access-list 15 deny   any
access-list 120 permit tcp host 198.51.100.20 any eq 22
!
snmp-server community <REDACTED> RO 15
snmp-server community <REDACTED> view LIMITED RW SNMP-RW
!
line con 0
 access-class 15 in
line vty 0 4
 access-class MGMT-VTY in vrf-also
 transport input ssh
line vty 5 15
 access-class MGMT-VTY in
 ipv6 access-class V6-MGMT in
!
end
"""

NXOS_CONFIG = """\
hostname lab-nx1
ip access-list VTY-NX
  10 permit ip 192.0.2.0/25 any
  20 deny ip any any
snmp-server community <REDACTED> group network-operator
snmp-server community <REDACTED> use-acl SNMP-NX
line vty
  access-class VTY-NX in
"""


def test_parse_named_and_numbered_acls():
    acls = sa.parse_acls(IOS_CONFIG)
    assert acls["MGMT-VTY"]["type"] == "standard"
    assert len(acls["MGMT-VTY"]["entries"]) == 3
    assert acls["VTY-EXT"]["type"] == "extended"
    assert acls["15"]["type"] == "standard"
    assert acls["15"]["entries"] == ["permit 192.0.2.64 0.0.0.63", "deny   any"]
    assert acls["120"]["type"] == "extended"


def test_nxos_untyped_acl_is_extended():
    assert sa.parse_acls(NXOS_CONFIG)["VTY-NX"]["type"] == "extended"


def test_vty_access_classes_only_from_vty_lines():
    assert sa.vty_access_classes(IOS_CONFIG) == ["MGMT-VTY"]
    assert sa.vty_access_classes(NXOS_CONFIG) == ["VTY-NX"]


def test_snmp_community_acls_with_redacted_community():
    assert sa.snmp_community_acls(IOS_CONFIG) == ["15", "SNMP-RW"]
    assert sa.snmp_community_acls(NXOS_CONFIG) == ["SNMP-NX"]


def _eval(name, ip, service=sa.VTY, config=IOS_CONFIG):
    return sa.evaluate(sa.parse_acls(config)[name], ip, service)[0]


def test_standard_wildcard_host_and_implicit_deny():
    assert _eval("MGMT-VTY", "192.0.2.200") == sa.PERMIT
    assert _eval("MGMT-VTY", "198.51.100.7") == sa.PERMIT
    assert _eval("MGMT-VTY", "198.51.100.8") == sa.DENY
    assert _eval("15", "192.0.2.100") == sa.PERMIT
    assert _eval("15", "192.0.2.10") == sa.DENY


def test_standard_acl_without_trailing_deny_denies_implicitly():
    acl = {"type": "standard", "entries": ["permit 192.0.2.1"]}
    assert sa.evaluate(acl, "192.0.2.1")[0] == sa.PERMIT
    assert sa.evaluate(acl, "192.0.2.2") == (sa.DENY, None)


def test_extended_source_and_port():
    assert _eval("VTY-EXT", "203.0.113.5") == sa.PERMIT
    assert _eval("VTY-EXT", "203.0.113.17") == sa.DENY
    # Permitted only to the web server port, so ssh falls to the deny.
    assert _eval("VTY-EXT", "198.51.100.9") == sa.DENY
    assert _eval("120", "198.51.100.20") == sa.PERMIT


def test_cidr_entries():
    assert _eval("VTY-NX", "192.0.2.100", config=NXOS_CONFIG) == sa.PERMIT
    assert _eval("VTY-NX", "192.0.2.130", config=NXOS_CONFIG) == sa.DENY


def test_non_contiguous_wildcard():
    acl = {"type": "standard", "entries": ["permit 192.0.2.1 0.0.255.0"]}
    assert sa.evaluate(acl, "192.0.7.1")[0] == sa.PERMIT
    assert sa.evaluate(acl, "192.0.2.2")[0] == sa.DENY


def test_object_group_is_unknown_not_deny():
    acl = {"type": "extended",
           "entries": ["10 permit tcp object-group MGMT any eq 22"]}
    assert sa.evaluate(acl, "192.0.2.1")[0] == sa.UNKNOWN
    acl = {"type": "extended",
           "entries": ["10 permit object-group SVC any any"]}
    assert sa.evaluate(acl, "192.0.2.1")[0] == sa.UNKNOWN


def test_udp_entries_do_not_apply_to_vty():
    acl = {"type": "extended",
           "entries": ["permit udp host 192.0.2.1 any eq snmp"]}
    assert sa.evaluate(acl, "192.0.2.1", sa.VTY)[0] == sa.DENY
    assert sa.evaluate(acl, "192.0.2.1", sa.SNMP)[0] == sa.PERMIT


def test_check_warns_for_denied_vty_and_snmp():
    warnings = sa.check_source_access(IOS_CONFIG, "198.51.100.50", "lab-core1")
    kinds = {(w["kind"], w["acl"]) for w in warnings}
    # SNMP-RW is named but never defined, so it is not judged.
    assert kinds == {("vty", "MGMT-VTY"), ("snmp", "15")}
    vty = [w for w in warnings if w["kind"] == "vty"][0]
    assert vty["message"] == (
        "This host (198.51.100.50) is not permitted by vty access-class "
        "MGMT-VTY on lab-core1; expect connection refused on devices sharing "
        "that ACL")
    assert vty["matched_entry"] == "30 deny   any log"


def test_check_quiet_when_permitted():
    assert sa.check_source_access(IOS_CONFIG, "192.0.2.100", "lab-core1") == []


def test_undefined_acl_is_not_reported():
    config = "line vty 0 4\n access-class NOT-DEFINED in\n"
    assert sa.check_source_access(config, "192.0.2.1", "lab-core1") == []


def test_acl_body_from_show_access_lists():
    config = "line vty 0 4\n access-class MGMT in\n"
    show = (
        "Standard IP access list MGMT\n"
        "    10 permit 192.0.2.0, wildcard bits 0.0.0.255 (12 matches)\n"
        "    20 deny   any (3 matches)\n"
        "Extended IP access list OTHER\n"
        "    10 permit tcp any any eq 22\n"
    )
    acls = sa.parse_show_access_lists(show)
    assert acls["MGMT"]["entries"] == ["10 permit 192.0.2.0 0.0.0.255",
                                       "20 deny   any"]
    assert sa.check_source_access(config, "192.0.2.9", "r1", acl_output=show) == []
    warnings = sa.check_source_access(config, "198.51.100.9", "r1",
                                      acl_output=show)
    assert [w["acl"] for w in warnings] == ["MGMT"]


def test_ipv6_source_is_not_checked():
    assert sa.check_source_access(IOS_CONFIG, "2001:db8::1", "lab-core1") == []


def test_local_source_ip_needs_no_listener():
    assert sa.local_source_ip("127.0.0.1") == "127.0.0.1"
    assert sa.local_source_ip("") is None
    assert sa.local_source_ip("not a host name.invalid") is None


def test_refused_hint_threshold():
    one = {"reason": "refused"}
    failed = {"192.0.2.1": one, "192.0.2.2": one,
              "192.0.2.3": {"reason": "auth"}}
    assert sa.refused_hint(failed, "198.51.100.5") is None
    failed["192.0.2.4"] = "Connection failed: [Errno 111] Connection refused"
    hint = sa.refused_hint(failed, "198.51.100.5")
    assert "3 devices refused" in hint
    assert "198.51.100.5" in hint
    assert "access-class" in hint
