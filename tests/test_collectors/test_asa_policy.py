"""ASA objects, ACLs and NAT."""
import ipaddress

from app.collectors import asa_policy as pol
from tests.test_collectors.asa_policy_fixtures import (
    NAT_DETAIL, POLICY_CONFIG, SHOW_ACCESS_LIST)


def _setup():
    objects = pol.parse_objects(POLICY_CONFIG)
    return objects, pol.Expander(objects), pol.parse_acl_config(POLICY_CONFIG, objects)


def test_objects_and_expansion():
    objects, exp, _ = _setup()
    assert objects["LAB-WEB"]["description"] == "lab web server"
    assert objects["LAB-WEB-PORTS"]["protocol"] == "tcp"
    assert [str(n) for n in exp.nets("LAB-SERVERS")] == [
        "10.1.0.10/32", "10.1.0.11/32", "10.3.0.0/16"]
    assert [str(n) for n in exp.nets("LAB-RANGE")] == ["10.2.0.1/32", "10.2.0.2/31",
                                                      "10.2.0.4/31", "10.2.0.6/32"]
    assert exp.services("LAB-WEB-PORTS") == [("tcp", (0, 65535), (80, 80)),
                                             ("tcp", (0, 65535), (443, 443))]
    assert exp.services("LAB-MIXED") == [("tcp", (0, 65535), (22, 22)),
                                         ("udp", (0, 65535), (5060, 5061)),
                                         ("tcp", (0, 65535), (443, 443))]
    assert exp.services("LAB-PROTOS") == [("tcp", (0, 65535), (0, 65535)),
                                          ("udp", (0, 65535), (0, 65535))]


def test_expansion_survives_a_loop():
    objects = pol.parse_objects("object-group network A\n group-object B\n"
                                "object-group network B\n group-object A\n"
                                " network-object host 192.0.2.1\n")
    assert [str(n) for n in pol.Expander(objects).nets("A")] == ["192.0.2.1/32"]


def test_acl_lines_number_remarks_like_the_device():
    _, _, acls = _setup()
    out = acls["LAB-OUTSIDE-IN"]
    assert out[0]["remark"] == "allow the web servers" and out[0]["line"] == 1
    first = out[1]
    assert (first["line"], first["action"], first["protocol"]) == (2, "permit", "tcp")
    assert first["src"] == "any" and first["dst"] == "object-group LAB-SERVERS"
    assert first["dst_port"] == "object-group LAB-WEB-PORTS"
    assert out[3]["log"] is True
    last = out[6]
    assert last["time_range"] == "LAB-HOURS" and last["inactive"] is True
    mixed = acls["LAB-INSIDE-IN"][1]
    assert mixed["service_ref"] == "LAB-MIXED" and mixed["dst"] == "any"
    std = acls["LAB-SPLIT"][0]
    assert std["action"] == "permit" and std["dst"] == "10.0.0.0 255.0.0.0"
    icmp = acls["LAB-ORPHAN"][0]
    assert icmp["protocol"] == "icmp" and icmp["dst_port"] == "echo-reply"


def test_hits_sum_children_and_keep_the_hash():
    lines, elements = pol.parse_acl_hits(SHOW_ACCESS_LIST)
    assert elements == {"LAB-OUTSIDE-IN": 9, "LAB-INSIDE-IN": 4}
    assert lines[("LAB-OUTSIDE-IN", 2)] == {"hits": 12, "hash": "0x11111111",
                                            "elements": 2, "child_hits": 12}
    assert lines[("LAB-OUTSIDE-IN", 3)]["hits"] == 0
    assert lines[("LAB-OUTSIDE-IN", 7)]["hash"] == "0x66666666"
    assert ("LAB-OUTSIDE-IN", 1) not in lines


def test_bindings():
    bound = pol.acl_bindings(POLICY_CONFIG)
    assert bound["LAB-OUTSIDE-IN"] == ["outside in"]
    assert bound["LAB-VPN"] == ["crypto map LAB-MAP"]
    assert bound["LAB-SPLIT"] == ["group-policy LAB-GP"]
    assert "LAB-ORPHAN" not in bound
    assert pol.interface_directions(POLICY_CONFIG)["LAB-INSIDE-IN"] == [("inside", "in")]


def test_shadowed_and_redundant_lines():
    _, exp, acls = _setup()
    flags = pol.shadow_flags(acls["LAB-OUTSIDE-IN"], exp)
    # https to 10.1.0.10 is already permitted by line 2.
    assert flags[3] == ("redundant", 2)
    # www to 10.1.0.11 is permitted by line 2 before the deny is reached.
    assert flags[4] == ("shadowed", 2)
    assert 5 not in flags and 6 not in flags
    # Inactive lines are never judged.
    assert 7 not in flags
    assert pol.shadow_flags(acls["LAB-INSIDE-IN"], exp) == {}


def test_shadow_check_skips_huge_acls(monkeypatch):
    _, exp, acls = _setup()
    monkeypatch.setattr(pol, "SHADOW_CHECK_LIMIT", 2)
    assert pol.shadow_flags(acls["LAB-OUTSIDE-IN"], exp) is None


def test_unknown_port_name_is_never_covered():
    a = pol.parse_acl_config(
        "access-list A extended permit tcp any any eq lab-odd-port\n"
        "access-list A extended permit tcp any any eq lab-odd-port\n")["A"]
    assert pol.shadow_flags(a, pol.Expander({})) == {}


def test_object_references_unused_and_duplicates():
    objects, exp, _ = _setup()
    refs = pol.object_references(POLICY_CONFIG, objects)
    assert refs["LAB-SERVERS"] == ["ACL LAB-OUTSIDE-IN"]
    assert refs["LAB-INNER"] == ["object-group LAB-SERVERS"]
    assert sorted(refs["LAB-NET"]) == ["ACL LAB-INSIDE-IN", "ACL LAB-VPN", "NAT"]
    assert refs["LAB-DMZ-WEB"] == ["NAT (object)"]
    assert refs["LAB-UNUSED"] == [] and refs["LAB-WEB-COPY"] == []
    assert refs["LAB-HTTPS"] == ["object-group LAB-MIXED"]
    sig = {n: pol.object_signature(o, exp) for n, o in objects.items()}
    assert sig["LAB-WEB"] == sig["LAB-WEB-COPY"] != sig["LAB-UNUSED"]


def test_nat_detail():
    rules = pol.parse_nat_detail(NAT_DETAIL)
    assert [(r["section"], r["rule"], r["type"]) for r in rules] == [
        (1, 1, "twice NAT"), (2, 1, "static"), (2, 2, "PAT"), (3, 1, "PAT")]
    twice, static, pat, pool = rules
    assert twice["flags"] == ["no-proxy-arp", "route-lookup"]
    assert twice["translate_hits"] == 10 and twice["public"] is False
    assert static["public"] is True and static["untranslate_hits"] == 0
    assert static["src_translated"] == "203.0.113.20/32"
    assert pool["flags"] == ["inactive"] and pool["public"] is None
    assert pol.rule_names(twice) == {"LAB-NET", "LAB-RANGE"}


def test_formatting_and_privacy():
    assert pol.format_nets(pol.ANY_NETS) == "any"
    nets = [ipaddress.ip_network(f"10.0.{i}.0/24") for i in range(25)]
    assert pol.format_nets(nets).endswith("; +5 more")
    assert pol.format_services([("tcp", (0, 65535), (443, 443)), ("ip", (0, 65535),
                                                                  (0, 65535))]) == "tcp 443; ip"
    assert pol.is_private("10.1.0.0/16") and not pol.is_private("203.0.113.0/24")


def test_nat_from_config_when_detail_is_missing():
    rules = pol.parse_nat_config(
        POLICY_CONFIG + "nat (any,outside) after-auto source dynamic any interface\n")
    assert [(r["section"], r["rule"], r["type"]) for r in rules] == [
        (1, 1, "twice NAT"), (3, 1, "PAT")]
    assert rules[0]["real_dst"] == "LAB-RANGE" and rules[0]["translate_hits"] is None
