import pytest
from app.collectors.edge_services import EdgeServicesCollector


@pytest.fixture
def collector():
    return EdgeServicesCollector()


def test_attrs(collector):
    assert collector.name == "edge_services"
    assert collector.label == "Edge Services"
    assert collector.enabled_by_default is True


def test_get_commands(collector):
    expected = [
        "show access-lists",
        "show ip interface",
        "show ip nat translations",
        "show ip nat statistics",
    ]

    cmds = collector.get_commands("cisco_ios")
    assert cmds == expected

    cmds_xe = collector.get_commands("cisco_xe")
    assert cmds_xe == expected

    cmds_nxos = collector.get_commands("cisco_nxos")
    assert cmds_nxos == expected

    cmds_unknown = collector.get_commands("some_unknown")
    assert cmds_unknown == expected


def test_parse_empty(collector):
    empty_expected = {
        "access_lists": [],
        "ip_interfaces": [],
        "nat_translations": [],
        "nat_statistics": {},
    }

    result = collector.parse({}, "cisco_ios")
    assert result == empty_expected

    result2 = collector.parse(
        {"show access-lists": "", "show ip interface": ""}, "cisco_ios"
    )
    assert result2 == empty_expected


def test_parse_acl_extended(collector):
    acl_output = """\
Extended IP access list OUTSIDE-IN
    10 permit tcp any host 10.0.0.1 eq 443 (1234 matches)
    20 deny ip any any (5678 matches)
    30 permit udp host 192.168.1.1 10.0.0.0 0.0.0.255 eq 53 (42 matches)"""

    result = collector.parse(
        {"show access-lists": acl_output, "show ip interface": ""},
        "cisco_ios",
    )
    acls = result["access_lists"]
    assert len(acls) == 1
    acl = acls[0]
    assert acl["name"] == "OUTSIDE-IN"
    assert acl["type"] == "Extended"
    assert len(acl["entries"]) == 3

    e0 = acl["entries"][0]
    assert e0["action"] == "permit"
    assert e0["protocol"] == "tcp"
    assert e0["source"] == "any"
    assert e0["destination"] == "host 10.0.0.1 eq 443"
    assert e0["hit_count"] == 1234

    e1 = acl["entries"][1]
    assert e1["action"] == "deny"
    assert e1["protocol"] == "ip"
    assert e1["source"] == "any"
    assert e1["destination"] == "any"
    assert e1["hit_count"] == 5678

    e2 = acl["entries"][2]
    assert e2["action"] == "permit"
    assert e2["protocol"] == "udp"
    assert e2["source"] == "host 192.168.1.1"
    assert e2["hit_count"] == 42


def test_parse_acl_standard(collector):
    acl_output = """\
Standard IP access list 10
    10 permit 10.0.0.0, wildcard bits 0.0.0.255 (100 matches)
    20 deny 192.168.1.0, wildcard bits 0.0.0.255
    30 permit any"""

    result = collector.parse(
        {"show access-lists": acl_output, "show ip interface": ""},
        "cisco_ios",
    )
    acls = result["access_lists"]
    assert len(acls) == 1
    acl = acls[0]
    assert acl["name"] == "10"
    assert acl["type"] == "Standard"
    assert len(acl["entries"]) == 3

    e0 = acl["entries"][0]
    assert e0["action"] == "permit"
    assert e0["protocol"] == "ip"
    assert e0["source"] == "10.0.0.0, wildcard bits 0.0.0.255"
    assert e0["destination"] == ""
    assert e0["hit_count"] == 100

    e1 = acl["entries"][1]
    assert e1["action"] == "deny"
    assert e1["source"] == "192.168.1.0, wildcard bits 0.0.0.255"
    assert e1["hit_count"] == 0

    e2 = acl["entries"][2]
    assert e2["action"] == "permit"
    assert e2["source"] == "any"


def test_parse_ip_interfaces(collector):
    iface_output = """\
GigabitEthernet0/0 is up, line protocol is up
  Internet address is 10.1.1.1/24
  Inbound  access list is OUTSIDE-IN
  Outgoing access list is not set
  Proxy ARP is disabled
  IP directed-broadcast forwarding is disabled
  IP verify source reachable-via rx
GigabitEthernet0/1 is up, line protocol is up
  Internet address is 192.168.1.1/24
  Inbound  access list is not set
  Outgoing access list is EGRESS-FILTER
  Proxy ARP is enabled
  IP directed-broadcast forwarding is enabled"""

    result = collector.parse(
        {"show access-lists": "", "show ip interface": iface_output},
        "cisco_ios",
    )
    ifaces = result["ip_interfaces"]
    assert len(ifaces) == 2

    g0 = ifaces[0]
    assert g0["interface"] == "GigabitEthernet0/0"
    assert g0["ip_address"] == "10.1.1.1/24"
    assert g0["acl_in"] == "OUTSIDE-IN"
    assert g0["acl_out"] == ""
    assert g0["proxy_arp"] is False
    assert g0["urpf"] is True
    assert g0["directed_broadcast"] is False

    g1 = ifaces[1]
    assert g1["interface"] == "GigabitEthernet0/1"
    assert g1["ip_address"] == "192.168.1.1/24"
    assert g1["acl_in"] == ""
    assert g1["acl_out"] == "EGRESS-FILTER"
    assert g1["proxy_arp"] is True
    assert g1["urpf"] is False
    assert g1["directed_broadcast"] is True
