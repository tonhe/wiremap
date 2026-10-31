from app.collectors.l3_routing import L3RoutingCollector, parse_ip_protocols

# IOS-XE 17.x shape: OSPF redistributing EIGRP and static, EIGRP
# redistributing OSPF, BGP redistributing connected/static.
IOS_XE_IP_PROTOCOLS = """\
*** IP Routing is NSF aware ***

Routing Protocol is "application"
  Sending updates every 0 seconds
  Invalid after 0 seconds, hold down 0, flushed after 0
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Maximum path: 32
  Routing for Networks:
  Routing Information Sources:
    Gateway         Distance      Last Update
  Distance: (default is 4)

Routing Protocol is "ospf 1"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Router ID 192.0.2.1
  It is an autonomous system boundary router
 Redistributing External Routes from,
    eigrp 100 with metric mapped to 20, includes subnets in redistribution
    static, includes subnets in redistribution, route-map STATIC-TO-OSPF
  Number of areas in this router is 1. 1 normal 0 stub 0 nssa
  Maximum path: 4
  Routing for Networks:
    192.0.2.0 0.0.0.255 area 0
    198.51.100.0 0.0.0.255 area 0
  Passive Interface(s):
    Loopback0
    GigabitEthernet0/0/3
  Routing Information Sources:
    Gateway         Distance      Last Update
    192.0.2.2            110      00:10:21
  Distance: (default is 110)

Routing Protocol is "eigrp 100"
  Outgoing update filter list for all interfaces is 10
  Incoming update filter list for all interfaces is not set
  Default networks flagged in outgoing updates
  Default networks accepted from incoming updates
  Redistributing: ospf 1 (internal, external 1 & 2, nssa-external 1 & 2), static
  EIGRP-IPv4 Protocol for AS(100)
    Metric weight K1=1, K2=0, K3=1, K4=0, K5=0
    Soft SIA disabled
    NSF-aware route hold timer is 240
    Router-ID: 192.0.2.1
    Topology : 0 (base)
      Active Timer: 3 min
      Distance: internal 90 external 170
      Maximum path: 4
      Maximum hopcount 100
      Maximum metric variance 1
      Total Prefix Count: 12
      Total Redist Count: 5

  Automatic Summarization: disabled
  Maximum path: 4
  Routing for Networks:
    203.0.113.0/24
  Routing Information Sources:
    Gateway         Distance      Last Update
    203.0.113.2           90      00:12:01
  Distance: internal 90 external 170

Routing Protocol is "bgp 65001"
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  IGP synchronization is disabled
  Automatic route summarization is disabled
  Redistributing: connected, static
  Neighbor(s):
    Address          FiltIn FiltOut DistIn DistOut Weight RouteMap
    203.0.113.9
  Maximum path: 1
  Routing Information Sources:
    Gateway         Distance      Last Update
  Distance: external 20 internal 200 local 200

"""


def _by_name(processes):
    return {p["name"]: p for p in processes}


def test_application_process_skipped():
    names = [p["name"] for p in parse_ip_protocols(IOS_XE_IP_PROTOCOLS)]
    assert names == ["ospf 1", "eigrp 100", "bgp 65001"]


def test_ospf_process_fields():
    ospf = _by_name(parse_ip_protocols(IOS_XE_IP_PROTOCOLS))["ospf 1"]
    assert ospf["protocol"] == "ospf"
    assert ospf["process"] == "1"
    assert ospf["router_id"] == "192.0.2.1"
    assert ospf["maximum_paths"] == "4"
    assert ospf["distance"] == "110"
    assert ospf["networks"] == ["192.0.2.0 0.0.0.255 area 0",
                                "198.51.100.0 0.0.0.255 area 0"]
    assert ospf["passive_interfaces"] == ["Loopback0", "GigabitEthernet0/0/3"]


def test_ospf_redistribution_lines():
    ospf = _by_name(parse_ip_protocols(IOS_XE_IP_PROTOCOLS))["ospf 1"]
    red = {r["from"]: r for r in ospf["redistribute"]}
    assert set(red) == {"eigrp 100", "static"}
    assert red["eigrp 100"]["metric"] == "20"
    assert red["eigrp 100"]["route_map"] == ""
    assert red["static"]["route_map"] == "STATIC-TO-OSPF"


def test_eigrp_redistributing_line_keeps_parenthesised_detail_together():
    eigrp = _by_name(parse_ip_protocols(IOS_XE_IP_PROTOCOLS))["eigrp 100"]
    assert [r["from"] for r in eigrp["redistribute"]] == ["ospf 1", "static"]
    assert eigrp["router_id"] == "192.0.2.1"
    assert eigrp["distance"] == "internal 90 external 170"
    assert eigrp["outgoing_filter"] == "10"
    assert eigrp["incoming_filter"] == ""
    assert eigrp["networks"] == ["203.0.113.0/24"]


def test_bgp_redistribution_and_distance():
    bgp = _by_name(parse_ip_protocols(IOS_XE_IP_PROTOCOLS))["bgp 65001"]
    assert [r["from"] for r in bgp["redistribute"]] == ["connected", "static"]
    assert bgp["distance"] == "external 20 internal 200 local 200"
    assert bgp["maximum_paths"] == "1"
    assert bgp["networks"] == []


def test_parse_empty_and_garbage():
    assert parse_ip_protocols("") == []
    assert parse_ip_protocols("nothing useful here") == []


def test_collector_stores_parsed_and_raw():
    c = L3RoutingCollector()
    cmds = c.get_commands("cisco_xe")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip protocols"] = IOS_XE_IP_PROTOCOLS
    result = c.parse(raw, "cisco_xe")
    assert result["ip_protocols_raw"] == IOS_XE_IP_PROTOCOLS
    assert len(result["ip_protocols"]) == 3


def test_collector_rejected_protocols_command_parses_nothing():
    c = L3RoutingCollector()
    cmds = c.get_commands("cisco_xe")
    raw = {cmd: "" for cmd in cmds}
    raw["show ip protocols"] = "% Invalid input detected at '^' marker."
    raw["show ip route"] = "Gateway of last resort is not set"
    result = c.parse_collected(raw, "cisco_xe")
    assert result["ip_protocols"] == []


def test_non_cisco_protocols_output_not_parsed():
    c = L3RoutingCollector()
    cmds = c.get_commands("juniper_junos")
    raw = {cmd: "" for cmd in cmds}
    raw["show protocols"] = 'Routing Protocol is "ospf 1"'
    assert c.parse(raw, "juniper_junos")["ip_protocols"] == []
