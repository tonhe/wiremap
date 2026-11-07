"""ASA VPN and routing parsers."""
from app.collectors import asa_routing as rt
from app.collectors import asa_vpn as vpn
from tests.test_collectors import asa_net_fixtures as fx


def test_ike_policies_and_transforms():
    pol = vpn.parse_ike_policies(fx.VPN_CONFIG)
    assert pol["ikev1"] == [{"priority": 10, "auth": "pre-share", "encryption": "3des",
                             "hash": "md5", "integrity": "", "group": "2", "prf": "",
                             "lifetime": "86400"}]
    assert pol["ikev2"][0]["integrity"] == "sha" and pol["ikev2"][0]["group"] == "14"
    ts = vpn.parse_transforms(fx.VPN_CONFIG)
    assert ts["LAB-TS-OLD"] == {"version": "ikev1", "encryption": "esp-3des",
                                "integrity": "esp-md5-hmac"}
    assert ts["LAB-PROP"] == {"version": "ikev2", "encryption": "aes-256",
                              "integrity": "sha-1"}


def test_crypto_maps():
    maps = vpn.parse_crypto_maps(fx.VPN_CONFIG)
    first, second = maps
    assert (first["map"], first["seq"], first["interface"]) == ("LAB-MAP", 10, "outside")
    assert first["peers"] == ["203.0.113.9"] and first["acl"] == "LAB-VPN-1"
    assert first["ikev1"] and not first["ikev2"] and first["pfs"] == "group2"
    assert first["lifetime_s"] == 28800
    assert second["ikev2"] and second["transforms"] == ["LAB-PROP"]


def test_weak_and_marginal_crypto():
    policies = vpn.parse_ike_policies(fx.VPN_CONFIG)
    ts = vpn.parse_transforms(fx.VPN_CONFIG)
    first, second = vpn.parse_crypto_maps(fx.VPN_CONFIG)
    weak = vpn.weak_reasons(policies, ts, first)
    assert "ikev1 policy 10: 3des md5" in weak
    assert "ikev1 policy 10: DH group 2" in weak
    assert "LAB-TS-OLD: esp-3des esp-md5-hmac" in weak and "PFS group2" in weak
    assert vpn.weak_reasons(policies, ts, second) == []
    marginal = vpn.marginal_reasons(policies, ts, second)
    assert marginal == ["ikev2 policy 20: SHA-1 only", "ikev2 policy 20: DH 14 only",
                        "LAB-PROP: SHA-1 only"]
    assert vpn.weak_reasons(policies, ts, dict(second, aggressive=True)) == [
        "IKEv1 aggressive mode"]


def test_tunnel_groups_policies_pools():
    groups = vpn.parse_tunnel_groups(fx.VPN_CONFIG)
    assert groups["203.0.113.9"]["type"] == "ipsec-l2l"
    assert vpn.tunnel_auth(groups["203.0.113.9"]) == "PSK"
    assert vpn.tunnel_auth(groups["203.0.113.10"]) == "certificate"
    assert "authentication-server-group LAB-LDAP" in groups["LAB-RA"]["general"]
    gp = vpn.parse_group_policies(fx.VPN_CONFIG)["LAB-GP"]
    assert gp["split-tunnel-policy"] == "tunnelspecified"
    assert gp["split-tunnel-network-list"] == "LAB-SPLIT" and gp["dns-server"] == "10.0.0.53"
    assert vpn.parse_pools(fx.VPN_CONFIG)["LAB-POOL"]["size"] == 254
    assert vpn.parse_pool_usage(fx.IP_LOCAL_POOL) == {
        "10.10.0.1-10.10.0.254": {"free": 252, "in_use": 2}}
    assert vpn.webvpn_packages(fx.VPN_CONFIG) == ["anyconnect-win-4.10.07073-webdeploy-k9.pkg"]
    assert vpn.webvpn_posture(fx.VPN_CONFIG) == {"hostscan": True, "dap": ["LAB-DAP"]}


def test_sessions_drop_usernames_and_public_ips():
    sessions = vpn.parse_sessions(fx.ANYCONNECT)
    assert len(sessions) == 2
    first = sessions[0]
    assert first["Tunnel Group"] == "LAB-RA" and first["Assigned IP"] == "10.10.0.5"
    assert vpn.session_bytes(first, "Bytes Tx") == 15000
    assert first["Duration"] == "1h:22m:31s"
    text = repr(sessions)
    assert "lab-person" not in text and "198.51.100.50" not in text
    [l2l] = vpn.parse_sessions(fx.L2L_DETAIL)
    assert l2l["Connection"] == "203.0.113.9" and vpn.session_bytes(l2l, "Bytes Rx") == 2000


def test_routes():
    routes = rt.parse_routes(fx.SHOW_ROUTE)
    default = routes[0]
    assert default["code"] == "S" and default["default_candidate"]
    assert str(default["prefix"]) == "0.0.0.0/0" and default["nameif"] == "outside"
    connected = [r for r in routes if r["connected"]]
    assert {str(r["prefix"]) for r in connected} == {"10.0.0.0/24", "10.0.0.1/32",
                                                    "198.51.100.0/29"}
    e2 = [r for r in routes if r["code"] == "O E2"]
    assert [r["next_hop"] for r in e2] == ["10.0.0.2", "10.0.0.3"]
    assert rt.gateway_of_last_resort(fx.SHOW_ROUTE) == "198.51.100.1"
    summary = rt.parse_route_summary(fx.ROUTE_SUMMARY)
    assert summary["static"] == 2 and summary["ospf 1"] == 2 and summary["Total"] == 12
    assert summary["ospf_detail"] == {"Intra-area": 1, "Inter-area": 0, "External-1": 0,
                                      "External-2": 1}


def test_static_routes_and_tracking():
    statics = rt.parse_static_routes(fx.VPN_CONFIG)
    assert [(s["nameif"], str(s["prefix"]), s["distance"], s["track"]) for s in statics] == [
        ("outside", "0.0.0.0/0", 1, "1"), ("outside", "0.0.0.0/0", 254, ""),
        ("inside", "10.5.0.0/16", 1, "")]
    slas, tracks = rt.parse_sla(fx.VPN_CONFIG)
    assert slas == {"10": "198.51.100.1 (outside)"} and tracks == {"1": "10"}
    assert rt.parse_track_state(fx.SHOW_TRACK) == {"1": "Up"}


def test_neighbours_and_routing_config():
    ospf = rt.parse_ospf_neighbors(fx.OSPF_NEIGHBOR)
    assert ospf[0] == {"router_id": "10.0.0.2", "state": "FULL", "address": "10.0.0.2",
                       "nameif": "inside"}
    assert rt.parse_ospf_interfaces(fx.OSPF_INTERFACE_BRIEF)["inside"] == {
        "process": "1", "area": "0", "cost": 10}
    assert rt.parse_eigrp_neighbors(fx.EIGRP_NEIGHBORS) == [
        {"asn": "100", "address": "10.0.0.9", "nameif": "inside", "uptime": "1d02h"}]
    local, bgp = rt.parse_bgp_summary(fx.BGP_SUMMARY)
    assert local == "65001"
    assert bgp == [{"address": "203.0.113.1", "remote_as": "65010", "uptime": "2d00h",
                    "state": "Established", "prefixes_received": 5}]
    assert rt.parse_bgp_neighbor_prefixes(fx.BGP_NEIGHBORS) == {"203.0.113.1": (3, 5)}
    procs, intf = rt.routing_config(fx.VPN_CONFIG)
    assert procs["ospf 1"]["area_auth"] == {"0"}
    assert procs["ospf 1"]["redistribute"] == [
        {"source": "static", "route_map": ""}, {"source": "connected", "route_map": "LAB-RM"}]
    assert procs["bgp 65001"]["bgp_password"] == set()
    assert intf["inside"]["ospf"] is True and intf["outside"]["ospf"] is False
