"""Shared test fixtures for report tests."""
import pytest


@pytest.fixture
def sample_inventory():
    """A minimal inventory with data from all collectors."""
    return {
        "discovery_id": "2026-03-05_10-00-00_192.168.1.1",
        "seed_ip": "192.168.1.1",
        "timestamp": "2026-03-05T10:00:00Z",
        "params": {},
        "devices": {
            "SW1": {
                "hostname": "SW1",
                "mgmt_ip": "192.168.1.1",
                "device_type": "cisco_ios",
                "device_category": "switch",
                "platform": "WS-C3750X-48",
                "collector_data": {
                    "cdp_lldp": {
                        "raw": {},
                        "parsed": {
                            "neighbors": [
                                {
                                    "remote_device": "SW2",
                                    "local_intf": "Gi0/1",
                                    "remote_intf": "Gi0/1",
                                    "remote_ip": "192.168.1.2",
                                    "protocols": ["cdp"],
                                    "remote_platform": "WS-C2960X-48",
                                },
                            ],
                        },
                    },
                    "device_inventory": {
                        "raw": {},
                        "parsed": {
                            "version": [
                                {
                                    "version": "15.2(4)E10",
                                    "serial_number": "FOC1234ABCD",
                                    "hardware": "WS-C3750X-48",
                                }
                            ],
                            "inventory": [
                                {"sn": "FOC1234ABCD", "pid": "WS-C3750X-48",
                                 "name": "1", "descr": "WS-C3750X-48"},
                            ],
                            "modules": [
                                {"module": "1", "ports": "48",
                                 "type": "Supervisor Module",
                                 "model": "WS-C3750X-48",
                                 "status": "active *",
                                 "serial": "FOC1234ABCD"},
                                {"module": "2", "ports": "48",
                                 "type": "Line Card",
                                 "model": "WS-C3750X-48",
                                 "status": "ok",
                                 "serial": "FOC5678EFGH"},
                                {"module": "3", "ports": "4",
                                 "type": "FRULink 1G Module",
                                 "model": "C3KX-NM-1G",
                                 "status": "ok",
                                 "serial": "FOC9999XYZZ"},
                            ],
                            "stack_members": [
                                {"switch": "1", "role": "Active",
                                 "mac_address": "0cd0.f8e4.8f00",
                                 "priority": "15", "hw_ver": "V05",
                                 "state": "Ready"},
                                {"switch": "2", "role": "Standby",
                                 "mac_address": "0cd0.f8e5.9e00",
                                 "priority": "14", "hw_ver": "V05",
                                 "state": "Ready"},
                            ],
                        },
                    },
                    "arp": {
                        "raw": {},
                        "parsed": {
                            "entries": [
                                {"ip": "192.168.1.1", "mac": "aabb.cc00.0001",
                                 "interface": "Vlan1", "age": "-"},
                                {"ip": "192.168.1.2", "mac": "aabb.cc00.0002",
                                 "interface": "Gi0/1", "age": "5"},
                            ],
                        },
                    },
                    "interfaces": {
                        "raw": {},
                        "parsed": {
                            "interfaces_status": [
                                {"port": "Gi0/1", "name": "Uplink to SW2",
                                 "status": "connected", "vlan": "trunk",
                                 "duplex": "a-full", "speed": "a-1000",
                                 "type": "10/100/1000BaseTX"},
                            ],
                            "interfaces_description": [],
                            "ip_interfaces": [
                                {"intf": "Vlan1", "ipaddr": "192.168.1.1",
                                 "status": "up", "proto": "up"},
                            ],
                            "etherchannel": [],
                        },
                    },
                    "config": {
                        "raw": {},
                        "parsed": {
                            "config": "hostname SW1\n!\ninterface Vlan1\n ip address 192.168.1.1 255.255.255.0\n!",
                        },
                    },
                    "l3_routing": {
                        "raw": {},
                        "parsed": {
                            "neighbors": [
                                {"remote_ip": "192.168.1.2",
                                 "remote_device": "SW2",
                                 "protocols": ["ospf"]},
                            ],
                            "routes": [
                                {"network": "192.168.1.0", "mask": "24",
                                 "nexthop_ip": "0.0.0.0", "nexthop_if": "Vlan1",
                                 "protocol": "C", "metric": "0"},
                            ],
                            "ip_protocols_raw": "",
                        },
                    },
                    "mac_table": {
                        "raw": {},
                        "parsed": {
                            "entries": [
                                {"mac": "aabb.cc00.0002", "vlan": "1",
                                 "type": "DYNAMIC", "ports": "Gi0/1"},
                            ],
                        },
                    },
                    "stp_vlan": {
                        "raw": {},
                        "parsed": {
                            "spanning_tree": [],
                            "spanning_tree_root": [],
                            "blocked_ports": [],
                            "vlans": [],
                            "vtp_status": [],
                        },
                    },
                    "switchport": {"raw": {}, "parsed": {"switchports": [], "port_security": [], "port_security_addresses": [], "errdisable_recovery": [], "storm_control": []}},
                    "stp_detail": {"raw": {}, "parsed": {"stp_detail": [], "inconsistent_ports": [], "stp_root_summary": []}},
                    "routing_detail": {
                        "raw": {},
                        "parsed": {
                            "route_summary": [],
                            "ip_protocols": {"raw": "", "protocols_detected": []},
                            "ospf_processes": [],
                            "ospf_interfaces": [],
                            "bgp_summary": [
                                {
                                    "neighbor": "10.0.0.2",
                                    "asn": "65002",
                                    "state": "Established",
                                    "prefixes_received": 50,
                                    "up_down": "01:02:03",
                                },
                            ],
                            "eigrp_topology": [],
                            "eigrp_neighbors": [],
                            "bgp_table": [],
                        },
                    },
                    "ntp_logging": {"raw": {}, "parsed": {"ntp_status": {"synchronized": False, "stratum": "", "reference": "", "raw": ""}, "ntp_peers": [], "logging": {"logging_hosts": [], "buffer_size": "", "console_level": "", "raw": ""}, "snmp": {"raw": "", "communities_detected": False, "v3_configured": False, "contact": "", "location": ""}}},
                    "vrf": {"raw": {}, "parsed": {"vrfs": [], "vrf_interfaces": []}},
                    "edge_services": {
                        "raw": {},
                        "parsed": {
                            "access_lists": [
                                {
                                    "name": "OUTSIDE_IN",
                                    "type": "Extended",
                                    "entries": [
                                        {"action": "permit", "protocol": "tcp", "source": "any",
                                         "destination": "10.0.0.0/24", "hit_count": 150},
                                        {"action": "deny", "protocol": "ip", "source": "any",
                                         "destination": "any", "hit_count": 0},
                                    ],
                                },
                            ],
                            "ip_interfaces": [
                                {
                                    "interface": "GigabitEthernet0/0",
                                    "ip_address": "203.0.113.1/30",
                                    "acl_in": "OUTSIDE_IN",
                                    "acl_out": "",
                                    "proxy_arp": False,
                                    "urpf": True,
                                    "directed_broadcast": False,
                                },
                            ],
                            "nat_translations": [],
                            "nat_statistics": {
                                "active_translations": 450,
                                "peak_translations": 500,
                                "outside_interfaces": ["GigabitEthernet0/0"],
                                "inside_interfaces": ["GigabitEthernet0/1"],
                                "hits": 150000,
                                "misses": 12,
                                "pools": [
                                    {"name": "NATPOOL", "total_addresses": 10,
                                     "allocated": 5, "utilization_pct": 50},
                                ],
                            },
                        },
                    },
                    "hsrp": {
                        "raw": {},
                        "parsed": {
                            "entries": [
                                {
                                    "interface": "Vlan1",
                                    "group": "1",
                                    "priority": "110",
                                    "virtual_ip": "10.1.1.1",
                                    "state": "Active",
                                },
                            ],
                        },
                    },
                },
            },
            "SW2": {
                "hostname": "SW2",
                "mgmt_ip": "192.168.1.2",
                "device_type": "cisco_ios",
                "device_category": "switch",
                "platform": "WS-C2960X-48",
                "collector_data": {
                    "cdp_lldp": {
                        "raw": {},
                        "parsed": {
                            "neighbors": [
                                {
                                    "remote_device": "SW1",
                                    "local_intf": "Gi0/1",
                                    "remote_intf": "Gi0/1",
                                    "remote_ip": "192.168.1.1",
                                    "protocols": ["cdp"],
                                },
                            ],
                        },
                    },
                    "device_inventory": {
                        "raw": {},
                        "parsed": {
                            "version": [{"version": "15.2(7)E6"}],
                            "inventory": [],
                            "modules": [],
                            "stack_members": [],
                        },
                    },
                    "arp": {"raw": {}, "parsed": {"entries": []}},
                    "interfaces": {
                        "raw": {},
                        "parsed": {
                            "interfaces_status": [],
                            "interfaces_description": [],
                            "ip_interfaces": [],
                            "etherchannel": [],
                        },
                    },
                    "config": {"raw": {}, "parsed": {"config": "hostname SW2\n!"}},
                    "l3_routing": {
                        "raw": {},
                        "parsed": {"neighbors": [], "routes": [], "ip_protocols_raw": ""},
                    },
                    "mac_table": {"raw": {}, "parsed": {"entries": []}},
                    "stp_vlan": {
                        "raw": {},
                        "parsed": {
                            "spanning_tree": [],
                            "spanning_tree_root": [],
                            "blocked_ports": [],
                            "vlans": [],
                            "vtp_status": [],
                        },
                    },
                    "switchport": {"raw": {}, "parsed": {"switchports": [], "port_security": [], "port_security_addresses": [], "errdisable_recovery": [], "storm_control": []}},
                    "stp_detail": {"raw": {}, "parsed": {"stp_detail": [], "inconsistent_ports": [], "stp_root_summary": []}},
                    "routing_detail": {"raw": {}, "parsed": {"route_summary": [], "ip_protocols": {"raw": "", "protocols_detected": []}, "ospf_processes": [], "ospf_interfaces": [], "bgp_summary": []}},
                    "ntp_logging": {"raw": {}, "parsed": {"ntp_status": {"synchronized": False, "stratum": "", "reference": "", "raw": ""}, "ntp_peers": [], "logging": {"logging_hosts": [], "buffer_size": "", "console_level": "", "raw": ""}, "snmp": {"raw": "", "communities_detected": False, "v3_configured": False, "contact": "", "location": ""}}},
                    "vrf": {"raw": {}, "parsed": {"vrfs": [], "vrf_interfaces": []}},
                    "edge_services": {"raw": {}, "parsed": {"access_lists": [], "ip_interfaces": []}},
                    "hsrp": {"raw": {}, "parsed": {"entries": []}},
                },
            },
        },
    }
