import pytest
from app.collectors.vrf import VrfCollector


@pytest.fixture
def collector():
    return VrfCollector()


def test_attrs(collector):
    assert collector.name == "vrf"
    assert collector.label == "VRF Configuration"
    assert collector.enabled_by_default is True


def test_get_commands_ios(collector):
    cmds = collector.get_commands("cisco_ios")
    assert len(cmds) == 2
    assert cmds == ["show ip vrf", "show ip vrf interfaces"]


def test_get_commands_nxos(collector):
    cmds = collector.get_commands("cisco_nxos")
    assert cmds[0] == "show vrf"
    assert "show ip vrf" not in cmds


def test_parse_empty(collector):
    result = collector.parse({}, "cisco_ios")
    assert result == {"vrfs": [], "vrf_interfaces": [], "vrf_routes": {}, "vrf_arp": {}}


def test_parse_vrfs_basic(collector):
    vrf_output = """\
Name                             Default RD            Protocols   Interfaces
MGMT                             65000:100             ipv4        Gi0/1
                                                                   Gi0/2
PRODUCTION                       65000:200             ipv4        Gi0/3"""
    raw = {"show ip vrf": vrf_output, "show ip vrf interfaces": ""}
    result = collector.parse(raw, "cisco_ios")
    vrfs = result["vrfs"]
    assert len(vrfs) == 2
    mgmt = [v for v in vrfs if v["name"] == "MGMT"][0]
    assert mgmt["rd"] == "65000:100"
    assert "Gi0/1" in mgmt["interfaces"]
    assert "Gi0/2" in mgmt["interfaces"]
    assert len(mgmt["interfaces"]) == 2
    prod = [v for v in vrfs if v["name"] == "PRODUCTION"][0]
    assert prod["interfaces"] == ["Gi0/3"]


def test_parse_vrf_interfaces(collector):
    intf_output = """\
Interface              IP-Address      VRF                              Protocol
Gi0/1                  10.1.1.1        MGMT                             up
Gi0/3                  10.2.1.1        PRODUCTION                       up"""
    raw = {"show ip vrf": "", "show ip vrf interfaces": intf_output}
    result = collector.parse(raw, "cisco_ios")
    vrf_intfs = result["vrf_interfaces"]
    assert len(vrf_intfs) == 2
    assert vrf_intfs[0]["vrf"] == "MGMT"
    assert vrf_intfs[0]["interface"] == "Gi0/1"
    assert vrf_intfs[0]["ip_address"] == "10.1.1.1"
    assert vrf_intfs[1]["vrf"] == "PRODUCTION"


def test_parse_nxos_vrfs(collector):
    vrf_output = """\
VRF-Name                           VRF-ID State   Reason
default                                 1 Up      --
management                              2 Up      --
PROD                                    3 Up      --"""
    intf_output = """\
Interface                 VRF-Name                        VRF-ID  Site-of-Origin
Ethernet1/1               PROD                                 3  --
mgmt0                     management                           2  --"""
    raw = {"show vrf": vrf_output, "show vrf all interface": intf_output}
    result = collector.parse(raw, "cisco_nxos")
    vrfs = result["vrfs"]
    assert len(vrfs) == 3
    names = [v["name"] for v in vrfs]
    assert "PROD" in names
    assert "management" in names
    vrf_intfs = result["vrf_interfaces"]
    assert len(vrf_intfs) == 2
    assert vrf_intfs[0]["vrf"] == "PROD"
    assert vrf_intfs[0]["interface"] == "Ethernet1/1"


NXOS_VRF_ARP = """Flags: * - Adjacencies learnt on non-active FHRP router
       + - Adjacencies synced via CFSoE
       # - Adjacencies Throttled for Glean
       CP - Added via L2RIB, Control plane Adjacencies
       D - Static Adjacencies attached to down interface

IP ARP Table for context TENANT-A
Total number of entries: 3
Address         Age       MAC Address     Interface       Flags
198.51.100.10   00:01:23  0050.56aa.bb01  Vlan210
198.51.100.11   00:00:42  0050.56aa.bb02  Vlan210         +
198.51.100.12   00:00:05  INCOMPLETE      Vlan210
"""

IOS_VRF_ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  203.0.113.1             -   0050.56aa.cc01  ARPA   GigabitEthernet0/0/1.100
Internet  203.0.113.20           12   0050.56aa.cc14  ARPA   GigabitEthernet0/0/1.100
"""


def test_parse_nxos_vrf_arp(collector):
    # Regression: the IOS-only regex required an "Internet" column, so
    # every NX-OS VRF ARP table parsed to nothing.
    raw = {"show vrf": "", "show vrf all interface": "",
           "show ip arp vrf TENANT-A": NXOS_VRF_ARP}
    entries = collector.parse(raw, "cisco_nxos")["vrf_arp"]["TENANT-A"]
    assert [e["ip_address"] for e in entries] == [
        "198.51.100.10", "198.51.100.11", "198.51.100.12"]
    assert entries[0]["interface"] == "Vlan210"
    assert entries[0]["mac_address"] == "00:50:56:aa:bb:01"
    assert entries[2]["incomplete"] is True


def test_parse_ios_vrf_arp(collector):
    raw = {"show ip vrf": "", "show ip vrf interfaces": "",
           "show ip arp vrf CUST-B": IOS_VRF_ARP}
    entries = collector.parse(raw, "cisco_xe")["vrf_arp"]["CUST-B"]
    assert len(entries) == 2
    assert entries[0]["ip_address"] == "203.0.113.1"
    assert entries[0]["interface"] == "GigabitEthernet0/0/1.100"
    assert entries[1]["age"] == "12"
