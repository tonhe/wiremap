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
