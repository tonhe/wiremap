import pytest

from app.ifname import canonical_ifname


@pytest.mark.parametrize("short, long", [
    ("Gi1/0/1", "GigabitEthernet1/0/1"),
    ("Te1/1/5", "TenGigabitEthernet1/1/5"),
    ("Twe1/0/25", "TwentyFiveGigE1/0/25"),
    ("Tw1/0/3", "TwoGigabitEthernet1/0/3"),
    ("Fi1/0/7", "FiveGigabitEthernet1/0/7"),
    ("Fo1/1/1", "FortyGigabitEthernet1/1/1"),
    ("Hu1/0/49", "HundredGigE1/0/49"),
    ("Fa0/1", "FastEthernet0/1"),
    ("Eth1/49", "Ethernet1/49"),
    ("Et49/1", "Ethernet49/1"),
    ("Po10", "Port-channel10"),
    ("Vl100", "Vlan100"),
    ("Lo0", "Loopback0"),
    ("Tu1", "Tunnel1"),
    ("Ap1/0/1", "AppGigabitEthernet1/0/1"),
    ("BE100", "Bundle-Ether100"),
])
def test_short_and_long_forms_agree(short, long):
    assert canonical_ifname(short) == canonical_ifname(long) == long


@pytest.mark.parametrize("variant, expected", [
    ("gigabitethernet1/0/1", "GigabitEthernet1/0/1"),
    ("GI1/0/1", "GigabitEthernet1/0/1"),
    ("  Gi 1/0/1 ", "GigabitEthernet1/0/1"),
    ("port-channel1", "Port-channel1"),
    ("Port-Channel1", "Port-channel1"),
    ("TenGigE0/0/0/1", "TenGigabitEthernet0/0/0/1"),
    ("HundredGigabitEthernet1/0/1", "HundredGigE1/0/1"),
    ("Gi0/0.100", "GigabitEthernet0/0.100"),
    ("BDI20", "BDI20"),
    ("mgmt0", "mgmt0"),
    ("Management1", "Management1"),
    ("Ma1", "Management1"),
])
def test_case_and_spelling_variants(variant, expected):
    assert canonical_ifname(variant) == expected


def test_unknown_names_compare_case_insensitively():
    assert canonical_ifname("ge-0/0/0") == "ge-0/0/0"
    assert canonical_ifname("GE-0/0/0") == canonical_ifname("ge-0/0/0")
    assert canonical_ifname("ethernet1/1/1:1") == "Ethernet1/1/1:1"


def test_empty_values():
    assert canonical_ifname(None) == ""
    assert canonical_ifname("") == ""
    assert canonical_ifname("   ") == ""
