"""Port Security tab: BPDU guard and root guard per interface."""
import io

from openpyxl import load_workbook

from app.reports.l2_discovery import L2DiscoveryReport, _port_security_rows

IOS_CONFIG = """hostname SW1
!
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
!
interface GigabitEthernet1/0/1
 description uplink
 switchport mode trunk
 spanning-tree guard root
!
interface GigabitEthernet1/0/2
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet1/0/3
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/4
 switchport mode access
 spanning-tree portfast edge
 spanning-tree bpduguard disable
!
interface GigabitEthernet1/0/5
 switchport mode trunk
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/6
 switchport mode trunk
 spanning-tree portfast edge trunk
!
end
"""


def _inventory(config, ports):
    return {"devices": {"SW1": {"hostname": "SW1", "collector_data": {
        "switchport": {"raw": {}, "parsed": {
            "switchports": ports, "port_security": [], "storm_control": []}},
        "config": {"raw": {}, "parsed": {"config": config}},
    }}}}


def _ports(*specs):
    return [{"interface": i, "mode": m, "voice_vlan": ""} for i, m in specs]


IOS_PORTS = _ports(("Gi1/0/1", "trunk"), ("Gi1/0/2", "static access"),
                   ("Gi1/0/3", "static access"), ("Gi1/0/4", "static access"),
                   ("Gi1/0/5", "trunk"), ("Gi1/0/6", "trunk"))


def _guards(inv):
    return {r[2]: (r[4], r[5]) for r in _port_security_rows(inv)}


def test_global_bpduguard_default_skips_trunks_and_non_portfast():
    g = _guards(_inventory(IOS_CONFIG, IOS_PORTS))
    assert g["Gi1/0/1"][0] == "No"     # trunk, not edge
    assert g["Gi1/0/2"][0] == "Yes"    # portfast access port
    assert g["Gi1/0/3"][0] == "No"     # access, but no portfast
    assert g["Gi1/0/4"][0] == "No"     # explicit disable wins
    assert g["Gi1/0/5"][0] == "Yes"    # explicit enable on a trunk
    assert g["Gi1/0/6"][0] == "Yes"    # edge trunk


def test_portfast_default_makes_access_ports_edge():
    config = IOS_CONFIG.replace("spanning-tree mode rapid-pvst\n",
                                "spanning-tree mode rapid-pvst\nspanning-tree portfast default\n")
    g = _guards(_inventory(config, IOS_PORTS))
    assert g["Gi1/0/3"][0] == "Yes"
    assert g["Gi1/0/1"][0] == "No"


def test_interface_enable_does_not_spread_to_other_ports():
    config = IOS_CONFIG.replace("spanning-tree portfast bpduguard default\n", "")
    g = _guards(_inventory(config, IOS_PORTS))
    assert g["Gi1/0/5"][0] == "Yes"
    assert g["Gi1/0/2"][0] == "No"
    assert g["Gi1/0/1"][0] == "No"


def test_root_guard_is_per_interface():
    g = _guards(_inventory(IOS_CONFIG, IOS_PORTS))
    assert g["Gi1/0/1"][1] == "Yes"
    assert g["Gi1/0/5"][1] == "No"


def test_nxos_port_type_edge_forms():
    config = """hostname NX1
spanning-tree port type edge bpduguard default
interface Ethernet1/1
  switchport mode trunk
interface Ethernet1/2
  switchport access vlan 10
  spanning-tree port type edge
"""
    g = _guards(_inventory(config, _ports(("Eth1/1", "trunk"), ("Eth1/2", "access"))))
    assert g["Eth1/1"][0] == "No"
    assert g["Eth1/2"][0] == "Yes"


def test_xlsx_matches_tabular():
    inv = _inventory(IOS_CONFIG, IOS_PORTS)
    ws = load_workbook(io.BytesIO(L2DiscoveryReport().generate(inv)))["Port Security"]
    xlsx = {ws.cell(row=r, column=3).value: ws.cell(row=r, column=5).value
            for r in range(2, ws.max_row + 1)}
    assert xlsx["Gi1/0/1"] == "No"
    assert xlsx["Gi1/0/2"] == "Yes"
    tabular = L2DiscoveryReport().generate_tabular_data(inv)["Port Security"][1]
    assert {r[2]: r[4] for r in tabular} == xlsx
