"""Edge definition, NAT state, ACL usage and VRF peer handling in the
internet edge report."""
import io

from openpyxl import load_workbook

from app.reports.findings import OVERFIRE_TYPE
from app.reports.internet_edge import (
    InternetEdgeReport, _analyze_edge, _is_public_ip, _is_public_asn,
    _summary_rows, _public_rows, NAT_NOT_CONFIGURED,
)


def _device(hostname, bgp=None, acls=None, ip_interfaces=None, nat=None,
            config=None, routes=None, vrf_interfaces=None, ospf_interfaces=None):
    cd = {
        "routing_detail": {"raw": {}, "parsed": {
            "bgp_summary": bgp or [],
            "ospf_interfaces": ospf_interfaces or [],
            "eigrp_neighbors": [],
        }},
        "edge_services": {"raw": {}, "parsed": {
            "access_lists": acls or [],
            "ip_interfaces": ip_interfaces or [],
            "nat_translations": [],
            "nat_statistics": nat if nat is not None else {},
        }},
        "l3_routing": {"raw": {}, "parsed": {"neighbors": [], "routes": routes or []}},
        "vrf": {"raw": {}, "parsed": {"vrfs": [], "vrf_interfaces": vrf_interfaces or []}},
    }
    if config is not None:
        cd["config"] = {"raw": {}, "parsed": {"config": config}}
    return {"hostname": hostname, "collector_data": cd}


def _inv(*devices):
    return {"devices": {d["hostname"]: d for d in devices}}


def _peer(neighbor, asn, vrf="default", state="Established"):
    return {"neighbor": neighbor, "asn": asn, "state": state,
            "prefixes_received": 5, "up_down": "1d", "vrf": vrf}


def _titles(analysis, host=None):
    return [f["title"] for f in analysis["findings"]
            if host is None or f["hostname"] == host]


# NAT stats as parsed on a box that has no NAT at all.
_NO_NAT_STATS = {"active_translations": 0, "peak_translations": 0,
                 "outside_interfaces": [], "inside_interfaces": [],
                 "hits": 0, "misses": 0, "pools": []}


# --- address / ASN classification ---------------------------------------

def test_public_ip_classification():
    assert _is_public_ip("203.0.113.1")
    assert _is_public_ip("198.51.100.2/30")
    for ip in ("10.1.1.1", "172.16.0.1", "192.168.1.1", "100.64.0.1",
               "169.254.1.1", "127.0.0.1", "224.0.0.5", "garbage", ""):
        assert not _is_public_ip(ip), ip


def test_public_asn_classification():
    assert _is_public_asn("64496")
    assert _is_public_asn("65536")
    assert _is_public_asn("1.10")         # asdot
    for asn in ("64512", "65000", "65534", "4200000001", "23456", "0", "", None):
        assert not _is_public_asn(asn), asn


# --- edge definition (#18) -----------------------------------------------

def test_edge_definition_excludes_internal_devices():
    inv = _inv(
        # internal router: iBGP to private AS, ACLs, NAT stats all zero
        _device("RTR-B", bgp=[_peer("10.0.0.1", "65001"), _peer("10.0.0.2", "65001")],
                acls=[{"name": "MGMT-ONLY", "type": "Standard", "entries": []}],
                nat=_NO_NAT_STATS,
                ip_interfaces=[{"interface": "Gi0/0", "ip_address": "10.0.0.3/24"}]),
        _device("RTR-A", bgp=[_peer("192.0.2.1", "64496", vrf="INET")]),
    )
    analysis = _analyze_edge(inv)
    assert list(analysis["edge"]) == ["RTR-A"]
    assert "public AS 64496" in analysis["edge"]["RTR-A"][0]


def test_edge_by_public_address_nat_and_static_default():
    inv = _inv(
        _device("RTR-A", ip_interfaces=[{"interface": "Gi0/0",
                                         "ip_address": "203.0.113.5/29"}]),
        _device("RTR-B", config="interface Gi0/1\n ip nat outside\n"),
        _device("RTR-C", routes=[{"network": "0.0.0.0", "prefix_length": "0",
                                  "protocol": "S", "nexthop_ip": "10.9.0.1",
                                  "nexthop_if": "GigabitEthernet0/2"}],
                ospf_interfaces=[{"interface": "Gi0/1"}]),
        # static default out an OSPF interface is internal
        _device("RTR-D", routes=[{"network": "0.0.0.0", "prefix_length": "0",
                                  "protocol": "S", "nexthop_ip": "10.9.0.1",
                                  "nexthop_if": "GigabitEthernet0/1"}],
                ospf_interfaces=[{"interface": "Gi0/1"}]),
    )
    edge = _analyze_edge(inv)["edge"]
    assert set(edge) == {"RTR-A", "RTR-B", "RTR-C"}
    assert edge["RTR-B"] == ["NAT configured"]


# --- NAT not configured vs 0 (#18) ---------------------------------------

def test_nat_not_configured_in_summary():
    inv = _inv(_device("RTR-A", nat=_NO_NAT_STATS))
    rows = dict(_summary_rows(_analyze_edge(inv), inv))
    assert rows["Active NAT Translations"] == NAT_NOT_CONFIGURED


def test_nat_configured_idle_reports_zero():
    stats = dict(_NO_NAT_STATS, outside_interfaces=["Gi0/0"], inside_interfaces=["Gi0/1"])
    inv = _inv(_device("RTR-A", nat=stats))
    rows = dict(_summary_rows(_analyze_edge(inv), inv))
    assert rows["Active NAT Translations"] == 0


# --- public addresses sheet (#18) ----------------------------------------

def test_public_addresses_with_vrf():
    inv = _inv(_device(
        "RTR-A",
        ip_interfaces=[
            {"interface": "GigabitEthernet0/0", "ip_address": "198.51.100.2/30", "vrf": "INET"},
            {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.1/24"},
            {"interface": "Loopback0", "ip_address": "192.0.2.10/32"},
        ],
    ))
    rows = _public_rows(inv)
    assert ["RTR-A", rows[0][1], "GigabitEthernet0/0", "198.51.100.2", "30", "INET"] in rows
    assert any(r[3] == "192.0.2.10" and r[5] == "default" for r in rows)
    assert not any(r[3] == "10.0.0.1" for r in rows)


def test_public_addresses_vrf_from_vrf_collector():
    inv = _inv(_device(
        "RTR-A",
        ip_interfaces=[{"interface": "Gi0/2", "ip_address": "203.0.113.9/30"}],
        vrf_interfaces=[{"vrf": "WAN", "interface": "Gi0/2", "ip_address": "203.0.113.9"}],
    ))
    assert _public_rows(inv)[0][5] == "WAN"


def test_public_addresses_sheet_present():
    inv = _inv(_device("RTR-A", ip_interfaces=[
        {"interface": "Gi0/0", "ip_address": "203.0.113.1/30"}]))
    wb = load_workbook(io.BytesIO(InternetEdgeReport().generate(inv)))
    assert "Public Addresses" in wb.sheetnames
    assert wb["Public Addresses"].cell(row=2, column=4).value == "203.0.113.1"
    assert "Edge Devices" in wb.sheetnames


# --- BGP across VRFs (#9) ------------------------------------------------

def test_single_homed_counts_peers_in_all_vrfs():
    inv = _inv(_device("RTR-A", bgp=[_peer("192.0.2.1", "64496", vrf="INET"),
                                     _peer("198.51.100.1", "64497", vrf="INET")]))
    assert "Single-homed BGP" not in _titles(_analyze_edge(inv))


def test_single_homed_vrf_peer_flagged():
    inv = _inv(_device("RTR-A", bgp=[_peer("192.0.2.1", "64496", vrf="INET")]))
    findings = [f for f in _analyze_edge(inv)["findings"] if f["title"] == "Single-homed BGP"]
    assert len(findings) == 1
    assert "VRF INET" in findings[0]["description"]


def test_bgp_peer_down_names_vrf():
    inv = _inv(_device("RTR-A", bgp=[_peer("192.0.2.1", "64496", vrf="INET", state="Idle"),
                                     _peer("198.51.100.1", "64497", vrf="INET")]))
    down = [f for f in _analyze_edge(inv)["findings"]
            if f["title"] == "BGP peer not Established"]
    assert down and "VRF INET" in down[0]["description"]
    assert down[0]["severity"] == "Critical"


# --- ACL usage classification (#10) -------------------------------------

_CONFIG = """hostname RTR-A
class-map match-any CM-VOICE
 match access-group name ACL-QOS-VOICE
interface GigabitEthernet0/0
 ip access-group 110 in
route-map RM-OUT permit 10
 match ip address ACL-RM
ip nat inside source list ACL-NAT interface GigabitEthernet0/0 overload
"""


def _acl(name, hits=0, permit_any=False):
    entries = [{"action": "permit", "protocol": "tcp", "source": "any",
                "destination": "host 10.0.0.1", "hit_count": hits}]
    if permit_any:
        entries.append({"action": "permit", "protocol": "ip", "source": "any",
                        "destination": "any", "hit_count": 0})
    return {"name": name, "type": "Extended", "entries": entries}


def test_acl_findings_follow_usage():
    inv = _inv(_device("RTR-A", config=_CONFIG, acls=[
        _acl("ACL-QOS-VOICE", permit_any=True),
        _acl("ACL-RM"),
        _acl("ACL-NAT", permit_any=True),
        _acl("110", permit_any=True),
        _acl("OLD-UNUSED"),
    ]))
    findings = _analyze_edge(inv)["findings"]
    by_acl = {}
    for f in findings:
        for name in ("ACL-QOS-VOICE", "ACL-RM", "ACL-NAT", "'110'", "OLD-UNUSED"):
            if name.strip("'") in f["description"]:
                by_acl.setdefault(name.strip("'"), []).append(f["title"])
    # QoS, route-map and NAT ACLs: no hit-count or permit-any findings
    assert "ACL-QOS-VOICE" not in by_acl
    assert "ACL-RM" not in by_acl
    assert "ACL-NAT" not in by_acl
    # interface filter keeps both checks
    assert sorted(by_acl["110"]) == ["ACL permit ip any any", "Dead ACL (all zero hits)"]
    assert by_acl["OLD-UNUSED"] == ["Unreferenced ACL"]
    unref = [f for f in findings if f["title"] == "Unreferenced ACL"][0]
    assert unref["severity"] == "Info"


def test_acl_usage_unknown_without_config():
    inv = _inv(
        _device("RTR-A", acls=[_acl("ACL-QOS-VOICE", permit_any=True), _acl("OUTSIDE-IN")],
                ip_interfaces=[{"interface": "Gi0/0", "ip_address": "10.0.0.1/24",
                                "acl_in": "OUTSIDE-IN", "acl_out": ""}]),
        _device("RTR-B", acls=[_acl("ACL-X")]),
    )
    findings = _analyze_edge(inv)["findings"]
    notes = [f for f in findings
             if f["title"] == "ACL usage unknown (config collector not enabled)"]
    assert len(notes) == 1
    assert notes[0]["severity"] == "Info"
    assert "2 device(s)" in notes[0]["description"]
    # unknown ACLs are not flagged
    assert not any("ACL-QOS-VOICE" in f["description"] for f in findings)
    assert not any("ACL-X" in f["description"] for f in findings)
    # an ACL seen applied to an interface is still audited
    assert any(f["title"] == "Dead ACL (all zero hits)" and "OUTSIDE-IN" in f["description"]
               for f in findings)


def test_acl_audit_usage_column():
    inv = _inv(_device("RTR-A", config=_CONFIG, acls=[_acl("ACL-QOS-VOICE"), _acl("110")]))
    sheets = InternetEdgeReport().generate_tabular_data(inv)
    headers, rows = sheets["ACL Audit"]
    col = headers.index("ACL Usage")
    usage = {r[2]: r[col] for r in rows}
    assert usage == {"ACL-QOS-VOICE": "QoS classifier", "110": "Interface filter"}


# --- over-firing self check (#20) ----------------------------------------

def test_overfire_note_when_check_hits_most_devices():
    devices = [_device(f"RTR-{c}", config="hostname x\n", acls=[_acl("OLD")])
               for c in "ABCD"]
    findings = _analyze_edge(_inv(*devices))["findings"]
    meta = [f for f in findings if f["type"] == OVERFIRE_TYPE]
    assert [m["about"] for m in meta] == ["Unreferenced ACL"]


# --- aggregated findings (#26) ------------------------------------------

def test_template_acl_unreferenced_everywhere_is_one_row():
    devices = [_device(f"SW{i}", config="hostname x\n",
                       acls=[_acl("ACL-TEMPLATE-REDIRECT")] * (1 + i % 2))
               for i in range(1, 13)]
    inv = _inv(*devices)
    sheets = InternetEdgeReport().generate_tabular_data(inv)
    headers, rows = sheets["Findings"]
    assert headers == ["Severity", "Finding", "Details", "Device count", "Devices"]
    unref = [r for r in rows if r[1] == "Unreferenced ACL"]
    assert len(unref) == 1
    assert unref[0][3] == 12
    assert unref[0][4].endswith(", +2 more")
    assert "ACL-TEMPLATE-REDIRECT" in unref[0][2]
    # the over-fire note stays on the aggregated sheet
    assert any(r[1].startswith("Check may be miscalibrated") for r in rows)
    # per-device rows move to the detail sheet
    dheaders, drows = sheets["Findings (detail)"]
    assert dheaders == ["Device", "Site/Location", "Severity", "Finding", "Details"]
    assert sum(1 for r in drows if r[3] == "Unreferenced ACL") >= 12
    summary = dict(sheets["Summary"][1])
    assert summary["Info Finding Types"] == len(
        [r for r in rows if r[0] == "Info"])


def test_findings_xlsx_matches_tabular():
    devices = [_device(f"SW{i}", config="hostname x\n",
                       acls=[_acl("ACL-TEMPLATE-REDIRECT")])
               for i in range(1, 5)]
    inv = _inv(*devices)
    report = InternetEdgeReport()
    sheets = report.generate_tabular_data(inv)
    wb = load_workbook(io.BytesIO(report.generate(inv)))
    for name in ("Findings", "Findings (detail)"):
        ws = wb[name]
        headers, rows = sheets[name]
        got = [["" if c.value is None else c.value for c in r]
               for r in ws.iter_rows(min_row=1)]
        assert got[0] == headers
        assert got[1:] == rows
