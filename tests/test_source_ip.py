"""Source address as the devices see it, and the per-service verdict of the
seed's management ACLs against it."""
import pytest

import app.connection_manager as cmod
import app.discovery_engine as engine_mod
from app import source_access as sa
from app.discovery_engine import DiscoveryEngine

IOS_XE_SHOW_USERS = """\
    Line       User       Host(s)              Idle       Location
   1 vty 0     opsuser    idle                 00:12:40 198.51.100.7
*  2 vty 1     netadmin   idle                 00:00:00 192.0.2.50

  Interface    User               Mode         Idle     Peer Address
"""

NXOS_SHOW_USERS = """\
NAME     LINE         TIME         IDLE          PID COMMENT
opsuser  pts/0        Oct 30 09:15 00:20       12001 (198.51.100.7) session=ssh
netadmin pts/1        Oct 30 10:01   .         12345 (192.0.2.50) session=ssh *
"""

NXOS_SHOW_USERS_UNMARKED = """\
NAME     LINE         TIME         IDLE          PID COMMENT
netadmin pts/0        Oct 30 09:15 00:20       12001 (198.51.100.9) session=ssh
opsuser  pts/1        Oct 30 09:40 00:05       12101 (198.51.100.7) session=ssh
netadmin pts/2        Oct 30 10:01   .         12345 (192.0.2.50) session=ssh
"""

IOS_XE_TCP_BRIEF = """\
TCB       Local Address               Foreign Address             (state)
7F3A1C2D48  192.0.2.1.22               192.0.2.50.53122            ESTAB
7F3A1C2E10  192.0.2.1.179              192.0.2.9.11000             ESTAB
7F3A1C2F00  192.0.2.1.22               198.51.100.7.40001          CLOSEWAIT
"""

SEED_CONFIG = """\
hostname lab-core1
!
interface GigabitEthernet0/0
 ip address 192.0.2.1 255.255.255.0
 ip access-group EDGE-IN in
interface GigabitEthernet0/1
 ip access-group 150 in
!
ip access-list standard VTY-IN
 10 permit 192.0.2.0 0.0.0.255
 20 deny   any log
ip access-list extended EDGE-IN
 10 permit tcp host 192.0.2.50 any eq 22
 20 deny   ip any any
access-list 99 permit 198.51.100.0 0.0.0.255
access-list 150 deny   tcp any any eq 22
access-list 150 permit ip any any
!
snmp-server community <REDACTED> RO 99
!
line con 0
 access-class 99 in
line vty 0 4
 access-class VTY-IN in vrf-also
 ipv6 access-class V6-MGMT in
 transport input ssh
line vty 5 15
 access-class VTY-IN in vrf-also
!
end
"""


# --- show users / show tcp brief -----------------------------------------

def test_ios_xe_show_users_takes_the_starred_line():
    assert sa.parse_show_users(IOS_XE_SHOW_USERS) == "192.0.2.50"


def test_nxos_show_users_takes_the_trailing_star():
    assert sa.parse_show_users(NXOS_SHOW_USERS) == "192.0.2.50"


def test_unmarked_show_users_takes_latest_line_for_our_user():
    assert sa.parse_show_users(NXOS_SHOW_USERS_UNMARKED,
                               username="netadmin") == "192.0.2.50"
    assert sa.parse_show_users(NXOS_SHOW_USERS_UNMARKED) is None


def test_show_users_with_a_hostname_location_is_not_guessed():
    out = "*  2 vty 0     netadmin   idle   00:00:00 mgmt-station\n"
    assert sa.parse_show_users(out, username="netadmin") is None


def test_tcp_brief_established_session_to_port_22():
    assert sa.parse_tcp_brief(IOS_XE_TCP_BRIEF) == "192.0.2.50"
    assert sa.parse_tcp_brief(IOS_XE_TCP_BRIEF, local_ip="192.0.2.1") \
        == "192.0.2.50"
    assert sa.parse_tcp_brief(IOS_XE_TCP_BRIEF, local_ip="192.0.2.99") is None


def test_tcp_brief_with_two_peers_is_ambiguous():
    out = IOS_XE_TCP_BRIEF + (
        "7F3A1C3000  192.0.2.1.22               198.51.100.8.40002  ESTAB\n")
    assert sa.parse_tcp_brief(out) is None


def test_tcp_brief_telnet_port():
    out = "7F3A1C2D48  192.0.2.1.23   192.0.2.60.50000   ESTAB\n"
    assert sa.parse_tcp_brief(out, port=23) == "192.0.2.60"
    assert sa.parse_tcp_brief(out) is None


class ScriptedConn:
    def __init__(self, outputs):
        self.outputs = outputs
        self.commands = []

    def send_command(self, cmd, **kwargs):
        self.commands.append(cmd)
        return self.outputs.get(cmd, "% Invalid input detected at '^' marker.")


def test_learn_from_show_users_first():
    conn = ScriptedConn({"show users": IOS_XE_SHOW_USERS,
                         "show tcp brief": IOS_XE_TCP_BRIEF})
    assert sa.learn_source_ip(conn, "cisco_xe") == ("192.0.2.50",
                                                    sa.SOURCE_SHOW_USERS)
    assert conn.commands == ["show users"]


def test_learn_falls_back_to_tcp_brief_on_ios_xe():
    conn = ScriptedConn({"show tcp brief": IOS_XE_TCP_BRIEF})
    assert sa.learn_source_ip(conn, "cisco_xe", local_ip="192.0.2.1") == (
        "192.0.2.50", sa.SOURCE_TCP_BRIEF)


def test_learn_on_nxos_uses_show_users_only():
    conn = ScriptedConn({"show users": NXOS_SHOW_USERS})
    assert sa.learn_source_ip(conn, "cisco_nxos")[0] == "192.0.2.50"
    empty = ScriptedConn({})
    assert sa.learn_source_ip(empty, "cisco_nxos") == (None, None)
    assert empty.commands == ["show users"]


def test_learn_skips_unsupported_platforms():
    conn = ScriptedConn({"show users": IOS_XE_SHOW_USERS})
    assert sa.learn_source_ip(conn, "juniper_junos") == (None, None)
    assert conn.commands == []


def test_learn_survives_a_failing_session():
    class Broken:
        def send_command(self, cmd, **kwargs):
            raise OSError("socket closed")
    assert sa.learn_source_ip(Broken(), "cisco_ios") == (None, None)


def test_clean_source_ip():
    assert sa.clean_source_ip(" 192.0.2.50 ") == "192.0.2.50"
    assert sa.clean_source_ip("") == ""
    assert sa.clean_source_ip(None) == ""
    for bad in ("192.0.2.256", "2001:db8::1", "192.0.2.0/24", "host"):
        with pytest.raises(ValueError):
            sa.clean_source_ip(bad)


# --- per-service verdict ---------------------------------------------------

def test_ssh_permitted_by_vrf_also_access_class_and_snmp_blocked():
    result = sa.assess_source_access(SEED_CONFIG, "192.0.2.50")
    assert result["ssh"]["permitted"] is True
    assert result["ssh"]["acl"] == "VTY-IN"
    assert result["snmp"]["permitted"] is False
    assert result["snmp"]["acl"] == "99"
    assert sa.summary_line("192.0.2.50", sa.SOURCE_SHOW_USERS, result) == (
        "Scanning from 192.0.2.50 (learned from seed session) — "
        "SSH permitted by VTY-IN, SNMP blocked by ACL 99")


def test_warnings_only_for_blocked_services():
    result = sa.assess_source_access(SEED_CONFIG, "192.0.2.50")
    warnings = sa.access_warnings(result, "192.0.2.50", "lab-core1")
    assert [(w["service"], w["acl"]) for w in warnings] == [("snmp", "99")]
    assert warnings[0]["kind"] == sa.SNMP
    assert warnings[0]["matched_entry"] == "implicit deny"


def test_interface_acls_are_reported_for_information():
    ssh = sa.assess_source_access(SEED_CONFIG, "192.0.2.50")["ssh"]
    by_acl = {e["acl"]: e for e in ssh["interface_acls"]}
    assert by_acl["EDGE-IN"]["permitted"] is True
    assert by_acl["EDGE-IN"]["interface"] == "GigabitEthernet0/0"
    assert by_acl["EDGE-IN"]["matched_entry"] == \
        "10 permit tcp host 192.0.2.50 any eq 22"
    assert by_acl["150"]["permitted"] is False


def test_no_access_class_permits_ssh():
    config = "line vty 0 4\n transport input ssh\n"
    result = sa.assess_source_access(config, "203.0.113.5")
    assert result["ssh"]["permitted"] is True
    assert sa.service_phrase("ssh", result["ssh"]) == \
        "SSH permitted (no vty access-class)"


def test_ipv6_access_class_is_ignored():
    config = "line vty 0 4\n ipv6 access-class V6-ONLY in\n"
    assert sa.vty_blocks(config) == [("line vty 0 4", None)]
    assert sa.assess_source_access(config, "203.0.113.5")["ssh"]["permitted"]


def test_vty_blocks_that_disagree_are_unknown():
    config = (
        "access-list 10 permit 192.0.2.0 0.0.0.255\n"
        "line vty 0 4\n access-class 10 in\n"
        "line vty 5 15\n")
    ssh = sa.assess_source_access(config, "203.0.113.5")["ssh"]
    assert ssh["permitted"] is None
    assert "line vty 0 4: deny" in ssh["detail"]
    assert "line vty 5 15: permit" in ssh["detail"]
    warnings = sa.access_warnings({"ssh": ssh, "snmp": {
        "permitted": None, "configured": False}}, "203.0.113.5", "r1")
    assert len(warnings) == 1
    assert warnings[0]["message"].startswith("Could not tell whether")


def test_extended_vty_acl_on_port_22():
    config = (
        "ip access-list extended MGMT-SSH\n"
        " 10 permit tcp 192.0.2.0 0.0.0.255 any eq 22\n"
        " 20 permit tcp host 198.51.100.7 any eq telnet\n"
        "line vty 0 15\n access-class MGMT-SSH in\n")
    assert sa.assess_source_access(config, "192.0.2.10")["ssh"]["permitted"]
    blocked = sa.assess_source_access(config, "198.51.100.200")["ssh"]
    assert blocked["permitted"] is False
    assert blocked["acl"] == "MGMT-SSH"


def test_snmp_group_access_acl_and_extended_udp_161():
    config = (
        "ip access-list extended SNMP-MGR\n"
        " 10 permit udp host 192.0.2.50 any eq 161\n"
        "snmp-server group V3GRP v3 priv read RO access ipv6 V6ACL SNMP-MGR\n")
    assert sa.snmp_sources(config) == [("group V3GRP", "SNMP-MGR")]
    result = sa.assess_source_access(config, "192.0.2.50")
    assert result["snmp"]["permitted"] is True
    assert sa.service_phrase("snmp", result["snmp"]) == \
        "SNMP permitted by SNMP-MGR"
    assert sa.assess_source_access(config, "192.0.2.51")["snmp"][
        "permitted"] is False


def test_snmp_any_open_community_permits():
    config = (
        "access-list 99 permit 198.51.100.0 0.0.0.255\n"
        "snmp-server community <REDACTED> RO 99\n"
        "snmp-server community <REDACTED> RO\n")
    assert sa.assess_source_access(config, "192.0.2.50")["snmp"][
        "permitted"] is True


def test_nxos_group_line_does_not_open_a_community_with_an_acl():
    config = (
        "ip access-list SNMP-NX\n"
        "  10 permit udp 198.51.100.0/24 any eq snmp\n"
        "snmp-server community <REDACTED> group network-operator\n"
        "snmp-server community <REDACTED> use-ipv4acl SNMP-NX\n")
    snmp = sa.assess_source_access(config, "192.0.2.50")["snmp"]
    assert snmp["permitted"] is False
    assert snmp["acl"] == "SNMP-NX"


def test_snmp_not_configured_never_warns():
    config = "line vty 0 4\n"
    result = sa.assess_source_access(config, "192.0.2.50")
    assert result["snmp"]["configured"] is False
    assert sa.service_phrase("snmp", result["snmp"]) == "SNMP not configured"
    assert sa.access_warnings(result, "192.0.2.50", "r1") == []


def test_object_group_is_unknown_and_warns_as_unknown():
    config = (
        "ip access-list extended VTY-OG\n"
        " 10 permit tcp object-group MGMT-HOSTS any eq 22\n"
        "line vty 0 4\n access-class VTY-OG in\n")
    ssh = sa.assess_source_access(config, "192.0.2.50")["ssh"]
    assert ssh["permitted"] is None
    assert sa.service_phrase("ssh", ssh) == \
        "SSH unknown (VTY-OG could not be evaluated)"


def test_local_socket_warning_says_the_address_may_be_wrong():
    result = sa.assess_source_access(SEED_CONFIG, "172.18.0.2")
    warnings = sa.access_warnings(result, "172.18.0.2", "lab-core1",
                                  method=sa.SOURCE_LOCAL_SOCKET)
    assert warnings
    assert all("set Source IP" in w["message"] for w in warnings)
    assert "local socket, may be a NAT or container address" in \
        sa.summary_line("172.18.0.2", sa.SOURCE_LOCAL_SOCKET, result)


# --- engine ----------------------------------------------------------------

class FakeConn:
    def __init__(self, show_users=IOS_XE_SHOW_USERS, config=SEED_CONFIG):
        self.show_users = show_users
        self.config = config
        self.commands = []

    def find_prompt(self):
        return "lab-core1#"

    def send_command(self, cmd, **kwargs):
        self.commands.append(cmd)
        if cmd == "show running-config":
            return self.config
        if cmd == "show users":
            return self.show_users
        return ""

    def disconnect(self):
        pass


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("WIREMAP_MOCK", raising=False)
    monkeypatch.setattr(engine_mod, "snmp_make_walker",
                        lambda ip, creds: (lambda oid: {}))
    monkeypatch.setattr(engine_mod, "snmp_collect_all", lambda walker: {})
    # The container bridge address the local socket reports.
    monkeypatch.setattr(engine_mod, "local_source_ip",
                        lambda dest: "172.18.0.2")


def _run(monkeypatch, tmp_path, conn, **kw):
    monkeypatch.setattr(cmod, "_connect_handler", lambda **p: conn)
    events = []
    eng = DiscoveryEngine(seed_ip="192.0.2.1", seed_device_type="cisco_xe",
                          username="netadmin", password="p", max_depth=0,
                          inventory_dir=str(tmp_path),
                          progress_callback=events.append, **kw)
    return eng.discover(), events


def test_engine_learns_source_from_seed_and_checks_acls_with_it(
        monkeypatch, tmp_path):
    conn = FakeConn()
    inv, events = _run(monkeypatch, tmp_path, conn)
    summary = inv.to_dict()["scan_summary"]
    assert summary["source_ip"] == "192.0.2.50"
    assert summary["source_ip_method"] == sa.SOURCE_SHOW_USERS
    assert summary["source_access"]["ssh"]["permitted"] is True
    assert summary["source_access"]["snmp"]["permitted"] is False
    line = ("Scanning from 192.0.2.50 (learned from seed session) — "
            "SSH permitted by VTY-IN, SNMP blocked by ACL 99")
    assert summary["source_access_line"] == line
    # Regression: the bridge address used to be judged and reported.
    assert [w["acl"] for w in summary["source_access_warnings"]] == ["99"]
    assert all("172.18.0.2" not in w["message"]
               for w in summary["source_access_warnings"])
    # Asked once, on the live session, before the collectors ran.
    assert conn.commands.count("show users") == 1
    identity = [c for c in conn.commands if "Adaptive Security" not in c]
    assert identity[0] == "show users"
    learned = [e for e in events if e["event"] == "source_ip_learned"][0]
    assert learned["previous"] == "172.18.0.2"
    assert [e["message"] for e in events
            if e["event"] == "source_access"] == [line]
    done = [e for e in events if e["event"] == "scan_complete"][0]
    assert done["source_access_line"] == line
    assert inv.get_summary()["source_access_line"] == line
    assert inv.get_summary()["source_ip_method"] == sa.SOURCE_SHOW_USERS


def test_engine_falls_back_to_local_socket_when_the_seed_cannot_say(
        monkeypatch, tmp_path):
    inv, _ = _run(monkeypatch, tmp_path, FakeConn(show_users=""))
    summary = inv.to_dict()["scan_summary"]
    assert summary["source_ip"] == "172.18.0.2"
    assert summary["source_ip_method"] == sa.SOURCE_LOCAL_SOCKET


def test_configured_source_ip_wins_and_nothing_is_asked(monkeypatch, tmp_path):
    conn = FakeConn()
    inv, events = _run(monkeypatch, tmp_path, conn, source_ip="198.51.100.20")
    summary = inv.to_dict()["scan_summary"]
    assert summary["source_ip"] == "198.51.100.20"
    assert summary["source_ip_method"] == sa.SOURCE_CONFIGURED
    assert "show users" not in conn.commands
    started = [e for e in events if e["event"] == "scan_started"][0]
    assert started["source_ip_method"] == sa.SOURCE_CONFIGURED
    assert summary["source_access"]["ssh"]["permitted"] is False
    assert summary["source_access"]["snmp"]["permitted"] is True
