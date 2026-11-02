"""QoS collector: parsers, platform gating, port selection and the join."""
import pytest

from app.collectors import get_registry
from app.collectors.qos import (
    QosCollector, platform_family, commands_for, parse_policy_map_interface,
    parse_policy_maps, parse_class_maps, parse_mls_qos, parse_mls_interface,
    parse_mls_queueing, parse_mls_statistics, parse_queue_sets, queue_sets_tuned,
    parse_dscp_output_q, parse_cos_output_q, parse_auto_qos,
    parse_fed_queue_stats, neighbor_class, select_queue_ports,
    fed_switch_keyword, map_queue, DEFAULT_DSCP_OUTPUT_Q, DEFAULT_COS_OUTPUT_Q,
    FAMILY_CLASSIC, FAMILY_CAT9K, FAMILY_ROUTER_QFP, FAMILY_ROUTER,
    FAMILY_UNKNOWN, FAMILY_NXOS, FAMILY_MQC_SWITCH, FAMILY_CAT4500,
    MLS_QOS, MLS_INTERFACE, MLS_QUEUEING, MLS_STATISTICS, MLS_QUEUE_SET,
    MLS_DSCP_MAP, MLS_COS_MAP, POLICY_MAP_INTERFACE, POLICY_MAP, CLASS_MAP,
    AUTO_QOS, FED_POLICY_SUMMARY, QFP_QOS_GLOBAL, QUEUE_STATS_CAP, READ_TIMEOUT,
)

CLASSIC_POLICY_MAP_INTERFACE = """\
 GigabitEthernet1/0/5

  Service-policy input: LAB-PHONE-IN

    Class-map: LAB-VOICE (match-any)
      1500 packets, 300000 bytes
      5 minute offered rate 2000 bps, drop rate 0 bps
      Match: cos  5
        1500 packets, 300000 bytes
        5 minute rate 2000 bps
      QoS Set
        dscp ef
      police:
          cir 128000 bps, bc 8000 bytes
        conformed 300000 bytes; actions:
          transmit
        exceeded 120 bytes; actions:
          set-dscp-transmit dscp table policed-dscp
        conformed 0000 bps, exceeded 0000 bps

    Class-map: class-default (match-any)
      900 packets, 90000 bytes
      5 minute offered rate 0 bps, drop rate 0 bps
      Match: any
        900 packets, 90000 bytes
        5 minute rate 0 bps
"""

CAT9K_POLICY_MAP_INTERFACE = """\
 GigabitEthernet1/0/48

  Service-policy output: LAB-OUT

    queue stats for all priority classes:
      Queueing
      priority level 1

      (total drops) 25
      (bytes output) 987654

    Class-map: LAB-PQ (match-any)
      0 packets
      Match:  dscp cs4 (32) cs5 (40) ef (46)
        0 packets, 0 bytes
        5 minute rate 0 bps
      Priority: 30% (300000 kbps), burst bytes 7500000,

      Priority Level: 1

    Class-map: LAB-BULK (match-any)
      0 packets
      Match:  dscp af11 (10)
        0 packets, 0 bytes
        5 minute rate 0 bps
      Queueing

      (total drops) 4
      (bytes output) 5000
      bandwidth remaining 10%

    Class-map: class-default (match-any)
      0 packets
      Match: any
      Queueing

      (total drops) 7
      (bytes output) 123456
      bandwidth remaining 25%
"""

ROUTER_POLICY_MAP_INTERFACE = """\
 GigabitEthernet0/0/1

  Service-policy output: LAB-WAN-SHAPE

    Class-map: class-default (match-any)
      500000 packets, 60000000 bytes
      5 minute offered rate 4000000 bps, drop rate 1000 bps
      Match: any
      Queueing
      queue limit 64 packets
      (queue depth/total drops/no-buffer drops) 0/300/0
      (pkts output/bytes output) 499700/59900000
      shape (average) cir 50000000, bc 200000, be 200000
      target shape rate 50000000

      Service-policy : LAB-WAN-CHILD

        Class-map: LAB-RT (match-any)
          80000 packets, 16000000 bytes
          5 minute offered rate 900000 bps, drop rate 0000 bps
          Match: dscp ef (46)
            80000 packets, 16000000 bytes
            5 minute rate 900000 bps
          Priority: 20% (10000 kbps), burst bytes 250000, b/w exceed drops: 12

        Class-map: class-default (match-any)
          420000 packets, 44000000 bytes
          5 minute offered rate 3100000 bps, drop rate 1000 bps
          Match: any
          Queueing
          queue limit 64 packets
          (queue depth/total drops/no-buffer drops/flowdrops) 2/288/0/288
          (pkts output/bytes output) 419712/43900000
          bandwidth remaining 80%
 Control Plane

  Service-policy input: LAB-COPP

    Class-map: class-default (match-any)
      10 packets, 1000 bytes
      5 minute offered rate 0 bps, drop rate 0 bps
      Match: any
"""

SHOW_POLICY_MAP = """\
  Policy Map LAB-PHONE-IN
    Class LAB-VOICE
      set dscp ef
      police 128000 8000 exceed-action policed-dscp-transmit
    Class class-default
      set dscp default

  Policy Map LAB-WAN-CHILD
    Class LAB-RT
      priority percent 20
    Class class-default
      bandwidth remaining percent 80
"""

SHOW_CLASS_MAP = """\
 Class Map match-any LAB-VOICE (id 1)
   Match cos  5
   Match  dscp ef (46)

 Class Map match-all LAB-SIGNALLING (id 2)
   Match access-group name LAB-SIP-ACL

 Class Map match-any class-default (id 0)
   Match any
"""

SHOW_MLS_QOS_ON = """\
QoS is enabled
QoS ip packet dscp rewrite is enabled
"""

SHOW_MLS_INTERFACE = """\
GigabitEthernet1/0/5
Attached policy-map for Ingress: LAB-PHONE-IN
trust state: trust cos
trust mode: trust cos
trust enabled flag: ena
COS override: dis
default COS: 0
DSCP Mutation Map: Default DSCP Mutation Map
Trust device: cisco-phone
qos mode: port-based

GigabitEthernet1/0/6
trust state: not trusted
trust mode: not trusted
trust enabled flag: ena
COS override: dis
default COS: 0
DSCP Mutation Map: Default DSCP Mutation Map
Trust device: none
qos mode: port-based

GigabitEthernet1/0/49
trust state: trust dscp
trust mode: trust dscp
Trust device: none
"""

SHOW_MLS_QUEUEING = """\
GigabitEthernet1/0/5
Egress Priority Queue : enabled
Shaped queue weights (absolute) :  25 0 0 0
Shared queue weights  :  25 25 25 25
The port bandwidth limit : 100  (Operational Bandwidth:100.0)
The port is mapped to qset : 1

GigabitEthernet1/0/49
Egress Priority Queue : disabled
Shaped queue weights (absolute) :  25 0 0 0
Shared queue weights  :  25 25 25 25
The port is mapped to qset : 2
"""

SHOW_MLS_STATISTICS = """\
GigabitEthernet1/0/5 (All statistics are in packets)

  dscp: incoming
-------------------------------

  0 -  4 :         100            0            0            0            0
  5 -  9 :           0            0            0            0            0
 20 - 24 :           0            0            0            0           30
 45 - 49 :           0         1500            0            0            0
 60 - 64 :           0            0            0            0
  dscp: outgoing
-------------------------------

  0 -  4 :          50            0            0            0            0
  cos: incoming
-------------------------------

  0 -  4 :         100            0            0            0            0
  5 -  7 :        1500            0            0
  cos: outgoing
-------------------------------

  0 -  4 :          50            0            0            0            0
  output queues enqueued:
 queue:    threshold1   threshold2   threshold3
-----------------------------------------------
 queue 0:         700           0           0
 queue 1:          50          10           0
 queue 2:           0           0           0
 queue 3:           0           0           0

  output queues dropped:
 queue:    threshold1   threshold2   threshold3
-----------------------------------------------
 queue 0:           3           0           0
 queue 1:           0           0           0
 queue 2:           0           0           0
 queue 3:           0           0           0

Policer: Inprofile:         1500 OutofProfile:            2
"""

SHOW_QUEUE_SET_DEFAULT = """\
Queueset: 1
Queue     :       1       2       3       4
----------------------------------------------
buffers   :      25      25      25      25
threshold1:     100     100     100     100
threshold2:     100     100     100     100
reserved  :      50      50      50      50
maximum   :     400     400     400     400
Queueset: 2
Queue     :       1       2       3       4
----------------------------------------------
buffers   :      25      25      25      25
threshold1:     100     100     100     100
threshold2:     100     100     100     100
reserved  :      50      50      50      50
maximum   :     400     400     400     400
"""

SHOW_DSCP_MAP_DEFAULT = "   Dscp-outputq-threshold map:\n" \
    "     d1 :d2    0     1     2     3     4     5     6     7     8     9 \n" \
    "     ------------------------------------------------------------\n" + "".join(
        f"      {tens} :    " + " ".join(
            DEFAULT_DSCP_OUTPUT_Q[str(tens * 10 + u)]
            for u in range(10) if tens * 10 + u < 64) + " \n"
        for tens in range(7))

SHOW_COS_MAP = """\
   Cos-outputq-threshold map:
              cos:  0     1     2     3     4     5     6     7
              ------------------------------------
  queue-threshold: 2-1   2-1   3-1   3-1   4-1   1-1   4-1   4-1
"""

SHOW_AUTO_QOS = """\
auto qos srnd4
GigabitEthernet1/0/5
auto qos voip cisco-phone
"""

FED_QUEUE_STATS_NEW = """\
----------------------------------------------------------------------------------------------
AQM Global counters
GlobalHardLimit:  3976   |   GlobalHardBufCount: 0
GlobalSoftLimit: 15872   |   GlobalSoftBufCount: 0
----------------------------------------------------------------------------------------------
Asic:0 Core:0 DATA Port:47 Hardware Enqueue Counters
----------------------------------------------------------------------------------------------
 Q Buffers          Enqueue-TH0          Enqueue-TH1          Enqueue-TH2             Qpolicer
   (Count)              (Bytes)              (Bytes)              (Bytes)              (Bytes)
-- ------- -------------------- -------------------- -------------------- --------------------
 0       0                    0               900000                    0                    0
 1       0                   10              5000000                   20                    0
 2       0                    0                    0                    0                    0
Asic:0 Core:0 DATA Port:47 Hardware Drop Counters
---------------------------------------------------------------------------------------------------------------------------------
 Q             Drop-TH0             Drop-TH1             Drop-TH2             SBufDrop              QebDrop           QpolicerDrop
                (Bytes)              (Bytes)              (Bytes)              (Bytes)              (Bytes)              (Bytes)
-- -------------------- -------------------- -------------------- -------------------- -------------------- --------------------
 0                    0                   25                    0                    0                    0                    0
 1                    0                    0                    0                    4                    0                    0
 2                    0                    0                    0                    0                    0                    0
"""

FED_QUEUE_STATS_OLD = """\
DATA Port:0 Enqueue Counters
-------------------------------
Queue Buffers Enqueue-TH0 Enqueue-TH1 Enqueue-TH2 Qpolicer
----- ------- ----------- ----------- ----------- --------
    0       0           0           0         400        0
    1       0           0           0        8000        0
DATA Port:0 Drop Counters
-------------------------------
Queue Drop-TH0    Drop-TH1    Drop-TH2    SBufDrop    QebDrop  QpolicerDrop
----- ----------- ----------- ----------- ----------- ----------- ------------
    0           0           0           9           0           0            0
    1           0           0           0           0           0            0
"""

INVALID = "                 ^\n% Invalid input detected at '^' marker.\n"


def _context(neighbors=(), switchports=(), root_ports=(), stack=1, model="WS-C2960X-48FPD-L"):
    return {
        "model": model,
        "router": False,
        "collector_data": {
            "cdp_lldp": {"parsed": {"neighbors": list(neighbors)}},
            "switchport": {"parsed": {"switchports": list(switchports)}},
            "stp_detail": {"parsed": {"stp_root_summary": [
                {"vlan": 1, "port": p} for p in root_ports]}},
            "device_inventory": {"parsed": {"stack_members": [
                {"switch": str(i + 1)} for i in range(stack)] if stack > 1 else []}},
        },
    }


def _phone(port):
    return {"remote_device": "SEP00005E005301", "local_intf": port,
            "remote_platform": "Cisco IP Phone 8845",
            "remote_capabilities": "Host Phone Two-port Mac Relay"}


def _switch(port, name="LAB-DIST-01", platform="cisco WS-C3850-24XS"):
    return {"remote_device": name, "local_intf": port,
            "remote_platform": platform,
            "remote_capabilities": "Switch IGMP"}


class FakeConn:
    def __init__(self, outputs):
        self.outputs = outputs
        self.sent = []

    def send_command(self, cmd, read_timeout=None):
        self.sent.append((cmd, read_timeout))
        return self.outputs.get(cmd, INVALID)


# --- registry and gating -------------------------------------------------

def test_registered_optional_and_on_by_default():
    collector = get_registry()["qos"]
    assert collector.optional is True
    assert collector.enabled_by_default is True
    assert collector.needs_custom_collect is True
    assert collector.needs_device_context is True


@pytest.mark.parametrize("model,router,family", [
    ("WS-C2960X-48FPD-L", False, FAMILY_CLASSIC),
    ("WS-C3560CX-12PC-S", False, FAMILY_CLASSIC),
    ("C9300-48P", False, FAMILY_CAT9K),
    ("C9200L-48P-4G", False, FAMILY_CAT9K),
    ("C9500-24Y4C", False, FAMILY_CAT9K),
    ("WS-C3850-48P", False, FAMILY_MQC_SWITCH),
    ("WS-C4500X-32", False, FAMILY_CAT4500),
    ("ASR1001-HX", True, FAMILY_ROUTER_QFP),
    ("ISR4351/K9", True, FAMILY_ROUTER_QFP),
    ("CISCO2921/K9", True, FAMILY_ROUTER),
    ("VG310", True, FAMILY_ROUTER),
    ("", False, FAMILY_UNKNOWN),
])
def test_platform_family(model, router, family):
    assert platform_family("cisco_ios", model, router) == family


def test_platform_family_by_device_type():
    assert platform_family("cisco_nxos", "N9K-C93180YC-EX") == FAMILY_NXOS


def test_commands_by_family():
    classic = commands_for("cisco_ios", FAMILY_CLASSIC)
    assert MLS_QOS in classic and POLICY_MAP_INTERFACE in classic
    cat9k = commands_for("cisco_xe", FAMILY_CAT9K)
    assert MLS_QOS not in cat9k and FED_POLICY_SUMMARY in cat9k
    qfp = commands_for("cisco_xe", FAMILY_ROUTER_QFP)
    assert QFP_QOS_GLOBAL in qfp and MLS_QOS not in qfp
    # An unrecognised model gets everything; rejections become n/a.
    assert MLS_QOS in commands_for("cisco_ios", FAMILY_UNKNOWN)
    assert commands_for("cisco_wlc", FAMILY_UNKNOWN) == []


# --- show policy-map interface -------------------------------------------

def test_policy_map_interface_classic_input_policer():
    [policy] = parse_policy_map_interface(CLASSIC_POLICY_MAP_INTERFACE)
    assert policy["interface"] == "GigabitEthernet1/0/5"
    assert policy["direction"] == "input"
    assert policy["policy_name"] == "LAB-PHONE-IN"
    voice, default = policy["classes"]
    assert voice["class_name"] == "LAB-VOICE"
    assert voice["match_type"] == "match-any"
    assert voice["match"] == ["cos 5"]
    assert voice["packets"] == 1500 and voice["bytes"] == 300000
    assert voice["offered_rate_bps"] == 2000
    assert voice["set"] == ["dscp ef"]
    assert voice["police_cir_bps"] == 128000
    assert voice["police_exceeded"] == 120
    assert voice["action"] == ["set dscp ef", "police cir 128000 bps"]
    assert not voice["is_priority"]
    assert default["class_name"] == "class-default"
    assert default["packets"] == 900


def test_policy_map_interface_cat9k_priority_queue():
    [policy] = parse_policy_map_interface(CAT9K_POLICY_MAP_INTERFACE)
    assert policy["direction"] == "output"
    assert policy["priority_queue"] == {"level": 1, "drops": 25, "bytes_output": 987654}
    pq, bulk, default = policy["classes"]
    assert pq["is_priority"] and pq["priority_percent"] == 30
    assert pq["priority_kbps"] == 300000
    assert pq["match"] == ["dscp cs4 (32) cs5 (40) ef (46)"]
    assert pq["packets"] == 0
    assert bulk["drops"] == 4 and bulk["bandwidth"] == "remaining 10%"
    assert default["drops"] == 7


def test_policy_map_interface_nested_child_and_control_plane():
    policies = parse_policy_map_interface(ROUTER_POLICY_MAP_INTERFACE)
    parent, child, copp = policies
    assert parent["policy_name"] == "LAB-WAN-SHAPE"
    assert [c["class_name"] for c in parent["classes"]] == ["class-default"]
    shaped = parent["classes"][0]
    assert shaped["shape_bps"] == 50000000
    assert shaped["drops"] == 300 and shaped["queue_depth"] == 0
    assert shaped["pkts_output"] == 499700
    assert child["policy_name"] == "LAB-WAN-CHILD"
    assert child["parent_policy"] == "LAB-WAN-SHAPE"
    assert child["parent_class"] == "class-default"
    assert child["direction"] == "output"
    rt, cdef = child["classes"]
    assert rt["is_priority"] and rt["priority_percent"] == 20
    assert rt["priority_kbps"] == 10000 and rt["priority_drops"] == 12
    assert rt["match"] == ["dscp ef (46)"]
    assert cdef["drops"] == 288 and cdef["queue_depth"] == 2
    assert cdef["bandwidth"] == "remaining 80%"
    assert copp["interface"] == "Control Plane"
    assert copp["direction"] == "input"


def test_policy_map_interface_empty_and_error():
    assert parse_policy_map_interface("") == []
    assert parse_policy_map_interface(INVALID) == []


# --- definitions -----------------------------------------------------------

def test_policy_map_definitions_and_hash():
    defs = {p["name"]: p for p in parse_policy_maps(SHOW_POLICY_MAP)}
    assert set(defs) == {"LAB-PHONE-IN", "LAB-WAN-CHILD"}
    phone = defs["LAB-PHONE-IN"]
    assert [c["name"] for c in phone["classes"]] == ["LAB-VOICE", "class-default"]
    assert phone["classes"][0]["actions"] == [
        "set dscp ef", "police 128000 8000 exceed-action policed-dscp-transmit"]
    # Whitespace does not change the hash; a different body does.
    again = parse_policy_maps(SHOW_POLICY_MAP.replace("set dscp ef", "set  dscp   ef"))
    assert {p["name"]: p["hash"] for p in again}["LAB-PHONE-IN"] == phone["hash"]
    drift = parse_policy_maps(SHOW_POLICY_MAP.replace("set dscp ef", "set dscp cs5"))
    assert {p["name"]: p["hash"] for p in drift}["LAB-PHONE-IN"] != phone["hash"]


def test_class_map_definitions():
    defs = {c["name"]: c for c in parse_class_maps(SHOW_CLASS_MAP)}
    assert defs["LAB-VOICE"]["match_type"] == "match-any"
    assert defs["LAB-VOICE"]["match"] == ["cos 5", "dscp ef (46)"]
    assert defs["LAB-SIGNALLING"]["match_type"] == "match-all"
    assert defs["LAB-SIGNALLING"]["acls"] == ["LAB-SIP-ACL"]
    assert "class-default" in defs


# --- classic MLS -----------------------------------------------------------

def test_mls_qos_global():
    assert parse_mls_qos(SHOW_MLS_QOS_ON) == {"mls_qos_enabled": True, "dscp_rewrite": True}
    assert parse_mls_qos("QoS is disabled\n")["mls_qos_enabled"] is False
    assert parse_mls_qos("")["mls_qos_enabled"] is None


def test_mls_interface_trust():
    trust = parse_mls_interface(SHOW_MLS_INTERFACE)
    assert trust["GigabitEthernet1/0/5"]["trust_state"] == "trust cos"
    assert trust["GigabitEthernet1/0/5"]["trust_device"] == "cisco-phone"
    assert trust["GigabitEthernet1/0/5"]["ingress_policy"] == "LAB-PHONE-IN"
    assert trust["GigabitEthernet1/0/6"]["trust_state"] == "not trusted"
    assert trust["GigabitEthernet1/0/49"]["trust_state"] == "trust dscp"


def test_mls_queueing():
    q = parse_mls_queueing(SHOW_MLS_QUEUEING)
    assert q["GigabitEthernet1/0/5"]["expedite_queue"] is True
    assert q["GigabitEthernet1/0/5"]["queue_set"] == 1
    assert q["GigabitEthernet1/0/49"]["expedite_queue"] is False
    assert q["GigabitEthernet1/0/49"]["queue_set"] == 2


def test_mls_statistics_counters_and_queue_numbering():
    stats = parse_mls_statistics(SHOW_MLS_STATISTICS)["GigabitEthernet1/0/5"]
    assert stats["dscp_in"] == {"0": 100, "24": 30, "46": 1500}
    assert stats["dscp_out"] == {"0": 50}
    assert stats["cos_in"] == {"0": 100, "5": 1500}
    # Output queue 0 in the statistics is queue 1 in the maps.
    assert stats["enqueued"] == {"1": 700, "2": 60, "3": 0, "4": 0}
    assert stats["dropped"]["1"] == 3
    assert stats["policer_out_of_profile"] == 2


def test_queue_sets_default_and_tuned():
    sets = parse_queue_sets(SHOW_QUEUE_SET_DEFAULT)
    assert sets["1"]["buffers"] == [25, 25, 25, 25]
    assert queue_sets_tuned(sets) is False
    tuned = parse_queue_sets(SHOW_QUEUE_SET_DEFAULT.replace(
        "buffers   :      25      25      25      25",
        "buffers   :      15      25      40      20", 1))
    assert queue_sets_tuned(tuned) is True
    assert queue_sets_tuned({}) is None


def test_output_queue_maps():
    dscp = parse_dscp_output_q(SHOW_DSCP_MAP_DEFAULT)
    assert dscp == DEFAULT_DSCP_OUTPUT_Q
    assert map_queue(dscp["46"]) == 1
    assert parse_cos_output_q(SHOW_COS_MAP) == DEFAULT_COS_OUTPUT_Q


def test_auto_qos_global_and_per_interface():
    auto = parse_auto_qos(SHOW_AUTO_QOS)
    assert auto["global"] == ["auto qos srnd4"]
    assert auto["interfaces"] == {"GigabitEthernet1/0/5": ["auto qos voip cisco-phone"]}
    assert parse_auto_qos("AutoQoS not enabled on any interface\n") == \
        {"global": [], "interfaces": {}}


# --- Catalyst 9000 queue counters -----------------------------------------

def test_fed_queue_stats_current_format():
    rows = parse_fed_queue_stats(FED_QUEUE_STATS_NEW)
    assert rows == [
        {"queue_id": 0, "enqueued": 900000, "dropped": 25},
        {"queue_id": 1, "enqueued": 5000030, "dropped": 4},
        {"queue_id": 2, "enqueued": 0, "dropped": 0},
    ]


def test_fed_queue_stats_older_format():
    rows = parse_fed_queue_stats(FED_QUEUE_STATS_OLD)
    assert rows == [{"queue_id": 0, "enqueued": 400, "dropped": 9},
                    {"queue_id": 1, "enqueued": 8000, "dropped": 0}]


# --- neighbours and port selection ----------------------------------------

@pytest.mark.parametrize("neighbor,expected", [
    (_phone("Gi1/0/1"), "phone"),
    ({"remote_device": "LAB-AP-01", "remote_platform": "cisco AIR-AP2802I-B-K9",
      "remote_capabilities": "Trans-Bridge Source-Route-Bridge IGMP"}, "ap"),
    ({"remote_device": "LAB-AP-02", "remote_platform": "cisco C9120AXI-B",
      "remote_capabilities": "Router Trans-Bridge"}, "ap"),
    ({"remote_device": "LAB-VG-01", "remote_platform": "cisco VG310",
      "remote_capabilities": "Router"}, "vg"),
    ({"remote_device": "LAB-CUBE-01", "remote_platform": "cisco ISR4351/K9",
      "remote_capabilities": "Router Switch IGMP"}, "router"),
    (_switch("Gi1/0/49"), "switch"),
    ({"remote_device": "host", "remote_platform": "Linux",
      "remote_capabilities": "Host"}, "other"),
])
def test_neighbor_class(neighbor, expected):
    assert neighbor_class(neighbor) == expected


def test_select_queue_ports_uplinks_first_and_capped():
    neighbors = [_phone(f"GigabitEthernet1/0/{i}") for i in range(1, 31)]
    neighbors.append(_switch("TenGigabitEthernet1/1/1"))
    switchports = [{"interface": "Te1/1/2", "operational_mode": "trunk"},
                   {"interface": "Po1", "operational_mode": "trunk"},
                   {"interface": "Gi1/0/40", "operational_mode": "static access"}]
    selected, eligible = select_queue_ports(_context(neighbors, switchports))
    assert eligible == 32
    assert len(selected) == QUEUE_STATS_CAP
    assert selected[:2] == ["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2"]
    assert "Port-channel1" not in selected
    assert "GigabitEthernet1/0/40" not in selected


def test_fed_switch_keyword():
    assert fed_switch_keyword("GigabitEthernet2/0/7", stacked=True) == "2"
    assert fed_switch_keyword("GigabitEthernet2/0/7", stacked=False) == "active"


# --- collect() end to end --------------------------------------------------

def _classic_outputs():
    return {
        POLICY_MAP_INTERFACE: CLASSIC_POLICY_MAP_INTERFACE,
        CLASS_MAP: SHOW_CLASS_MAP,
        POLICY_MAP: SHOW_POLICY_MAP,
        AUTO_QOS: SHOW_AUTO_QOS,
        MLS_QOS: SHOW_MLS_QOS_ON,
        MLS_INTERFACE: SHOW_MLS_INTERFACE,
        MLS_QUEUEING: SHOW_MLS_QUEUEING,
        MLS_STATISTICS: SHOW_MLS_STATISTICS,
        MLS_QUEUE_SET: SHOW_QUEUE_SET_DEFAULT,
        MLS_DSCP_MAP: SHOW_DSCP_MAP_DEFAULT,
        MLS_COS_MAP: SHOW_COS_MAP,
    }


def test_collect_classic_switch_joins_neighbours():
    conn = FakeConn(_classic_outputs())
    ctx = _context(
        neighbors=[_phone("Gi1/0/5"), _phone("Gi1/0/6"), _switch("Gi1/0/49")],
        switchports=[{"interface": "Gi1/0/5", "voice_vlan": "110",
                      "operational_mode": "static access"},
                     {"interface": "Gi1/0/49", "operational_mode": "trunk"}])
    result = QosCollector().collect(conn, "cisco_ios", context=ctx)
    assert all(t == READ_TIMEOUT for _, t in conn.sent)
    assert not any("fed" in c for c, _ in conn.sent)
    parsed = result["parsed"]
    assert parsed["qos_global"]["platform_family"] == FAMILY_CLASSIC
    assert parsed["qos_global"]["mls_qos_enabled"] is True
    assert parsed["qos_global"]["auto_qos_applied"] is True
    assert parsed["qos_global"]["queue_set_tuned"] is False
    ports = {i["interface"]: i for i in parsed["interfaces"]}
    gi5 = ports["GigabitEthernet1/0/5"]
    assert gi5["neighbor_class"] == "phone"
    assert gi5["voice_vlan"] == "110"
    assert gi5["trust_state"] == "trust cos"
    assert gi5["ingress_policy"] == "LAB-PHONE-IN"
    assert gi5["auto_qos_macro"] == "auto qos voip cisco-phone"
    assert gi5["expedite_queue"] is True and not gi5["is_uplink"]
    gi49 = ports["GigabitEthernet1/0/49"]
    assert gi49["is_uplink"] and gi49["is_trunk"]
    assert gi49["neighbor_class"] == "switch"
    queues = [q for q in parsed["queues"] if q["interface"] == "GigabitEthernet1/0/5"]
    assert [q["is_priority"] for q in queues] == [True, False, False, False]
    assert queues[0]["dropped"] == 3 and queues[0]["unit"] == "packets"
    dscp_in = [d for d in parsed["dscp_counters"] if d["direction"] == "in"][0]
    assert dscp_in["dscp"]["46"] == 1500
    assert parsed["maps"]["dscp_output_q"]["46"] == "01-01"
    assert not any(k.startswith("_") for k in parsed)


def test_collect_cat9k_runs_capped_queue_stats_per_member():
    outputs = {
        POLICY_MAP_INTERFACE: CAT9K_POLICY_MAP_INTERFACE,
        CLASS_MAP: SHOW_CLASS_MAP, POLICY_MAP: SHOW_POLICY_MAP,
        AUTO_QOS: "AutoQoS not enabled on any interface\n",
        "show platform hardware fed switch 1 qos queue stats interface "
        "GigabitEthernet1/0/48": FED_QUEUE_STATS_NEW,
    }
    neighbors = [_switch("Gi1/0/48")] + [
        _phone(f"GigabitEthernet2/0/{i}") for i in range(1, 30)]
    conn = FakeConn(outputs)
    result = QosCollector().collect(
        conn, "cisco_xe", context=_context(neighbors, stack=2, model="C9300-48P"))
    sent = [c for c, _ in conn.sent]
    assert MLS_QOS not in sent
    fed = [c for c in sent if "qos queue stats" in c]
    assert len(fed) == QUEUE_STATS_CAP
    assert fed[0].endswith("switch 1 qos queue stats interface GigabitEthernet1/0/48")
    assert "fed switch 2 qos queue stats interface GigabitEthernet2/0/1" in fed[1]
    parsed = result["parsed"]
    assert parsed["qos_global"]["platform_family"] == FAMILY_CAT9K
    assert parsed["qos_global"]["mls_qos_enabled"] is None
    assert parsed["queue_stats_ports"]["capped"] is True
    assert parsed["queue_stats_ports"]["eligible"] == 30
    queues = [q for q in parsed["queues"] if q["interface"] == "GigabitEthernet1/0/48"]
    # Queue 0 holds the priority class, the first queuing class of LAB-OUT.
    assert [q["is_priority"] for q in queues] == [True, False, False]
    assert queues[0]["dropped"] == 25 and queues[0]["unit"] == "bytes"
    # Rejected queue-stat commands are recorded, not parsed.
    rejected = [c for c in parsed["failed_commands"] if "qos queue stats" in c]
    assert len(rejected) == QUEUE_STATS_CAP - 1


def test_collect_router_without_classic_commands():
    conn = FakeConn({POLICY_MAP_INTERFACE: ROUTER_POLICY_MAP_INTERFACE})
    result = QosCollector().collect(
        conn, "cisco_xe", context={"model": "ASR1001-HX", "router": True})
    sent = [c for c, _ in conn.sent]
    assert MLS_QOS not in sent and QFP_QOS_GLOBAL in sent
    parsed = result["parsed"]
    ports = {i["interface"]: i for i in parsed["interfaces"]}
    assert ports["GigabitEthernet0/0/1"]["egress_policy"] == "LAB-WAN-SHAPE"
    assert "Control Plane" not in ports


def test_collect_all_rejected_is_not_applicable():
    result = QosCollector().collect(FakeConn({}), "cisco_ios", context={})
    assert result["parsed"]["not_applicable"] is True
    assert not any(k.startswith("_") for k in result["parsed"])


def test_collect_unsupported_platform():
    result = QosCollector().collect(FakeConn({}), "cisco_wlc")
    assert result["parsed"]["not_applicable"] is True
