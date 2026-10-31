import pytest

from app.collectors.interface_counters import (
    InterfaceCountersCollector, parse_interfaces, READ_TIMEOUT,
)


IOS_SHOW_INTERFACES = """\
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 0000.5e00.5301 (bia 0000.5e00.5301)
  Description: uplink to lab-core-01
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
  Last input 00:00:01, output 00:00:00, output hang never
  Last clearing of "show interface" counters 3w2d
  Input queue: 0/2000/12/0 (size/max/drops/flushes); Total output drops: 4521
  Queueing strategy: fifo
  5 minute input rate 2000 bits/sec, 3 packets/sec
  5 minute output rate 5000 bits/sec, 6 packets/sec
     8765432 packets input, 987654321 bytes, 0 no buffer
     Received 12345 broadcasts (10000 multicasts)
     3 runts, 0 giants, 0 throttles
     1250 input errors, 1200 CRC, 47 frame, 0 overrun, 0 ignored
     0 watchdog, 10000 multicast, 0 pause input
     0 input packets with dribble condition detected
     1234567 packets output, 123456789 bytes, 0 underruns
     0 output errors, 0 collisions, 2 interface resets
     0 unknown protocol drops
GigabitEthernet1/0/2 is administratively down, line protocol is down (disabled)
  Hardware is Gigabit Ethernet, address is 0000.5e00.5302 (bia 0000.5e00.5302)
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
     0 packets input, 0 bytes, 0 no buffer
     0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 collisions, 1 interface resets
Vlan10 is up, line protocol is up
  Hardware is Ethernet SVI, address is 0000.5e00.5310 (bia 0000.5e00.5310)
  Internet address is 192.0.2.1/24
  Last input 00:00:00, output 00:00:00, output hang never
     100 packets input, 6400 bytes, 0 no buffer
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     200 packets output, 12800 bytes, 0 underruns
     0 output errors, 0 interface resets
"""

NXOS_SHOW_INTERFACE = """\
Ethernet1/1 is up
admin state is up, Dedicated Interface
  Hardware: 1000/10000/25000 Ethernet, address: 0000.5e00.5401 (bia 0000.5e00.5401)
  Description: link to lab-leaf-02
  MTU 9216 bytes, BW 10000000 Kbit , DLY 10 usec
  Last link flapped 1week(s) 2day(s)
  Last clearing of "show interface" counters never
  RX
    500 unicast packets  20 multicast packets  5 broadcast packets
    525 input packets  65000 bytes
    0 jumbo packets  0 storm suppression packets
    0 runts  0 giants  9 CRC  0 no buffer
    9 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  3 input discard
    0 Rx pause
  TX
    700 unicast packets  10 multicast packets  0 broadcast packets
    710 output packets  90000 bytes
    0 jumbo packets
    0 output error  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble  7 output discard
    0 Tx pause
Vlan1 is down (Administratively down), line protocol is down, autostate enabled
  Hardware is EtherSVI, address is  0000.5e00.5400
  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec
"""


@pytest.fixture
def collector():
    return InterfaceCountersCollector()


def test_commands(collector):
    assert collector.get_commands("cisco_ios") == ["show interfaces"]
    assert collector.get_commands("cisco_nxos") == ["show interface"]
    assert collector.get_commands("vyos") == []
    assert collector.needs_custom_collect is True


def test_parse_ios():
    rows = {r["interface"]: r for r in parse_interfaces(IOS_SHOW_INTERFACES)}
    assert list(rows) == ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "Vlan10"]
    gi1 = rows["GigabitEthernet1/0/1"]
    assert gi1["status"] == "up" and gi1["protocol"] == "up"
    assert gi1["description"] == "uplink to lab-core-01"
    assert gi1["input_packets"] == 8765432
    assert gi1["output_packets"] == 1234567
    assert gi1["input_errors"] == 1250
    assert gi1["crc"] == 1200
    assert gi1["frame"] == 47
    assert gi1["runts"] == 3
    assert gi1["input_drops"] == 12
    assert gi1["output_drops"] == 4521
    assert gi1["interface_resets"] == 2
    assert gi1["last_input"] == "00:00:01"
    assert gi1["last_output"] == "00:00:00"
    assert gi1["counters_cleared"] == "3w2d"
    gi2 = rows["GigabitEthernet1/0/2"]
    assert gi2["status"] == "administratively down"
    assert gi2["last_input"] == "never"
    vlan = rows["Vlan10"]
    assert vlan["output_drops"] is None
    assert vlan["collisions"] is None


def test_parse_nxos():
    rows = {r["interface"]: r for r in parse_interfaces(NXOS_SHOW_INTERFACE)}
    assert list(rows) == ["Ethernet1/1", "Vlan1"]
    eth = rows["Ethernet1/1"]
    assert eth["status"] == "up"
    assert eth["input_packets"] == 525
    assert eth["output_packets"] == 710
    assert eth["crc"] == 9
    assert eth["input_errors"] == 9
    assert eth["input_drops"] == 3
    assert eth["output_drops"] == 7
    assert eth["collisions"] == 0
    assert eth["last_flap"] == "1week(s)"
    assert rows["Vlan1"]["status"] == "down"


class _RecordingConnection:
    def __init__(self, output):
        self.output = output
        self.calls = []

    def send_command(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        return self.output


def test_collect_uses_long_read_timeout(collector):
    conn = _RecordingConnection(IOS_SHOW_INTERFACES)
    result = collector.collect(conn, "cisco_xe")
    assert conn.calls == [("show interfaces", {"read_timeout": READ_TIMEOUT})]
    assert READ_TIMEOUT > 30
    assert len(result["parsed"]["interfaces"]) == 3
    assert result["raw"]["show interfaces"] == IOS_SHOW_INTERFACES


def test_collect_records_send_failure(collector):
    class Boom:
        def send_command(self, cmd, **kwargs):
            raise TimeoutError("Pattern not detected")
    result = collector.collect(Boom(), "cisco_ios")
    assert result["parsed"]["collector_failed"] is True


def test_collect_without_commands(collector):
    result = collector.collect(_RecordingConnection(""), "paloalto_panos")
    assert result["parsed"]["not_applicable"] is True
