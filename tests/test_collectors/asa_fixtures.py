"""Synthetic ASA / ASAv command output for the ASA collector and report tests.

Lab names, documentation and private addresses only.
"""

VERSION_ASA = """\
Cisco Adaptive Security Appliance Software Version 9.16(4)
SSP Operating System Version 2.10(1.162)
Device Manager Version 7.18(1)

Compiled on Wed 01-Feb-23 10:00 GMT by builders
System image file is "disk0:/asa9-16-4-smp-k8.bin"
Config file at boot was "startup-config"

LAB-FW-01 up 120 days 3 hours
failover cluster up 200 days 4 hours
Start-up time 25 secs

Hardware:   FPR-2130, 13703 MB RAM, CPU MIPS 1200 MHz, 1 CPU (12 cores)

Licensed features for this platform:
Maximum Physical Interfaces       : Unlimited      perpetual
Maximum VLANs                     : 1024           perpetual
Failover                          : Active/Active  perpetual
Encryption-DES                    : Enabled        perpetual
Encryption-3DES-AES               : Enabled        perpetual
Security Contexts                 : 2              perpetual
AnyConnect Premium Peers          : 250            perpetual
Other VPN Peers                   : 7500           perpetual
Total VPN Peers                   : 7500           perpetual

This platform has an FPR-2130 Security Plus license.

Serial Number: JAD00000AAA
Configuration register is 0x1
Configuration last modified by enable_15 at 10:00:00.000 UTC Mon Nov 3 2026
"""

VERSION_ASAV = """\
Cisco Adaptive Security Appliance Software Version 9.18(3)
Device Manager Version 7.18(1)

System image file is "boot:/asa9183-smp-k8.bin"
LAB-VFW-01 up 30 days 2 hours

Hardware:   ASAv, 8192 MB RAM, CPU Xeon 4100/6100/8100 series 2200 MHz, 1 CPU (4 cores)
Model Id:   ASAv30

License mode: Smart Licensing
ASAv Platform License State: Licensed

Licensed features for this platform:
Maximum Physical Interfaces       : 10             perpetual
Encryption-3DES-AES               : Enabled        perpetual
AnyConnect Premium Peers          : 250            perpetual

Serial Number: 9A0000AAAAA
"""

INVENTORY = """\
Name: "Chassis", DESCR: "Cisco Firepower 2130 Security Appliance, 1U"
PID: FPR-2130          , VID: V01     , SN: JAD00000AAA

Name: "power supply 0", DESCR: "Firepower 2000 Series AC Power Supply"
PID: FPR2K-PWR-AC-400  , VID: V01     , SN: LIT00000AAA
"""

CLOCK = "14:22:31.123 UTC Fri Nov 7 2026\n"
MODE_SINGLE = "Security context mode: single\n"
MODE_MULTIPLE = "Security context mode: multiple\n"
CPU = "CPU utilization for 5 seconds = 12%; 1 minute: 75%; 5 minutes: 72%\n"
MEMORY = """\
Free memory:        1717986918 bytes (20%)
Used memory:        6871947674 bytes (80%)
-------------     ------------------
Total memory:       8589934592 bytes (100%)
"""
DISK = """\
-#- --length-- -----date/time------ path
  1 33 Nov 03 2026 10:00:00 asa9-16-4-smp-k8.bin

8571076608 bytes total (2142769152 bytes free)
"""
BOOTVAR = "BOOT variable = disk0:/asa9-16-4-smp-k8.bin\nCurrent BOOT variable = disk0:/asa9-16-4-smp-k8.bin\n"
PROCESSES = """\
Hardware  CPU Utilization(PC: 5Sec 1Min 5Min Process)
0x000055aa00000001  0x00007f0000000001     4.0%     6.5%     6.1%   DATAPATH-0-1825
0x000055aa00000002  0x00007f0000000002     1.0%     0.5%     0.4%   SSH
0x000055aa00000003  0x00007f0000000003     2.0%     2.5%     2.4%   Logger
"""
BLOCKS = """\
  SIZE    MAX    LOW    CNT
     0   1450   1446   1450
     4    100     99     99
  1550   6144      0   6100
"""
ASP_DROP = """\
Frame drop:
  Flow is denied by configured rule (acl-drop)                            12345
  First TCP packet not SYN (tcp-not-syn)                                    678
  Slowpath security checks failed (sp-security-failed)                       90
Last clearing: Never

Flow drop:
  NAT failed (nat-failed)                                                    40
"""
CONN_COUNT = "80000 in use, 95000 most used\n"
XLATE_COUNT = "20 in use, 300 most used\n"
RESOURCE_USAGE = """\
Resource                 Current         Peak        Limit        Denied Context
SSH Server                     1            2            5             0 System
Conns                      80000        95000       100000             0 System
Xlates                        20          300    unlimited             0 System
"""
CRASHINFO = """\
: Saved_Crash at 10:00:00 UTC Mar 1 2026
Thread Name: DATAPATH-1-1826
Traceback:
"""
NTP_SYNCED = "Clock is synchronized, stratum 3, reference is 192.0.2.123\n"
NTP_UNSYNCED = "Clock is unsynchronized, stratum 16, no reference clock\n"
CRITICAL_LOGS = """\
Nov 07 2026 10:00:01: %ASA-2-106001: Inbound TCP connection denied
Nov 07 2026 10:00:02: %ASA-1-105005: (Primary) Lost Failover communications with mate on interface inside
"""
CHECKSUM = "Cryptochecksum: 1a2b3c4d 5e6f7a8b 9c0d1e2f 3a4b5c6d\n"
STARTUP_SAME = "Cryptochecksum:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\n"
STARTUP_DIFFERENT = "Cryptochecksum:ffffffffffffffffffffffffffffffff\n"

FAILOVER_ACTIVE = """\
Failover On
Failover unit Primary
Failover LAN Interface: FOLINK GigabitEthernet0/3 (up)
Reconnect timeout 0:00:00
Unit Poll frequency 1 seconds, holdtime 15 seconds
Interface Poll frequency 5 seconds, holdtime 25 seconds
Interface Policy 1
Monitored Interfaces 3 of 1293 maximum
Version: Ours 9.16(4), Mate 9.16(3)
Serial Number: Ours JAD00000AAA, Mate JAD00000AAB
Last Failover at: 10:15:22 UTC Oct 1 2026
        This host: Primary - Active
                Active time: 3000000 (sec)
                slot 0: FPR-2130 hw/sw rev (1.0/9.16(4)) status (Up Sys)
                  Interface outside (198.51.100.2): Normal (Monitored)
                  Interface inside (10.0.0.1): Normal (Monitored)
                  Interface dmz (10.1.0.1): Failed (Waiting)
        Other host: Secondary - Standby Ready
                Active time: 0 (sec)
                slot 0: FPR-2130 hw/sw rev (1.0/9.16(3)) status (Up Sys)
                  Interface outside (198.51.100.3): Normal (Monitored)
                  Interface inside (10.0.0.2): Normal (Monitored)

Stateful Failover Logical Update Statistics
        Link : STATELINK GigabitEthernet0/4 (down)
        Stateful Obj    xmit       xerr       rcv        rerr
        General         1000       0          900        0
"""
FAILOVER_OFF = "Failover Off\nFailover unit Primary\nFailover LAN Interface: not Configured\n"
FAILOVER_HISTORY = """\
==========================================================================
From State                 To State                   Reason
==========================================================================
10:15:20 UTC Oct 1 2026
Not Detected               Negotiation                No Error

10:15:22 UTC Oct 1 2026
Negotiation                Just Active                No Active unit found

==========================================================================
"""
MONITOR_INTERFACE = """\
       This host: Primary - Active
               Interface outside (198.51.100.2): Normal (Monitored)
               Interface inside (10.0.0.1): Normal (Monitored)
               Interface dmz (10.1.0.1): Failed (Waiting)
       Other host: Secondary - Standby Ready
               Interface outside (198.51.100.3): Normal (Monitored)
"""

RUNNING_CONFIG = """\
: Saved
ASA Version 9.16(4)
!
hostname LAB-FW-01
enable password ***** pbkdf2
passwd ***** encrypted
names
!
interface GigabitEthernet0/0
 description LAB uplink
 nameif outside
 security-level 0
 ip address 198.51.100.2 255.255.255.248 standby 198.51.100.3
!
interface GigabitEthernet0/1
 channel-group 1 mode active
 no nameif
 no security-level
 no ip address
!
interface Port-channel1.10
 vlan 10
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0 standby 10.0.0.2
!
interface Management0/0
 management-only
 nameif management
 security-level 100
 ip address 192.0.2.10 255.255.255.0
!
same-security-traffic permit inter-interface
ssh 0.0.0.0 0.0.0.0 outside
ssh 10.0.0.0 255.0.0.0 inside
ssh version 2
ssh key-exchange group dh-group14-sha256
telnet 10.0.0.0 255.0.0.0 inside
http server enable
http 0.0.0.0 0.0.0.0 outside
icmp permit any outside
aaa-server LAB-TACACS protocol tacacs+
aaa-server LAB-TACACS (inside) host 10.0.0.20
 key *****
aaa authentication ssh console LOCAL
aaa authentication http console LAB-TACACS LOCAL
aaa authentication enable console LAB-TACACS LOCAL
aaa local authentication attempts max-fail 5
username lab-admin password ***** pbkdf2 privilege 15
username lab-ro password ***** pbkdf2 privilege 5
snmp-server host inside 10.0.0.30 community ***** version 2c
snmp-server host inside 10.0.0.31 poll community *****
snmp-server community *****
snmp-server user lab-snmp LAB-GRP v3 encrypted auth sha ***** priv aes 256 *****
logging enable
logging timestamp
logging buffered informational
logging trap debugging
logging host inside 10.0.0.40
logging host inside 10.0.0.41 6/1470
flow-export destination inside 10.0.0.50 2055
ntp server 10.0.0.60 key 1
dns server-group DefaultDNS
 name-server 10.0.0.53 inside
 domain-name lab.example
banner motd Authorised use only
management-access inside
ssl trust-point LAB-TP outside
crypto map LAB-MAP 10 set peer 203.0.113.9
crypto map LAB-MAP 20 set peer 203.0.113.10
tunnel-group 203.0.113.9 type ipsec-l2l
tunnel-group 203.0.113.9 ipsec-attributes
 ikev1 pre-shared-key *****
tunnel-group LAB-RA type remote-access
tunnel-group LAB-RA ipsec-attributes
 ikev2 local-authentication certificate LAB-TP
failover
failover lan unit primary
failover lan interface FOLINK GigabitEthernet0/3
failover key *****
call-home
 profile License
license smart
 feature tier standard
: end
"""

SHOW_INTERFACE = """\
Interface GigabitEthernet0/0 "outside", is up, line protocol is up
  Hardware is i82574L rev00, BW 1000 Mbps, DLY 10 usec
        Auto-Duplex(Full-duplex), Auto-Speed(1000 Mbps)
        Description: LAB uplink
        MAC address 0000.5e00.5301, MTU 1500
        IP address 198.51.100.2, subnet mask 255.255.255.248
        100000 packets input, 98765432 bytes, 0 no buffer
        Received 120 broadcasts, 0 runts, 0 giants
        500 input errors, 200 CRC, 0 frame, 3 overrun, 0 ignored, 0 abort
        200000 packets output, 123456789 bytes, 4 underruns
        0 output errors, 0 collisions, 0 interface resets
  Traffic Statistics for "outside":
        100000 packets input, 96000000 bytes
        200000 packets output, 120000000 bytes
        12 packets dropped
      1 minute input rate 120 pkts/sec,  45000 bytes/sec
      1 minute output rate 130 pkts/sec,  50000 bytes/sec
      1 minute drop rate, 0 pkts/sec
      5 minute input rate 100 pkts/sec,  40000 bytes/sec
      5 minute output rate 110 pkts/sec,  45000 bytes/sec
      5 minute drop rate, 0 pkts/sec
Interface GigabitEthernet0/1 "", is up, line protocol is up
  Hardware is i82574L rev00, BW 1000 Mbps, DLY 10 usec
        Full-Duplex, 1000 Mbps
        MTU not set
Interface Port-channel1.10 "inside", is up, line protocol is up
  Hardware is EtherChannel/LACP, BW 1000 Mbps, DLY 10 usec
        VLAN identifier 10
        MAC address 0000.5e00.5302, MTU 1500
        IP address 10.0.0.1, subnet mask 255.255.255.0
        5000 packets input, 1000000 bytes, 0 no buffer
        0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort
        6000 packets output, 2000000 bytes, 0 underruns
        0 output errors, 0 collisions, 0 interface resets
Interface GigabitEthernet0/5 "", is administratively down, line protocol is down
  Hardware is i82574L rev00, BW 1000 Mbps, DLY 10 usec
Interface Management0/0 "management", is up, line protocol is up
  Hardware is i82574L rev00, BW 1000 Mbps, DLY 10 usec
        Management-only interface. Blocked 0 through-the-device packets
        MAC address 0000.5e00.5303, MTU 1500
        IP address 192.0.2.10, subnet mask 255.255.255.0
"""
NAMEIF = """\
Interface                Name                     Security
GigabitEthernet0/0       outside                    0
Port-channel1.10         inside                   100
Management0/0            management               100
"""
IP_BRIEF = """\
Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         198.51.100.2    YES CONFIG up                    up
GigabitEthernet0/1         unassigned      YES unset  up                    up
Port-channel1.10           10.0.0.1        YES CONFIG up                    up
GigabitEthernet0/5         unassigned      YES unset  administratively down down
Management0/0              192.0.2.10      YES CONFIG up                    up
"""
CERTIFICATES = """\
Certificate
  Status: Available
  Certificate Serial Number: 1a2b3c
  Certificate Usage: General Purpose
  Public Key Type: RSA (2048 bits)
  Signature Algorithm: SHA256 with RSA Encryption
  Issuer Name:
    cn=LAB-CA
    o=Lab
  Subject Name:
    cn=vpn.lab.example
  Validity Date:
    start date: 10:00:00 UTC Jan 1 2026
    end   date: 10:00:00 UTC Dec 1 2026
  Storage: config
  Associated Trustpoints: LAB-TP

CA Certificate
  Status: Available
  Certificate Serial Number: 01
  Certificate Usage: Signature
  Public Key Type: RSA (4096 bits)
  Signature Algorithm: SHA256 with RSA Encryption
  Issuer Name:
    cn=LAB-CA
    o=Lab
  Subject Name:
    cn=LAB-CA
    o=Lab
  Validity Date:
    start date: 10:00:00 UTC Jan 1 2020
    end   date: 10:00:00 UTC Jan 1 2030
  Associated Trustpoints: LAB-TP
"""
AAA_SERVER = """\
Server Group:    LAB-TACACS
Server Protocol: tacacs+
Server Address:  10.0.0.20
Server port:     49
Server status:   FAILED, Server disabled at 10:00:00 UTC Fri Nov 7 2026
"""
ACCESS_LIST = """\
access-list cached ACL log flows: total 0, denied 0 (deny-flow-max 4096)
access-list LAB-OUTSIDE-IN; 12 elements; name hash: 0x1a2b3c4d
access-list LAB-OUTSIDE-IN line 1 extended permit ip any any (hitcnt=10) 0x11111111
access-list LAB-INSIDE-IN; 3 elements; name hash: 0x2b3c4d5e
"""
NAT_DETAIL = """\
Manual NAT Policies (Section 1)
1 (inside) to (outside) source static LAB-NET LAB-NET destination static LAB-REMOTE LAB-REMOTE no-proxy-arp route-lookup
    translate_hits = 0, untranslate_hits = 0

Auto NAT Policies (Section 2)
1 (inside) to (outside) source dynamic LAB-NET interface
    translate_hits = 500, untranslate_hits = 20
"""
VPN_SUMMARY = """\
---------------------------------------------------------------------------
VPN Session Summary
---------------------------------------------------------------------------
                               Active : Cumulative : Peak Concur : Inactive
                             ----------------------------------------------
AnyConnect Client            :     12 :       3456 :          45 :        0
  SSL/TLS/DTLS               :     12 :       3456 :          45 :        0
Site-to-Site VPN             :      1 :        120 :           2
  IKEv1 IPsec                :      1 :        120 :           2
---------------------------------------------------------------------------
Total Active and Inactive    :     13             Total Cumulative :   3576
Device Total VPN Capacity    :   7500
Device Load                  :      1%
"""
L2L = """\
Session Type: LAN-to-LAN

Connection   : 203.0.113.9
Index        : 1                      IP Addr      : 203.0.113.9
"""
CONTEXTS = """\
Context Name      Class      Interfaces           Mode         URL
*admin            default    Management0/0        Routed       disk0:/admin.cfg
 lab-ctx-a        default    GigabitEthernet0/0,  Routed       disk0:/lab-ctx-a.cfg
                             GigabitEthernet0/1
 lab-ctx-b        default    GigabitEthernet0/2   Transparent  disk0:/lab-ctx-b.cfg

Total active Security Contexts: 3
"""
CONTEXT_CONFIG = """\
hostname lab-ctx-a
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.0
telnet 0.0.0.0 0.0.0.0 outside
snmp-server community Plain-ctx-secret
"""


def single_mode_outputs(failover=FAILOVER_OFF):
    return {
        "show clock": CLOCK, "show version": VERSION_ASA, "show inventory": INVENTORY,
        "show mode": MODE_SINGLE, "show cpu usage": CPU, "show memory": MEMORY,
        "show disk0:": DISK, "show bootvar": BOOTVAR,
        "show processes cpu-usage sorted non-zero": PROCESSES, "show blocks": BLOCKS,
        "show asp drop": ASP_DROP, "show conn count": CONN_COUNT,
        "show xlate count": XLATE_COUNT, "show resource usage": RESOURCE_USAGE,
        "show crashinfo | include Saved|Traceback|Thread Name|ERROR": CRASHINFO,
        "show ntp status": NTP_SYNCED, "show logging | include %ASA-[1-3]-": CRITICAL_LOGS,
        "show failover": failover, "show failover history": FAILOVER_HISTORY,
        "show monitor-interface": MONITOR_INTERFACE if failover is FAILOVER_ACTIVE else "",
        "show running-config": RUNNING_CONFIG, "show checksum": CHECKSUM,
        "show startup-config | include Cryptochecksum": STARTUP_DIFFERENT,
        "show interface": SHOW_INTERFACE, "show nameif": NAMEIF,
        "show interface ip brief": IP_BRIEF, "show crypto ca certificates": CERTIFICATES,
        "show aaa-server": AAA_SERVER, "show access-list": ACCESS_LIST,
        "show nat detail": NAT_DETAIL, "show vpn-sessiondb summary": VPN_SUMMARY,
        "show vpn-sessiondb l2l": L2L,
    }


class FakeAsa:
    """send_command over a dict; unknown commands answer as an ASA rejects them.
    changeto switches which dict answers."""

    def __init__(self, outputs, contexts=None, reject=(), timeout=()):
        self.outputs = outputs
        self.contexts = contexts or {}
        self.reject = set(reject)
        self.timeout = set(timeout)
        self.current = None
        self.sent = []

    def send_command(self, cmd, **kwargs):
        self.sent.append((self.current, cmd, kwargs.get("read_timeout")))
        if cmd in self.timeout:
            raise TimeoutError("Pattern not detected")
        if cmd in self.reject:
            return "ERROR: % Invalid input detected at '^' marker."
        if cmd == "changeto system":
            self.current = None
            return ""
        if cmd.startswith("changeto context "):
            name = cmd.split()[-1]
            if name not in self.contexts:
                return "ERROR: % Invalid input detected at '^' marker."
            self.current = name
            return ""
        source = self.contexts[self.current] if self.current else self.outputs
        if cmd in source:
            return source[cmd]
        return "ERROR: % Invalid input detected at '^' marker."
