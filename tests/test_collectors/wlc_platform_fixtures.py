"""Synthetic AireOS 8.5 / 8.10 platform output. Names are lab-*, addresses
RFC 5737 or private, MACs and serials made up."""

# 8.5 on a 5508: no Licensing Type, no Field Recovery line, under a day up.
SYSINFO_85 = """\
Manufacturer's Name.............................. Cisco Systems Inc.
Product Name..................................... Cisco Controller
Product Version.................................. 8.5.182.0
Bootloader Version............................... 1.0.20
Build Type....................................... DATA + WPS

System Name...................................... lab-wlc-02
System Location.................................. Lab rack 4
System Contact................................... lab-noc
System ObjectID.................................. 1.3.6.1.4.1.9.1.1069
Redundancy Mode.................................. Disabled
IP Address....................................... 192.0.2.60
Last Reset....................................... Power on reset
System Up Time................................... 0 days 5 hrs 2 mins 40 secs
Configured Country............................... GB  - United Kingdom
Internal Temp Alarm Limits....................... 0 to 65 C
Internal Temperature............................. +38 C
External Temperature............................. +22 C
Fan Status....................................... 4900 rpm
Power Supply 1................................... Absent
Power Supply 2................................... Present, OK
Number of WLANs.................................. 2
Number of Active Clients......................... 0
Memory Current Usage............................. Unknown
CPU Current Usage................................ Unknown
Burned-in MAC Address............................ 00:A0:C9:00:00:20
Maximum number of APs supported.................. 500
"""

INVENTORY_5520 = """\
Burned-in MAC Address............................ 00:A0:C9:00:00:01
Power Supply 1................................... Present, OK
Power Supply 2................................... Present, OK
Maximum number of APs supported.................. 1500

NAME: "Chassis"    , DESCR: "Cisco 5520 Wireless Controller"
PID: AIR-CT5520-K9, VID: V01, SN: FCW0000A001
NAME: "NIC Card 1" , DESCR: "Intel X710 10G NIC"
PID: AIR-CT5520-NIC, VID: V01, SN: FCW0000A101
"""

INVENTORY_5508 = """\
Burned-in MAC Address............................ 00:A0:C9:00:00:20
Crypto Accelerator 1............................. Absent
Crypto Accelerator 2............................. Absent
Power Supply 1................................... Absent
Power Supply 2................................... Present, OK
Maximum number of APs supported.................. 500
NAME: "Chassis"   , DESCR: "Chassis"
PID: AIR-CT5508-K9, VID: V02, SN: FCW0000A002
"""

BOOT = """\
Primary Boot Image............................... 8.10.185.0 (default) (active)
Backup Boot Image................................ 8.10.181.0
"""

BOOT_BACKUP_ACTIVE = """\
Primary Boot Image............................... 8.5.182.0 (default)
Backup Boot Image................................ 8.5.171.0 (active)
"""

LICENSE_CAPACITY = """\
Licensed Feature    Max Count    Current Count    Remaining Count
-----------------   ---------    -------------    ---------------
AP Count            500          120              380
"""

LICENSE_SUMMARY_RTU = """\
Index 1   Feature: ap_count
        Period left: Permanent
        License Type: Permanent
        License State: Active, In Use
        License Count: 500/500/0
        License Priority: High
RTU Licensing is in use on this controller
"""

# 5508 CLM: a base count plus one adder, one inactive evaluation.
LICENSE_ALL_5508 = """\
License Store: Primary License Storage
StoreIndex:  0  Feature: base-ap-count    Version: 1.0
        License Type: Permanent
        License State: Active, In Use
        License Count: 50/0/0
        License Priority: Medium
StoreIndex:  1  Feature: ap-count    Version: 1.0
        License Type: Permanent
        License State: Active, In Use
        License Count: 25/0/0
        License Priority: Medium
StoreIndex:  2  Feature: ap-count    Version: 1.0
        License Type: Evaluation
        License State: Inactive
        License Count: 500/0/0
        License Priority: None
"""

LICENSE_DOTTED = """\
Licensed AP count................................ 250
"""

LICENSE_SMART = """\
Smart Licensing is ENABLED

Registration:
  Status: REGISTERED
  Smart Account: lab-account
"""

CPU = """\
Current CPU(s) load: 4%

Individual CPU load: 2%/0%, 5%/1%, 3%/1%, 6%/2%
"""

CPU_CORES_ONLY = """\
Individual CPU load: 10%/2%, 6%/2%
"""

MEMORY_BYTES = """\
System Memory Statistics:
Total System Memory............: 3943690240 bytes
Used System Memory.............: 1577476096 bytes
Free System Memory.............: 2366214144 bytes
Bytes allocated from RTOS......: 524288 bytes
Chunks Free....................: 4
"""

MEMORY_KB_ONELINE = """\
System Memory Statistics: Total System Memory: 3851260 kB, Free System Memory: 1925630 kB
"""

MEMORY_USED_ONLY = """\
Total System Memory.............................. 2000000 kB
Used System Memory............................... 500000 kB
"""

REDUNDANCY_SUMMARY_SSO = """\
 Redundancy Mode = SSO ENABLED
     Local State = ACTIVE
      Peer State = STANDBY HOT
            Unit = Primary
         Unit ID = 00:A0:C9:00:00:01
Redundancy State = SSO
    Mobility MAC = 00:A0:C9:00:00:01
     BulkSync Status = Complete
Average Redundancy Peer Reachability Latency = 412 Micro Seconds
Average Management Gateway Reachability Latency = 1120 Micro Seconds
"""

REDUNDANCY_SUMMARY_OFF = """\
 Redundancy Mode = SSO DISABLED
     Local State = ACTIVE
      Peer State = N/A
            Unit = Secondary (HA SKU)
         Unit ID = 00:A0:C9:00:00:20
Redundancy State = N/A
    Mobility MAC = 00:A0:C9:00:00:20
"""

# Real redundancy port addresses are link-local; documentation addresses here.
REDUNDANCY_DETAIL = """\
 Redundancy Management IP Address................. 192.0.2.41
 Peer Redundancy Management IP Address............ 192.0.2.42
 Redundancy Port IP Address....................... 198.51.100.41
 Peer Redundancy Port IP Address.................. 198.51.100.42
 Peer Service Port IP Address..................... 10.0.0.42
 Redundancy Port Status........................... UP
"""

REDUNDANCY_DETAIL_OFF = """\
 Redundancy Management IP Address................. 0.0.0.0
 Peer Redundancy Management IP Address............ 0.0.0.0
 Redundancy Port IP Address....................... 0.0.0.0
 Peer Redundancy Port IP Address.................. 0.0.0.0
"""

REDUNDANCY_STATISTICS = """\
Redundancy Manager Statistics
 Number of Switchovers............................ 2
 Last Switchover Time............................. Thu Oct  1 08:12:44 2026
 Last Switchover Reason........................... Active unit reload
 Keep Alive Request Sent.......................... 1209344
 Keep Alive Response Received..................... 1209330
"""

REDUNDANCY_TIMERS = """\
Keep Alive Timeout............................... 100 milliseconds
Peer Search Timeout.............................. 120 seconds
Management Gateway Failover...................... Enabled
Local Keep Alive Retries......................... 3
Peer Keep Alive Retries.......................... 3
"""

REDUNDANCY_TIMERS_SECONDS = """\
Keep Alive Timeout............................... 1 seconds
Peer Search Timeout.............................. 120000 milliseconds
"""

PEER_ROUTE = """\
Peer Network Routes:

 Destination Network         Netmask              Gateway
 ---------------------   -------------------   -------------------
 10.10.0.0                  255.255.0.0          192.0.2.1
 203.0.113.0                255.255.255.0        192.0.2.1
"""

INTERFACE_DETAIL_MGMT = """\
Interface Name................................... management
MAC Address...................................... 00:a0:c9:00:00:01
IP Address....................................... 192.0.2.40
IP Netmask....................................... 255.255.255.0
IP Gateway....................................... 192.0.2.1
External NAT IP State............................ Disabled
External NAT IP Address.......................... 0.0.0.0
Link Local IPv6 Address.......................... fe80::2a0:c9ff:fe00:1/64
STATE ........................................... REACHABLE
Primary IPv6 Address............................. ::/128
STATE ........................................... NONE
Primary IPv6 Gateway............................. ::
VLAN............................................. untagged
Quarantine-vlan.................................. 0
NAS-Identifier................................... lab-wlc-01
Active Physical Port............................. LAG (13)
Primary Physical Port............................ LAG (13)
Backup Physical Port............................. Unconfigured
DHCP Proxy Mode.................................. Global
Primary DHCP Server.............................. 192.0.2.10
Secondary DHCP Server............................ Unconfigured
DHCP Option 82................................... Disabled
IPv4 ACL......................................... Unconfigured
URL ACL.......................................... Unconfigured
mDNS Profile Name................................ Unconfigured
AP Manager....................................... Yes
Guest Interface.................................. N/A
L2 Multicast..................................... Enabled
"""

# 8.5 dynamic interface: "Physical Port", a quarantine VLAN, an ACL, IPv6.
INTERFACE_DETAIL_DYN_85 = """\
Interface Name................................... lab-quarantine
MAC Address...................................... 00:a0:c9:00:00:21
IP Address....................................... 10.40.0.5
IP Netmask....................................... 255.255.255.0
IP Gateway....................................... 10.40.0.1
Primary IPv6 Address............................. 2001:db8:40::5/64
VLAN............................................. 40
Quarantine-vlan.................................. 41
Physical Port.................................... 2
Backup Port...................................... 0
Primary DHCP Server.............................. 10.40.0.2
Secondary DHCP Server............................ 10.40.0.3
DHCP Proxy Mode.................................. Enabled
ACL.............................................. lab-acl-in
NAS-Identifier................................... none
AP Manager....................................... No
Guest Interface.................................. Yes
"""

INTERFACE_GROUPS = """\
Interface Group Name             Total Interfaces  Total WLANs  Total AP Groups  Quarantine Interface
-------------------------------- ----------------  -----------  ---------------  --------------------
lab-ifg-users                    2                 1            0                No
lab-ifg-quar                     1                 0            1                Yes
"""

RUN_CONFIG_IFG = """\
config interface group create lab-ifg-users
config interface group interface add lab-ifg-users lab-guest
config interface group interface add lab-ifg-users lab-voice
config interface group interface add lab-ifg-quar lab-quarantine
"""

# 8.5 / 5508 with copper and SFP ports.
PORT_SUMMARY_85 = """\
           STP   Admin   Physical   Physical   Link   Link
Pr  Type   Stat  Mode    Mode       Status     Status Trap     POE    SFPType
--  ------ ----  ------- ---------- ---------- ------ ------- ------- ----------
1   Normal Forw  Enable  Auto       1000 Full  Up     Enable  N/A     1000BaseSX
2   Normal Disa  Disable Auto       Auto       Down   Enable  N/A     Not Present
3   Normal Forw  Enable  1000 Full  1000 Full  Up     Disable N/A     1000BaseT
"""

LAG_ON = "LAG Enabled\n"
LAG_OFF = """\
LAG Disabled
"""

PORT_STATS = """\
PORT 1
 Binary Counters:
   Total Bytes Received.......................... 9812345678
   Packets Received 64 Octets.................... 1200
   Total Packets Received......................... 81234567
   Unicast Packets Received...................... 80000000
   Multicast Packets Received.................... 1000000
   Broadcast Packets Received.................... 234567
   Total Packets Received with MAC Errors........ 17
   Jabbers Received.............................. 1
   Fragments/Undersize Received.................. 2
   Alignment Errors.............................. 0
   FCS Errors.................................... 12
   Overruns...................................... 2
   Received Packets Discarded.................... 40
   Total Bytes Transmitted....................... 8812345678
   Total Packets Transmitted Successfully........ 71234567
   Unicast Packets Transmitted................... 70000000
   Total Transmit Errors......................... 3
   FCS Errors.................................... 1
   Total Transmit Packets Discarded.............. 5
   Single Collision Frames....................... 0
"""

# Older code: no totals, so the error counters are summed.
PORT_STATS_NO_TOTALS = """\
   Total Packets Received......................... 1000
   Jabbers Received.............................. 1
   Fragments/Undersize Received.................. 1
   Alignment Errors.............................. 1
   FCS Errors.................................... 4
   Overruns...................................... 0
   Total Packets Transmitted Successfully........ 900
   FCS Errors.................................... 2
   Tx Oversized.................................. 0
   Underrun Errors............................... 1
"""

CDP_NEIGHBORS = """\
----------------------------------
Device ID: lab-sw-01.lab.example
Entry address(es):
  IP address: 192.0.2.2
Platform: cisco C9300-48P,  Capabilities: Router Switch IGMP
Interface: 1,  Port ID (outgoing port): TenGigabitEthernet1/0/1
Holdtime : 155 sec

Version :
Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.3.4, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport

advertisement version: 2
----------------------------------
Device ID: lab-sw-02
Entry address(es):
  IP address: 192.0.2.3
Platform: cisco WS-C3850-24XS,  Capabilities: Switch IGMP
Interface: 2,  Port ID (outgoing port): TenGigabitEthernet2/0/1
Holdtime : 170 sec
"""

TIME_810 = """\
Time............................................. Thu Nov 12 10:00:00 2026

Timezone delta................................... 0:0
Timezone location................................ (GMT) London, Lisbon, Dublin, Edinburgh

NTP Servers
    NTP Version.................................. 3
    NTP Polling Interval.........................  3600

     Index     NTP Key Index      NTP Server       Status            NTP Msg Auth Status
    -------  ---------------------------------------------------------------------------
       1            0              192.0.2.123     In Sync              AUTH DISABLED
       2            1              192.0.2.124     Not Synced           AUTH SUCCESS
"""

TIME_NOT_SYNCED = """\
Time............................................. Thu Nov 12 10:00:00 2026

Timezone delta................................... 0:0

NTP Servers
    NTP Polling Interval.........................  86400

     Index     NTP Key Index      NTP Server       Status            NTP Msg Auth Status
    -------  ---------------------------------------------------------------------------
       1            0              lab-ntp-01      Not Synced           AUTH DISABLED
"""

# 8.0-era: table without a Status column.
TIME_NO_STATUS = """\
Time............................................. Thu Nov 12 10:00:00 2026

Timezone delta................................... 0:0

NTP Servers
    NTP Polling Interval.........................  3600

     Index     NTP Key Index      NTP Server       NTP Msg Auth Status
    -------  ---------------------------------------------------------------
       1            0              192.0.2.123        AUTH DISABLED
"""

TIME_DOTTED_NTP = """\
Time............................................. Thu Nov 12 10:00:00 2026
Timezone delta................................... 0:0
NTP Server 1..................................... 192.0.2.123
NTP Server 2..................................... 0.0.0.0
"""

TIME_NO_NTP = """\
Time............................................. Thu Nov 12 10:00:00 2026

Timezone delta................................... 0:0

NTP Servers
    NTP Polling Interval.........................  3600

     Index     NTP Key Index      NTP Server       Status            NTP Msg Auth Status
    -------  ---------------------------------------------------------------------------
"""

COREDUMP_NONE = """\
Core Dump is enabled

FTP Server IP.................................... 0.0.0.0
FTP Filename.....................................
FTP Username.....................................

No Core Dump Files in Flash Memory
"""

COREDUMP_PRESENT = """\
Core Dump is disabled

Core Dump file is saved on flash

Sw Version....................................... 8.10.185.0
Time Stamp....................................... Thu Oct  1 08:12:00 2026
File Size........................................ 4718592
File Name Suffix................................. core_lab-wlc-01.gz
"""

AP_CRASH = """\
Local Core Files:
lrad_lab-ap-01.rdump0 (156)
The number in parentheses indicates the size of the file. The size should be greater than zero if a core dump file has been uploaded.

AP Crash Files:
lab-ap-02_crash_20261001
"""

AP_CRASH_NONE = """\
Local Core Files:
No Core Files Found

AP Crash Files:
No Crash files
"""

SWITCHCONFIG = """\
802.3x Flow Control Mode......................... Disabled
FIPS prerequisite features....................... Disabled
WLANCC prerequisite features..................... Disabled
UCAPL prerequisite features...................... Disabled
DTLS WLC MIC..................................... Enabled
secret obfuscation............................... Enabled
Strong Password Check Features:

       case-check ...........Enabled
       consecutive-check ....Enabled
       default-check .......Enabled
       username-check ......Enabled
       position-check ......Disabled
Min. Password length .....8

Mgmt User:
       Password Lifetime [days].........0
       Password Lockout.................Enabled
       Lockout Attempts.................3
       Lockout Timeout [mins]...........5

SNMPv3 User:
       Password Lifetime [days].........0
       Password Lockout.................Disabled
       Lockout Attempts.................3
       Lockout Timeout [mins]...........5
"""

STATS_SWITCH = """\
Packets Received Without Error................... 51234567
Broadcast Packets Received....................... 23456
Packets Received With Error...................... 4
Packets Transmitted Without Error................ 41234567
Broadcast Packets Transmitted.................... 1234
Transmit Packet Errors........................... 0
Address Entries Currently In Use................. 12
VLAN Entries Currently In Use.................... 4
Time Since Counters Last Cleared................. 41 day 3 hr 12 min 9 sec
"""

SERIAL = """\
Serial Port Login Timeout (minutes)......... 15
Baud Rate (bps)............................ 9600
Character Size............................. 8
Flow Control:.............................. Disable
Stop Bits.................................. 1
Parity Type:............................... none
"""

SESSIONS = """\
CLI Login Timeout (minutes)............ 5
Maximum Number of CLI Sessions......... 5
"""

LOGINSESSION = """\
ID User Name               Connection From Idle Time  Session Time
-- ---------------         --------------- ---------- ------------
00 lab-admin               EIA-232         00:00:00   00:19:04
*01 lab-ro                 192.0.2.99      00:00:00   00:00:03
"""

INCORRECT = "Incorrect usage. Use the '?' or <TAB> key to list commands."
