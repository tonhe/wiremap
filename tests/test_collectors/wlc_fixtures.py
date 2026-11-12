"""Synthetic AireOS output. Names are lab-*, addresses RFC 5737 or private,
MACs and serials made up."""

SYSINFO = """\
Manufacturer's Name.............................. Cisco Systems Inc.
Product Name..................................... Cisco Controller
Product Version.................................. 8.10.185.0
RTOS Version..................................... 8.10.185.0
Bootloader Version............................... 8.5.103.0
Emergency Image Version.......................... 8.10.185.0
Field Recovery Image Version..................... 7.6.101.1
Firmware Version................................. PIC 20.0

OUI File Last Update Time........................ Sun Sep 07 10:44:07 IST 2014

Build Type....................................... DATA + WPS

System Name...................................... lab-wlc-01
System Location.................................. Lab/Building 1/Floor 2
System Contact................................... lab-noc
System ObjectID.................................. 1.3.6.1.4.1.9.1.1615
Redundancy Mode.................................. SSO
IP Address....................................... 192.0.2.40
IPv6 Address..................................... ::
Last Reset....................................... Software reset
System Up Time................................... 41 days 3 hrs 12 mins 9 secs
System Timezone Location......................... (GMT) London, Lisbon, Dublin, Edinburgh
System Stats Realtime Interval................... 5
System Stats Normal Interval..................... 180

Configured Country............................... US  - United States
Operating Environment............................ Commercial (10 to 35 C)
Internal Temp Alarm Limits....................... 10 to 38 C
Internal Temperature............................. +23 C
Fan Status....................................... OK
Power Supply 1................................... Present, OK
Power Supply 2................................... Present, OK

State of 802.11b Network......................... Enabled
State of 802.11a Network......................... Enabled
Number of WLANs.................................. 3
Number of Active Clients......................... 42

OUI Classification Failure Count................. 0

Memory Current Usage............................. 39
Memory Average Usage............................. 39
CPU Current Usage................................ 4
CPU Average Usage................................ 3

Burned-in MAC Address............................ 00:A0:C9:00:00:01
Maximum number of APs supported.................. 1500
System Nas-Id....................................
WLC MIC Certificate Types........................ SHA1/SHA2
Licensing Type................................... RTU
"""

INTERFACE_SUMMARY = """\
 Number of Interfaces.......................... 5

Interface Name                   Port Vlan Id  IP Address      Type    Ap Mgr Guest
-------------------------------- ---- -------- --------------- ------- ------ -----
lab-guest                        LAG  20       10.20.0.5       Dynamic No     No
lab-voice                        LAG  30       10.30.0.5       Dynamic No     No
management                       LAG  untagged 192.0.2.40      Static  Yes    No
redundancy-management            LAG  untagged 192.0.2.41      Static  No     No
virtual                          N/A  N/A      192.0.2.1       Static  No     No
"""

WLAN_SUMMARY = """\
Number of WLANs.................................. 3

WLAN ID  WLAN Profile Name / SSID               Status    Interface Name        PMIPv6 Mobility
-------  -------------------------------------  --------  --------------------  ---------------
1        lab-corp / lab-corp                     Enabled   management            none
2        lab-guest / lab-guest                   Enabled   lab-guest             none
3        lab-voice / lab-voice                   Disabled  lab-voice             none
"""

AP_SUMMARY = """\
Number of APs.................................... 2

Global AP User Name.............................. Not Configured
Global AP Dot1x User Name........................ Not Configured

AP Name             Slots  AP Model              Ethernet MAC       Location          Country     IP Address       Clients   DSE Location
------------------  -----  --------------------  -----------------  ----------------  ----------  ---------------  --------  --------------
lab-ap-01            2     AIR-AP2802I-B-K9      00:11:22:00:00:01  floor 1           US          10.1.1.10          30      [0 ,0 ,0 ]
lab-ap-02            2     AIR-CAP2602I-A-K9     00:11:22:00:00:02  floor 2           US          10.1.1.11          12      [0 ,0 ,0 ]
"""

JOIN_SUMMARY = """\
Number of APs.............................................. 3

Base Mac             AP EthernetMac       AP Name           IP Address         Status
00:11:22:aa:00:01    00:11:22:00:00:01    lab-ap-01         10.1.1.10          Joined
00:11:22:aa:00:02    00:11:22:00:00:02    lab-ap-02         10.1.1.11          Joined
00:11:22:aa:00:03    00:11:22:00:00:03    lab-ap-03         10.1.1.12          Not Joined
"""
# AireOS prints this table without a dash rule on some code; the 8.10 form:
JOIN_SUMMARY_RULED = """\
Number of APs.............................................. 3

Base Mac             AP EthernetMac       AP Name           IP Address         Status
-----------------    -----------------    ---------------   ---------------    ----------
00:11:22:aa:00:01    00:11:22:00:00:01    lab-ap-01         10.1.1.10          Joined
00:11:22:aa:00:02    00:11:22:00:00:02    lab-ap-02         10.1.1.11          Joined
00:11:22:aa:00:03    00:11:22:00:00:03    lab-ap-03         10.1.1.12          Not Joined
"""

RF_PROFILE_SUMMARY = """\
Number of RF Profiles............................ 1
Out Of Box State................................. Disabled

RF Profile Name                  Band     Description                          Applied
-------------------------------- -------  ------------------------------------ ----------
lab-rf-5g                        5 GHz    <none>                               Yes
"""

ACL_SUMMARY = """\
ACL Counter Status               Disabled
----------------------------------------
IPv4 ACL Name                    Applied
-------------------------------- -------
lab-preauth                      Yes
"""

FLEX_GROUP_SUMMARY = """\
FlexConnect Group Summary: Count: 1
Group Name                # Aps
lab-flex-01                  4
"""

PORT_SUMMARY = """\
           STP   Admin   Physical   Physical   Link   Link
Pr  Type   Stat  Mode    Mode       Status     Status Trap     POE    SFPType
--  ------ ----  ------- ---------- ---------- ------ ------- ------- ----------
1   Normal Forw  Enable  Auto       10000 Full Up     Enable  N/A     10GBase-SR
2   Normal Disa  Enable  Auto       Auto       Down   Enable  N/A     Not Present
"""

CLIENT_SUMMARY = """\
Number of Clients................................ 2

Number of PMIPV6 Clients......................... 0

                                                                        GLAN/
                                                                        RLAN/
MAC Address       AP Name                        Slot Status        WLAN  Auth Protocol         Port Wired Tunnel  Role
----------------- ------------------------------ ---- ------------- ----- ---- ---------------- ---- ----- ------- ----------------
a4:5e:60:00:00:01 lab-ap-01                       1   Associated     1    Yes  802.11ac(5 GHz)  1    No    No      Local
a4:5e:60:00:00:02 lab-ap-02                       0   Associated     2    No   802.11n(2.4 GHz) 1    No    No      Local
"""

EXCLUSION = """\
Excluded Clients

MAC Address             Exclusion Reason        Time Remaining (in secs)
-----------             ----------------        ------------------------
a4:5e:60:00:00:09       802.1X Failure           42
"""

TRAPLOG = """\
Number of Traps Since Last Reset ............ 12
Number of Traps Since Log Last Displayed .... 12

Log System Time              Trap
--- ------------------------ -------------------------------------------------
  0 Thu Nov 12 10:00:01 2026 Client Excluded: MACAddress:a4:5e:60:00:00:09 Base Radio MAC :00:11:22:aa:00:01 Slot: 1 User Name: lab-person Ip Address: 10.1.50.20 Reason:802.1X Failure
  1 Thu Nov 12 09:00:00 2026 AP Disassociated. Base Radio MAC:00:11:22:aa:00:02
"""

NETUSER = """\
Maximum logins allowed for a given user name...... Unlimited

User Name               WLAN Id   User Type   Lifetime  Description
---------------------   -------   ---------   --------  -----------
lab-guest-user          2         Guest       Unlimited lab guest
"""

SNMPCOMMUNITY = """\
SNMP Community Name Client IP Address Client IP Mask  IPv6 Address  IPv6 Prefix Length Access Mode Status
------------------- ----------------- --------------- ------------- ------------------ ----------- ------
public              0.0.0.0           0.0.0.0         ::/0          0                  Read Only   Enable
lab-ro-comm         192.0.2.0         255.255.255.0   ::/0          0                  Read Only   Enable
"""

RUN_CONFIG = """\
config sysname lab-wlc-01
config radius auth add 1 192.0.2.50 1812 ascii LabRadiusKey1
config snmp community create lab-ro-comm
config snmp community accessmode ro lab-ro-comm
config wlan security wpa akm psk set-key ascii LabPskValue9 2
config netuser add lab-guest-user GuestPw55 wlan 2 userType guest lifetime 0
config netuser description lab-guest-user "lab guest"
config mgmtuser add lab-admin AdminPw77 read-write
"""

SHOW_WLAN_2 = """\
WLAN Identifier.................................. 2
Profile Name..................................... lab-guest
Network Name (SSID).............................. lab-guest
Status........................................... Enabled
PSK Key.......................................... LabPskValue9
"""

CONTROLLER = {
    "show sysinfo": SYSINFO,
    "show interface summary": INTERFACE_SUMMARY,
    "show wlan summary": WLAN_SUMMARY,
    "show ap summary": AP_SUMMARY,
    "show ap join stats summary all": JOIN_SUMMARY_RULED,
    "show rf-profile summary": RF_PROFILE_SUMMARY,
    "show acl summary": ACL_SUMMARY,
    "show flexconnect group summary": FLEX_GROUP_SUMMARY,
    "show port summary": PORT_SUMMARY,
    "show client summary": CLIENT_SUMMARY,
    "show exclusionlist": EXCLUSION,
    "show traplog": TRAPLOG,
    "show netuser summary": NETUSER,
    "show snmpcommunity": SNMPCOMMUNITY,
    "show run-config commands": RUN_CONFIG,
    "show wlan 2": SHOW_WLAN_2,
    "show flexconnect acl summary": "Incorrect usage. Use the '?' or <TAB> key to list commands.",
    "config paging disable": "Incorrect usage. Use the '?' or <TAB> key to list commands.",
}

# Every secret and client identifier above; none may survive collection.
SECRETS = ["LabRadiusKey1", "LabPskValue9", "GuestPw55", "AdminPw77", "lab-ro-comm"]
CLIENT_IDS = ["a4:5e:60:00:00:01", "a4:5e:60:00:00:02", "a4:5e:60:00:00:09", "lab-person",
              "10.1.50.20", "lab-guest-user"]
