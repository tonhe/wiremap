"""Synthetic AireOS 8.5 / 8.10 service command output for wlc_services tests.

Names are lab-*, addresses are documentation or private ranges, MACs are
00:11:22:xx:xx:xx. Text is as the collector stores it: secrets already read
<REDACTED> and local net user names are pseudonyms.
"""

RADIUS_SUMMARY = """\
Vendor Id Backward Compatibility................. Disabled
Call Station Id Case............................. lower
Accounting Call Station Id Type.................. Mac Address
Auth Call Station Id Type........................ AP's Radio MAC Address:SSID
Extended Source Ports Support.................... Enabled
Aggressive Failover.............................. Enabled
Keywrap.......................................... Disabled

Fallback Test:
    Test Mode.................................... Passive
    Probe User Name.............................. lab-probe
    Interval (in seconds)........................ 300

MAC Delimiter for Authentication Messages........ hyphen
MAC Delimiter for Accounting Messages............ hyphen
RADIUS Authentication Framed-MTU................. 1300 Bytes

Authentication Servers

Idx  Type  Server Address    Port    State     Tout  MgmtTout RFC3576  IPSec - state/Profile Name/RadiusRegionString
---  ----  ----------------  ------  --------  ----  -------- -------  -------------------------------------------------------
1    NM    192.0.2.50        1812    Enabled   5     5        Enabled  Disabled - none/unknown/off
2    N     192.0.2.51        1812    Disabled  2     5        Disabled Disabled - none/unknown/off

Accounting Servers

Idx  Type  Server Address    Port    State     Tout  RFC3576  IPSec - state/Profile Name/RadiusRegionString
---  ----  ----------------  ------  --------  ----  -------  -------------------------------------------------------
1    N     192.0.2.50        1813    Enabled   5     N/A      Disabled - none/unknown/off
"""

# Older code: no Type or MgmtTout column and no keywrap line.
RADIUS_SUMMARY_OLD = """\
Vendor Id Backward Compatibility................. Disabled
Credentials Caching.............................. Disabled
Call Station Id Type............................. IP Address
Aggressive Failover.............................. Enabled

Authentication Servers

Idx  Server Address    Port    State     Tout  RFC3576  IPSec - AuthMode/Phase1/Group/Lifetime/Auth/Encr
---  ----------------  ------  --------  ----  -------  ------------------------------------------------
1    10.20.0.5         1812    Enabled   2     Disabled Disabled - none/unknown/group-0/0 none/none

Accounting Servers

Idx  Server Address    Port    State     Tout  RFC3576  IPSec - AuthMode/Phase1/Group/Lifetime/Auth/Encr
---  ----------------  ------  --------  ----  -------  ------------------------------------------------
"""

RADIUS_AUTH_STATS = """\
Authentication Servers:

Server Index..................................... 1
Server Address................................... 192.0.2.50
Msg Round Trip Time.............................. 3 (msec)
First Requests................................... 1000
Retry Requests................................... 40
Accept Responses................................. 800
Reject Responses................................. 120
Challenge Responses.............................. 60
Malformed Msgs................................... 0
Bad Authenticator Msgs........................... 2
Pending Requests................................. 0
Timeout Requests................................. 30
Unknowntype Msgs................................. 0
Other Drops...................................... 1

Server Index..................................... 2
Server Address................................... 192.0.2.51
Msg Round Trip Time.............................. 0 (msec)
First Requests................................... 0
Retry Requests................................... 0
Accept Responses................................. 0
Reject Responses................................. 0
Challenge Responses.............................. 0
Malformed Msgs................................... 0
Bad Authenticator Msgs........................... 0
Pending Requests................................. 0
Timeout Requests................................. 0
Unknowntype Msgs................................. 0
Other Drops...................................... 0
"""

RADIUS_ACCT_STATS = """\
Accounting Servers:

Server Index..................................... 1
Server Address................................... 192.0.2.50
Msg Round Trip Time.............................. 2 (msec)
First Requests................................... 5000
Retry Requests................................... 10
Accounting Responses............................. 4990
Malformed Msgs................................... 0
Bad Authenticator Msgs........................... 0
Pending Requests................................. 0
Timeout Requests................................. 10
Unknowntype Msgs................................. 0
Other Drops...................................... 0
"""

RFC3576_STATS = """\
Total Disconnect Requests........................ 4
Total CoA Requests............................... 7
Total Retransmissions............................ 0
Total Responses Sent............................. 11
Total Responses Dropped.......................... 0

Server Index..................................... 1
Server Address................................... 192.0.2.50
Disconnect Requests.............................. 4
Disconnect NAKs.................................. 0
CoA Requests..................................... 7
CoA NAKs......................................... 1
"""

TACACS_SUMMARY = """\
Authentication Servers

Idx  Server Address    Port    State     Tout  MgmtTout
---  ----------------  ------  --------  ----  --------
1    192.0.2.60        49      Enabled   5     5
2    192.0.2.61        49      Enabled   5     5

Accounting Servers

Idx  Server Address    Port    State     Tout  MgmtTout
---  ----------------  ------  --------  ----  --------
1    192.0.2.60        49      Enabled   5     5

Authorization Servers

Idx  Server Address    Port    State     Tout  MgmtTout
---  ----------------  ------  --------  ----  --------
1    192.0.2.60        49      Disabled  5     5
"""

TACACS_AUTH_STATS = """\
Server Index..................................... 1
Server Address................................... 192.0.2.60
Msg Round Trip Time.............................. 1 (1/100 second)
First Requests................................... 25
Retry Requests................................... 0
Accept Responses................................. 24
Reject Responses................................. 1
Error Responses.................................. 0
Restart Responses................................ 0
Follow Responses................................. 0
GetData Responses................................ 0
Encrypt no secret Responses...................... 0
Challenge Responses.............................. 0
Malformed Msgs................................... 0
Bad Authenticator Msgs........................... 0
Timeout Requests................................. 0
Unknowntype Msgs................................. 0
Other Drops...................................... 0
"""

AAA_AUTH = """\
Management authentication server order:
    1............................................ local
    2............................................ tacacs
"""

AAA_AUTH_LOCAL = """\
Management authentication server order:
    1............................................ local
"""

AAA_AUTH_ONE_LINE = "Management authentication server order: local, radius\n"

LOCAL_AUTH_CONFIG = """\
User credentials database search order:
    Primary ..................................... Local DB

Timer:
    Active timeout .............................. 300

Configured EAP profiles:
    Name ........................................ lab-eap-prof
      Certificate issuer ........................ cisco
      Peer verification options:
        Check against CA certificates ........... Enabled
        Verify certificate CN identity .......... Disabled
        Check certificate date validity ......... Enabled
      EAP-FAST configuration:
        Local certificate required .............. No
        Client certificate required ............. No
      Enabled methods ........................... peap eap-fast
      Configured on WLANs ....................... 3 4

EAP Method configuration:
    EAP-FAST:
      Server key ................................ <REDACTED>
      TTL for the PAC ........................... 10
      Anonymous provision allowed ............... Yes
      Authority ID .............................. 436973636f0000000000000000000000
      Authority Information ..................... Cisco A-ID
"""

LOCAL_AUTH_CONFIG_UNUSED = """\
User credentials database search order:
    Primary ..................................... Local DB

Timer:
    Active timeout .............................. Undefined

Configured EAP profiles:

EAP Method configuration:
    EAP-FAST:
      Server key ................................ <REDACTED>
      TTL for the PAC ........................... 10
      Anonymous provision allowed ............... No
"""

LOCAL_AUTH_STATS = """\
Local EAP authentication DB statistics:
  Requests received ............................... 14
  Responses returned .............................. 14
  Requests dropped (no EAP AVP) ................... 0
  Requests dropped (other reasons) ................ 1
  Authentication timeouts ......................... 2

Authentication statistics:
  Method                                    Success     Fail
  ------------------------------------    --------  -------
  Unknown                                        0        0
  LEAP                                           0        0
  EAP-FAST                                       3        1
  EAP-TLS                                        0        0
  PEAP                                          10        0
"""

# As stored: real names already replaced by pseudonyms.
NETUSER = """\
Maximum logins allowed for a given user name...... Unlimited

User Name               WLAN Id   User Type   Lifetime  Description
---------------------   -------   ---------   --------  -----------
user-0a1b2c3d4e         2         Guest       Unlimited lab guest
user-5f6a7b8c9d         2         Guest       86311     lab visitor
user-1122334455         Any       Permanent   0         lab device
"""

MGMTUSER = """\
User Name                 Permissions        Description              Password Strength       Telnet Capable
-----------------------   ------------       --------------------     ------------------      ----------------
lab-admin                 read-write                                  Strong                  Yes
lab-ro                    read-only          lab read only            Strong                  No
lab-lobby                 lobby-admin        lab lobby                Weak                    Yes
"""

ACL_SUMMARY = """\
ACL Counter Status               Enabled

----------------------------------------
IPv4 ACL Name                    Applied
-------------------------------- -------
lab-preauth                      Yes
lab-guest-acl                    No

----------------------------------------
IPv6 ACL Name                    Applied
-------------------------------- -------
lab-v6-acl                       No
"""

ACL_DETAIL = """\

                       Source                        Destination                Source Port  Dest Port
Index  Dir       IP Address/Netmask              IP Address/Netmask        Prot    Range       Range    DSCP  Action      Counter
------ ---- ------------------------------- ------------------------------- ---- ----------- ----------- ----- ------- -----------
     1   In          10.0.0.0/255.0.0.0              192.0.2.53/255.255.255.255   17     0-65535       53-53   Any  Permit          42
     2  Out        192.0.2.53/255.255.255.255          10.0.0.0/255.0.0.0          17       53-53     0-65535   Any  Permit          40
     3  Any           0.0.0.0/0.0.0.0                  0.0.0.0/0.0.0.0           Any     0-65535     0-65535   Any    Deny           7
DenyCounter : 3
"""

# Older layout: direction after DSCP, no counter column.
ACL_DETAIL_OLD = """\
       Source                Destination                Source Port  Dest Port
I  IP Address/Netmask      IP Address/Netmask      Prot    Range       Range    DSCP  Dir  Action
-- ----------------------- ----------------------- ---- ----------- ----------- ----- ---- -------
 1 10.1.0.0/255.255.0.0    198.51.100.10/255.255.255.255  6   0-65535     443-443     Any  Any  Permit
 2 0.0.0.0/0.0.0.0         0.0.0.0/0.0.0.0         Any  0-65535     0-65535     Any  In   Deny
"""

ACL_CPU = """\
CPU Acl Name................................ lab-cpu-acl
Wireless Traffic............................ Enabled
Wired Traffic............................... Enabled
"""

ACL_CPU_NONE = """\
CPU Acl Name................................
Wireless Traffic............................ Disabled
Wired Traffic............................... Disabled
"""

FLEX_ACL_SUMMARY = """\
ACL Name                         Status
-------------------------------- -------
lab-flex-acl                     Applied
lab-flex-split                   Modified
"""

FLEX_ACL_DETAIL = """\

                       Source                        Destination                Source Port  Dest Port
Index         IP Address/Netmask              IP Address/Netmask        Prot    Range       Range    DSCP  Action
------ ------------------------------- ------------------------------- ---- ----------- ----------- ----- -------
     1          10.30.0.0/255.255.0.0        203.0.113.10/255.255.255.255     6     0-65535     443-443   Any  Permit
     2            0.0.0.0/0.0.0.0              0.0.0.0/0.0.0.0             Any     0-65535     0-65535   Any    Deny
"""

WPS_SUMMARY = """\
Auto-Immune
  Auto-Immune.................................... Disabled

Client Exclusion Policy
  Excessive 802.11-association failures.......... Enabled
  Excessive 802.11-authentication failures....... Enabled
  Excessive 802.1x-authentication................ Enabled
  IP-theft....................................... Disabled
  Excessive Web authentication failure........... Enabled
  Maximum 802.1x-AAA failure attempts............ 3

Trusted AP Policy
  Management Frame Protection.................... Enabled
  Mis-configured AP Action....................... Alarm Only
    Enforced encryption policy................... none
    Enforced preamble policy..................... none
    Enforced radio type policy................... none
    Validate SSID................................ Disabled
  Alert if Trusted AP is missing................. Disabled
  Trusted AP timeout............................. 120

Untrusted AP Policy
  Rogue Location Discovery Protocol.............. Disabled
    RLDP Action.................................. Alarm Only
  Rogue APs
    Rogues AP advertising my SSID................ Alarm Only
    Detect and report Ad-Hoc Networks............ Enabled
  Rogue Clients
    Validate rogue clients against AAA........... Disabled
    Detect trusted clients on rogue APs.......... Contain
  Rogue AP timeout............................... 1200

Signature Policy
  Signature Processing........................... Enabled
"""

MFP_SUMMARY = """\
Global Infrastructure MFP state.................. Enabled
Controller Time Source Valid..................... False

                                   WLAN    Infra.     Client
WLAN ID  WLAN Name                 Status  Protection Protection
-------  ------------------------- ------- ---------- ----------
1        lab-corp                  Enabled Enabled    Required
2        lab-guest                 Enabled Enabled    Optional but inactive (WPA2 not configured)
3        lab-iot                   Disabled Disabled  Disabled
"""

MFP_SUMMARY_OFF = """\
Global Infrastructure MFP state.................. Disabled
Controller Time Source Valid..................... True
"""

SIGNATURES = """\
Signature-ID..................................... 1
Precedence....................................... 1
Signature Name................................... Bcast deauth
Type............................................. standard
FrequencyType.................................... all
State............................................ enabled
Action........................................... report

Signature-ID..................................... 2
Precedence....................................... 2
Signature Name................................... NULL probe resp 1
Type............................................. standard
FrequencyType.................................... all
State............................................ disabled
Action........................................... report

Signature-ID..................................... 3
Precedence....................................... 3
Signature Name................................... lab-custom-sig
Type............................................. custom
FrequencyType.................................... all
State............................................ enabled
Action........................................... report
"""

AP_AUTH_OFF = "AP neighbor authentication is <disabled>.\n"
AP_AUTH_ON = """\
AP neighbor authentication is <enabled>.
Authentication alarm threshold is 1.
RF-Network Name: <lab-rf>
"""

ROGUE_AP_SUMMARY = """\
Rogue Detection Security Level................... custom
Rogue Pending Time............................... 180 secs
Rogue on wire Auto-Contain....................... Disabled
Rogue using our SSID Auto-Contain................ Disabled
Valid client on rogue AP Auto-Contain............ Disabled
Rogue AP timeout................................. 1200
Rogue Detection Report Interval.................. 10
Rogue Detection Min Rssi......................... -90
Validate rogue AP against AAA.................... Disabled
Total Rogues(AP+Ad-hoc) supported................ 2000
Total Rogues classified.......................... 4

MAC Address        Class          State                #Det Aps  #Clients  Type
-----------------  ------------   --------------------  --------  --------  -----------
00:11:22:f0:00:01  Malicious      Contained             1         0         AP
00:11:22:f0:00:02  Friendly       Internal              2         0         AP
00:11:22:f0:00:03  Unclassified   Alert                 3         1         AP
00:11:22:f0:00:04  Unclassified   Alert                 1         0         On Wire
00:11:22:f0:00:05  Custom         Alert                 1         0         AP
"""

ROGUE_CLIENT_SUMMARY = """\
Validate rogue clients against AAA............... Disabled
Validate rogue clients against MSE............... Disabled

MAC Address        State              # APs Last Heard
-----------------  ------------------ ----- -----------------------
00:11:22:f1:00:01  Alert              1     Thu Nov 12 10:00:00 2026
00:11:22:f1:00:02  Contained          2     Thu Nov 12 10:01:00 2026
"""

ROGUE_ADHOC_SUMMARY = """\
Detect and report Ad-Hoc Networks................ Enabled
Auto-contain Ad-Hoc.............................. Disabled

Client MAC Address Adhoc BSSID       State              # APs Last Heard
------------------ ----------------- ------------------ ----- -----------------------
"""

ROGUE_RULES = """\
Priority  Rule Name                         Rule state  Class Type    Notify   State     Match  Hit Count
--------  --------------------------------  ----------  ------------  -------- --------  -----  ---------
1         lab-rule-ssid                     Enabled     Malicious     Global   Contain   Any    3
2         lab-rule-friendly                 Disabled    Friendly      None     Internal  All    0
"""

ROGUE_RULES_OLD = """\
Priority  Rule Name                       State     Type          Match  Hit Count
--------  ------------------------------  --------  ------------  -----  ---------
1         lab-rule-old                    Enabled   Malicious     Any    9
"""

AUTO_CONTAIN = """\
Containment Level................................ 3
monitor_ap_only.................................. false

Rogue on wire Auto-Contain....................... Enabled
Rogue using our SSID Auto-Contain................ Disabled
Valid client on rogue AP Auto-Contain............ Disabled
Rogue AP timeout................................. 1200
Auto-contain Ad-Hoc.............................. Disabled
"""

AUTO_CONTAIN_OFF = """\
Containment Level................................ 1
monitor_ap_only.................................. false

Rogue on wire Auto-Contain....................... Disabled
Rogue using our SSID Auto-Contain................ Disabled
Valid client on rogue AP Auto-Contain............ Disabled
Auto-contain Ad-Hoc.............................. Disabled
"""

MOBILITY_SUMMARY = """\
Mobility Protocol Port........................... 16666
Default Mobility Domain.......................... lab-mob-grp
Multicast Mode .................................. Disabled
DTLS Mode ....................................... Enabled
Mobility Domain ID for 802.11r................... 0xac5f
Mobility Keepalive Interval...................... 10
Mobility Keepalive Count......................... 3
Mobility Group Members Configured................ 4
Mobility Control Message DSCP Value.............. 0

Controllers configured in the Mobility Group
 MAC Address        IP Address                                       Group Name                        Multicast IP                                     Status
 00:11:22:00:aa:01  192.0.2.10                                       lab-mob-grp                       0.0.0.0                                          Up
 00:11:22:00:aa:02  192.0.2.11                                       lab-mob-grp                       0.0.0.0                                          Data Path Down
 00:11:22:00:aa:03  198.51.100.10                                    lab-mob-dmz                       0.0.0.0                                          Control and Data Paths Down
 00:11:22:00:aa:04  198.51.100.11                                    lab-mob-dmz                       0.0.0.0                                          Control Path Down
"""

# 8.x with a Public IP column and multicast messaging on.
MOBILITY_SUMMARY_PUBLIC = """\
Default Mobility Domain.......................... lab-mob-grp
Multicast Mode .................................. Enabled
Mobility Multicast Ip Address.................... 239.10.10.10

Controllers configured in the Mobility Group
 MAC Address        IP Address       Group Name        Multicast IP     Public IP Address   Status
 00:11:22:00:aa:01  192.0.2.10       lab-mob-grp       239.10.10.10     192.0.2.10          Up
"""

MOBILITY_STATS = """\
Global Mobility Statistics
  Rx Errors...................................... 1
  Tx Errors...................................... 0
  Responses Retransmitted........................ 0
  Handoff Requests Received...................... 12
  Handoff End Requests Received.................. 0
  State Transitions Disallowed................... 0
  Resource Unavailable........................... 0
Mobility Initiator Statistics
  Handoff Requests Sent.......................... 10
  Handoff Replies Received....................... 10
  Handoff as Local Received...................... 5
  Handoff as Foreign Received.................... 3
  Handoff Denys Received......................... 2
  Anchor Request Sent............................ 0
  Anchor Deny Received........................... 0
Mobility Responder Statistics
  Handoff Requests Ignored....................... 0
  Ping Pong Handoff Requests Dropped............. 0
  Handoff Requests Dropped....................... 1
  Handoff Requests Denied........................ 0
  Client Handoff as Local........................ 4
  Client Handoff as Foreign...................... 2
"""

MOBILITY_ANCHOR = """\
Mobility Anchor Export List

 WLAN ID     IP Address            Status                          Priority
 -------     ---------------       ------------------------------  --------
 2           198.51.100.10         Up                              1
 2           198.51.100.11         Control and Data Paths Down     2

 GLAN ID     IP Address            Status                          Priority
 -------     ---------------       ------------------------------  --------
"""

MOBILITY_AP_LIST = """\
AP name                           AP Radio MAC        Controller IP Address        Learnt from
--------------------------------  -----------------   ---------------------------  -----------
lab-ap-01                         00:11:22:aa:00:01   192.0.2.10                   Self
lab-ap-02                         00:11:22:aa:00:02   192.0.2.10                   Self
lab-ap-03                         00:11:22:aa:00:03   192.0.2.11                   192.0.2.11
"""

FLEX_GROUP_DETAIL = """\
Number of AP's in Group: 2

AP Ethernet MAC    Name                       Status       Mode         Type     Conflict with PnP
-----------------  ------------------------   ----------   ----------   ------   ------------------
00:11:22:aa:00:01  lab-ap-01                  Joined       Flexconnect  Manual   No
00:11:22:aa:00:02  lab-ap-02                  Joined       Flexconnect  Manual   No

Efficient AP Image Upgrade ..... Enabled
Efficient AP Image Upgrade Master AP ..... lab-ap-01
Auto ApType Conversion..... Disabled
Master-AP-Mode: Manual
Group Radius Servers Settings:
  Type           Server Address     Port
  -------------  ----------------   -------
  Primary        192.0.2.50         1812
  Secondary      Unconfigured       Unconfigured

Group Radius AP Settings:
  AP RADIUS server............ Enabled
  EAP-FAST Auth............... Enabled
  LEAP Auth................... Disabled
  EAP-TLS Auth................ Disabled
  PEAP Auth................... Enabled
  Server Key Auto Generated... No
  Server Key.................. <REDACTED>
  PAC Timeout................. 0
  Number of User's in Group: 0

Group-Specific FlexConnect Local-Split ACLs :
WLAN ID     SSID                         ACL
-------     ---------------------------  ---------------
1           lab-corp                     lab-flex-split

Group-Specific Vlan Config:
Vlan Mode.................... Enabled
Native Vlan.................. 100
Override AP Config........... Disabled

Group-Specific FlexConnect Wlan-Vlan Mapping:
WLAN ID     Vlan ID
-------     --------
1           110
3           130

Group-specific FlexConnect WebAuthentication ACLs:
WLAN ID     SSID                         ACL
-------     ---------------------------  ---------------
2           lab-guest                    lab-flex-acl

Group-Specific FlexConnect VLAN-ACL Mapping:
ACL Mapping for Vlan ID: 110
Ingress ACL..............lab-flex-acl
Egress ACL...............lab-flex-acl
"""

FLEX_GROUP_DETAIL_MIN = """\
Number of AP's in Group: 0

Efficient AP Image Upgrade ..... Disabled
Group Radius Servers Settings:
  Type           Server Address     Port
  -------------  ----------------   -------
  Primary        Unconfigured       Unconfigured
  Secondary      Unconfigured       Unconfigured

Group Radius AP Settings:
  AP RADIUS server............ Disabled
"""

QOS_PLATINUM = """\
Description...................................... For Voice Applications
Maximum Priority................................. voice
Unicast Default Priority......................... voice
Multicast Default Priority....................... voice
Per-SSID Rate Limits............................. UpstreamDownstream
Average Data Rate................................ 0           0
Average Realtime Rate............................ 0           0
Burst Data Rate.................................. 0           0
Burst Realtime Rate.............................. 0           0
Per-Client Rate Limits........................... UpstreamDownstream
Average Data Rate................................ 2000        4000
Average Realtime Rate............................ 0           0
Burst Data Rate.................................. 0           0
Burst Realtime Rate.............................. 0           0
protocol......................................... dot1p
dot1p Tag........................................ 6
"""

# Older code: one rate per line, 802.1p label.
QOS_BRONZE_OLD = """\
Description...................................... For Background
Maximum Priority................................. background
Unicast Default Priority......................... background
Multicast Default Priority....................... background
Per-User Rate Limits.............................
Average Data Rate................................ 512
Burst Data Rate.................................. 0
Protocol......................................... none
802.1p Tag....................................... 1
"""

QOS_MAP = """\
Status : Enabled
Trust DSCP UpStream : Disabled

  UP-TO-DSCP Map:
  Up         Dscp Default   Dscp Start    Dscp End
  ----------------------------------------------
  0          0              0              7
  1          8              8              15
  6          46             46             47
  7          56             56             63

  DSCP Exceptions:
  Dscp       Up
  -------------
  48         6
"""

QOS_MAP_OFF = """\
Status : Disabled
Trust DSCP UpStream : Disabled
"""

AVC_PROFILES = """\
Profile-Name                        Number of Rules
============                        ================
lab-avc-prof                        2
lab-avc-guest                       5
"""

FLOW_EXPORTERS = """\
Exporter-Name                     Exporter-IP     Port
=============                     ===========     ====
lab-prime                         192.0.2.70      9995
"""

FLOW_MONITORS = """\
Monitor-Name                      Exporter-Name   Exporter-IP     Port      Record Name
============                      =============   ===========     ====      ===========
lab-mon                           lab-prime       192.0.2.70      9995      ipv4_client_app_flow_record
"""

MDNS_SUMMARY = """\
mDNS Global Snooping............................. Enabled
mDNS Policy...................................... Disabled
mDNS Query Interval.............................. 15 (mins)
Number of Services............................... 3
Number of Profiles............................... 1
"""

MDNS_SERVICES = """\
Number of Services.............................. 2

Service-Name                     LSS  Origin  No SP  Service-id    Service String
-------------------------------  ---  ------  -----  ------------  -------------------------------
AirPrint                         No   ALL     0      1             _ipp._tcp.local.
AppleTV                          Yes  ALL     2      2             _airplay._tcp.local.
"""

MDNS_PROFILES = """\
Number of Profiles.............................. 1

ProfileName                      No. Interfaces     No. Interface Groups   No. Wlans       No. Local Policies    No. Ap Groups
-------------------------------  ---------------    --------------------   -----------     -----------------     -------------
default-mdns-profile             2                  0                      1               0                     0
"""

NMSP_STATUS = """\
NMSP Status
-----------

LocalIP         PeerIP          Echo Request Count  Echo Response Count  Data Packets Sent  Data Packets Received  Transport
--------------  --------------  ------------------  -------------------  -----------------  ---------------------  ---------
192.0.2.10      192.0.2.80      1200                1200                 340                12                     TLS
"""

NMSP_STATUS_OLD = """\
MSE IP Address   Tx Echo Resp  Rx Echo Req  Tx Data  Rx Data  Transport
--------------   ------------  -----------  -------  -------  ---------
192.0.2.81       500           500          20       3        TLS
"""

NMSP_SUBSCRIPTION = """\
Mobility Services Subscribed:

Server IP          Services
---------          --------
192.0.2.80         RSSI, Info, Statistics,
                   AP Monitor, AP Info
"""

MGID = """\
Layer2 MGID Mapping:
-------------------
InterfaceName                     vlanId   MGID
--------------------------------  ------   ----
management                        0        0
lab-guest                         20       1

Layer3 MGID Mapping:
-------------------
Number of Layer3 MGIDs........................... 2

Group address    Vlan  MGID
---------------  ----  ----
239.255.255.250  0     550
224.0.0.251      0     551
"""

NETWORK_SUMMARY = """\
RF-Network Name............................. lab-rf
DNS Server IP..................................... 192.0.2.53
Web Mode.................................... Disable
Secure Web Mode............................. Enable
Secure Web Mode Cipher-Option High.......... Disable
Secure Web Mode SSL Protocol................ Disable
Web CSRF check ............................. Enable
Secure Shell (ssh).......................... Enable
Secure Shell (ssh) Cipher-Option High....... Disable
Telnet...................................... Enable
Ethernet Multicast Forwarding............... Disable
Ethernet Broadcast Forwarding............... Disable
IPv4 AP Multicast/Broadcast Mode............ Multicast   Address : 239.1.1.1
IPv6 AP Multicast/Broadcast Mode............ Unicast
IGMP snooping............................... Enabled
IGMP timeout................................ 60 seconds
MLD snooping................................ Disabled
User Idle Timeout........................... 300 seconds
ARP Idle Timeout............................ 300 seconds
Mgmt Via Wireless Interface................. Enable
Mgmt Via Dynamic Interface.................. Disable
AP Fallback ................................ Enable
Web Auth Secure Web  ....................... Enable
Web Auth Secure Redirection  ............... Disable
Fast SSID Change ........................... Disabled
mDNS snooping............................... Disabled
"""

# Older wording: one multicast mode line, no IPv6.
NETWORK_SUMMARY_OLD = """\
RF-Network Name............................. lab-rf
Web Mode.................................... Enable
Secure Web Mode............................. Enable
Secure Shell (ssh).......................... Enable
Telnet...................................... Disable
AP Multicast Mode........................... Unicast
IGMP snooping............................... Disabled
Mgmt Via Wireless Interface................. Disable
Mgmt Via Dynamic Interface.................. Disable
"""

SNMPVERSION = """\
SNMP v1 Mode.................................. Disable
SNMP v2c Mode.................................. Enable
SNMP v3 Mode.................................. Enable
"""

# As stored: community names masked by the collector.
SNMPCOMMUNITY_MASKED = """\
SNMP Community Name Client IP Address Client IP Mask  IPv6 Address  IPv6 Prefix Length Access Mode Status
------------------- ----------------- --------------- ------------- ------------------ ----------- ------
<REDACTED>          0.0.0.0           0.0.0.0         ::/0          0                  Read Only   Enable
<REDACTED>          192.0.2.0         255.255.255.0   ::/0          0                  Read-Write  Disable
"""

SNMPV3USER = """\
SNMP v3 User Name          AccessMode   Authentication  Encryption
-------------------------  -----------  --------------  ----------
default                    Read Write   HMAC-SHA        CFB-AES
lab-v3                     Read Only    HMAC-SHA        CFB-AES
lab-v3-md5                 Read Only    HMAC-MD5        None
"""

SNMPTRAP = """\
SNMP Trap Receiver Name       IP Address                                Status
------------------------      ----------------------------------------  --------
lab-prime                     192.0.2.70                                Enable
lab-old-nms                   198.51.100.70                             Disable
"""

LOGGING = """\
Logging to buffer :
- Level of logging to buffer.................... errors
- Number of system messages logged.............. 41012
- Number of system messages dropped............. 3456
Logging to console :
- Level of logging to console................... disabled
- Number of system messages logged.............. 0
Logging to syslog :
- Syslog facility................................ local0
- Logging of system messages to syslog :
 - Logging of system messages to syslog :........ notifications
- Logging of debug messages to syslog ........... Disabled
- Number of system messages sent to syslog...... 41009
- Number of remote syslog hosts.................. 2
- syslog over tls................................ Disabled
- Host 0....................................... 192.0.2.90
- Host 1....................................... 192.0.2.91
- Host 2.......................................
Logging to IP Address :
- Logging of traceinfo.......................... Disabled
"""

LOGGING_NO_HOSTS = """\
Logging to buffer :
- Level of logging to buffer.................... errors
Logging to syslog :
- Syslog facility................................ local0
- Number of remote syslog hosts.................. 0
- Host 0.......................................
- Host 1.......................................
"""

CERT_SUMMARY = """\
Web Administration Certificate................. Locally Generated
Web Authentication Certificate................. 3rd Party
Certificate compatibility mode:................ off
Lifetime Check Ignore for MIC ................. Disable
Lifetime check ignore for SSC ................. Disable
"""

CERT_LSC_OFF = """\
LSC Enabled.......................................... No
LSC CA-Server........................................ Not Configured

LSC AP-Provisioning.................................. No
   Provision-List................................... Not Configured
   LSC Revert Count in AP reboots................... 3

LSC Params:
   Country.............................................. US
   KeySize.............................................. 2048

LSC Certs:
   CA Cert.............................................. Not Configured
   RA Cert.............................................. Not Configured
"""

CERT_LSC_ON = """\
LSC Enabled.......................................... Yes
LSC CA-Server........................................ http://192.0.2.95/certsrv/mscep/mscep.dll

LSC Params:
   Country.............................................. US
   Orgn................................................. lab
   KeySize.............................................. 2048

LSC Certs:
   CA Cert.............................................. Configured
                Subject Name :
                   C=US, O=lab, CN=lab-issuing-ca
                Validity :
                   Start : 2024 Jan 10th, 12:00:00 GMT
                   End : 2029 Jan 10th, 12:00:00 GMT
   RA Cert.............................................. Not Configured
"""

LOCAL_AUTH_CERTS = """\
Certificates available for Local EAP authentication:

Certificate issuer .............................. cisco
  CA certificate:
    Subject: O=Cisco Systems, CN=Cisco Manufacturing CA
    Issuer:  O=Cisco Systems, CN=Cisco Root CA 2048
    Valid:   2005 Jun 10th, 22:16:01 GMT to 2029 May 14th, 20:25:41 GMT
  Device certificate:
    Subject: O=Cisco Systems, CN=AIR-CT5520-K9-001122aabbcc
    Issuer:  O=Cisco Systems, CN=Cisco Manufacturing CA
    Valid:   2016 Mar 29th, 11:43:47 GMT to 2026 Mar 29th, 11:53:47 GMT

Certificate issuer .............................. vendor
  CA certificate:
    Not installed.
  Device certificate:
    Subject: CN=lab-wlc-01
    Issuer:  CN=lab-wlc-01
    Valid:   2025 Feb 1st, 00:00:00 GMT to 2030 Feb 1st, 00:00:00 GMT
"""

ERROR = "Incorrect usage. Use the '?' or <TAB> key to list commands."
