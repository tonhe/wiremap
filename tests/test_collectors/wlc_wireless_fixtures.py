"""Synthetic AireOS wireless output (8.5 and 8.10 wording). Names are lab-*,
addresses RFC 5737 or private, MACs 00:11:22:xx:xx:xx, serials made up.
Client lists are shown as the collector stores them, already scrubbed."""

# --- show wlan <id> -----------------------------------------------------------

# 8.10: WPA2-Enterprise with 802.11r, PMF optional, two RADIUS servers.
WLAN_CORP = """\
WLAN Identifier.................................. 1
Profile Name..................................... lab-corp
Network Name (SSID).............................. lab-corp
Status........................................... Enabled
MAC Filtering.................................... Disabled
Broadcast SSID................................... Enabled
AAA Policy Override.............................. Enabled
Network Admission Control
  Client Profiling Status
    Radius Profiling ............................ Disabled
     DHCP ....................................... Disabled
     HTTP ....................................... Disabled
    Local Profiling ............................. Disabled
     DHCP ....................................... Disabled
     HTTP ....................................... Disabled
  Radius-NAC State............................... Disabled
  SNMP-NAC State................................. Disabled
  Quarantine VLAN................................ 0
Maximum number of Associated Clients............. 0
Maximum number of Clients per AP Radio........... 200
ATF Policy....................................... 0
Number of Active Clients......................... 30
Exclusionlist Timeout............................ 60 seconds
Session Timeout.................................. 1800 seconds
User Idle Timeout................................ 300 seconds
Sleep Client..................................... disable
Sleep Client Timeout............................. 12 hours
Web Auth Captive Bypass Mode..................... disable
User Idle Threshold.............................. 0 Bytes
NAS-identifier................................... lab-wlc-01
CHD per WLAN..................................... Enabled
Webauth DHCP exclusion........................... Disabled
Interface........................................ management
Multicast Interface.............................. Not Configured
WLAN IPv4 ACL.................................... unconfigured
WLAN IPv6 ACL.................................... unconfigured
WLAN Layer2 ACL.................................. unconfigured
WLAN URL ACL..................................... unconfigured
mDNS Status...................................... Disabled
mDNS Profile Name................................ unconfigured
DHCP Server...................................... Default
Central NAT Peer-Peer Blocking................... Disabled
DHCP Address Assignment Required................. Disabled
Static IP client tunneling....................... Disabled
Tunnel Profile................................... Unconfigured
PMIPv6 Mobility Type............................. none
    PMIPv6 MAG Profile........................... Unconfigured
    PMIPv6 Default Realm......................... Unconfigured
    PMIPv6 NAI Type.............................. Hexadecimal
Quality of Service............................... Silver
Per-SSID Rate Limits............................. Upstream      Downstream
Average Data Rate................................   0             0
Average Realtime Data Rate.......................   0             0
Burst Data Rate..................................   0             0
Burst Realtime Data Rate.........................   0             0
Scan Defer Priority.............................. 4,5,6
Scan Defer Time.................................. 100 milliseconds
WMM.............................................. Allowed
WMM UAPSD Compliant Client Support............... Disabled
Media Stream Multicast-direct.................... Disabled
CCX - AironetIe Support.......................... Disabled
CCX - Gratuitous ProbeResponse (GPR)............. Disabled
CCX - Diagnostics Channel Capability............. Disabled
Dot11-Phone Mode (7920).......................... Disabled
Wired Protocol................................... None
Passive Client Feature........................... Disabled
Peer-to-Peer Blocking Action..................... Disabled
Radio Policy..................................... All
DTIM period for 802.11a radio.................... 1
DTIM period for 802.11b radio.................... 1
Radius Servers
   Authentication................................ 192.0.2.50 1812
   Authentication................................ 192.0.2.51 1812
   Accounting.................................... 192.0.2.50 1813
      Interim Update............................. Enabled
      Interim Update Interval.................... 600
      Framed IPv6 Acct AVP ...................... Prefix
   Dynamic Interface............................. Disabled
   Dynamic Interface Priority.................... wlan
Local EAP Authentication......................... Disabled
Radius NAI-Realm................................. Disabled
Mu-Mimo.......................................... Enabled
Security

   802.11 Authentication:........................ Open System
   FT Support.................................... Enabled
   Static WEP Keys............................... Disabled
   802.1X........................................ Disabled
   Wi-Fi Protected Access (WPA/WPA2/WPA3)........ Enabled
      WPA (SSN IE)............................... Disabled
      WPA2 (RSN IE).............................. Enabled
         TKIP Cipher............................. Disabled
         AES Cipher.............................. Enabled
         CCMP256 Cipher.......................... Disabled
         GCMP128 Cipher.......................... Disabled
         GCMP256 Cipher.......................... Disabled
      OSEN IE.................................... Disabled
      WPA3 (WPA3 IE)............................. Disabled
         Auth Key Management
            802.1x............................... Enabled
            PSK.................................. Disabled
            CCKM................................. Disabled
            FT-1X(802.11r)....................... Enabled
            FT-PSK(802.11r)...................... Disabled
            PMF-1X(802.11w)...................... Disabled
            PMF-PSK(802.11w)..................... Disabled
            OSEN-1X.............................. Disabled
            SUITEB-1X............................ Disabled
            SUITEB192-1X......................... Disabled
            SAE.................................. Disabled
            FT-SAE............................... Disabled
            OWE.................................. Disabled
   FT Reassociation Timeout......................... 20
   FT Over-The-DS mode.............................. Disabled
   GTK Randomization................................ Disabled
   SKC Cache Support................................ Disabled
   CCKM TSF Tolerance............................... 1000
   OWE Transition Mode.............................. Disabled
   WAPI.......................................... Disabled
   Wi-Fi Direct policy configured................ Disabled
   EAP-Passthrough............................... Disabled
   CKIP ......................................... Disabled
   Web Based Authentication...................... Disabled
   Web Authentication Timeout.................... 300
   Web-Passthrough............................... Disabled
   Mac-auth-server............................... 0.0.0.0
   Web-portal-server............................. 0.0.0.0
   Conditional Web Redirect...................... Disabled
   Splash-Page Web Redirect...................... Disabled
   Auto Anchor................................... Disabled
   FlexConnect Local Switching................... Disabled
   FlexConnect Central Association............... Disabled
   flexconnect Central Dhcp Flag................. Disabled
   flexconnect nat-pat Flag...................... Disabled
   flexconnect Dns Override Flag................. Disabled
   flexconnect PPPoE pass-through................ Disabled
   flexconnect local-switching IP-source-guar.... Disabled
   FlexConnect Vlan based Central Switching ..... Disabled
   FlexConnect Local Authentication.............. Disabled
   FlexConnect Learn IP Address.................. Enabled
   Client MFP.................................... Optional
   PMF........................................... Optional
   PMF Association Comeback Time................. 1
   PMF SA Query RetryTimeout..................... 200
   Tkip MIC Countermeasure Hold-down Timer....... 60
   Eap-params.................................... Disabled
AVC Visibilty.................................... Disabled
AVC Profile Name................................. None
OpenDns Profile Name............................. None
Flow Monitor Name................................ None
Split Tunnel Configuration
    Split Tunnel................................. Disabled
Call Snooping.................................... Disabled
Roamed Call Re-Anchor Policy..................... Disabled
SIP CAC Fail Send-486-Busy Policy................ Enabled
SIP CAC Fail Send Dis-Association Policy......... Disabled
KTS based CAC Policy............................. Disabled
Assisted Roaming Prediction Optimization......... Disabled
802.11k Neighbor List............................ Enabled
802.11k Neighbor List Dual Band.................. Enabled
802.11v Directed Multicast Service............... Enabled
802.11v BSS Max Idle Service..................... Enabled
802.11v BSS Transition Service................... Enabled
802.11v BSS Transition Disassoc Imminent......... Disabled
802.11v BSS Transition Disassoc Timer............ 200
802.11v BSS Transition OpRoam Disassoc Timer..... 40
DMS DB is empty
Band Select...................................... Disabled
Load Balancing................................... Disabled
Multicast Buffer................................. Disabled

 Mobility Anchor List
 WLAN ID     IP Address            Status
 -------     ---------------       ------

802.11u........................................ Disabled
MSAP Services.................................. Disabled
Local Policy
----------------
Priority  Policy Name
--------  ---------------
"""

# 8.10: open guest WLAN with internal web auth, anchored to a guest controller.
WLAN_GUEST = """\
WLAN Identifier.................................. 2
Profile Name..................................... lab-guest
Network Name (SSID).............................. lab-guest
Status........................................... Enabled
MAC Filtering.................................... Disabled
Broadcast SSID................................... Enabled
AAA Policy Override.............................. Disabled
Maximum number of Associated Clients............. 150
Maximum number of Clients per AP Radio........... 200
Number of Active Clients......................... 12
Exclusionlist Timeout............................ 60 seconds
Session Timeout.................................. 28800 seconds
User Idle Timeout................................ Disabled
Interface........................................ lab-guest
Multicast Interface.............................. Not Configured
mDNS Status...................................... Disabled
mDNS Profile Name................................ unconfigured
DHCP Server...................................... Default
DHCP Address Assignment Required................. Enabled
Quality of Service............................... Bronze
WMM.............................................. Allowed
Peer-to-Peer Blocking Action..................... Drop
Radio Policy..................................... All
DTIM period for 802.11a radio.................... 1
DTIM period for 802.11b radio.................... 1
Radius Servers
   Authentication................................ Disabled
   Accounting.................................... Disabled
   Dynamic Interface............................. Disabled
Local EAP Authentication......................... Disabled
Security

   802.11 Authentication:........................ Open System
   FT Support.................................... Disabled
   Static WEP Keys............................... Disabled
   802.1X........................................ Disabled
   Wi-Fi Protected Access (WPA/WPA2/WPA3)........ Disabled
   WAPI.......................................... Disabled
   EAP-Passthrough............................... Disabled
   Web Based Authentication...................... Enabled
   Web Authentication Timeout.................... 300
   Web-Passthrough............................... Disabled
   Conditional Web Redirect...................... Disabled
   Splash-Page Web Redirect...................... Disabled
   Auto Anchor................................... Enabled
   FlexConnect Local Switching................... Disabled
   FlexConnect Local Authentication.............. Disabled
   Client MFP.................................... Optional but inactive (WPA2 not configured)
   PMF........................................... Disabled
AVC Visibilty.................................... Enabled
AVC Profile Name................................. lab-avc
Flow Monitor Name................................ lab-flow
802.11k Neighbor List............................ Disabled
802.11v BSS Transition Service................... Disabled
Band Select...................................... Enabled
Load Balancing................................... Enabled

 Mobility Anchor List
 WLAN ID     IP Address            Status
 -------     ---------------       ------
 2           198.51.100.20         Up
 2           198.51.100.21         Up

802.11u........................................ Disabled
"""

# 8.5 wording: WPA/WPA2 heading, WPA-TKIP with PSK, no 11k/11v lines, no
# mobility anchor section, exclusion off, session timeout infinite.
WLAN_LEGACY = """\
WLAN Identifier.................................. 4
Profile Name..................................... lab-scanners
Network Name (SSID).............................. lab-scanners
Status........................................... Enabled
MAC Filtering.................................... Enabled
Broadcast SSID................................... Disabled
AAA Policy Override.............................. Disabled
Maximum number of Associated Clients............. 0
Number of Active Clients......................... 3
Exclusionlist Timeout............................ Disabled
Session Timeout.................................. Infinity
User Idle Timeout................................ 300 seconds
Interface........................................ lab-scan-grp
Interface Group Name............................. lab-scan-grp
Multicast Interface.............................. lab-scan
DHCP Address Assignment Required................. Disabled
Quality of Service............................... Silver
WMM.............................................. Disabled
Peer-to-Peer Blocking Action..................... Disabled
Radio Policy..................................... 802.11b/g only
DTIM period for 802.11a radio.................... 1
DTIM period for 802.11b radio.................... 3
Radius Servers
   Authentication................................ Global Servers
   Accounting.................................... Global Servers
Security

   802.11 Authentication:........................ Open System
   FT Support.................................... Disabled
   Static WEP Keys............................... Disabled
   802.1X........................................ Disabled
   Wi-Fi Protected Access (WPA/WPA2)............. Enabled
      WPA (SSN IE)............................... Enabled
         TKIP Cipher............................. Enabled
         AES Cipher.............................. Disabled
      WPA2 (RSN IE).............................. Disabled
         TKIP Cipher............................. Disabled
         AES Cipher.............................. Disabled
      Auth Key Management
         802.1x.................................. Disabled
         PSK..................................... Enabled
         CCKM.................................... Disabled
         FT-1X(802.11r).......................... Disabled
         FT-PSK(802.11r)......................... Disabled
         PMF-1X(802.11w)......................... Disabled
         PMF-PSK(802.11w)........................ Disabled
   FT Reassociation Timeout......................... 20
   FT Over-The-DS mode.............................. Enabled
   Web Based Authentication...................... Disabled
   Web-Passthrough............................... Disabled
   Conditional Web Redirect...................... Disabled
   Splash-Page Web Redirect...................... Disabled
   FlexConnect Local Switching................... Enabled
   FlexConnect Local Authentication.............. Enabled
   PMF........................................... Disabled
AVC Visibilty.................................... Disabled
Flow Monitor Name................................ None
Band Select...................................... Disabled
Load Balancing................................... Disabled
"""

# 8.10: WPA3-only SAE, PMF left optional, mDNS snooping on, FT adaptive.
WLAN_WPA3 = """\
WLAN Identifier.................................. 5
Profile Name..................................... lab-iot
Network Name (SSID).............................. lab-iot
Status........................................... Enabled
MAC Filtering.................................... Disabled
Broadcast SSID................................... Enabled
AAA Policy Override.............................. Disabled
Maximum number of Associated Clients............. 0
Number of Active Clients......................... 0
Exclusionlist Timeout............................ 120 seconds
Session Timeout.................................. 1800 seconds
User Idle Timeout................................ 300 seconds
Interface........................................ lab-iot
Multicast Interface.............................. Not Configured
mDNS Status...................................... Enabled
mDNS Profile Name................................ default-mdns-profile
DHCP Address Assignment Required................. Disabled
Quality of Service............................... Silver
WMM.............................................. Required
Peer-to-Peer Blocking Action..................... Disabled
Radio Policy..................................... 802.11a only
DTIM period for 802.11a radio.................... 2
DTIM period for 802.11b radio.................... 1
Radius Servers
   Authentication................................ Global Servers
   Accounting.................................... Global Servers
Security

   802.11 Authentication:........................ Open System
   FT Support.................................... Adaptive
   Static WEP Keys............................... Disabled
   802.1X........................................ Disabled
   Wi-Fi Protected Access (WPA/WPA2/WPA3)........ Enabled
      WPA (SSN IE)............................... Disabled
      WPA2 (RSN IE).............................. Disabled
         TKIP Cipher............................. Disabled
         AES Cipher.............................. Enabled
         CCMP256 Cipher.......................... Disabled
         GCMP128 Cipher.......................... Disabled
         GCMP256 Cipher.......................... Disabled
      OSEN IE.................................... Disabled
      WPA3 (WPA3 IE)............................. Enabled
         Auth Key Management
            802.1x............................... Disabled
            PSK.................................. Disabled
            CCKM................................. Disabled
            FT-1X(802.11r)....................... Disabled
            FT-PSK(802.11r)...................... Disabled
            PMF-1X(802.11w)...................... Disabled
            PMF-PSK(802.11w)..................... Disabled
            OSEN-1X.............................. Disabled
            SUITEB-1X............................ Disabled
            SUITEB192-1X......................... Disabled
            SAE.................................. Enabled
            FT-SAE............................... Disabled
            OWE.................................. Disabled
   FT Over-The-DS mode.............................. Disabled
   Web Based Authentication...................... Disabled
   Web-Passthrough............................... Disabled
   Conditional Web Redirect...................... Disabled
   Splash-Page Web Redirect...................... Disabled
   FlexConnect Local Switching................... Disabled
   FlexConnect Local Authentication.............. Disabled
   PMF........................................... Optional
AVC Visibilty.................................... Disabled
Flow Monitor Name................................ None
802.11k Neighbor List............................ Enabled
802.11v BSS Transition Service................... Enabled
Band Select...................................... Enabled
Load Balancing................................... Disabled
"""

# Open, disabled, nothing else configured; most sections missing.
WLAN_OPEN = """\
WLAN Identifier.................................. 3
Profile Name..................................... lab-open
Network Name (SSID).............................. lab-open
Status........................................... Disabled
Broadcast SSID................................... Enabled
Number of Active Clients......................... 0
Interface........................................ management
Security

   802.11 Authentication:........................ Open System
   Static WEP Keys............................... Disabled
   802.1X........................................ Disabled
   Wi-Fi Protected Access (WPA/WPA2/WPA3)........ Disabled
   Web Based Authentication...................... Disabled
   Web-Passthrough............................... Disabled
   Conditional Web Redirect...................... Disabled
   Splash-Page Web Redirect...................... Disabled
"""

# Older code with a static WEP key (key itself never shown on AireOS).
WLAN_WEP = """\
WLAN Identifier.................................. 6
Profile Name..................................... lab-legacy-wep
Network Name (SSID).............................. lab-legacy-wep
Status........................................... Enabled
Security

   802.11 Authentication:........................ Shared Key
   Static WEP Keys............................... Enabled
      Key Index:................................. 1
      Encryption:................................ 104-bit WEP
   802.1X........................................ Disabled
   Wi-Fi Protected Access (WPA/WPA2)............. Disabled
   Web Based Authentication...................... Disabled
   Web-Passthrough............................... Enabled
"""

# --- show wlan apgroups ------------------------------------------------------

APGROUPS = """\
Total Number of AP Groups........................ 2


Site Name........................................ lab-site-a
Site Description................................. lab floor 1

Venue Group Code................................. Unspecified
Venue Type Code.................................. Unspecified

NAS-identifier................................... none
Client Traffic QinQ Enable....................... FALSE
DHCPv4 Option 82 Enable.......................... FALSE
AP Operating Class............................... 83,84,112,115,118,121,123,125
Capwap Prefer Mode .............................. ipv4 (ApGroup Config)
CAPWAP UDP-Lite.................................. Not Configured

Lan Port configs
----------------
LAN    Status    POE      RLAN
---    -------   ----     ----
1      Disabled  Disabled None
2      Disabled  Disabled None
3      Disabled  Disabled None

External 3G/4G module configs
-----------------------------
LAN    Status    POE      RLAN
---    -------   ----     ----
1      Disabled  Disabled None

RF Profile
----------
2.4 GHz band..................................... lab-rf-24g
5 GHz band....................................... lab-rf-5g

WLAN ID          Interface          Network Admission Control          Radio Policy   OpenDnsProfile   NAT-PAT
-------          -----------        --------------------------         ------------   --------------   -------
 1               management             Disabled                          All          None           Disabled
 2               lab-guest              Disabled                          All          None           Disabled

*AP3600 with 802.11ac Module will only advertise first 8 WLANs on 5GHz radios.


 AP Name             Slots  AP Model              Ethernet MAC       Location          Port  Country  Priority
 ------------------  -----  --------------------  -----------------  ----------------  ----  -------  --------
 lab-ap-01            2     AIR-AP2802I-B-K9      00:11:22:00:00:01  floor 1           1     US       1
 lab-ap-02            2     AIR-CAP2602I-A-K9     00:11:22:00:00:02  floor 2           1     US       1


Site Name........................................ default-group
Site Description................................. <none>

Venue Group Code................................. Unspecified
Venue Type Code.................................. Unspecified

RF Profile
----------
2.4 GHz band..................................... <none>
5 GHz band....................................... <none>

WLAN ID          Interface          Network Admission Control          Radio Policy   OpenDnsProfile   NAT-PAT
-------          -----------        --------------------------         ------------   --------------   -------
 1               management             Disabled                          All          None           Disabled
 3               management             Disabled                          All          None           Disabled

*AP3600 with 802.11ac Module will only advertise first 8 WLANs on 5GHz radios.


 AP Name             Slots  AP Model              Ethernet MAC       Location          Port  Country  Priority
 ------------------  -----  --------------------  -----------------  ----------------  ----  -------  --------
 lab-ap-03            2     AIR-AP1832I-B-K9      00:11:22:00:00:03  default location  1     US       1
"""

# --- show 802.11a / b ------------------------------------------------------

BAND_A = """\
802.11a Network.................................. Enabled
11nSupport....................................... Enabled
      802.11a Low Band........................... Enabled
      802.11a Mid Band........................... Enabled
      802.11a High Band.......................... Enabled
802.11a Operational Rates
    802.11a 6M Rate.............................. Disabled
    802.11a 9M Rate.............................. Disabled
    802.11a 12M Rate............................. Mandatory
    802.11a 18M Rate............................. Supported
    802.11a 24M Rate............................. Mandatory
    802.11a 36M Rate............................. Supported
    802.11a 48M Rate............................. Supported
    802.11a 54M Rate............................. Supported
802.11n MCS Settings:
    MCS 0........................................ Supported
    MCS 1........................................ Supported
    MCS 2........................................ Supported
802.11n Status:
    A-MPDU Tx:
        Priority 0............................... Enabled
        Priority 1............................... Disabled
    Guard Interval............................... Any
    Rifs Rx...................................... Enabled
802.11ac.............................................Enabled
802.11ac MCS Settings:
    Nss=1: MCS 0-9 ....................................Supported
    Nss=2: MCS 0-9 ....................................Supported
802.11ax......................................... Enabled
Beacon Interval.................................. 100
CF Pollable mandatory............................ Disabled
CF Poll Request mandatory........................ Disabled
CFP Period....................................... 4
CFP Maximum Duration............................. 60
Default Channel.................................. 36
Default Tx Power Level........................... 1
DTPC Status...................................... Enabled
Fragmentation Threshold.......................... 2346
RSSI Low Check................................... Disabled
RSSI Threshold................................... -80
TI Threshold..................................... 0
Legacy Tx Beamforming setting.................... Disabled
Traffic Stream Metrics Status.................... Disabled
Expedited BW Request Status...................... Disabled
EDCA profile type................................ default-wmm
Voice MAC optimization status.................... Disabled
"""

# 8.5: no 802.11ax line; the low 802.11b rates still on.
BAND_B = """\
802.11b Network.................................. Enabled
11gSupport....................................... Enabled
11nSupport....................................... Enabled
802.11b/g Operational Rates
    802.11b/g 1M Rate............................ Mandatory
    802.11b/g 2M Rate............................ Mandatory
    802.11b/g 5.5M Rate.......................... Mandatory
    802.11b/g 11M Rate........................... Mandatory
    802.11g 6M Rate.............................. Supported
    802.11g 9M Rate.............................. Supported
    802.11g 12M Rate............................. Supported
    802.11g 18M Rate............................. Supported
    802.11g 24M Rate............................. Supported
    802.11g 36M Rate............................. Supported
    802.11g 48M Rate............................. Supported
    802.11g 54M Rate............................. Supported
802.11n MCS Settings:
    MCS 0........................................ Supported
Beacon Interval.................................. 100
Default Channel.................................. 1
Short Preamble mandatory......................... Enabled
DTPC Status...................................... Enabled
Fragmentation Threshold.......................... 2346
"""

# --- show advanced 802.11a|b ... ----------------------------------------

CHANNEL_A = """\
Automatic Channel Assignment
  Channel Assignment Mode........................ AUTO
  Channel Update Interval........................ 600 seconds
  Anchor time (Hour of the day).................. 0
  Update Contribution
    Noise........................................ Enable
    Interference................................. Enable
    Load......................................... Disable
    Device Aware................................. Disable
  CleanAir Event-driven RRM option............... Enabled
  Channel Assignment Leader...................... lab-wlc-01 (192.0.2.40)
  Last Run....................................... 291 seconds ago
  DCA Sensitivity Level.......................... MEDIUM (15 dB)
  DCA 802.11n/ac Channel Width................... 40 MHz
  DCA Minimum Energy Limit....................... -95 dBm
  Channel Energy Levels
    Minimum...................................... unknown
    Average...................................... unknown
    Maximum...................................... unknown
  Channel Dwell Times
    Minimum...................................... unknown
    Average...................................... unknown
    Maximum...................................... unknown
  802.11a 5 GHz Auto-RF Channel List
    Allowed Channel List......................... 36,40,44,48,52,56,60,64,100,
                                                  104,108,112,116,132,136,140,
                                                  149,153,157,161
    Unused Channel List.......................... 120,124,128,144,165
  802.11a 4.9 GHz Auto-RF Channel List
    Allowed Channel List.........................
    Unused Channel List.......................... 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                                  17,18,19,20,21,22,23,24,25,26
  DCA Outdoor AP option.......................... Disabled
"""

CHANNEL_B = """\
Automatic Channel Assignment
  Channel Assignment Mode........................ AUTO
  Channel Update Interval........................ 12 hours
  Anchor time (Hour of the day).................. 2
  CleanAir Event-driven RRM option............... Disabled
  Channel Assignment Leader...................... lab-wlc-01 (192.0.2.40)
  DCA Sensitivity Level.......................... LOW (20 dB)
  DCA 802.11n Channel Width...................... 20 MHz
  802.11b Auto-RF Channel List
    Allowed Channel List......................... 1,6,11
    Unused Channel List.......................... 2,3,4,5,7,8,9,10
"""

TXPOWER_A = """\
Automatic Transmit Power Assignment
  Transmit Power Assignment Mode................. AUTO
  Transmit Power Update Interval................. 600 seconds
  Transmit Power Threshold....................... -70 dBm
  Transmit Power Neighbor Count.................. 3 APs
  Min Transmit Power............................. -10 dBm
  Max Transmit Power............................. 30 dBm
  Update Contribution
    Noise........................................ Enable
    Interference................................. Enable
    Load......................................... Disable
    Device Aware................................. Disable
  Transmit Power Assignment Leader............... lab-wlc-01 (192.0.2.40)
  Last Run....................................... 289 seconds ago

  TPC Mode....................................... Version 1 (Coverage Optimal Mode)
"""

# Older wording.
TXPOWER_B_OLD = """\
Automatic Transmit Power Assignment
  Transmit Power Assignment Mode................. ON DEMAND
  Transmit Power Update Interval................. 600 seconds
  Transmit Power Threshold....................... -65 dBm
  Transmit Power Neighbor Count.................. 3 APs
  Min Transmit Power............................. 5 dBm
  Max Transmit Power............................. 20 dBm
  Transmit Power Assignment Leader............... lab-wlc-02
"""

COVERAGE_A = """\
Coverage Hole Detection
  802.11a Coverage Hole Detection Mode........... Enabled
  802.11a Coverage Voice Packet Count............ 100 packets
  802.11a Coverage Voice Packet Percentage....... 50%
  802.11a Coverage Voice RSSI Threshold.......... -80 dBm
  802.11a Coverage Data Packet Count............. 50 packets
  802.11a Coverage Data Packet Percentage........ 50%
  802.11a Coverage Data RSSI Threshold........... -80 dBm
  802.11a Global coverage exception level........ 25 %
  802.11a Global client minimum exception lev.... 3 clients
"""

GROUP_A = """\
Radio RF Grouping
  802.11a Group Mode............................. AUTO
  802.11a Group Update Interval.................. 600 seconds
  802.11a Group Leader........................... lab-wlc-01 (192.0.2.40)
    802.11a Group Member......................... lab-wlc-01 (192.0.2.40)
                                                  lab-wlc-02 (192.0.2.42)
  802.11a Last Run............................... 133 seconds ago

  Mobility Agents RF membership information
  -----------------------------------------------------
  No of 802.11a MA RF-members : 0
"""

MONITOR_A = """\
Default 802.11a AP monitoring
  802.11a Monitor Mode........................... enable
  802.11a Monitor Mode for Mesh AP Backhaul...... disable
  802.11a Monitor Channels....................... Country channels
  802.11a RRM Neighbor Discover Type............. Transparent
  802.11a RRM Neighbor RSSI Normalization........ Enabled
  802.11a AP Coverage Interval................... 90 seconds
  802.11a AP Load Interval....................... 60 seconds
  802.11a AP Monitor Measurement Interval........ 180 seconds
  802.11a AP Neighbor Timeout Factor............. 20
  802.11a AP Report Measurement Interval......... 180 seconds
"""

PROFILE_GLOBAL_A = """\
Default 802.11a AP performance profiles
  802.11a Global Interference threshold.......... 10 %
  802.11a Global noise threshold................. -70 dBm
  802.11a Global RF utilization threshold........ 80 %
  802.11a Global throughput threshold............ 1000000 bps
  802.11a Global clients threshold............... 12 clients
"""

CLEANAIR_A = """\
Clean Air Solution............................... Enabled
Air Quality Settings:
    Air Quality Reporting........................ Enabled
    Air Quality Reporting Period (min)........... 15
    Air Quality Alarms........................... Enabled
    Air Quality Alarm Threshold.................. 35
    Unclassified Interference.................... Disabled
    Unclassified Severity Threshold.............. 20
Interference Device Settings:
    Interference Device Reporting................ Enabled
        Bluetooth Link........................... Enabled
        Microwave Oven........................... Enabled
CleanAir ED-RRM State............................ Enabled
CleanAir ED-RRM Sensitivity...................... Medium
CleanAir ED-RRM Custom Threshold................. 50
CleanAir Rogue Contribution...................... Disabled
CleanAir Rogue Duty-Cycle Threshold.............. 80
CleanAir Persistent Devices state................ Disabled
CleanAir Persistent Device Propagation........... Enabled
"""

CLEANAIR_B_OFF = """\
Clean Air Solution............................... Disabled
Air Quality Settings:
    Air Quality Reporting........................ Disabled
CleanAir ED-RRM State............................ Disabled
CleanAir ED-RRM Sensitivity...................... Medium
"""

FRA = """\
FRA State........................................ Enabled
FRA Sensitivity.................................. medium (95%)
FRA Interval..................................... 1 Hour(s)
Last Run......................................... 1350 seconds ago
Last Run Time.................................... 0 seconds
Service Priority................................. Coverage
Client Aware FRA................................. Disabled
Client Select.................................... 50%
Client Reset..................................... 5%
"""

DOT11H = """\
Power Constraint................................. 3
Channel Switch................................... Enabled
Channel Switch Mode.............................. 1
Smart DFS........................................ Enabled
"""

# --- RF profiles -------------------------------------------------------------

RF_PROFILE_5G = """\
Description...................................... lab 5 GHz high density
AP Group Name.................................... lab-site-a
Radio policy..................................... 5 GHz
11n-client-only.................................. disabled
Transmit Power Threshold v1...................... -65 dBm
Transmit Power Threshold v2...................... -67 dBm
Min Transmit Power............................... 5 dBm
Max Transmit Power............................... 17 dBm
802.11a Operational Rates
    802.11a 6M Rate.............................. Disabled
    802.11a 9M Rate.............................. Disabled
    802.11a 12M Rate............................. Mandatory
    802.11a 18M Rate............................. Supported
    802.11a 24M Rate............................. Mandatory
    802.11a 36M Rate............................. Supported
    802.11a 48M Rate............................. Supported
    802.11a 54M Rate............................. Supported
Max Clients...................................... 200
Trap Threshold
  Clients........................................ 12 clients
  Interference................................... 10%
  Noise.......................................... -70 dBm
  Utilization.................................... 80%
Multicast Data Rate.............................. auto
Rx SOP Threshold................................. auto
Cca Threshold.................................... 0 dBm
Slot Admin State:................................ Enabled
Client Aware FRA................................. Disabled
Band Select
  Probe Response................................. Disabled
  Cycle Count.................................... 2 cycles
Load Balancing
  Denial......................................... 3
  Window......................................... 5 clients
Coverage Data
  Data........................................... -80 dBm
  Voice.......................................... -80 dBm
  Minimum Client Level........................... 3 clients
  Exception Level................................ 25%
DCA Channel List................................. 36,40,44,48,52,56,60,64,100,
                                                  104,108,112,116,132,136,140,
                                                  149,153,157,161
DCA Bandwidth.................................... 80
DCA Foreign AP Contribution...................... Enabled
"""

RF_PROFILE_SUMMARY_TWO = """\
Number of RF Profiles............................ 2
Out Of Box State................................. Disabled

RF Profile Name                  Band     Description                          Applied
-------------------------------- -------  ------------------------------------ ----------
lab-rf-24g                       2.4 GHz  lab 2.4 GHz                          Yes
lab-rf-5g                        5 GHz    <none>                               No
"""

# --- radios ------------------------------------------------------------------

RADIO_SUMMARY_A = """\
Member RRM Information
AP Name             MAC Address        Slot  Admin   Oper   Channel                 TxPower
------------------  -----------------  ----  ------  -----  ----------------------  ---------------
lab-ap-01           00:11:22:aa:00:01   1    ENABLED  UP    (36,40)*                *1/6 (17 dBm)
lab-ap-02           00:11:22:aa:00:02   1    ENABLED  UP    (100,104,108,112)*      *2/8 (14 dBm)
lab-ap-03           00:11:22:aa:00:03   1    DISABLED DOWN  52                      1/7 (20 dBm)
"""

# 8.5, 2.4 GHz.
RADIO_SUMMARY_B = """\
AP Name             MAC Address        Slot  Admin   Oper      Channel   TxPower
------------------  -----------------  ----  ------  --------  --------  ---------
lab-ap-01           00:11:22:aa:00:01   0    ENABLED  UP        6*        *3/8
lab-ap-02           00:11:22:aa:00:02   0    ENABLED  UP        11*       *1/8 (20 dBm)
"""

# --- access points -----------------------------------------------------------

AP_INVENTORY = """\
Inventory for lab-ap-01
NAME: "AP2800"    , DESCR: "Cisco Aironet 2800 Series (IEEE 802.11ac) Access Point"
PID: AIR-AP2802I-B-K9,  VID: 01,  SN: FCW0000A001

Inventory for lab-ap-02
NAME: "AP2600"    , DESCR: "Cisco Aironet 2600 Series (IEEE 802.11n) Access Point"
PID: AIR-CAP2602I-A-K9,  VID: V01,  SN: FCW0000A002

NAME: "Module 0"  , DESCR: "802.11ac module"
PID: AIR-RM3000AC-A-K9,  VID: V01,  SN: FCW0000M001
"""

AP_CDP = """\
AP Name                          AP IP              Neighbor Name           Neighbor IP          Neighbor Port
-------------------------------- ---------------    --------------------    ---------------      ------------------
lab-ap-01                        10.1.1.10          lab-sw-01.lab.example   10.1.1.2             GigabitEthernet1/0/10
lab-ap-02                        10.1.1.11          lab-sw-01               10.1.1.2             GigabitEthernet1/0/11
"""

AP_IMAGE = """\
Total number of APs.............................. 2

Number of APs
        Initiated.................................... 0
        Downloading.................................. 0
        Predownloading............................... 0
        Completed predownloading..................... 0
        Not Supported................................ 0
        Failed to Predownload........................ 0

AP Name             Primary Image  Backup Image   Predownload Status   Predownload Version  Next Retry Time  Retry Count
------------------  -------------  -------------  -------------------  -------------------  ---------------  ------------
lab-ap-01           8.10.185.0     8.10.162.0     None                 None                 NA               NA
lab-ap-02           8.5.182.0      8.5.171.0      None                 None                 NA               NA
"""

AP_UPTIME = """\
Number of APs.................................... 2
Global AP User Name.............................. Not Configured
Global AP Dot1x User Name........................ Not Configured

AP Name             Ethernet MAC       AP Up Time                    Association Up Time
------------------  -----------------  ----------------------------  ----------------------
lab-ap-01           00:11:22:00:00:01  41 days, 03 h 10 m 05 s       41 days, 02 h 58 m 44 s
lab-ap-02           00:11:22:00:00:02  2 days, 01 h 00 m 10 s        0 days, 00 h 12 m 30 s
"""

JOIN_DETAIL = """\
Discovery phase statistics
- Discovery requests received.............................. 4
- Successful discovery responses sent...................... 4
- Unsuccessful discovery request processing................ 0
- Reason for last unsuccessful discovery attempt........... Not applicable
- Time at last successful discovery attempt................ Nov 10 09:00:01.120
- Time at last unsuccessful discovery attempt.............. Not applicable

Join phase statistics
- Join requests received................................... 3
- Successful join responses sent........................... 0
- Unsuccessful join request processing..................... 3
- Reason for last unsuccessful join attempt................ Regulatory domain check failed
- Time at last successful join attempt..................... Not applicable
- Time at last unsuccessful join attempt................... Nov 10 09:00:05.430

Configuration phase statistics
- Configuration requests received.......................... 0
- Successful configuration responses sent.................. 0
- Unsuccessful configuration request processing............ 0
- Reason for last unsuccessful configuration attempt....... Not applicable
- Time at last successful configuration attempt............ Not applicable
- Time at last unsuccessful configuration attempt.......... Not applicable

Last AP message decryption failure details
- Reason for last message decryption failure............... Not applicable

Last AP disconnect details
- Reason for last AP connection failure.................... Not applicable
- Last AP disconnect reason................................ Not applicable

Last join error summary
- Type of error that occurred last......................... Join
- Reason for error that occurred last...................... Regulatory domain check failed
- Time at which the last join error occurred............... Nov 10 09:00:05.430

Ethernet Mac : 00:11:22:00:00:03  Ip Address : 10.1.1.12
"""

AP_GENERAL = """\
Cisco AP Identifier.............................. 1
Cisco AP Name.................................... lab-ap-01
Country code..................................... US  - United States
Regulatory Domain allowed by Country............. 802.11bg:-A    802.11a:-AB
AP Country code.................................. US  - United States
AP Regulatory Domain............................. -B
Switch Port Number .............................. 1
MAC Address...................................... 00:11:22:00:00:01
IP Address Configuration......................... DHCP
IP Address....................................... 10.1.1.10
IP NetMask....................................... 255.255.255.0
Gateway IP Addr.................................. 10.1.1.1
NAT External IP Address.......................... None
CAPWAP Path MTU.................................. 1485
Telnet State..................................... Globally Disabled
Ssh State........................................ Globally Disabled
Jumbo MTU Status................................. Disabled
Cisco AP Location................................ floor 1
Cisco AP Floor Label............................. 0
Cisco AP Group Name.............................. lab-site-a
Primary Cisco Switch Name........................ lab-wlc-01
Primary Cisco Switch IP Address.................. 192.0.2.40
Secondary Cisco Switch Name...................... lab-wlc-02
Secondary Cisco Switch IP Address................ 192.0.2.42
Tertiary Cisco Switch Name.......................
Tertiary Cisco Switch IP Address................. Not Configured
Administrative State ............................ ADMIN_ENABLED
Operation State ................................. REGISTERED
Mirroring Mode .................................. Disabled
AP Mode ......................................... Local
Public Safety ................................... Disabled
AP SubMode ...................................... Not Configured
Rogue Detection ................................. Enabled
Remote AP Debug ................................. Disabled
Logging trap severity level ..................... informational
Logging syslog facility ......................... kern
S/W  Version .................................... 8.10.185.0
Boot  Version ................................... 1.1.2.4
Mini IOS Version ................................ 0.0.0.0
Stats Reporting Period .......................... 180
Stats Collection Mode ........................... normal
LED State........................................ Enabled
LED Flash State.................................. 0 sec
PoE Pre-Standard Switch.......................... Disabled
PoE Power Injector MAC Addr...................... Disabled
Power Type/Mode.................................. PoE/Full Power
Number Of Slots.................................. 3
AP Model......................................... AIR-AP2802I-B-K9
AP Image......................................... AP3G3-K9W8-M
IOS Version...................................... 8.10.185.0
Reset Button..................................... Enabled
AP Serial Number................................. FCW0000A001
AP Certificate Type.............................. Manufacture Installed
AP User Mode..................................... AUTOMATIC
AP User Name..................................... Not Configured
AP Dot1x User Mode............................... Not Configured
AP Dot1x User Name............................... Not Configured
Cisco AP system logging host..................... 255.255.255.255
AP Up Time....................................... 41 days, 03 h 10 m 05 s
AP LWAPP Up Time................................. 41 days, 02 h 58 m 44 s
Join Date and Time............................... Thu Oct 01 07:01:20 2026
Join Taken Time.................................. 0 days, 00 h 00 m 12 s
Join Priority.................................... 1
Ethernet Port Duplex............................. Auto
Ethernet Port Speed.............................. Auto
AP Link Latency.................................. Disabled
AP TCP MSS Adjust................................ Enabled
AP TCP MSS Size.................................. 1250
Last Reboot Reason............................... Reload command
Last AP Disconnect Reason........................ AP Message Timeout
"""

# FlexConnect AP on an injector-less low-power switch port, static IP, no
# secondary or tertiary controller.
AP_GENERAL_FLEX = """\
Cisco AP Identifier.............................. 7
Cisco AP Name.................................... lab-ap-02
AP Country code.................................. US  - United States
MAC Address...................................... 00:11:22:00:00:02
IP Address Configuration......................... Static IP assigned
IP Address....................................... 10.1.1.11
IP NetMask....................................... 255.255.255.0
Gateway IP Addr.................................. 10.1.1.1
Cisco AP Location................................ floor 2
Cisco AP Group Name.............................. default-group
FlexConnect Group Name........................... lab-flex-01
Primary Cisco Switch Name........................ lab-wlc-01
Primary Cisco Switch IP Address.................. 192.0.2.40
Secondary Cisco Switch Name......................
Secondary Cisco Switch IP Address................ Not Configured
Tertiary Cisco Switch Name.......................
Tertiary Cisco Switch IP Address................. Not Configured
Administrative State ............................ ADMIN_ENABLED
Operation State ................................. REGISTERED
AP Mode ......................................... FlexConnect
S/W  Version .................................... 8.5.182.0
Boot  Version ................................... 15.2.4.0
LED State........................................ Disabled
Power Type/Mode.................................. PoE/Low Power (degraded mode)
AP Model......................................... AIR-CAP2602I-A-K9
AP Serial Number................................. FCW0000A002
AP Up Time....................................... 2 days, 01 h 00 m 10 s
"""

AP_RADIO_A = """\
Cisco AP Identifier.............................. 1
Cisco AP Name.................................... lab-ap-01
Country code..................................... US  - United States
Regulatory Domain allowed by Country............. 802.11bg:-A    802.11a:-AB
AP Country code.................................. US  - United States
AP Regulatory Domain............................. -B
Switch Port Number .............................. 1
MAC Address...................................... 00:11:22:00:00:01
Administrative State ............................ ADMIN_ENABLED
Operation State ................................. REGISTERED
Attributes for Slot  1
    Radio Type................................... RADIO_TYPE_80211ac-5
    Radio Subband................................ RADIO_SUBBAND_ALL
    Administrative State ........................ ADMIN_ENABLED
    Operation State ............................. UP
    Mesh Radio Role ............................. ACCESS
    Radio Role .................................. Client Serving
    CellId ...................................... 0

    Station Configuration
      Configuration ............................. AUTOMATIC
      Number Of WLANs ........................... 2
      Medium Occupancy Limit .................... 100
      CFP Period ................................ 4
      CFP MaxDuration ........................... 60
      BSSID ..................................... 00:11:22:aa:00:01
      Beacon Period ............................. 100
      Fragmentation Threshold ................... 2346
      Country String ............................ US

    MAC Operation Parameters
      Configuration ............................. AUTOMATIC
      Fragmentation Threshold ................... 2346
      Packet Retry Limit ........................ 64

    Tx Power
      Num Of Supported Power Levels ............. 6
      Tx Power Level 1 .......................... 17 dBm
      Tx Power Level 2 .......................... 14 dBm
      Tx Power Level 3 .......................... 11 dBm
      Tx Power Level 4 .......................... 8 dBm
      Tx Power Level 5 .......................... 5 dBm
      Tx Power Level 6 .......................... 2 dBm
      Tx Power Configuration .................... AUTOMATIC
      Current Tx Power Level .................... 2
      Tx Power Assigned By ...................... DCA

    Phy OFDM parameters
      Configuration ............................. AUTOMATIC
      Current Channel ........................... 36
      Channel Assigned By ....................... DCA
      Extension Channel ......................... 40
      Channel Width.............................. 40 Mhz
      Allowed Channel List....................... 36,40,44,48,52,56,60,64,100,
      ......................................... 104,108,112,116,132,136,140,
      ......................................... 149,153,157,161
      TI Threshold .............................. -50
      Legacy Tx Beamforming Configuration ....... AUTOMATIC
      Legacy Tx Beamforming ..................... DISABLED
      Antenna Type............................... INTERNAL_ANTENNA

    Performance Profile Parameters
      Configuration ............................. AUTOMATIC
      Interference threshold..................... 10 %
      Noise threshold............................ -70 dBm
      RF utilization threshold................... 80 %
      Data-rate threshold........................ 1000000 bps
      Client threshold........................... 12 clients
      Coverage SNR threshold..................... 16 dB
      Coverage exception level................... 25 %
      Client minimum exception level............. 3 clients

    Rogue Containment Information
      Containment Count............................ 0

    CleanAir Management Information
      CleanAir Capable......................... Yes
      CleanAir Management Admin State.......... Disabled
      CleanAir Management Operation State...... Down
      Rapid Update Mode........................ Off
      Spectrum Expert connection............... Disabled
      CleanAir Sensor State.................... Configured

    Radio Extended Configurations:
      Buffer size..................................30
      Rx-Sop threshold.............................AUTO
      CCA threshold................................0
"""

# An XOR AP in dual-5 GHz mode prints both slots under 802.11a.
AP_RADIO_A_DUAL = """\
Cisco AP Identifier.............................. 9
Cisco AP Name.................................... lab-ap-09
Attributes for Slot  0
    Radio Type................................... RADIO_TYPE_80211ac-5
    Administrative State ........................ ADMIN_ENABLED
    Operation State ............................. UP
    Tx Power
      Tx Power Level 1 .......................... 20 dBm
      Current Tx Power Level .................... 1
    Phy OFDM parameters
      Current Channel ........................... 52
      Channel Width.............................. 20 Mhz
    CleanAir Management Information
      CleanAir Capable......................... Yes
      CleanAir Management Admin State.......... Enabled
Attributes for Slot  1
    Radio Type................................... RADIO_TYPE_80211ac-5
    Administrative State ........................ ADMIN_ENABLED
    Operation State ............................. UP
    Tx Power
      Tx Power Level 1 .......................... 17 dBm
      Tx Power Level 2 .......................... 14 dBm
      Current Tx Power Level .................... 2
    Phy OFDM parameters
      Current Channel ........................... 149
      Channel Width.............................. 20 Mhz
    CleanAir Management Information
      CleanAir Capable......................... Yes
      CleanAir Management Admin State.......... Enabled
"""

AP_RADIO_B = """\
Cisco AP Identifier.............................. 7
Cisco AP Name.................................... lab-ap-02
Attributes for Slot  0
    Radio Type................................... RADIO_TYPE_80211n-2.4
    Administrative State ........................ ADMIN_DISABLED
    Operation State ............................. DOWN
    Tx Power
      Num Of Supported Power Levels ............. 8
      Tx Power Level 1 .......................... 20 dBm
      Current Tx Power Level .................... 1
    Phy DSSS parameters
      Configuration ............................. AUTOMATIC
      Current Channel ........................... 11
    CleanAir Management Information
      CleanAir Capable......................... No
"""

LINK_ENCRYPTION = """\
                        Encryption  Dnstream    Upstream    Last
AP Name           State      Count      Count       Update
--------------    ---------- ---------- ----------  ------
lab-ap-01           En       0          0           Never
lab-ap-02           Dis      0          0           Never
"""

AP_ETHERNET = """\
AP Name                 Ethernet Interface Name   Status   Speed       Duplex  Rx Unicast Pkts  Tx Unicast Pkts
----------------------  ------------------------  -------  ----------  ------  ---------------  ---------------
lab-ap-01               GigabitEthernet0          UP       1000 Mbps   Full    1234567          7654321
lab-ap-01               GigabitEthernet1          DOWN     Auto        Auto    0                0
lab-ap-02               GigabitEthernet0          UP       100 Mbps    Half    5555             4444
"""

# No duplex column; speed in Gbps for a multigigabit AP.
AP_ETHERNET_OLD = """\
AP Name                 Ethernet Name             Status   Speed       Rx Unicast Pkts  Tx Unicast Pkts
----------------------  ------------------------  -------  ----------  ---------------  ---------------
lab-ap-04               GigabitEthernet0          UP       2.5 Gbps    1                2
"""

TCP_MSS = """\
AP Name                         TCP State  MSS Size
------------------------------  ---------  --------
lab-ap-01                       enabled    1250
lab-ap-02                       disabled   -
"""

RETRANSMIT = """\
Global control packet retransmit interval: 3 (default)
Global control packet retransmit count: 5 (default)

AP Name             Retransmit Interval     Retransmit count
------------------  ---------------------   ---------------------
lab-ap-01           3                       5
lab-ap-02           5                       8
"""

MAX_COUNT = """\
The max number of AP's supported................. 1500
"""

AIR_QUALITY_A = """\
AQ = Air Quality
DFS = Dynamic Frequency Selection

AP Name            Channel Avg AQ Min AQ Interferers DFS
--------------     ------- ------ ------ ----------- ---
lab-ap-01          36      99     98     0           No
lab-ap-02          100     87     70     2           Yes
"""

# --- clients (as stored: scrubbed) -------------------------------------------

CLIENT_SUMMARY_SCRUBBED = """\
Number of Clients................................ 5

Number of PMIPV6 Clients......................... 0

                                                                        GLAN/
                                                                        RLAN/
MAC Address       AP Name                        Slot Status        WLAN  Auth Protocol         Port Wired Tunnel  Role
----------------- ------------------------------ ---- ------------- ----- ---- ---------------- ---- ----- ------- ----------------
xx:xx:xx:xx:xx:xx lab-ap-01                       1   Associated     1    Yes  802.11ac(5 GHz)  1    No    No      Local
xx:xx:xx:xx:xx:xx lab-ap-01                       1   Associated     1    Yes  802.11ac(5 GHz)  1    No    No      Local
xx:xx:xx:xx:xx:xx lab-ap-02                       0   Associated     2    No   802.11n(2.4 GHz) 1    No    No      Local
xx:xx:xx:xx:xx:xx lab-ap-02                       1   Associated     2    Yes  802.11ax(5 GHz)  1    No    No      Local
xx:xx:xx:xx:xx:xx lab-ap-01                       0   Probing        1    No   802.11g          1    No    No      Local
"""

EXCLUSION_SCRUBBED = """\
Excluded Clients

MAC Address             Exclusion Reason        Time Remaining (in secs)
-----------             ----------------        ------------------------
xx:xx:xx:xx:xx:xx       802.1X Failure           42
xx:xx:xx:xx:xx:xx       802.1X Failure           12
xx:xx:xx:xx:xx:xx       Web Auth Failure         50
"""

EXCLUSION_EMPTY = """\
Excluded Clients

MAC Address             Exclusion Reason        Time Remaining (in secs)
-----------             ----------------        ------------------------
"""

CLI_ERROR = "Incorrect usage. Use the '?' or <TAB> key to list commands."
