"""Synthetic ASA VPN and routing output."""

VPN_CONFIG = """\
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.2 255.255.255.248
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
 ospf message-digest-key 1 md5 *****
!
object network LAB-LOCAL
 subnet 10.0.0.0 255.255.255.0
object network LAB-REMOTE
 subnet 172.16.50.0 255.255.255.0
object network LAB-REMOTE2
 subnet 172.16.60.0 255.255.255.0
access-list LAB-VPN-1 remark lab branch one
access-list LAB-VPN-1 extended permit ip object LAB-LOCAL object LAB-REMOTE
access-list LAB-VPN-2 extended permit ip object LAB-LOCAL object LAB-REMOTE2
access-list LAB-SPLIT standard permit 10.0.0.0 255.255.255.0
nat (inside,outside) source static LAB-LOCAL LAB-LOCAL destination static LAB-REMOTE LAB-REMOTE no-proxy-arp route-lookup
ip local pool LAB-POOL 10.10.0.1-10.10.0.254 mask 255.255.255.0
crypto ipsec ikev1 transform-set LAB-TS-OLD esp-3des esp-md5-hmac
crypto ipsec ikev2 ipsec-proposal LAB-PROP
 protocol esp encryption aes-256
 protocol esp integrity sha-1
crypto map LAB-MAP 10 match address LAB-VPN-1
crypto map LAB-MAP 10 set peer 203.0.113.9
crypto map LAB-MAP 10 set ikev1 transform-set LAB-TS-OLD
crypto map LAB-MAP 10 set pfs group2
crypto map LAB-MAP 10 set security-association lifetime seconds 28800
crypto map LAB-MAP 20 match address LAB-VPN-2
crypto map LAB-MAP 20 set peer 203.0.113.10
crypto map LAB-MAP 20 set ikev2 ipsec-proposal LAB-PROP
crypto map LAB-MAP interface outside
crypto ikev1 policy 10
 authentication pre-share
 encryption 3des
 hash md5
 group 2
 lifetime 86400
crypto ikev2 policy 20
 encryption aes-256
 integrity sha
 group 14
 prf sha
 lifetime seconds 86400
crypto ikev1 enable outside
crypto ikev2 enable outside
webvpn
 enable outside
 anyconnect image disk0:/anyconnect-win-4.10.07073-webdeploy-k9.pkg 1
 anyconnect enable
 hostscan image disk0:/hostscan_4.10.07073-k9.pkg
dynamic-access-policy-record DfltAccessPolicy
dynamic-access-policy-record LAB-DAP
group-policy LAB-GP internal
group-policy LAB-GP attributes
 dns-server value 10.0.0.53
 vpn-simultaneous-logins 3
 vpn-idle-timeout 30
 vpn-tunnel-protocol ikev2 ssl-client
 split-tunnel-policy tunnelspecified
 split-tunnel-network-list value LAB-SPLIT
 split-dns value lab.example
tunnel-group 203.0.113.9 type ipsec-l2l
tunnel-group 203.0.113.9 ipsec-attributes
 ikev1 pre-shared-key *****
tunnel-group 203.0.113.10 type ipsec-l2l
tunnel-group 203.0.113.10 ipsec-attributes
 ikev2 remote-authentication certificate
 ikev2 local-authentication certificate LAB-TP
tunnel-group LAB-RA type remote-access
tunnel-group LAB-RA general-attributes
 address-pool LAB-POOL
 authentication-server-group LAB-LDAP
 default-group-policy LAB-GP
tunnel-group LAB-RA webvpn-attributes
 group-alias LAB-RA enable
tunnel-group LAB-RA-CERT type remote-access
tunnel-group LAB-RA-CERT general-attributes
 address-pool LAB-POOL
 default-group-policy LAB-GP
tunnel-group LAB-RA-CERT webvpn-attributes
 authentication certificate
 group-url https://vpn.lab.example/cert enable
aaa-server LAB-LDAP protocol ldap
route outside 0.0.0.0 0.0.0.0 198.51.100.1 1 track 1
route outside 0.0.0.0 0.0.0.0 198.51.100.5 254
route inside 10.5.0.0 255.255.0.0 10.0.0.254 1
sla monitor 10
 type echo protocol ipIcmpEcho 198.51.100.1 interface outside
sla monitor schedule 10 life forever start-time now
track 1 rtr 10 reachability
router ospf 1
 network 10.0.0.0 255.255.255.0 area 0
 area 0 authentication message-digest
 redistribute static subnets
 redistribute connected subnets route-map LAB-RM
router bgp 65001
 address-family ipv4 unicast
  neighbor 203.0.113.1 remote-as 65010
  neighbor 203.0.113.1 activate
"""

SHOW_ROUTE = """\
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area

Gateway of last resort is 198.51.100.1 to network 0.0.0.0

S*       0.0.0.0 0.0.0.0 [1/0] via 198.51.100.1, outside
C        10.0.0.0 255.255.255.0 is directly connected, inside
L        10.0.0.1 255.255.255.255 is directly connected, inside
S        10.5.0.0 255.255.0.0 [1/0] via 10.0.0.254, inside
O        10.6.0.0 255.255.0.0 [110/20] via 10.0.0.2, 1d02h, inside
O E2     10.7.0.0 255.255.0.0 [110/20] via 10.0.0.2, 1d02h, inside
                              [110/20] via 10.0.0.3, 1d02h, inside
B        172.20.0.0 255.255.0.0 [20/0] via 203.0.113.1, 2d00h, outside
C        198.51.100.0 255.255.255.248 is directly connected, outside
"""

ROUTE_SUMMARY = """\
IP routing table maximum-paths is 8
Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
connected       0           4           0           352         1152
static          1           1           0           176         576
ospf 1          0           2           0           176         576
  Intra-area: 1 Inter-area: 0 External-1: 0 External-2: 1
  NSSA External-1: 0 NSSA External-2: 0
bgp 65001       0           1           0           88          288
internal        3                                               1068
Total           4           8           0           792         3660
"""

OSPF_NEIGHBOR = """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/DR         0:00:35     10.0.0.2        inside
10.0.0.3          1   FULL/DROTHER    0:00:33     10.0.0.3        inside
"""
OSPF_INTERFACE_BRIEF = """\
Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C
inside       1     0               10.0.0.1/24        10    BDR   2/2
"""
BGP_SUMMARY = """\
BGP router identifier 10.0.0.1, local AS number 65001
BGP table version is 10, main routing table version 10

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
203.0.113.1     4        65010     100      90       10    0    0 2d00h           5
"""
BGP_NEIGHBORS = """\
BGP neighbor is 203.0.113.1,  context single_vf,  remote AS 65010, external link
  For address family: IPv4 Unicast
                                 Sent       Rcvd
  Prefix activity:               ----       ----
    Prefixes Current:               3          5 (Consumes 400 bytes)
"""
SHOW_TRACK = """\
Track 1
  Response Time Reporter 10 reachability
  Reachability is Up
"""
EIGRP_NEIGHBORS = """\
EIGRP-IPv4 Neighbors for AS(100)
H   Address                 Interface       Hold Uptime   SRTT   RTO  Q  Seq
                                            (sec)         (ms)       Cnt Num
0   10.0.0.9                inside            13 1d02h    1      200  0  15
"""

L2L_DETAIL = """\
Session Type: LAN-to-LAN Detailed

Connection   : 203.0.113.9
Index        : 1                      IP Addr      : 203.0.113.9
Protocol     : IKEv1 IPsec
Encryption   : IKEv1: (1)3DES  IPsec: (1)3DES
Hashing      : IKEv1: (1)MD5  IPsec: (1)MD5
Bytes Tx     : 1000                   Bytes Rx     : 2000
Login Time   : 10:00:00 UTC Fri Nov 7 2026
Duration     : 4h:22m:31s
"""
ANYCONNECT = """\
Session Type: AnyConnect

Username     : lab-person-one         Index        : 5
Assigned IP  : 10.10.0.5              Public IP    : 198.51.100.50
Protocol     : AnyConnect-Parent SSL-Tunnel DTLS-Tunnel
License      : AnyConnect Premium
Encryption   : AnyConnect-Parent: (1)none  SSL-Tunnel: (1)AES-GCM-256  DTLS-Tunnel: (1)AES-GCM-256
Bytes Tx     : 15000                  Bytes Rx     : 3000
Group Policy : LAB-GP                 Tunnel Group : LAB-RA
Login Time   : 13:00:00 UTC Fri Nov 7 2026
Duration     : 1h:22m:31s
Audt Sess ID : 0a0000010000500063a1b2c3

Username     : lab-person-two         Index        : 6
Assigned IP  : 10.10.0.6              Public IP    : 198.51.100.51
Protocol     : AnyConnect-Parent SSL-Tunnel
Encryption   : AnyConnect-Parent: (1)none  SSL-Tunnel: (1)AES256
Bytes Tx     : 500                    Bytes Rx     : 400
Group Policy : LAB-GP                 Tunnel Group : LAB-RA-CERT
Duration     : 0h:05m:00s
"""
IP_LOCAL_POOL = """\
Begin           End             Mask            Free     Held     In use
10.10.0.1       10.10.0.254     255.255.255.0    252        0        2
"""
