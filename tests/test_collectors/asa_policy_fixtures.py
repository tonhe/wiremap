"""Synthetic ASA policy: objects, ACLs, access-groups and NAT."""

POLICY_CONFIG = """\
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.2 255.255.255.248
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
!
object network LAB-WEB
 host 10.1.0.10
 description lab web server
object network LAB-WEB-COPY
 host 10.1.0.10
object network LAB-NET
 subnet 10.0.0.0 255.255.255.0
object network LAB-RANGE
 range 10.2.0.1 10.2.0.6
object network LAB-UNUSED
 host 10.9.9.9
object network LAB-DMZ-WEB
 host 10.1.0.20
 nat (inside,outside) static 203.0.113.20
object service LAB-HTTPS
 service tcp destination eq https
object-group network LAB-SERVERS
 network-object object LAB-WEB
 network-object host 10.1.0.11
 group-object LAB-INNER
object-group network LAB-INNER
 network-object 10.3.0.0 255.255.0.0
object-group service LAB-WEB-PORTS tcp
 port-object eq www
 port-object eq https
object-group service LAB-MIXED
 service-object tcp destination eq ssh
 service-object udp destination range 5060 5061
 service-object object LAB-HTTPS
object-group protocol LAB-PROTOS
 protocol-object tcp
 protocol-object udp
access-list LAB-OUTSIDE-IN remark allow the web servers
access-list LAB-OUTSIDE-IN extended permit tcp any object-group LAB-SERVERS object-group LAB-WEB-PORTS
access-list LAB-OUTSIDE-IN extended permit tcp any host 10.1.0.10 eq https
access-list LAB-OUTSIDE-IN extended deny tcp any host 10.1.0.11 eq www log
access-list LAB-OUTSIDE-IN extended permit ip any 10.3.0.0 255.255.0.0
access-list LAB-OUTSIDE-IN extended permit ip any any
access-list LAB-OUTSIDE-IN extended permit udp any any eq domain time-range LAB-HOURS inactive
access-list LAB-INSIDE-IN extended permit ip object LAB-NET any
access-list LAB-INSIDE-IN extended permit object-group LAB-MIXED any any
access-list LAB-SPLIT standard permit 10.0.0.0 255.0.0.0
access-list LAB-VPN extended permit ip object LAB-NET object LAB-RANGE
access-list LAB-ORPHAN extended permit icmp any any echo-reply
access-group LAB-OUTSIDE-IN in interface outside
access-group LAB-INSIDE-IN in interface inside
crypto map LAB-MAP 10 match address LAB-VPN
group-policy LAB-GP attributes
 split-tunnel-network-list value LAB-SPLIT
nat (inside,outside) source static LAB-NET LAB-NET destination static LAB-RANGE LAB-RANGE no-proxy-arp route-lookup
"""

SHOW_ACCESS_LIST = """\
access-list cached ACL log flows: total 0, denied 0 (deny-flow-max 4096)
access-list LAB-OUTSIDE-IN; 9 elements; name hash: 0x1a2b3c4d
access-list LAB-OUTSIDE-IN line 1 remark allow the web servers
access-list LAB-OUTSIDE-IN line 2 extended permit tcp any object-group LAB-SERVERS object-group LAB-WEB-PORTS (hitcnt=12) 0x11111111
  access-list LAB-OUTSIDE-IN line 2 extended permit tcp any host 10.1.0.10 eq www (hitcnt=5) 0x21111111
  access-list LAB-OUTSIDE-IN line 2 extended permit tcp any host 10.1.0.10 eq https (hitcnt=7) 0x31111111
access-list LAB-OUTSIDE-IN line 3 extended permit tcp any host 10.1.0.10 eq https (hitcnt=0) 0x22222222
access-list LAB-OUTSIDE-IN line 4 extended deny tcp any host 10.1.0.11 eq www log informational interval 300 (hitcnt=0) 0x33333333
access-list LAB-OUTSIDE-IN line 5 extended permit ip any 10.3.0.0 255.255.0.0 (hitcnt=0) 0x44444444
access-list LAB-OUTSIDE-IN line 6 extended permit ip any any (hitcnt=900) 0x55555555
access-list LAB-OUTSIDE-IN line 7 extended permit udp any any eq domain time-range LAB-HOURS (hitcnt=0) (inactive) 0x66666666
access-list LAB-INSIDE-IN; 4 elements; name hash: 0x2b3c4d5e
access-list LAB-INSIDE-IN line 1 extended permit ip object LAB-NET any (hitcnt=4000) 0x77777777
"""

NAT_DETAIL = """\
Manual NAT Policies (Section 1)
1 (inside) to (outside) source static LAB-NET LAB-NET destination static LAB-RANGE LAB-RANGE no-proxy-arp route-lookup
    translate_hits = 10, untranslate_hits = 10
    Source - Origin: 10.0.0.0/24, Translated: 10.0.0.0/24
    Destination - Origin: 10.2.0.1/32, 10.2.0.2/31, Translated: 10.2.0.1/32, 10.2.0.2/31

Auto NAT Policies (Section 2)
1 (inside) to (outside) source static LAB-DMZ-WEB 203.0.113.20
    translate_hits = 0, untranslate_hits = 0
    Source - Origin: 10.1.0.20/32, Translated: 203.0.113.20/32
2 (inside) to (outside) source dynamic LAB-NET interface
    translate_hits = 500, untranslate_hits = 20
    Source - Origin: 10.0.0.0/24, Translated: 198.51.100.2/29

Manual NAT Policies (Section 3)
1 (any) to (outside) source dynamic any pat-pool LAB-POOL inactive
    translate_hits = 0, untranslate_hits = 0
"""
