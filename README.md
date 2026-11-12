# Wiremap

**Network topology discovery and assessment tool.** Connects to a seed device, discovers neighbors via CDP/LLDP, recursively crawls the network, collects data from every device, and generates detailed assessment reports.

> Built on [neighbor-mapper](https://github.com/aconaway-rens/neighbor-mapper) by **Aaron Conaway**. Wiremap extends his original CDP/LLDP discovery tool with a modular collector/report architecture, multi-vendor support, recursive BFS crawling, discovery inventories, and automated network assessment reporting.

---

## Features

### Discovery
- **SSH, Telnet, or Auto-detect** -- Tries SSH first, falls back to Telnet automatically
- **Recursive BFS Crawling** -- Discovers neighbors hop-by-hop from a seed device with configurable depth (0-10, including crawl from targets)
- **Multi-threaded** -- Parallel device collection with configurable concurrent workers (1-20, default 10), persisted in Settings
- **Async with Live Progress** -- Scans run in the background with real-time Server-Sent Events (SSE) streaming authentication, fallback, data collection, neighbor discovery, and completion status to a live console panel. Above the console, each device being collected shows the command it is on, how many it has run and how long the current one has taken; every problem with a command is written to the console and to `logs/app.log` as `collection issue [kind] host (ip) 'command': detail`, and kept for the Collection Issues report
- **Cancellable Scans** -- Cancel a running scan gracefully; in-progress devices finish and partial results are saved
- **L3 Neighbor Discovery** -- Optionally discover OSPF, EIGRP, BGP, and ISIS neighbors alongside CDP/LLDP
- **Device Type Auto-detection** -- YAML-based pattern matching against CDP platform strings and LLDP system descriptions
- **Hostname Dedup** -- Prevents collecting the same device twice when it's reachable via multiple IPs (management, loopback, SVI)
- **Loop Prevention** -- Tracks visited devices and enforces depth limits
- **Multiple Neighbour Sources** -- Crawls from CDP/LLDP, routing adjacencies (OSPF, EIGRP, BGP, IS-IS), HSRP/VRRP peers, and optionally routing next-hops. A device seen by several sources is merged into one record that keeps every sighting
- **Crawl Boundaries** -- Private address space only by default, with CIDR allow/deny lists and a device ceiling, so next-hop crawling cannot wander into transit or ISP space. Addresses skipped by a boundary are reported, never silently dropped
- **SNMP Fallback** -- When a login fails (auth, refused, timeout), SNMP v2c or v3 identifies the device and collects interfaces, addressing, routes, ARP and neighbours from the standard MIBs. Reaches gear that never accepts a CLI session, such as firewalls shipped with SSH disabled
- **Add to a Previous Scan** -- Continue an earlier scan instead of starting over. Devices already collected are skipped, ones that failed are retried, and results merge into a new scan. The original is never modified
- **Device Provenance** -- Every device records how it was found (`login`, `cdp_lldp`, `routing_adjacency`, `snmp`, ...), whether login succeeded, and why it failed. A device seen only in a neighbour table is never mistaken for one that was fully collected
- **Failure Classification** -- Every failed login is classified as timeout, refused, auth, legacy crypto, no telnet driver, or other, with a remediation hint. Reasons show in the scan console and in a Failed Devices sheet. SSH negotiation failures are retried once with legacy key exchange and cipher algorithms
- **Controller-managed Devices** -- ACI fabric nodes and UCS Fabric Interconnects authenticate against their controller, so they are recorded and skipped instead of burning a failed login (override with `collect_controller_managed`). Meraki gear is recorded as a neighbour and never logged into
- **Neighbour Accuracy** -- LLDP detail is parsed per record, neighbour type comes from the LLDP system description, parallel links between the same pair stay separate, and interface names are canonicalized (`Gi1/0/1` and `GigabitEthernet1/0/1` are one port)
- **Scan Timing** -- Per-device and per-collector timings are recorded, and the slowest devices and collectors are listed in the console when a scan finishes

### Multi-Vendor Support
Cisco IOS / IOS-XE / NX-OS / IOS-XR, Cisco ASA / ASAv, Cisco AireOS WLC, Arista EOS, Juniper JunOS, Palo Alto PAN-OS, WatchGuard Firebox (Fireware), VyOS, MikroTik RouterOS, Fortinet FortiGate, HPE Comware / ProCurve, Aruba OS-CX, Dell OS10, Extreme ExtremeXOS / VOSS, Ubiquiti EdgeOS

Each platform has its own command set per collector. A collector that cannot serve a platform -- spanning tree on a firewall, switchports on a router -- declares it and is skipped, rather than sending commands the device will reject.

**Legacy SSH:** paramiko is pinned to 3.5.x deliberately. Version 4.0 removed the SHA-1 key exchanges and the `ssh-rsa` host key algorithm outright, which strands older Catalyst and Nexus hardware that offers nothing else. Modern algorithms are still preferred wherever the device supports them.

### Data Collection (23 Collectors)
All collectors run automatically on every device -- no pre-selection needed. Each decides from the device type whether it applies, so the Cisco ASA and Cisco WLC collectors only run on those devices. QoS checks whether QoS is in use before its per-port commands: a classic Catalyst with `mls qos` off, or a Catalyst 9000 with no policy attached (the control-plane policy does not count) and no auto-QoS, skips them, and the Voice and QoS report shows "QoS off" and lists the commands not run.

| Collector | Data Gathered |
|-----------|--------------|
| CDP/LLDP | Neighbor adjacencies and protocols |
| Interfaces | Port status, descriptions, IP assignments, etherchannel, interface VRF |
| Device Inventory | Version, hardware modules, serial numbers, stack members, StackWise Virtual / VSS / vPC, uptime, last reload reason, image, licensing, call-home |
| Config | Running configuration backup, secrets redacted by default |
| ARP | ARP table entries with interface mappings, per-VRF tables, incomplete entries flagged |
| MAC Table | MAC address to port mappings |
| STP/VLAN | Root bridges, blocked ports, VLAN list, VTP status |
| STP Detail | Port roles, costs, topology change counts, inconsistent ports |
| L3 Routing | OSPF/EIGRP/BGP/ISIS neighbors and route tables, BGP peers inside VRFs |
| Routing Detail | Protocol summaries, per-VRF route counts, OSPF interfaces with passive state and network type, OSPF LSDB and EIGRP topology size, routing processes, redistribution |
| VRF | VRF definitions and interface assignments |
| Switchport | Port-security, BPDU guard, storm-control, trunk config |
| HSRP | HSRP, GLBP and VRRP state, virtual IPs, active/standby roles; groups configured but not collected are still listed from the config |
| Edge Services | ACLs and what references them, applied ACLs per interface, NAT, proxy-ARP, uRPF |
| NTP/Logging | NTP sync, logging config and the full log buffer, SNMP settings (credentials redacted) |
| Environment | PSU, fan and temperature state, PoE budget and faulted ports |
| Redundancy | Supervisor redundancy mode and peer state, switchovers, stack ports and ring |
| Management Security | SSH version and host key size, Smart Install state |
| Interface Counters | Per-interface errors, CRC, drops, resets, last input/output, link flap, input/output rate and queueing strategy |
| Cisco ASA | ASA and ASAv only: platform, licence and health (show version, CPU, memory, conns, ASP drops, crashinfo), failover state and history, running-config, interfaces, routing, ACLs, objects, NAT, site-to-site and AnyConnect VPN, certificates and the management plane. The standby unit of a pair gets the platform, failover and config blocks; on a multiple-context unit every context is visited with `changeto` |
| Cisco WLC | AireOS controllers only: platform, licence, health, redundancy, running-config, interfaces, ports, WLANs and AP groups, RF, access points, client counts (never client MACs, addresses or names), AAA, ACLs, rogue and WIPS settings, mobility, FlexConnect, QoS and the management plane, then the per-item commands (each interface, WLAN, RF profile, ACL, FlexConnect group and port, then three per AP, last) |
| QoS | Attached policy-map counters (per-class packets, drops, priority queue), class-map and policy-map definitions, auto-QoS; on 2960/3560/3750 `mls qos` state, port trust, expedite queue, queue-sets, DSCP/CoS-to-queue maps and per-port DSCP and queue counters; on Catalyst 9000 per-port hardware queue counters for uplinks and voice ports (capped at 24 per device) |
| CPU/Memory | CPU 5s/1m/5m, CPU history, memory pools and top processes |

Parsing uses [NTC Templates](https://github.com/networktocode/ntc-templates) (TextFSM) with regex fallbacks for vendor-aware structured output.

Command output is checked for CLI errors (`% Invalid input`, a caret under the bad token) before parsing. A rejected command is recorded as an error and listed in the Collection Errors sheet, never parsed as data. Switching collectors are skipped on routers.

**Secret redaction.** With `redact_secrets` on (the default), SNMP communities, enable and user secrets, AAA server keys, routing protocol keys and VPN pre-shared keys are replaced with `<REDACTED>` before the config is stored. Only the secret token is swapped, so line counts and diffs still line up. The config archive includes a `SUMMARY.txt` stating whether secrets were redacted and naming any config collected with redaction off.

### Reports Tab
A dedicated **Reports** tab serves as the single destination for all report generation. After a discovery completes, a targeted scan finishes, or a saved scan is loaded, the UI automatically switches to the Reports tab showing a summary stat bar (devices, failed, elapsed time, scan date) and available report cards grouped by category with format selectors. Old inventories without summary metadata display gracefully with `--` placeholders.

| Report | Formats | Description |
|--------|---------|-------------|
| Topology Map | HTML | Interactive D3.js network diagram with color-coded device types |
| Device Inventory | XLSX, JSON, CSV, XML | Device summary with provenance (discovered via, collection status, failure reason), redundancy (stack, StackWise Virtual, VSS, vPC), uptime, last reload reason, image, license, stack members, modules and line cards. Licenses, Failed Devices (by category, with likely cause) and Not Collected (controller-managed, not attempted) sheets |
| Link Inventory | XLSX, JSON, CSV, XML | All discovered neighbor links (CDP/LLDP + L3) |
| Collection Issues | XLSX, JSON, CSV | Everything that went wrong while collecting, to hand over when a scan misbehaves: command issues recorded as they happened (timeouts, a pager prompt nobody answered, pager text left in output, unexpected questions, paging that could not be turned off, refused and slow commands), every refused command read back from the saved outputs, and devices that could not be logged into |
| L2/L3 Diagram Data | XLSX, JSON, CSV, XML | Node and edge lists for drawing diagrams: device details, deduplicated L2 links, L3 adjacencies, subnets |
| Interface Summary | XLSX, JSON, CSV, XML | Port status, descriptions, IP assignments |
| ARP Summary | XLSX, JSON, CSV, XML | ARP entries by device and VRF with summary and detail tabs, incomplete entries flagged |
| MAC Table | XLSX, JSON, CSV, XML | MAC-to-port mappings per device |
| L2 Discovery | XLSX, JSON, CSV, XML | VLANs, STP topology and root bridges, trunk and interface status with neighbors, routed interfaces, anomaly findings |
| L3 Routing & IP | XLSX, JSON, CSV, XML | Protocol neighbors, route tables, per-VRF route summary, OSPF topology (with a Passive column from the full `show ip ospf interface`, since the brief form shows a passive interface and an active one with no neighbours the same way), Routing Scale (OSPF LSDB, EIGRP topology), Routing Processes, Redistribution, FHRP status, IP audit, ARP/MAC map, VRF summary, and a Collection Errors sheet listing any command a device rejected |
| Internet Edge | XLSX, JSON, CSV, XML | Edge Devices (and why each qualifies), BGP peering across VRFs, Public Addresses, NAT overview, ACL audit by usage, FHRP status, edge interface security |
| Platform Health | XLSX, JSON, CSV, XML | Environment (PSU, fan, temperature), PoE budget, redundancy and stack ring, SSH and Smart Install exposure, CPU and memory, interface errors and drops, with findings |
| Voice & QoS | XLSX, JSON, CSV, XML | Switch QoS posture, voice ports (phone, voice gateway, AP or voice VLAN) with trust and EF counters, uplinks and WAN circuits with egress policy, priority class and priority-queue drops, a Policy Catalog and Class Catalog showing template drift, findings, and Collection Errors |
| Cisco ASA | XLSX, JSON, CSV, XML | Summary of the assessment checks, Devices (one row per unit, and per context), Lifecycle (Cisco EoX dates per model and ASA version), Failover (one row per pair), Interfaces, Zones and Reachability, Routes Summary, Static Routes (with SLA tracking), Routing Neighbours, Access Lists, ACL Lines (expanded objects, hit counts, shadowed and redundant lines), Objects (references, unused, duplicates), NAT (type, hits, public exposure), Site-to-site VPN (crypto, protected networks, status, NAT exemption), Remote Access VPN (authentication, pool use, split tunnel, posture), VPN Sessions (no usernames), Certificates, Management Plane, Health and Capacity, Changes and Hygiene, Relationships (failover pairs, shared subnets, routing neighbours and VPN peers matched to other devices), and Collection Errors |
| Cisco WLC | XLSX, JSON, CSV, XML | Summary of the assessment checks with controllers and items affected, Controllers, Lifecycle (Cisco EoX dates per controller and AP model, last AireOS release, Catalyst 9800 support and Wi-Fi generation), Redundancy, Interfaces (with the WLANs using each), Ports and Uplinks (CDP neighbour, whether it is in the scan, error counters), WLANs (security, AKM, PMF, 802.11r/k/v, AAA servers, QoS, anchors, FlexConnect, client count), AP Groups, RF Global (per band: rates, DCA, TPC, coverage, RF group, CleanAir), RF Profiles, Radios (per AP radio), Access Points (keyed by base radio MAC: model, mode, groups, controllers, software, power, uplink switch port, lifecycle), AP Join Issues, Clients (counts per WLAN, band and protocol only), AAA Servers (with request, reject and timeout counts), ACLs, ACL Rules, Security and WIPS, Mobility (peers and anchors with path state), FlexConnect, QoS and Services (QoS profiles and map, AVC, NetFlow, multicast, mDNS), Management Plane, Certificates, Health and Capacity, Configuration Hygiene, Relationships (uplinks, AP access ports, mobility peers, anchors, AAA servers and management targets, matched to devices in the scan), and Collection Errors |
| EOX Lifecycle | XLSX | Hardware/software end-of-life dates, module EOX status (requires Cisco API credentials) |
| Config Archive | ZIP | Running configs as individual text files; an ASA standby unit is `<hostname>_stby.txt` and each security context `<hostname>_<context>.txt`; an AireOS controller's comes from `show run-config commands` |

**Findings.** The L2, L3, Internet Edge, Platform Health, Voice & QoS and Cisco ASA reports rate findings on one scale. Critical is a reachability, redundancy or security exposure backed by collected data (a BGP session down, overlapping subnets). Warning is something usually wrong that may be intentional (`permit ip any any` on an interface filter). Info is documentation grade (an unreferenced ACL, an EIGRP stub peer). When one check fires on more than half the devices, an Info note says so, since that is more often a miscalibrated check than a network-wide defect.

**Cisco ASA.** ASAs and ASAv are logged into as `cisco_asa`: on the ASA driver, entering enable with the login password. Typing them `cisco_asa` in a host list saves a login, but an untyped one is recognised from show version and reopened on the right driver. Both units of a failover pair are kept: the standby unit appears as `<hostname>/stby`, and the Failover sheet shows the pair side by side. Every sheet starts with Hostname, Context and Site (from the Settings site rules). A value whose command was not collected reads `n/a`; a blank cell was collected and empty. The Summary lists each check with the assessment's own rating (High, Medium, Low, Info); in the shared findings scale High is Critical, Medium is Warning, and Low and Info are Info. Checks include telnet enabled, SSH or ASDM open from any or an outside interface, SSH on local accounts only, no command authorization or accounting, SNMP v1/v2c, no syslog host, no NTP sync, debug-level syslog, certificates expired or expiring within 90 days, CPU, memory and connection-table pressure, interface errors, unsaved configuration, a recent crash, an unset enable password, and failover problems (secondary active, version or licence mismatch, failover or stateful link down, a monitored interface failed). The rule base is read from the running-config with every object and object-group expanded, so each ACL line can be compared with the lines above it: a line covered by an earlier one with the opposite action is shadowed, one covered by an earlier one with the same action is redundant (ACLs over 3,000 lines skip that comparison and say so). Rule-base checks: permit ip any any inbound on a lower-security interface, any-port permits to internal subnets, rules with no hits on a unit up 30 days or more, shadowed or redundant lines, unused objects, and static NAT that publishes an internal host and has never been used. VPN and routing checks: weak site-to-site crypto (DES, 3DES, MD5, DH 1/2/5, aggressive mode) and SHA-1 or DH 14 as the only choice, configured tunnels with no session, remote-access profiles authenticating with a password alone (RADIUS is treated as possible MFA and not flagged), the split-tunnel policy of each profile, routing neighbours without authentication, redistribution without a route-map, and hardware or software past its Cisco support dates (the Lifecycle sheet uses the same EOX API credentials and cache as the EOX Lifecycle report).

**Cisco WLC.** AireOS controllers are logged into as `cisco_wlc`. Typing them so in a host list saves a login; an untyped one is recognised at login (the second `User:` prompt AireOS asks after SSH, or its `(name) >` prompt) and reopened on the right driver, and SNMP and CDP also recognise them. A read-only account cannot turn paging off, so every pause (`--More--` in any wording, "display the next entries", "Press Enter", "Press any key") is answered as it comes, any other yes/no question is answered no, and nothing but show commands is ever sent. If a command still times out, the session backs out of the pager or question before the next command, so one missed prompt costs one command. Each command waits up to 120 seconds from the last output (300 for the configuration). The controller is named by the System Name in `show sysinfo`, since the prompt reads `(Cisco Controller)` until someone changes it. Per-AP commands run last, about three seconds per AP on a large controller, so a timeout late in the run leaves everything before it intact. RADIUS and TACACS+ secrets, PSKs, SNMP communities (on every line that names them), SNMPv3 keys and user passwords are redacted before anything is stored; client MACs, addresses and user names are never stored, only counts, and local guest account names are replaced by a stable pseudonym. Every sheet starts with Controller, Site and Model. Lifecycle facts that the EoX API does not give (the last AireOS release per model, Catalyst 9800 support, Wi-Fi generation) come from `config/wlc_models.yaml`, which can be edited to match Cisco's current compatibility matrix. Platform checks: controller past end of support or software maintenance, a release past support or hardware that cannot reach 8.10, AP licence or platform maximum over 80% used, no controller redundancy (no SSO, no HA-SKU secondary, no backup controller on any AP), an SSO peer not Standby Hot, uplinks without LAG or with one port up, core dumps or AP crash files, CPU over 70% or memory free under 20%, no syslog server, and NTP not configured or not in sync. Wireless checks: open WLANs without web auth, WEP or WPA-TKIP, PSK on a WLAN not named as guest or IoT (flagged for review), WPA3/SAE without PMF required, guest WLANs not anchored or on the management interface, 802.11b rates enabled, wide channels, CleanAir off on capable radios, an 802.1X WLAN with a single RADIUS server, voice WLANs not on Platinum or with WMM off, APs past end of support, APs that cannot join a Catalyst 9800 (or only up to 17.3), APs with no primary controller or in default-group, mixed AP images, APs on PoE low power, AP uplinks below 1 Gb or half duplex, and AP join failures in the last 30 days. Service checks: RADIUS timeouts over 2%, management logins with no TACACS+ (or RADIUS) server, telnet or HTTP management, management over wireless, SNMP v1/v2c or a default community, rogue auto-containment, infrastructure MFP disabled, a mobility peer or anchor with a path down, the QoS map disabled, certificates expired or expiring within 90 days, web auth on the self-signed certificate, and local net users that never expire. APs also join the Topology Map and Diagram Data reports on the switch port their controller reports for them.

**Internet edge.** A device counts as edge when it has BGP to a public AS, a public address on an interface, NAT configured, or a static default pointing outside the IGP, and the Edge Devices sheet says which. The ACL audit classifies each ACL by what references it in the running config (interface filter, management, QoS, route-map, NAT, crypto, or unreferenced), so a QoS class-map ACL with zero hits is not reported as dead. A device with no NAT config reads "not configured" rather than 0 translations.

**Voice and QoS.** The config shows what a QoS policy was meant to do; the counters show whether it is working. Classic Catalyst switches (2960/3560/3750) are judged on `mls qos`, port trust and the egress expedite queue. Catalyst 9000, 3850 and 4500-X trust DSCP by default, so a voice port there is only flagged if a policy says otherwise. Routers are judged on their egress LLQ. A router interface counts as a WAN or DCI circuit only with evidence, shown in the WAN Evidence column: a public address, a BGP peer on its subnet, `ip nat outside`, or a description naming WAN, MPLS, INET, ISP, DCI or Megaport. Subinterfaces take their parent's evidence. WAN circuits without a priority class are flagged; interfaces facing a switch, and port-channels or other interfaces with no CDP neighbour and no WAN evidence, are listed but not flagged. Every drop count carries its counter window ("cleared 1d02h ago" or "since boot (36 weeks, ...)"), because counters that have run since boot are totals, not rates. Critical: QoS off on a switch with voice endpoints, untrusted voice ports with no marking policy, uplinks or WAN circuits with no priority queue, EF mapped outside the priority queue. Warning: priority-queue drops, EF arriving on access ports but leaving the uplink re-marked, a policy-map name with more than one version across the fleet. Info: auto-QoS on some phone ports but not others, counters never cleared on a device up more than 12 weeks.

### Targeted Scan
Connect to a specific list of devices without BFS crawling. Designed for edge assessments where you know exactly which devices to audit (firewalls, border routers). Enter one device per line in the format `host [device_type]`, where host is an IPv4 address, hostname or FQDN. Device type is optional (auto-detect if omitted).

- **Hostnames** are resolved before the scan starts. Names that don't resolve are listed in the console and skipped, with the resolver that was used. If the names live in a customer zone this host can't see, set **DNS Server** and **DNS Search Suffix** in Settings rather than changing the host's `/etc/resolv.conf`
- **Upload** a `.txt` (same format as the text box) or a `.csv` with a header row. CSV needs a `hostname` and/or `ip` column (`host`, `fqdn`, `address`, `mgmt_ip` and similar also work) and may carry a `device_type` column. Pasted and uploaded hosts are combined
- **Duplicates** are collected once, even when two entries reach the same device
- **Crawl from targets** optionally discovers onward from each target, with its own crawl depth and device-type filters

A supplied device type is authoritative: no other platform is tried against that host.

### Saved Scans
- Every discovery saves a JSON scan data file (raw command output + parsed data)
- Browse, load, and delete saved scans from the **Saved Scans** tab
- Upload a scan data JSON to generate reports without re-scanning
- Export full ZIP archives (scan data + device configs)

### Demo Mode
Built-in mock device simulator with a multi-vendor topology for testing without real hardware.

**Opt-in only.** Set `WIREMAP_MOCK=1` and use seed IP `192.168.1.1` with any credentials. Without that variable no host is ever simulated -- `192.168.1.0/24` is a real range on real networks, and a scan must never return fabricated data.

---

## Quick Start

### Docker Compose (Recommended)

```bash
git clone https://github.com/tonhe/wiremap.git
cd wiremap
docker-compose up -d
```

Access the UI at **http://localhost:8888**

Persistent volumes for logs, config, and inventories are configured automatically.

### Local Development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd app && python app.py
```

Use Python 3.12. `telnetlib` was removed in 3.13; on 3.13 and later
`requirements.txt` pulls in the `standard-telnetlib` backport so netmiko still
imports. The container runs 3.11.

**Iterating without rebuilds.** The Dockerfile copies `app/` and `templates/`
into the image, so `docker compose up -d` after a pull runs the previous build.
The dev overlay bind-mounts the source instead:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
docker compose restart wiremap   # picks up code and template changes
```

A rebuild is only needed when `requirements.txt` changes.

## Usage

1. Open the web UI at `http://localhost:8888`
2. Enter a seed device IP and select the platform type
3. Choose connection protocol (SSH / Telnet / Auto)
4. Provide credentials (add up to five sets with **Add credentials**, see below)
5. Set crawl depth and toggle device type filters (routers, switches, phones, servers, APs)
6. Click **Start Discovery**
7. Monitor real-time progress in the console (authentication, data collection, neighbor discovery)
8. After completion, the **Reports** tab opens automatically with available reports

### Multiple Credential Sets

Both the discovery and targeted forms take up to five username/password sets. The first set is the standard Username/Password fields; **Add credentials** adds another row, and blank extra rows are ignored. A row with a username and no password is rejected rather than skipped.

- Sets are tried in order, and the next set is only tried when a device **rejects the login**. A timeout, a refused port or an SSH negotiation failure means the device can't be reached, so no other set is tried
- A rejected set is not retried on that device with another device-type driver or over Telnet
- Whichever set last logged in is tried first on the next device, with the rest following in their configured order. On a site where most devices share one account, the other sets cost nothing after the first success
- Every try goes through the `max_logins_per_minute` limiter
- The Devices sheet has a **Login User** column with the account that logged in (left out on scans from before accounts were recorded) (the scan file also stores the set number). The Failed Devices sheet lists the set tried on each attempt, and an auth failure says all the sets were rejected
- Passwords are never saved: not in the scan file, logs, console events, settings or the browser. The scan file records the usernames offered, in order

**AAA lockout caution.** A device that rejects every set costs one authentication failure per set, up to five. Against TACACS+ or ISE with lockout thresholds, put the set most devices accept first, keep the list short, and set `max_logins_per_minute`.

In demo mode, `10.0.0.1` (WAN-ROUTER-01) only accepts the username `backup-admin`, so a targeted scan of it exercises the second-set path.

### Load Previous Scan

Switch to the **Saved Scans** tab to browse previous discoveries or upload a scan data JSON. Loading a scan automatically opens the **Reports** tab.

### Merge Saved Scans

Tick two or more scans in the **Saved Scans** tab and choose **Merge selected**.
An engagement accumulates scans -- a discovery here, a targeted run there, an
edge assessment from a different seed -- and the as-built picture lives across
all of them.

Merging uses the same identity rules discovery uses within one scan, so a
device named three ways is still one device. Where two files describe the same
device:

1. a record that was logged into beats one only seen in a neighbour table
2. between two collected records, the one carrying more data wins
3. failing that, the newer scan wins

The loser is never discarded -- it fills fields the winner lacks, and its
collector data and evidence are folded in. Two chassis that genuinely share a
hostname but differ by serial stay separate.

The result is a **new** scan; the originals are left in place and are never
modified. What it came from is recorded at three levels:

- the **Saved Scans** list badges it `merged x N`, listing each source on hover
- every device records the scan its winning record came from, shown as a
  **Source Scan** column in the Device Inventory report
- the workbook gains **Merge Sources** and **Merge Conflicts** sheets naming
  every input and, for each device seen in more than one scan, which record was
  kept and why

Scans that never went through this instance (copied off another host, or run
from different boxes at one site) can be merged from the command line:

```bash
python app/merge_scans.py scan-a.json.gz scan-b.json -o merged.json.gz
python app/merge_scans.py ./inventories/ -o ./inventories/   # every scan in it

# or inside the container
docker compose exec wiremap python merge_scans.py \
    /app/inventories/a.json.gz /app/inventories/b.json.gz -o /app/inventories
```

Scans are saved as gzip-compressed JSON (`<scan id>.json.gz`), which is about
a twentieth of the plain size on a large network. Everything that reads a scan
(the web app, the upload button, the merge and the CLI) takes either form, so
older `.json` scans still load.
`zcat scan.json.gz` or `gunzip -k` gets the plain JSON back. A named merge
output is compressed when it ends in `.gz`.

Configs in the output are redacted unless you pass `--no-redact`. Older scans
predate collection-time redaction, and the merged file is usually the one that
gets passed around. Drop the result into `inventories/` and it shows up in
**Saved Scans** like any other. `wiremap_cli.py merge` takes the same
arguments.

### Reports from the Command Line

`app/wiremap_cli.py` generates the same reports as the Reports tab without the
web app running. It needs the packages in `requirements.txt` (on Python 3.13
and later that includes the `standard-telnetlib` backport netmiko needs).

```bash
python app/wiremap_cli.py                         # menu: pick scans, reports, format
python app/wiremap_cli.py list scan.json.gz       # which reports apply to this scan
python app/wiremap_cli.py report scan.json        # every report that applies, into ./<scan id>/
python app/wiremap_cli.py report scan.json -r device_inventory -r link_inventory -f csv -o out/
python app/wiremap_cli.py report a.json b.json    # several scans are merged first
python app/wiremap_cli.py summary scan.json       # devices, failures and causes, targets, source access
python app/wiremap_cli.py merge a.json b.json -o merged.json

# or inside the container
docker compose exec wiremap python wiremap_cli.py
docker compose exec wiremap python wiremap_cli.py report \
    /app/inventories/<scan>.json.gz -o /app/inventories/reports
```

`-f` picks csv, json, xml or xlsx where a report offers it; the config archive
(zip) and topology map (html) are always written in their own format. Reports
the scan has no data for are skipped and listed. The exit code is non-zero
when a report fails or a report named with `-r` could not be generated. A csv
export of a multi-sheet report is written as one file per sheet. At the menu,
`q` quits.

The EoX report uses the Cisco API credentials saved in the web UI, read from
`config/` (`/app/config` in the container). Point elsewhere with `--config-dir`,
or pass `--offline` to skip it, as it is the only report that calls out to the
network.

### Add to a Previous Scan

Both scan forms offer **Add results to a previous scan**. Pick a saved scan and
the run continues it rather than starting empty:

- devices already collected are skipped
- devices that failed last time are retried automatically
- hosts you list explicitly are always scanned, which is how a single device is
  refreshed. If a refresh fails, the device keeps its earlier data and the
  console warns that its neighbours weren't crawled from it this run
- results are written to a **new** scan that records what it continued from, so
  the original is never modified

### Running from a Restricted Management Network

Most networks only accept SSH and SNMP from a management subnet, enforced with
a vty `access-class` and SNMP community ACLs. If the host running wiremap isn't
in that subnet, devices refuse the connection and the scan fills up with
"Connection refused" failures.

After the seed is collected, wiremap checks the address the seed sees it as
against the seed's vty and SNMP ACLs. That address comes from the `source_ip`
setting if set, otherwise from the seed's own `show users` / `show tcp brief`.
Inside Docker the local socket address is the bridge address, so it's only
used as a last resort and flagged as such. The console reports SSH and SNMP
separately and warns when either is blocked, since the rest of the network
usually shares the seed's management ACL. When three or more devices refuse the connection during a
scan, the console points at the vty ACLs again. The fix is to run wiremap from
a permitted management host or add its address to the ACL.

The check is IPv4 only and conservative: object-groups or anything it can't
parse count as unknown and never raise a warning.

## Configuration

### Cisco EOX API (for EOX Lifecycle Report)

The EOX Lifecycle report queries Cisco's Support APIs to look up end-of-life and end-of-support dates for hardware and software. To use it, you need API credentials from Cisco:

1. Register an application at [Cisco API Console](https://apiconsole.cisco.com/) and request access to the **EOX API**
2. In Wiremap, go to the **Settings** tab and enter your **Client ID** and **Client Secret** under the Cisco EOX API section
3. Click **Test Connection** to verify the credentials work
4. The EOX Lifecycle report will appear as available in the Reports tab once credentials are configured

### Device Type Detection

Edit `config/device_type_patterns.yaml` to add or modify device type patterns:

```yaml
device_types:
  cisco_ios:
    platforms:
      - catalyst
      - c3750
    system_descriptions:
      - "Cisco IOS Software"
    priority: 50
```

### Discovery Settings

Set from the **Settings** tab under **Discovery Settings**. Values are persisted to `config/discovery.json` and used by all scan types.

| Setting | Default | Purpose |
|---------|---------|---------|
| `max_workers` | 10 | Concurrent device workers (1-20) |
| `disable_autodetect` | off | Require a device type for every host. No platform fallback is attempted |
| `site_rules` | none | Ordered hostname-to-site rules, see below |
| `redact_secrets` | on | Replace secrets in collected configs with `<REDACTED>` before they are stored |
| `collect_controller_managed` | off | Log into ACI fabric nodes and UCS Fabric Interconnects anyway instead of skipping them |
| `max_logins_per_minute` | 0 | Cap on login attempts per minute across all workers (SSH, Telnet and the legacy SSH retry), so a large run doesn't trip TACACS+/ISE throttling. 0 means no limit, max 600 |
| `connect_timeout_s` | 10 | Seconds each login waits for the device to answer (3-60). Raise it for branches behind SD-WAN or satellite links, where a full SSH login can take 10 seconds |
| `allow_telnet` | off | Fall back to Telnet when SSH fails on an auto-protocol login. Off because most networks only accept SSH and each try costs a timeout and a failed login. A scan with the Telnet protocol selected always uses Telnet |
| `expand_non_cdp_neighbors` | off | Crawl routing peers, next-hops and HSRP/VRRP addresses even when CDP/LLDP never saw them. Off, they're crawled only when CDP/LLDP sees them or an ARP entry shows a network-vendor MAC, and the rest are listed as not attempted |
| `source_ip` | blank | The address devices see this host as, used for the management ACL check. Blank learns it from the seed's own session list. Can also be set per scan |
| `dns_server` | blank | DNS server for host-list names. Blank uses this host's resolver |
| `dns_search` | none | Search suffixes tried on bare host-list names, in order |

Each scan records the connect timeout, the Telnet setting and the login cap in its `params`, and `scan_summary.peak_logins_per_minute` records the most logins actually started in any one minute.

**Site mapping.** Every report has a Site/Location column. By default the site is the first hyphen-delimited token of the short hostname (`AB001-IDF-SWA-01` maps to `AB001`). When a naming convention doesn't fit that, enter one `regex => SITE` rule per line. Rules are matched in order, case-insensitive, against the hostname as collected (FQDN included), and the site can use group references:

```
^sw\d+\.(\w+)\.example\.net$ => \1
^core- => DC1
```

Lines starting with `#` are comments. A hostname that matches no rule falls back to the default.

The Device Inventory Devices sheet shows each device's Site, and a **Site Naming** note for names the default rule probably got wrong: no hyphen at all, or a first token shaped unlike most of the site codes in the scan (`Switch-exec` among `AB001`-style codes). Those are the names to fix or cover with a rule.

### SNMP

SNMP credentials are entered per scan on both the discovery and targeted forms, alongside the login credentials. Both v2c (community string) and v3 (auth and privacy) are supported.

SNMP runs whenever a login fails -- rejected credentials, a refused port, a timeout or a failed SSH negotiation. It identifies the device and collects what the standard MIBs expose -- IF-MIB, IP-MIB, IP-FORWARD-MIB, LLDP-MIB, ENTITY-MIB, and CISCO-CDP-MIB where present. Because these are IETF standards rather than vendor commands, one implementation covers every supported platform.

A device reached this way is recorded with `discovery_source = snmp` and `login_succeeded = false`. SNMP identifies a device; it does not collect one, and the reports keep that distinction visible.

Every failure record carries an `snmp` field with the fallback's outcome: `v2c ok`, `v3 ok`, `timeout`, `auth/community rejected`, `no credentials` or `error: ...`. A v2c agent silently drops a wrong community, so for v2c a bad community reads as `timeout`; only v3 rejects credentials out loud. A device SNMP answered keeps its failure record (it explains the missing CLI data) but is not counted in the failed total. The scan log ends with a line such as `SNMP fallback: 12 tried, 9 answered (v2c 9, v3 0), 3 no response`.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `WIREMAP_MOCK` | Set to `1` to enable the built-in mock topology. Off by default; without it no host is ever simulated |

### Capability Filtering

Control which device types are crawled during recursive discovery:

```yaml
allowed_capabilities:
  - Router
  - Switch
  - Bridge
```

## Project Structure

```
wiremap/
├── app/
│   ├── app.py                # Flask application
│   ├── discovery_engine.py    # BFS topology discovery engine
│   ├── scan_manager.py        # Async scan execution and SSE streaming
│   ├── connection_manager.py # SSH/Telnet connection handling
│   ├── settings.py           # Discovery settings (JSON config)
│   ├── device_detector.py    # Device type detection
│   ├── parsers.py            # CDP/LLDP parsers
│   ├── parsers_panos.py      # PAN-OS routing and LLDP parsers
│   ├── identity.py           # Hostname normalization, device identity
│   ├── inventory_merge.py    # Merge several scans into one
│   ├── wiremap_cli.py        # Command-line reports, summary and merge
│   ├── merge_scans.py        # Command-line scan merge
│   ├── device_facts.py       # Serial/model/version extraction
│   ├── snmp_probe.py         # SNMP identification (v2c/v3)
│   ├── snmp_tables.py        # Standard-MIB table collection
│   ├── failures.py           # Login failure classification and hints
│   ├── source_access.py      # Source-host check against vty/SNMP ACLs
│   ├── target_list.py        # Targeted-scan host lists, DNS, CSV import
│   ├── site_mapping.py       # Hostname-to-site rules
│   ├── redact.py             # Config secret redaction
│   ├── mock_devices.py       # Demo mode simulator (opt-in)
│   ├── collectors/           # 23 modular data collectors
│   ├── neighbors/            # Neighbour sources and crawl scope
│   └── reports/              # On-demand report generators
├── config/
│   └── device_type_patterns.yaml
├── templates/                # Jinja2 web UI templates
├── inventories/              # Saved scan data
├── Dockerfile
├── docker-compose.yml
├── docker-compose.dev.yml    # Dev overlay: bind-mounts source, no rebuild
└── requirements.txt
```

## License

Open source -- feel free to modify and extend.
