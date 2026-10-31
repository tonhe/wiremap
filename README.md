# Wiremap

**Network topology discovery and assessment tool.** Connects to a seed device, discovers neighbors via CDP/LLDP, recursively crawls the network, collects data from every device, and generates detailed assessment reports.

> Built on [neighbor-mapper](https://github.com/aconaway-rens/neighbor-mapper) by **Aaron Conaway**. Wiremap extends his original CDP/LLDP discovery tool with a modular collector/report architecture, multi-vendor support, recursive BFS crawling, discovery inventories, and automated network assessment reporting.

---

## Features

### Discovery
- **SSH, Telnet, or Auto-detect** -- Tries SSH first, falls back to Telnet automatically
- **Recursive BFS Crawling** -- Discovers neighbors hop-by-hop from a seed device with configurable depth (0-10, including crawl from targets)
- **Multi-threaded** -- Parallel device collection with configurable concurrent workers (1-20, default 10), persisted in Settings
- **Async with Live Progress** -- Scans run in the background with real-time Server-Sent Events (SSE) streaming authentication, fallback, data collection, neighbor discovery, and completion status to a live console panel
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
Cisco IOS / IOS-XE / NX-OS / IOS-XR, Cisco AireOS WLC, Arista EOS, Juniper JunOS, Palo Alto PAN-OS, WatchGuard Firebox (Fireware), VyOS, MikroTik RouterOS, Fortinet FortiGate, HPE Comware / ProCurve, Aruba OS-CX, Dell OS10, Extreme ExtremeXOS / VOSS, Ubiquiti EdgeOS

Each platform has its own command set per collector. A collector that cannot serve a platform -- spanning tree on a firewall, switchports on a router -- declares it and is skipped, rather than sending commands the device will reject.

**Legacy SSH:** paramiko is pinned to 3.5.x deliberately. Version 4.0 removed the SHA-1 key exchanges and the `ssh-rsa` host key algorithm outright, which strands older Catalyst and Nexus hardware that offers nothing else. Modern algorithms are still preferred wherever the device supports them.

### Data Collection (20 Collectors)
All collectors run automatically on every device -- no pre-selection needed.

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
| Routing Detail | Protocol summaries, per-VRF route counts, OSPF LSDB and EIGRP topology size, routing processes, redistribution |
| VRF | VRF definitions and interface assignments |
| Switchport | Port-security, BPDU guard, storm-control, trunk config |
| HSRP | HSRP, GLBP and VRRP state, virtual IPs, active/standby roles; groups configured but not collected are still listed from the config |
| Edge Services | ACLs and what references them, applied ACLs per interface, NAT, proxy-ARP, uRPF |
| NTP/Logging | NTP sync, logging config and the full log buffer, SNMP settings (credentials redacted) |
| Environment | PSU, fan and temperature state, PoE budget and faulted ports |
| Redundancy | Supervisor redundancy mode and peer state, switchovers, stack ports and ring |
| Management Security | SSH version and host key size, Smart Install state |
| Interface Counters | Per-interface errors, CRC, drops, resets, last input/output and link flap |
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
| L2/L3 Diagram Data | XLSX, JSON, CSV, XML | Node and edge lists for drawing diagrams: device details, deduplicated L2 links, L3 adjacencies, subnets |
| Interface Summary | XLSX, JSON, CSV, XML | Port status, descriptions, IP assignments |
| ARP Summary | XLSX, JSON, CSV, XML | ARP entries by device and VRF with summary and detail tabs, incomplete entries flagged |
| MAC Table | XLSX, JSON, CSV, XML | MAC-to-port mappings per device |
| L2 Discovery | XLSX, JSON, CSV, XML | VLANs, STP topology and root bridges, trunk and interface status with neighbors, routed interfaces, anomaly findings |
| L3 Routing & IP | XLSX, JSON, CSV, XML | Protocol neighbors, route tables, per-VRF route summary, OSPF topology, Routing Scale (OSPF LSDB, EIGRP topology), Routing Processes, Redistribution, FHRP status, IP audit, ARP/MAC map, VRF summary, and a Collection Errors sheet listing any command a device rejected |
| Internet Edge | XLSX, JSON, CSV, XML | Edge Devices (and why each qualifies), BGP peering across VRFs, Public Addresses, NAT overview, ACL audit by usage, FHRP status, edge interface security |
| Platform Health | XLSX, JSON, CSV, XML | Environment (PSU, fan, temperature), PoE budget, redundancy and stack ring, SSH and Smart Install exposure, CPU and memory, interface errors and drops, with findings |
| EOX Lifecycle | XLSX | Hardware/software end-of-life dates, module EOX status (requires Cisco API credentials) |
| Config Archive | ZIP | Running configs as individual text files |

**Findings.** The L2, L3, Internet Edge and Platform Health reports rate findings on one scale. Critical is a reachability, redundancy or security exposure backed by collected data (a BGP session down, overlapping subnets). Warning is something usually wrong that may be intentional (`permit ip any any` on an interface filter). Info is documentation grade (an unreferenced ACL, an EIGRP stub peer). When one check fires on more than half the devices, an Info note says so, since that is more often a miscalibrated check than a network-wide defect.

**Internet edge.** A device counts as edge when it has BGP to a public AS, a public address on an interface, NAT configured, or a static default pointing outside the IGP, and the Edge Devices sheet says which. The ACL audit classifies each ACL by what references it in the running config (interface filter, management, QoS, route-map, NAT, crypto, or unreferenced), so a QoS class-map ACL with zero hits is not reported as dead. A device with no NAT config reads "not configured" rather than 0 translations.

### Targeted Scan
Connect to a specific list of devices without BFS crawling. Designed for edge assessments where you know exactly which devices to audit (firewalls, border routers). Enter one device per line in the format `host [device_type]`, where host is an IPv4 address, hostname or FQDN. Device type is optional (auto-detect if omitted).

- **Hostnames** are resolved before the scan starts. Names that don't resolve are listed in the console and skipped
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
python app/merge_scans.py scan-a.json scan-b.json -o merged.json
python app/merge_scans.py ./inventories/ -o ./inventories/   # every .json in it

# or inside the container
docker compose exec wiremap python merge_scans.py \
    /app/inventories/a.json /app/inventories/b.json -o /app/inventories
```

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
python app/wiremap_cli.py list scan.json          # which reports apply to this scan
python app/wiremap_cli.py report scan.json        # every report that applies, into ./<scan id>/
python app/wiremap_cli.py report scan.json -r device_inventory -r link_inventory -f csv -o out/
python app/wiremap_cli.py report a.json b.json    # several scans are merged first
python app/wiremap_cli.py summary scan.json       # devices, failures and causes, targets, source access
python app/wiremap_cli.py merge a.json b.json -o merged.json

# or inside the container
docker compose exec wiremap python wiremap_cli.py
docker compose exec wiremap python wiremap_cli.py report \
    /app/inventories/<scan>.json -o /app/inventories/reports
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
  refreshed
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
| `allow_telnet` | off | Fall back to Telnet when SSH fails on an auto-protocol login. Off because most networks only accept SSH and each try costs a timeout and a failed login. A scan with the Telnet protocol selected always uses Telnet |
| `expand_non_cdp_neighbors` | off | Crawl routing peers, next-hops and HSRP/VRRP addresses even when CDP/LLDP never saw them. Off, they're crawled only when CDP/LLDP sees them or an ARP entry shows a network-vendor MAC, and the rest are listed as not attempted |
| `source_ip` | blank | The address devices see this host as, used for the management ACL check. Blank learns it from the seed's own session list. Can also be set per scan |

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
│   ├── collectors/           # 20 modular data collectors
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
