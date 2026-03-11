# Wiremap

**Network topology discovery and assessment tool.** Connects to a seed device, discovers neighbors via CDP/LLDP, recursively crawls the network, collects data from every device, and generates detailed assessment reports.

> Built on [neighbor-mapper](https://github.com/aconaway-rens/neighbor-mapper) by **Aaron Conaway**. Wiremap extends his original CDP/LLDP discovery tool with a modular collector/report architecture, multi-vendor support, recursive BFS crawling, discovery inventories, and automated network assessment reporting.

---

## Features

### Discovery
- **SSH, Telnet, or Auto-detect** -- Tries SSH first, falls back to Telnet automatically
- **Recursive BFS Crawling** -- Discovers neighbors hop-by-hop from a seed device with configurable depth (1-5)
- **Multi-threaded** -- Parallel device collection with configurable concurrent workers (1-20, default 10), persisted in Settings
- **Async with Live Progress** -- Scans run in the background with real-time Server-Sent Events (SSE) streaming authentication, fallback, data collection, neighbor discovery, and completion status to a live console panel
- **Cancellable Scans** -- Cancel a running scan gracefully; in-progress devices finish and partial results are saved
- **L3 Neighbor Discovery** -- Optionally discover OSPF, EIGRP, BGP, and ISIS neighbors alongside CDP/LLDP
- **Device Type Auto-detection** -- YAML-based pattern matching against CDP platform strings and LLDP system descriptions
- **Hostname Dedup** -- Prevents collecting the same device twice when it's reachable via multiple IPs (management, loopback, SVI)
- **Loop Prevention** -- Tracks visited devices and enforces depth limits

### Multi-Vendor Support
Cisco IOS / IOS-XE / NX-OS / IOS-XR, Arista EOS, Juniper JunOS, Palo Alto PAN-OS, MikroTik RouterOS, Fortinet FortiGate, HPE Comware / ProCurve, Aruba OS-CX, Dell OS10, Extreme ExtremeXOS / VOSS, Ubiquiti EdgeOS, Barracuda

### Data Collection (15 Collectors)
All collectors run automatically on every device -- no pre-selection needed.

| Collector | Data Gathered |
|-----------|--------------|
| CDP/LLDP | Neighbor adjacencies and protocols |
| Interfaces | Port status, descriptions, IP assignments, etherchannel |
| Device Inventory | Version, hardware modules, serial numbers, stack members |
| Config | Running configuration backup |
| ARP | ARP table entries with interface mappings |
| MAC Table | MAC address to port mappings |
| STP/VLAN | Root bridges, blocked ports, VLAN list, VTP status |
| STP Detail | Port roles, costs, topology change counts, inconsistent ports |
| L3 Routing | OSPF/EIGRP/BGP/ISIS neighbors and route tables |
| Routing Detail | Protocol summaries, route counts, EIGRP topology, BGP full table |
| VRF | VRF definitions and interface assignments |
| Switchport | Port-security, BPDU guard, storm-control, trunk config |
| HSRP | HSRP/VRRP state, virtual IPs, active/standby roles |
| Edge Services | ACLs, applied ACLs per interface, proxy-ARP, uRPF |
| NTP/Logging | NTP sync, logging config, SNMP settings (credentials redacted) |

Parsing uses [NTC Templates](https://github.com/networktocode/ntc-templates) (TextFSM) with regex fallbacks for vendor-aware structured output.

### Reports Tab
A dedicated **Reports** tab serves as the single destination for all report generation. After a discovery completes, a targeted scan finishes, or a saved scan is loaded, the UI automatically switches to the Reports tab showing a summary stat bar (devices, failed, elapsed time, scan date) and available report cards grouped by category with format selectors. Old inventories without summary metadata display gracefully with `--` placeholders.

| Report | Formats | Description |
|--------|---------|-------------|
| Topology Map | HTML | Interactive D3.js network diagram with color-coded device types |
| Device Inventory | XLSX, JSON, CSV, XML | Device summary, stack members, modules and line cards |
| Link Inventory | XLSX, JSON, CSV, XML | All discovered neighbor links (CDP/LLDP + L3) |
| Interface Summary | XLSX, JSON, CSV, XML | Port status, descriptions, IP assignments |
| ARP Summary | XLSX, JSON, CSV, XML | ARP entries by device with summary and detail tabs |
| MAC Table | XLSX, JSON, CSV, XML | MAC-to-port mappings per device |
| L2 Discovery | XLSX, JSON, CSV, XML | VLANs, STP topology, routed interfaces, anomaly findings |
| L3 Routing & IP | XLSX, JSON, CSV, XML | Protocol neighbors, route tables, OSPF topology, FHRP status, IP audit, ARP/MAC map, VRF summary |
| Internet Edge | XLSX, JSON, CSV, XML | BGP peering, NAT overview, ACL audit, FHRP status, edge interface security |
| EOX Lifecycle | XLSX | Hardware/software end-of-life dates, module EOX status (requires Cisco API credentials) |
| Config Archive | ZIP | Running configs as individual text files |

### Targeted Scan
Connect to a specific list of devices without BFS crawling. Designed for edge assessments where you know exactly which devices to audit (firewalls, border routers). Enter one device per line in the format `IP [device_type]` — device type is optional (auto-detect if omitted).

### Saved Scans
- Every discovery saves a JSON scan data file (raw command output + parsed data)
- Browse, load, and delete saved scans from the **Saved Scans** tab
- Upload a scan data JSON to generate reports without re-scanning
- Export full ZIP archives (scan data + device configs)

### Demo Mode
Built-in mock device simulator with a multi-vendor topology for testing without real hardware. Use seed IP `192.168.1.1` with any credentials.

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
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd app && python app.py
```

## Usage

1. Open the web UI at `http://localhost:8888`
2. Enter a seed device IP and select the platform type
3. Choose connection protocol (SSH / Telnet / Auto)
4. Provide credentials
5. Set crawl depth and toggle device type filters (routers, switches, phones, servers, APs)
6. Click **Start Discovery**
7. Monitor real-time progress in the console (authentication, data collection, neighbor discovery)
8. After completion, the **Reports** tab opens automatically with available reports

### Load Previous Scan

Switch to the **Saved Scans** tab to browse previous discoveries or upload a scan data JSON. Loading a scan automatically opens the **Reports** tab.

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

Configure concurrent worker count from the **Settings** tab under **Discovery Settings**. The setting is persisted to `config/discovery.json` and used by all scan types.

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
│   ├── mock_devices.py       # Demo mode simulator
│   ├── collectors/           # 15 modular data collectors
│   └── reports/              # On-demand report generators
├── config/
│   └── device_type_patterns.yaml
├── templates/                # Jinja2 web UI templates
├── inventories/              # Saved scan data
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## License

Open source -- feel free to modify and extend.
