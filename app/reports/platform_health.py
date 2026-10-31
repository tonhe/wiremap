"""
Platform Health report: environment, PoE, redundancy and stack ring, SSH
and Smart Install, CPU/memory, and per-interface error counters.

Operates only on what the environment, redundancy, mgmt_security,
cpu_memory and interface_counters collectors stored.
"""
from collections import OrderedDict

from .base import BaseReport
from .findings import (
    CRITICAL, WARNING, INFO, AGGREGATE_HEADERS, DETAIL_SHEET,
    make_finding, overfire_check, aggregate_rows, summary_count_rows,
)

COLLECTORS = ["environment", "redundancy", "mgmt_security", "cpu_memory",
              "interface_counters"]

CPU_WARN_PCT = 80
MEMORY_WARN_PCT = 90
POE_WARN_PCT = 90
MIN_KEY_BITS = 2048
# CRC errors are flagged once they reach this share of input packets, or
# this absolute count when the packet counter is missing.
CRC_RATE = 0.0001
CRC_ABSOLUTE = 10000
DROP_RATE = 0.001
DROP_MIN = 1000

_CRITICAL_TEMP = {"red", "critical", "shutdown"}


def _parsed(device, name):
    return (device.get("collector_data", {}).get(name) or {}).get("parsed") or {}


def _has_any(device):
    cd = device.get("collector_data", {})
    return any(c in cd for c in COLLECTORS)


def _env_findings(hostname, env):
    out = []
    for item in env.get("faults", []):
        component = item.get("component", "sensor")
        status = item.get("status", "")
        severity = WARNING
        if component == "temperature" and status.lower() in _CRITICAL_TEMP:
            severity = CRITICAL
        out.append(make_finding(
            hostname, severity, f"Environmental fault: {component}",
            f"{component.capitalize()} '{item.get('name', '')}' reports {status}.",
            finding_type=f"env:{component}",
            aggregate_key=f"{component.capitalize()} reports {status}",
        ))
    poe = env.get("power_inline") or {}
    problems = poe.get("problem_ports") or []
    if problems:
        ports = ", ".join(f"{p['interface']} ({p['oper']})" for p in problems[:10])
        out.append(make_finding(
            hostname, WARNING, "PoE ports faulty or power-denied",
            f"{len(problems)} port(s) cannot draw PoE: {ports}.",
            finding_type="poe:problem_ports",
            aggregate_key="Ports faulty or denied PoE power",
        ))
    for budget in poe.get("budgets") or []:
        avail = budget.get("available_w") or 0
        if avail and 100 * budget.get("used_w", 0) / avail >= POE_WARN_PCT:
            mod = f" on module {budget['module']}" if budget.get("module") else ""
            out.append(make_finding(
                hostname, WARNING, "PoE budget nearly exhausted",
                (f"{budget['used_w']:.1f} W of {avail:.1f} W used{mod}; new "
                 f"powered devices may be denied."),
                finding_type="poe:budget",
                aggregate_key=f"PoE budget at or above {POE_WARN_PCT}% used",
            ))
    return out


def stack_degraded(members, ring):
    """Ports that are not OK in a stack of two or more, plus a half ring."""
    if len(members) < 2:
        return []
    issues = [f"switch {m['switch']} port {n} {m[f'port{n}']}"
              for m in members for n in (1, 2)
              if m.get(f"port{n}", "").upper() != "OK"]
    if (ring.get("configuration") or "").lower() == "half":
        issues.append("ring configuration Half")
    return issues


def _redundancy_findings(hostname, red):
    out = []
    r = red.get("redundancy") or {}
    hw = (r.get("hardware_mode") or "").lower()
    peer = (r.get("peer_state") or "").strip()
    if hw == "duplex" and "standby hot" not in peer.lower():
        out.append(make_finding(
            hostname, WARNING, "Redundant supervisor not in hot standby",
            f"Hardware mode is Duplex but the peer state is '{peer or 'unknown'}'.",
            finding_type="redundancy:peer_state",
            aggregate_key="Duplex redundancy without a STANDBY HOT peer",
        ))
    elif not hw and peer and peer.lower() not in ("not present", "") \
            and "standby" not in peer.lower():
        # NX-OS: a second supervisor is present but is not standby.
        out.append(make_finding(
            hostname, WARNING, "Redundant supervisor not in hot standby",
            f"The other supervisor reports '{peer}'.",
            finding_type="redundancy:peer_state",
            aggregate_key="Second supervisor present but not standby",
        ))
    conf = (r.get("configured_mode") or "").strip()
    oper = (r.get("operating_mode") or "").strip()
    if hw == "duplex" and conf and oper and conf.lower() != oper.lower():
        out.append(make_finding(
            hostname, WARNING, "Redundancy mode mismatch",
            f"Configured {conf} but operating {oper}.",
            finding_type="redundancy:mode_mismatch",
            aggregate_key=f"Configured {conf}, operating {oper}",
        ))
    switchovers = (r.get("switchovers") or "").strip()
    if switchovers.isdigit() and int(switchovers) > 0:
        reason = r.get("last_switchover_reason") or "unknown"
        out.append(make_finding(
            hostname, INFO, "Supervisor switchover recorded",
            f"{switchovers} switchover(s); last reason: {reason}.",
            finding_type="redundancy:switchover",
            aggregate_key="Switchovers recorded since boot",
        ))
    issues = stack_degraded(red.get("stack_ports") or [], red.get("stack_ring") or {})
    if issues:
        out.append(make_finding(
            hostname, WARNING, "Stack ring degraded",
            "Stack ring is not fully closed: " + "; ".join(issues) + ".",
            finding_type="stack:ring",
            aggregate_key="Stack ring not fully closed",
        ))
    return out


def _mgmt_findings(hostname, mgmt):
    out = []
    ssh = mgmt.get("ssh") or {}
    version = ssh.get("version") or ""
    if ssh.get("enabled") is False:
        out.append(make_finding(
            hostname, WARNING, "SSH not enabled",
            "SSH is disabled; management access is telnet or console only.",
            finding_type="ssh:disabled",
        ))
    elif ssh.get("enabled") and version == "1.5":
        out.append(make_finding(
            hostname, CRITICAL, "SSH version 1 only",
            "SSH runs version 1.5 (SSHv1 only), which has known protocol weaknesses.",
            finding_type="ssh:v1",
        ))
    elif ssh.get("enabled") and ssh.get("v1_enabled"):
        out.append(make_finding(
            hostname, WARNING, "SSH version 1 allowed",
            (f"SSH reports version {version}, so SSHv1 clients are accepted. "
             f"Set 'ip ssh version 2'."),
            finding_type="ssh:v1",
        ))
    bits = ssh.get("key_bits")
    if ssh.get("enabled") is not False and bits and bits < MIN_KEY_BITS:
        out.append(make_finding(
            hostname, WARNING, f"SSH host key under {MIN_KEY_BITS} bits",
            f"The RSA host key is {bits} bits.",
            finding_type="ssh:key_size",
            aggregate_key=f"RSA host key is {bits} bits",
        ))
    if (mgmt.get("smart_install") or {}).get("smart_install_enabled"):
        out.append(make_finding(
            hostname, CRITICAL, "Smart Install enabled",
            ("Smart Install (vstack) is enabled; it accepts unauthenticated "
             "config and image requests on TCP 4786 (CVE-2018-0171). Disable "
             "with 'no vstack'."),
            finding_type="smart_install",
        ))
    return out


def _cpu_memory_findings(hostname, cm):
    out = []
    cpu = cm.get("cpu") or {}
    five = cpu.get("cpu_5m")
    if five is not None and five >= CPU_WARN_PCT:
        out.append(make_finding(
            hostname, WARNING, "High CPU utilisation",
            f"5-minute CPU average is {five}%.",
            finding_type="cpu:high",
            aggregate_key=f"5-minute CPU at or above {CPU_WARN_PCT}%",
        ))
    for pool in (cm.get("memory") or {}).get("pools", []):
        if pool.get("pool") not in ("Processor", "System"):
            continue
        pct = pool.get("used_pct")
        if pct is not None and pct >= MEMORY_WARN_PCT:
            out.append(make_finding(
                hostname, WARNING, "Memory nearly exhausted",
                f"{pool['pool']} memory is {pct}% used.",
                finding_type="memory:high",
                aggregate_key=f"{pool['pool']} memory at or above {MEMORY_WARN_PCT}% used",
            ))
    return out


def interface_issues(intf):
    """(crc_flag, drop_flag) for one parsed interface row."""
    crc = intf.get("crc") or 0
    inp = intf.get("input_packets") or 0
    crc_flag = bool(crc) and (crc >= CRC_ABSOLUTE or (inp and crc / inp >= CRC_RATE))
    drops = intf.get("output_drops") or 0
    outp = intf.get("output_packets") or 0
    drop_flag = drops >= DROP_MIN and bool(outp) and drops / outp >= DROP_RATE
    return crc_flag, drop_flag


def _interface_findings(hostname, counters):
    out = []
    for intf in counters.get("interfaces", []):
        crc_flag, drop_flag = interface_issues(intf)
        name = intf.get("interface", "")
        cleared = intf.get("counters_cleared") or "unknown"
        if crc_flag:
            out.append(make_finding(
                hostname, WARNING, "Interface CRC errors",
                (f"{name}: {intf.get('crc')} CRC errors in "
                 f"{intf.get('input_packets') or 0} input packets (counters "
                 f"cleared {cleared}). Check cabling, optics and duplex."),
                finding_type="interface:crc",
                aggregate_key="CRC errors above threshold",
                interface=name,
            ))
        if drop_flag:
            out.append(make_finding(
                hostname, INFO, "Interface output drops",
                (f"{name}: {intf.get('output_drops')} output drops in "
                 f"{intf.get('output_packets')} output packets (counters "
                 f"cleared {cleared})."),
                finding_type="interface:output_drops",
                aggregate_key="Output drops above 0.1% of packets",
                interface=name,
            ))
    return out


def analyze(inventory_data):
    findings = []
    devices = inventory_data.get("devices", {})
    counted = 0
    for hostname, device in sorted(devices.items()):
        if not _has_any(device):
            continue
        counted += 1
        findings += _env_findings(hostname, _parsed(device, "environment"))
        findings += _redundancy_findings(hostname, _parsed(device, "redundancy"))
        findings += _mgmt_findings(hostname, _parsed(device, "mgmt_security"))
        findings += _cpu_memory_findings(hostname, _parsed(device, "cpu_memory"))
        findings += _interface_findings(hostname, _parsed(device, "interface_counters"))
    overfire_check(findings, counted)
    return {"findings": findings, "device_count": counted}


def _fmt(value):
    return "" if value is None else value


def _yes_no(value):
    if value is None:
        return ""
    return "Yes" if value else "No"


ENV_HEADERS = ["Device", "Component", "Name", "Status", "Reading", "State"]
POE_HEADERS = ["Device", "Module", "Available (W)", "Used (W)", "Remaining (W)",
               "Used %", "Ports On", "Problem Ports"]
REDUNDANCY_HEADERS = ["Device", "Hardware Mode", "Configured Mode", "Operating Mode",
                      "Active State", "Peer State", "Switchovers",
                      "Last Switchover Reason", "Stack Members", "Stack Ring Speed",
                      "Stack Ring Config", "Stack Issues"]
MGMT_HEADERS = ["Device", "SSH Enabled", "SSH Version", "SSHv1 Accepted",
                "RSA Key Bits", "Min DH Bits", "Smart Install Role",
                "Smart Install Enabled"]
CPU_HEADERS = ["Device", "CPU 5s %", "CPU 1m %", "CPU 5m %", "Memory Pool",
               "Memory Used %", "Top Process", "Top Holding (bytes)"]
INTF_HEADERS = ["Device", "Interface", "Description", "Status", "Protocol",
                "Input Packets", "Input Errors", "CRC", "Frame", "Runts", "Giants",
                "Input Drops", "Output Packets", "Output Errors", "Output Drops",
                "Collisions", "Resets", "Last Input", "Last Output",
                "Counters Cleared", "Flagged"]
FINDINGS_DETAIL_HEADERS = ["Device", "Severity", "Finding", "Details"]


def build_tabular(inventory_data, analysis):
    env_rows, poe_rows, red_rows, mgmt_rows, cpu_rows, intf_rows = [], [], [], [], [], []
    for hostname, device in sorted(inventory_data.get("devices", {}).items()):
        env = _parsed(device, "environment")
        for item in env.get("items", []):
            env_rows.append([hostname, item.get("component", ""), item.get("name", ""),
                             item.get("status", ""), item.get("reading", ""),
                             item.get("state", "")])
        poe = env.get("power_inline") or {}
        ports_on = (poe.get("ports_by_state") or {}).get("on", 0)
        problems = ", ".join(p["interface"] for p in poe.get("problem_ports") or [])
        for b in poe.get("budgets") or []:
            avail = b.get("available_w") or 0
            pct = round(100 * b.get("used_w", 0) / avail, 1) if avail else ""
            poe_rows.append([hostname, b.get("module", ""), b.get("available_w"),
                             b.get("used_w"), b.get("remaining_w"), pct, ports_on,
                             problems])

        red = _parsed(device, "redundancy")
        if red.get("redundancy") or red.get("stack_ports") or red.get("stack_ring"):
            r = red.get("redundancy") or {}
            ring = red.get("stack_ring") or {}
            members = red.get("stack_ports") or []
            red_rows.append([hostname, r.get("hardware_mode", ""),
                             r.get("configured_mode", ""), r.get("operating_mode", ""),
                             r.get("active_state", ""), r.get("peer_state", ""),
                             r.get("switchovers", ""), r.get("last_switchover_reason", ""),
                             len(members) or "", ring.get("speed", ""),
                             ring.get("configuration", ""),
                             "; ".join(stack_degraded(members, ring))])

        mgmt = _parsed(device, "mgmt_security")
        if mgmt.get("ssh") or mgmt.get("smart_install"):
            ssh = mgmt.get("ssh") or {}
            si = mgmt.get("smart_install") or {}
            mgmt_rows.append([hostname, _yes_no(ssh.get("enabled")), ssh.get("version", ""),
                              _yes_no(ssh.get("v1_enabled")) if ssh.get("version") else "",
                              _fmt(ssh.get("key_bits")), _fmt(ssh.get("min_dh_bits")),
                              si.get("role", ""), _yes_no(si.get("smart_install_enabled"))])

        cm = _parsed(device, "cpu_memory")
        if cm.get("cpu") or (cm.get("memory") or {}).get("pools"):
            cpu = cm.get("cpu") or {}
            mem = cm.get("memory") or {}
            pool = next((p for p in mem.get("pools", [])
                         if p.get("pool") in ("Processor", "System")), {})
            top = (mem.get("top_processes") or [{}])[0]
            cpu_rows.append([hostname,
                             _fmt(cpu.get("cpu_5s", cpu.get("cpu_now"))),
                             _fmt(cpu.get("cpu_1m")), _fmt(cpu.get("cpu_5m")),
                             pool.get("pool", ""), _fmt(pool.get("used_pct")),
                             top.get("process", ""), _fmt(top.get("holding"))])

        for intf in _parsed(device, "interface_counters").get("interfaces", []):
            crc_flag, drop_flag = interface_issues(intf)
            flags = ", ".join(f for f, on in (("CRC", crc_flag), ("Drops", drop_flag)) if on)
            intf_rows.append([hostname, intf.get("interface", ""),
                              intf.get("description", ""), intf.get("status", ""),
                              intf.get("protocol", ""),
                              _fmt(intf.get("input_packets")), _fmt(intf.get("input_errors")),
                              _fmt(intf.get("crc")), _fmt(intf.get("frame")),
                              _fmt(intf.get("runts")), _fmt(intf.get("giants")),
                              _fmt(intf.get("input_drops")), _fmt(intf.get("output_packets")),
                              _fmt(intf.get("output_errors")), _fmt(intf.get("output_drops")),
                              _fmt(intf.get("collisions")), _fmt(intf.get("interface_resets")),
                              intf.get("last_input", ""), intf.get("last_output", ""),
                              intf.get("counters_cleared", ""), flags])

    findings = analysis["findings"]
    sheets = OrderedDict()
    sheets["Summary"] = (["Metric", "Value"], [
        ["Devices with health data", analysis["device_count"]],
        ["Environment faults", sum(1 for f in findings
                                   if str(f.get("type", "")).startswith("env:"))],
        ["Interfaces with CRC errors", sum(1 for f in findings
                                           if f.get("type") == "interface:crc")],
    ] + summary_count_rows(findings))
    sheets["Findings"] = (list(AGGREGATE_HEADERS), aggregate_rows(findings))
    sheets[DETAIL_SHEET] = (list(FINDINGS_DETAIL_HEADERS),
                            [[f.get("hostname", ""), f.get("severity", INFO),
                              f.get("title", ""), f.get("description", "")]
                             for f in findings])
    sheets["Environment"] = (ENV_HEADERS, env_rows)
    sheets["PoE Budget"] = (POE_HEADERS, poe_rows)
    sheets["Redundancy & Stack"] = (REDUNDANCY_HEADERS, red_rows)
    sheets["Management Plane"] = (MGMT_HEADERS, mgmt_rows)
    sheets["CPU & Memory"] = (CPU_HEADERS, cpu_rows)
    sheets["Interface Health"] = (INTF_HEADERS, intf_rows)
    return sheets


class PlatformHealthReport(BaseReport):
    name = "platform_health"
    label = "Platform Health"
    description = ("Environment, PoE, redundancy and stack ring, SSH and Smart "
                   "Install, CPU/memory and interface error counters")
    category = "Compliance & Config"
    required_collectors = list(COLLECTORS)
    supported_formats = ["xlsx", "json", "csv", "xml"]

    def can_generate(self, inventory_data):
        return any(_has_any(d) for d in inventory_data.get("devices", {}).values())

    def generate_tabular_data(self, inventory_data):
        return build_tabular(inventory_data, analyze(inventory_data))

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        return self._generate_for_format(inventory_data, fmt)
