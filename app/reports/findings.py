"""
Shared findings helpers: severity rubric, finding constructor, and an
over-firing self-check.

Severity rubric -- pick the lowest level the evidence supports:

  Critical  Reachability, redundancy or security exposure, backed by
            evidence in the collected data (a BGP session down, overlapping
            subnets between devices, STP root disagreement).
  Warning   Probable misconfiguration: something that is usually wrong but
            may be intentional (default STP priority on a root, permit ip
            any any on an interface filter, a /16 user VLAN).
  Info      Documentation-grade observation: worth knowing, not a defect
            on its own (unreferenced ACL, EIGRP stub peer, infra subnets).

Every finding is a dict with hostname, severity, title, description and
type. ``type`` is a stable key for the kind of check (titles can embed
per-instance detail such as a VLAN id), and is what the over-firing check
groups on.
"""
from collections import defaultdict

CRITICAL = "Critical"
WARNING = "Warning"
INFO = "Info"
SEVERITIES = (CRITICAL, WARNING, INFO)

OVERFIRE_TYPE = "meta:overfire"


def make_finding(hostname, severity, title, description, finding_type=None, **extra):
    """Build a finding dict. finding_type defaults to the title."""
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")
    finding = {
        "hostname": hostname or "",
        "severity": severity,
        "title": title,
        "description": description,
        "type": finding_type or title,
    }
    finding.update(extra)
    return finding


def count_by_severity(findings):
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    for f in findings:
        sev = f.get("severity", INFO)
        counts[sev if sev in counts else INFO] += 1
    return counts


def overfire_check(findings, device_count, threshold=0.5, min_devices=4):
    """Append an Info meta-note for each finding type that fires on more
    than ``threshold`` of devices.

    A check that trips on most of the network is more likely a miscalibrated
    heuristic than a network-wide defect, and the reader should know that
    before acting on it. Findings without a hostname (fabric-wide ones) do
    not count toward a device ratio. Below ``min_devices`` the ratio means
    nothing, so no notes are added. Returns the same list for chaining.
    """
    if device_count < min_devices or device_count <= 0:
        return findings
    hosts_by_type = defaultdict(set)
    severity_by_type = {}
    for f in findings:
        ftype = f.get("type") or f.get("title", "")
        if ftype == OVERFIRE_TYPE or not f.get("hostname"):
            continue
        hosts_by_type[ftype].add(f["hostname"])
        severity_by_type.setdefault(ftype, f.get("severity", INFO))

    for ftype in sorted(hosts_by_type):
        hit = len(hosts_by_type[ftype])
        if hit / device_count > threshold:
            pct = round(100 * hit / device_count)
            findings.append(make_finding(
                "", INFO,
                f"Check may be miscalibrated: {ftype}",
                (f"'{ftype}' ({severity_by_type[ftype]}) fired on {hit} of "
                 f"{device_count} devices ({pct}%). A finding this widespread "
                 f"usually reflects a heuristic that does not fit this "
                 f"network; review before treating each instance as a defect."),
                finding_type=OVERFIRE_TYPE,
                about=ftype,
            ))
    return findings
