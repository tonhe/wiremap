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

Aggregation: a check that fires on hundreds of devices with the same
detail (one template ACL left unreferenced everywhere) is one problem, not
hundreds. ``aggregate_findings`` collapses findings that share type,
severity and normalized details into one row with a device count; the
per-device rows still go to a ``Findings (detail)`` sheet. A finding can
pin its grouping by passing ``aggregate_key`` (the details text shown on
the aggregated row) when its description carries per-device specifics
such as rule counts or peer addresses.

Summary counts: the ``<Severity> Findings`` metrics count per-device
instances (rows on the detail sheet); the ``(distinct)`` metrics count
aggregated rows (rows on the Findings sheet).
"""
import re
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


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

AGGREGATE_HEADERS = ["Severity", "Finding", "Details", "Device count", "Devices"]
DETAIL_SHEET = "Findings (detail)"
DEVICE_LIST_LIMIT = 10

_SEVERITY_ORDER = {sev: i for i, sev in enumerate(SEVERITIES)}


def default_aggregate_key(finding):
    """Details text a finding groups on: its explicit ``aggregate_key``, or
    the description with the device's own hostname replaced and whitespace
    collapsed."""
    key = finding.get("aggregate_key")
    if key:
        return key
    text = str(finding.get("description", ""))
    hostname = finding.get("hostname") or ""
    if hostname:
        text = re.sub(re.escape(hostname), "<device>", text, flags=re.IGNORECASE)
    return " ".join(text.split())


def format_device_list(hosts, limit=DEVICE_LIST_LIMIT):
    hosts = sorted(hosts)
    shown = ", ".join(hosts[:limit])
    if len(hosts) > limit:
        shown += f", +{len(hosts) - limit} more"
    return shown


def aggregate_findings(findings, key_fn=None):
    """Collapse findings identical in (type, severity, normalized details).

    Returns a list of dicts (severity, title, type, details, device_count,
    devices, findings) sorted Critical, Warning, Info, then by device count
    descending. ``title`` is the shared title, or the type when titles
    differ within the group. Findings with no hostname (fabric-wide ones,
    over-fire notes) contribute no devices.
    """
    key_fn = key_fn or default_aggregate_key
    groups = {}
    order = []
    for f in findings:
        severity = f.get("severity", INFO)
        ftype = f.get("type") or f.get("title", "")
        details = key_fn(f)
        k = (ftype, severity, details)
        group = groups.get(k)
        if group is None:
            group = groups[k] = {
                "severity": severity, "type": ftype, "details": details,
                "titles": [], "hosts": set(), "findings": [],
            }
            order.append(k)
        group["findings"].append(f)
        title = f.get("title", "")
        if title not in group["titles"]:
            group["titles"].append(title)
        if f.get("hostname"):
            group["hosts"].add(f["hostname"])

    result = []
    for k in order:
        g = groups[k]
        result.append({
            "severity": g["severity"],
            "type": g["type"],
            "title": g["titles"][0] if len(g["titles"]) == 1 else g["type"],
            "details": g["details"],
            "device_count": len(g["hosts"]),
            "devices": sorted(g["hosts"]),
            "findings": g["findings"],
        })
    result.sort(key=lambda a: (_SEVERITY_ORDER.get(a["severity"], len(SEVERITIES)),
                               -a["device_count"], a["title"], a["details"]))
    return result


def aggregate_rows(findings, key_fn=None):
    """Aggregated Findings sheet rows, matching AGGREGATE_HEADERS."""
    return [
        [a["severity"], a["title"], a["details"], a["device_count"],
         format_device_list(a["devices"])]
        for a in aggregate_findings(findings, key_fn)
    ]


def summary_count_rows(findings):
    """Summary-sheet metrics: per-device instance counts by severity, then
    distinct (aggregated) counts by severity."""
    raw = count_by_severity(findings)
    distinct = count_by_severity(aggregate_findings(findings))
    rows = [[f"{sev} Findings", raw[sev]] for sev in SEVERITIES]
    rows += [[f"{sev} Findings (distinct)", distinct[sev]] for sev in SEVERITIES]
    return rows
