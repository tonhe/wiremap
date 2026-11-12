"""
Collection Issues report: everything that went wrong while collecting, in one
place to hand over when a scan misbehaves.

Command issues come from the scan summary (recorded as commands ran); refused
commands are read back from the saved outputs, so older scans still get them.
"""
from collections import OrderedDict

from .base import BaseReport

try:
    from app.collectors.errors import KIND_LABELS, NOT_APPLICABLE, classify_error
    from app.command_issues import DESCRIPTION, SEVERITY
    from app.failures import failure_record
except ImportError:
    from collectors.errors import KIND_LABELS, NOT_APPLICABLE, classify_error
    from command_issues import DESCRIPTION, SEVERITY
    from failures import failure_record

SUMMARY = ["Severity", "Item", "Count", "Meaning"]
ISSUES = ["Time", "Device", "IP", "Severity", "Kind", "Command", "Seconds", "Detail"]
REFUSED = ["Device", "IP", "Collector", "Command", "Kind", "Response"]
FAILURES = ["IP", "Device", "Reason", "Hint", "Message"]

_ORDER = {"error": 0, "warning": 1, "info": 2}


def _ip(device):
    return device.get("reached_ip") or device.get("mgmt_ip") or ""


def issue_rows(inventory_data):
    issues = (inventory_data.get("scan_summary") or {}).get("command_issues") or []
    return [[i.get("time", ""), i.get("hostname", ""), i.get("ip", ""), i.get("severity", ""),
             i.get("kind", ""), i.get("command", ""), i.get("seconds"), i.get("detail", "")]
            for i in issues]


def refused_rows(inventory_data):
    rows = []
    for hostname, device in sorted((inventory_data.get("devices") or {}).items()):
        seen = set()
        for cname, data in sorted((device.get("collector_data") or {}).items()):
            for command, output in ((data or {}).get("raw") or {}).items():
                if command in seen or not isinstance(output, str):
                    continue
                found = classify_error(output)
                if found:
                    seen.add(command)
                    line, kind = found
                    rows.append([hostname, _ip(device), cname, command,
                                 KIND_LABELS.get(kind, kind), line])
    return rows


def failure_rows(inventory_data):
    failed = (inventory_data.get("scan_summary") or {}).get("failed") or {}
    rows = []
    for ip, value in sorted(failed.items()):
        rec = failure_record(value)
        rows.append([ip, rec.get("hostname") or "", rec.get("reason") or "",
                     rec.get("hint") or "", rec.get("message") or ""])
    return rows


def summary_rows(issues, refused, failures):
    counts = {}
    for row in issues:
        counts[row[4]] = counts.get(row[4], 0) + 1
    rows = [[SEVERITY.get(k, ""), k, n, DESCRIPTION.get(k, "")]
            for k, n in counts.items()]
    rows.sort(key=lambda r: (_ORDER.get(r[0], 3), -r[2], r[1]))
    by_kind = {}
    for row in refused:
        by_kind[row[4]] = by_kind.get(row[4], 0) + 1
    for label, n in sorted(by_kind.items()):
        meaning = ("normal for commands that do not exist on that platform"
                   if label == KIND_LABELS[NOT_APPLICABLE] else "see Refused Commands")
        rows.append(["", f"refused commands ({label})", n, meaning])
    rows.append(["", "devices not logged into", len(failures), "see Device Failures"])
    return rows


def build_tabular(inventory_data):
    issues = issue_rows(inventory_data)
    refused = refused_rows(inventory_data)
    failures = failure_rows(inventory_data)
    return OrderedDict([
        ("Summary", (SUMMARY, summary_rows(issues, refused, failures))),
        ("Command Issues", (ISSUES, issues)),
        ("Refused Commands", (REFUSED, refused)),
        ("Device Failures", (FAILURES, failures)),
    ])


class CollectionIssuesReport(BaseReport):
    name = "collection_issues"
    label = "Collection Issues"
    description = ("Command timeouts, pager problems, refused commands and login "
                   "failures from the scan")
    category = "Discovery & Topology"
    supported_formats = ["xlsx", "json", "csv"]

    def can_generate(self, inventory_data):
        return bool(inventory_data.get("devices") or
                    (inventory_data.get("scan_summary") or {}).get("failed"))

    def generate_tabular_data(self, inventory_data):
        return build_tabular(inventory_data)

    def generate(self, inventory_data: dict, fmt: str = "xlsx") -> bytes:
        return self._generate_for_format(inventory_data, fmt)
