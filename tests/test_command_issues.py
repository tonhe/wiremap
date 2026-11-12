"""Classifying what went wrong with a command."""
import threading
from datetime import datetime, timezone

import pytest

from app import command_issues as ci
from app.wlc_session import WlcReadTimeout


@pytest.mark.parametrize("exc, kind", [
    (WlcReadTimeout("no prompt after 120s waiting for output of x; "
                    "last line: 'Press Enter to continue or <Ctrl-Z> to abort'"), ci.PAGER_STUCK),
    (WlcReadTimeout("no prompt after 120s waiting for output of x; last line: '--More--'"),
     ci.PAGER_STUCK),
    (WlcReadTimeout("no prompt after 120s waiting for output of x; "
                    "last line: 'Are you sure you want to proceed? (y/N)'"), ci.PAGER_STUCK),
    (WlcReadTimeout("no prompt after 120s waiting for output of x; session recovered; "
                    "last line: '--More or (q)uit current module or <ctrl-z> to ab'"), ci.PAGER_STUCK),
    (WlcReadTimeout("no prompt after 120s waiting for output of x; last line: 'row 7'"),
     ci.TIMEOUT),
    (TimeoutError("Pattern not detected: 'sw#' in output."), ci.TIMEOUT),
    (OSError("Socket is closed"), ci.SEND_FAILED),
    (EOFError(""), ci.SEND_FAILED),
])
def test_failure_kind(exc, kind):
    assert ci.failure_kind(exc) == kind


@pytest.mark.parametrize("command, output, expected", [
    ("show version", "Cisco IOS Software", []),
    ("show logging", "a\n --More-- \nb", [(ci.PAGER_IN_OUTPUT, "--More--")]),
    ("show run", "x\n<--- More --->\ny", [(ci.PAGER_IN_OUTPUT, "<--- More --->")]),
    ("show msglog", "x\nPress Enter to continue...\n", [(ci.PAGER_IN_OUTPUT,
                                                         "Press Enter to continue...")]),
    ("show inventory", "% Permission denied", [(ci.REFUSED, "% Permission denied")]),
    ("show inventory", "% Authorization failed.", [(ci.REFUSED, "% Authorization failed.")]),
    ("show nat", "ERROR: no such table", [(ci.DEVICE_ERROR, "ERROR: no such table")]),
    ("config paging disable", "Incorrect usage. Use the '?' or <TAB> key to list commands.",
     [(ci.PAGING_NOT_DISABLED, "Incorrect usage. Use the '?' or <TAB> key to list commands.")]),
    ("terminal length 0", "% Invalid input detected at '^' marker.",
     [(ci.PAGING_NOT_DISABLED, "% Invalid input detected at '^' marker.")]),
    # A command for another platform is normal and is not logged one by one.
    ("show mac address-table", "% Invalid input detected at '^' marker.", []),
    ("show cpu", "", []),
    ("show cpu", None, []),
])
def test_output_issues(command, output, expected):
    assert ci.output_issues(command, output) == expected


def test_every_kind_has_a_severity_and_meaning():
    kinds = [ci.PAGER_STUCK, ci.TIMEOUT, ci.SEND_FAILED, ci.REFUSED, ci.PAGER_IN_OUTPUT,
             ci.UNEXPECTED_QUESTION, ci.PAGING_NOT_DISABLED, ci.DEVICE_ERROR, ci.SLOW]
    assert set(kinds) == set(ci.SEVERITY) == set(ci.DESCRIPTION)


def test_log_records_entries_and_counts():
    log = ci.IssueLog(clock=lambda: datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc))
    entry = log.record(ci.TIMEOUT, "192.0.2.10", "lab-sw-01", "show run", "x " * 300, 120.0)
    assert entry["time"] == "2026-11-12T10:00:00Z" and entry["severity"] == "error"
    assert len(entry["detail"]) == ci.DETAIL_LIMIT
    log.record(ci.SLOW, "192.0.2.10", "lab-sw-01", "show tech", "took 31s", 31.0)
    log.record(ci.TIMEOUT, "192.0.2.11", "lab-sw-02", "show run", "", 120.0)
    assert log.counts() == {"timeout": 2, "slow": 1}
    assert [e["hostname"] for e in log.entries()] == ["lab-sw-01", "lab-sw-01", "lab-sw-02"]


def test_log_is_safe_across_workers():
    log = ci.IssueLog()

    def work(n):
        for _ in range(200):
            log.record(ci.SLOW, f"192.0.2.{n}", f"lab-sw-{n}", "show tech", "", 30.0)
    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(log.entries()) == 1600
