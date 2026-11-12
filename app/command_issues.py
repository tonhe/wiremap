"""
Spotting what went wrong with a command while a device is collected: timeouts,
pager prompts nobody answered, pager text left in the output, refusals.

Every issue is logged as it happens and kept for the scan file, so a run that
misbehaved can be explained afterwards from one list.
"""
import logging
import re
import threading
from datetime import datetime, timezone

try:
    from app.collectors.errors import UNAUTHORIZED, FAILED, classify_error
except ImportError:
    from collectors.errors import UNAUTHORIZED, FAILED, classify_error

logger = logging.getLogger(__name__)

ERROR = "error"
WARNING = "warning"
INFO = "info"

PAGER_STUCK = "pager_stuck"
TIMEOUT = "timeout"
SEND_FAILED = "send_failed"
REFUSED = "unauthorized"
PAGER_IN_OUTPUT = "pager_in_output"
UNEXPECTED_QUESTION = "unexpected_question"
PAGING_NOT_DISABLED = "paging_not_disabled"
DEVICE_ERROR = "device_error"
SLOW = "slow"

SEVERITY = {
    PAGER_STUCK: ERROR,
    TIMEOUT: ERROR,
    SEND_FAILED: ERROR,
    REFUSED: ERROR,
    PAGER_IN_OUTPUT: WARNING,
    UNEXPECTED_QUESTION: WARNING,
    PAGING_NOT_DISABLED: WARNING,
    DEVICE_ERROR: WARNING,
    SLOW: INFO,
}

DESCRIPTION = {
    PAGER_STUCK: "stopped at a pager prompt or question that was not answered",
    TIMEOUT: "no prompt came back before the read timeout",
    SEND_FAILED: "the session failed while sending the command",
    REFUSED: "the device refused the command for this account",
    PAGER_IN_OUTPUT: "pager text was left in the output, which may be incomplete",
    UNEXPECTED_QUESTION: "the device asked a question that was answered no",
    PAGING_NOT_DISABLED: "paging could not be turned off, so pages are answered one by one",
    DEVICE_ERROR: "the device answered with an error",
    SLOW: "the command took 30 seconds or longer",
}

SLOW_AFTER = 30
DETAIL_LIMIT = 200

# Pager prompts across IOS, NX-OS, ASA, AireOS and friends.
PAGER_TEXT = re.compile(
    r"--\s*More\b|<-+\s*More\s*-+>|Press (?:Enter|RETURN|any key) to continue|"
    r"\(q\)uit|Would you like to display the next", re.I)
# A question waiting for an answer, as the last thing printed.
QUESTION = re.compile(r"\((?:y/n|yes/no)\)\s*\S*\s*$|\[confirm\]\s*$|\[(?:y/n|yes/no)\]\s*$",
                      re.I)

PAGING_DISABLE = re.compile(
    r"^(?:config paging disable|terminal length 0|terminal pager 0|set cli pager off|"
    r"no page|screen-length 0 temporary|terminal datadump)$", re.I)

_LAST_LINE = re.compile(r"last line: '(.*)'\s*$")


def _detail(text):
    text = " ".join(str(text).split())
    return text[:DETAIL_LIMIT]


def failure_kind(exc):
    """Classify an exception raised while sending a command."""
    text = str(exc)
    m = _LAST_LINE.search(text)
    if m and (PAGER_TEXT.search(m.group(1)) or QUESTION.search(m.group(1))):
        return PAGER_STUCK
    name = type(exc).__name__.lower()
    if "timeout" in name or "timed out" in text.lower() or "no prompt" in text.lower() \
            or "pattern not detected" in text.lower():
        return TIMEOUT
    return SEND_FAILED


def output_issues(command, output):
    """(kind, detail) pairs for a command that returned normally."""
    found = []
    text = output or ""
    rejected = classify_error(text)
    if rejected:
        line, kind = rejected
        if PAGING_DISABLE.match(command.strip()):
            found.append((PAGING_NOT_DISABLED, line))
        elif kind == UNAUTHORIZED:
            found.append((REFUSED, line))
        elif kind == FAILED:
            found.append((DEVICE_ERROR, line))
        return found
    m = PAGER_TEXT.search(text)
    if m:
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        found.append((PAGER_IN_OUTPUT, text[start:end if end != -1 else len(text)].strip()))
    return found


class IssueLog:
    """The issues found during one scan. Shared by the device workers."""

    def __init__(self, clock=None):
        self._lock = threading.Lock()
        self._entries = []
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def record(self, kind, ip, hostname, command, detail="", seconds=None):
        entry = {
            "time": self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hostname": hostname,
            "ip": ip,
            "command": command,
            "kind": kind,
            "severity": SEVERITY[kind],
            "seconds": seconds,
            "detail": _detail(detail),
        }
        with self._lock:
            self._entries.append(entry)
        level = {ERROR: logging.WARNING, WARNING: logging.WARNING}.get(entry["severity"],
                                                                        logging.INFO)
        took = f" after {seconds}s" if seconds is not None else ""
        logger.log(level, f"collection issue [{kind}] {hostname} ({ip}) "
                          f"'{command}'{took}: {entry['detail']}")
        return entry

    def entries(self):
        with self._lock:
            return list(self._entries)

    def counts(self):
        out = {}
        for e in self.entries():
            out[e["kind"]] = out.get(e["kind"], 0) + 1
        return out
