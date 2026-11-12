"""
Reporting each command as it is sent, so a scan that sits on one device for a
long time shows what it is waiting on, and recording anything that went wrong
with it (see app.command_issues).
"""
import time

try:
    from app.command_issues import (SLOW, SLOW_AFTER, UNEXPECTED_QUESTION, IssueLog,
                                    failure_kind, output_issues)
except ImportError:
    from command_issues import (SLOW, SLOW_AFTER, UNEXPECTED_QUESTION, IssueLog,
                                failure_kind, output_issues)


class ProgressConnection:
    """A connection whose send_command reports progress and issues through emit."""

    def __init__(self, conn, emit, ip, hostname, issues=None, clock=time.monotonic):
        self._conn = conn
        self._emit = emit
        self._ip = ip
        self._hostname = hostname
        self._issues = issues if issues is not None else IssueLog()
        self._clock = clock
        self._sent = 0

    def wrap(self, factory):
        """Put another layer (an AireOS pager session) under the reporting."""
        self._conn = factory(self._conn)

    def named(self, hostname):
        """Report under the device's name once it is known; the address until then."""
        self._hostname = hostname

    def _record(self, kind, command, detail, seconds=None):
        entry = self._issues.record(kind, self._ip, self._hostname, command, detail, seconds)
        self._emit({"event": "command_issue", **entry})

    def _questions(self, command):
        # Only an AireOS session keeps notes; a proxied attribute must not
        # stand in for one.
        take = getattr(type(self._conn), "take_notes", None)
        for question in (take(self._conn) if take else []):
            self._record(UNEXPECTED_QUESTION, command, question)

    def send_command(self, command_string, *args, **kwargs):
        self._sent += 1
        self._emit({"event": "command_running", "ip": self._ip, "hostname": self._hostname,
                    "command": command_string, "count": self._sent})
        started = self._clock()
        try:
            output = self._conn.send_command(command_string, *args, **kwargs)
        except Exception as e:
            seconds = round(self._clock() - started, 1)
            self._questions(command_string)
            self._record(failure_kind(e), command_string, f"{type(e).__name__}: {e}", seconds)
            raise
        seconds = round(self._clock() - started, 1)
        self._questions(command_string)
        for kind, detail in output_issues(command_string, output):
            self._record(kind, command_string, detail, seconds)
        if seconds >= SLOW_AFTER:
            self._record(SLOW, command_string, f"took {seconds}s", seconds)
        return output

    def __getattr__(self, name):
        return getattr(self._conn, name)
