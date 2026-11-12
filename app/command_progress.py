"""
Reporting each command as it is sent, so a scan that sits on one device for a
long time shows what it is waiting on.
"""
import logging
import time

logger = logging.getLogger(__name__)

SLOW_AFTER = 30


class ProgressConnection:
    """A connection whose send_command reports progress through emit."""

    def __init__(self, conn, emit, ip, hostname, clock=time.monotonic):
        self._conn = conn
        self._emit = emit
        self._ip = ip
        self._hostname = hostname
        self._clock = clock
        self._sent = 0

    def send_command(self, command_string, *args, **kwargs):
        self._sent += 1
        where = {"ip": self._ip, "hostname": self._hostname, "command": command_string}
        self._emit({"event": "command_running", **where, "count": self._sent})
        started = self._clock()
        try:
            output = self._conn.send_command(command_string, *args, **kwargs)
        except Exception as e:
            seconds = round(self._clock() - started, 1)
            logger.warning(f"{self._hostname}: '{command_string}' failed after "
                           f"{seconds}s: {e}")
            self._emit({"event": "command_failed", **where, "seconds": seconds,
                        "error": str(e)[:300]})
            raise
        seconds = round(self._clock() - started, 1)
        if seconds >= SLOW_AFTER:
            logger.info(f"{self._hostname}: '{command_string}' took {seconds}s")
            self._emit({"event": "command_slow", **where, "seconds": seconds})
        return output

    def __getattr__(self, name):
        return getattr(self._conn, name)
