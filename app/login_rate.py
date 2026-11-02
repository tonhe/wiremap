"""
Login rate limiting shared by every discovery worker.

TACACS+ and ISE throttle or lock out an account that authenticates too often.
With 20 workers and three driver fallbacks per device, a large scan can send
well over a hundred logins a minute. A limit spaces login attempts evenly
across all workers, so the AAA server sees a steady trickle instead of a burst.

The bucket holds one token, refilled every 60 / rate seconds. A worker that
finds it empty reserves the next slot and sleeps until then, so waiting
workers are served in arrival order and never all wake at once.
"""
import threading
import time
from collections import deque


class LoginRateLimiter:
    def __init__(self, per_minute, clock=None, sleep=None):
        self.per_minute = int(per_minute or 0)
        self._interval = 60.0 / self.per_minute if self.per_minute > 0 else 0.0
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._lock = threading.Lock()
        self._next_slot = None
        # Login start times in the last minute, and the most seen in any
        # one minute -- counted with or without a limit, so a run shows
        # what the AAA server actually saw.
        self._recent = deque()
        self.peak_per_minute = 0

    @property
    def enabled(self):
        return self._interval > 0

    def _count(self, start):
        self._recent.append(start)
        while self._recent and self._recent[0] <= start - 60:
            self._recent.popleft()
        self.peak_per_minute = max(self.peak_per_minute, len(self._recent))

    def acquire(self):
        """Block until a login may start. Returns the seconds waited."""
        with self._lock:
            now = self._clock()
            if not self.enabled:
                self._count(now)
                return 0.0
            slot = now if self._next_slot is None else max(now, self._next_slot)
            self._next_slot = slot + self._interval
            self._count(slot)
        wait = slot - now
        if wait > 0:
            self._sleep(wait)
        return wait
