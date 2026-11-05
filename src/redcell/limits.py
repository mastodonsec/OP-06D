"""Time-window and rate-cap primitives (RC-10).

Both limits come from the validated RC-6 engagement (``authorization.window``
and ``intensity.max_rps``); nothing here is hard-coded. Clocks are injected so
behavior is deterministic in tests.

Window semantics (documented, tested): the authorized window is the half-open
interval **[start, end)**. An action at exactly ``start`` is allowed; an action
at exactly ``end`` is denied. Choosing exclusive-end is the conservative side:
the instant the booking ends, the tool is out of bounds. Times are compared as
timezone-aware instants, so any offset on the clock or in the file is honored;
RC-6 already normalized the window to UTC.

Rate semantics: a sliding one-second log. At most ``max_rps`` actions are
admitted in any rolling one-second period (an action admitted at ``t`` stops
counting at ``t + 1s``). Over-cap actions are **blocked, not delayed**: the
gate decides immediately and reports ``retry_after``. Blocked actions do not
consume capacity. The rate uses a monotonic clock so wall-clock adjustments
cannot grant extra budget.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable

RATE_PERIOD_SECONDS = 1.0


def _aware(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def window_problem(window: object) -> str | None:
    """Return why a window is unusable, or None if it is well-formed."""
    if not isinstance(window, (tuple, list)) or len(window) != 2:
        return "authorized window is missing or malformed"
    start, end = window
    if not _aware(start) or not _aware(end):
        return "authorized window times must be timezone-aware datetimes"
    if end <= start:
        return "authorized window end is not after its start"
    return None


def evaluate_window(window: object, now: object) -> tuple[bool, str]:
    """Pure window check. Returns (allowed, reason). Never raises; anything
    malformed is a deny."""
    try:
        problem = window_problem(window)
        if problem:
            return False, f"deny: {problem}"
        if not _aware(now):
            return False, "deny: current time is not a timezone-aware datetime"
        start, end = window  # type: ignore[misc]
        if now < start:  # type: ignore[operator]
            return False, f"deny: outside authorized window (before start {start.isoformat()})"
        if now >= end:  # type: ignore[operator]
            return False, f"deny: outside authorized window (at or after end {end.isoformat()})"
        return True, "within authorized window"
    except Exception as exc:  # default deny
        return False, f"deny: window check error ({type(exc).__name__})"


class RateLimiter:
    """Thread-safe sliding-window limiter: at most ``max_rps`` admissions in
    any rolling one-second period."""

    def __init__(
        self, max_rps: object, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        if isinstance(max_rps, bool) or not isinstance(max_rps, int) or max_rps < 1:
            raise ValueError(f"max_rps must be a positive integer, got {max_rps!r}")
        self.max_rps = max_rps
        self._clock = monotonic
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def try_acquire(self) -> tuple[bool, float]:
        """Admit one action if capacity allows. Returns (admitted, retry_after
        seconds); retry_after is 0.0 when admitted."""
        with self._lock:
            now = self._clock()
            if not isinstance(now, (int, float)) or not math.isfinite(now):
                return False, RATE_PERIOD_SECONDS
            if self._stamps and now < self._stamps[-1]:
                return False, RATE_PERIOD_SECONDS  # clock went backwards: fail closed
            cutoff = now - RATE_PERIOD_SECONDS
            while self._stamps and self._stamps[0] <= cutoff:
                self._stamps.popleft()
            if len(self._stamps) >= self.max_rps:
                return False, max(0.0, self._stamps[0] + RATE_PERIOD_SECONDS - now)
            self._stamps.append(now)
            return True, 0.0
