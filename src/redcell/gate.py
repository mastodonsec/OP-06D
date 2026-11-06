"""The guardrail gate: window + scope + rate, one decision, one audit entry.

``Gate.check`` is the single enforcement point for "where" (RC-9), "when" and
"how fast" (RC-10). The model is asked; the gate decides. Limits come from the
validated RC-6 engagement only.

Order of checks (cheapest and most fundamental first, side effects last):

1. window  - outside the authorized window nothing else is even evaluated
2. scope   - includes DNS, and only for hostnames that pass the name checks
3. rate    - consumed last, so refused actions never use up capacity

Exactly one audit entry is written per ``check`` (the final decision, with the
reason), through the existing ``AuditSink`` interface: no second logging path.
If the audit write fails, the result is a deny.

Fail closed: if the engagement's window or rate is missing or malformed, every
check is denied with the reason. ``check`` never raises.

RC-23 (resolve-once): a ``Gate`` owns one ``DnsPinner`` for its whole life
(one ``Gate`` per engagement run), so each hostname is resolved **once** -
the first scope check pins it, and every later check of that hostname, no
matter how much later or how many other actions ran in between, reuses the
exact same address(es). This closes the DNS-rebinding TOCTOU between "the
gate approved this address" and "the tool scanned that address": the tool is
handed the pinned IP(s) via ``GateDecision.resolved_ips`` (see
``tools.py``/``GatedToolbox``), never the hostname, and never resolves on its
own. Pass ``audit_pin`` to have the first pin of each hostname recorded as a
``dns_pinned`` audit entry.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from redcell.audit import AuditSink
from redcell.engagement import Engagement
from redcell.limits import RateLimiter, evaluate_window, window_problem
from redcell.resolve import DnsPinner, PinAuditor, Resolver, system_resolver
from redcell.scope import check_scope

# Which stage produced the decision.
ALLOWED = "allowed"
DENIED_LIMITS = "limits"  # engagement window/rate unusable
DENIED_WINDOW = "window"
DENIED_SCOPE = "scope"
DENIED_RATE = "rate"
DENIED_AUDIT = "audit"
DENIED_ERROR = "error"


@dataclass(frozen=True)
class GateDecision:
    target: str
    allowed: bool
    reason: str
    stage: str
    resolved_ips: tuple[str, ...] = ()
    retry_after: float | None = None  # seconds; set only for rate blocks


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _label(target: object) -> str:
    return target if isinstance(target, str) else f"<{type(target).__name__}>"


class Gate:
    """Enforces one engagement's window, scope and rate cap."""

    def __init__(
        self,
        engagement: Engagement,
        *,
        resolver: Resolver = system_resolver,
        audit_pin: PinAuditor | None = None,
        now: Callable[[], datetime] = _utcnow,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        # RC-23: one pinner for this Gate's whole life = one per engagement.
        # ``resolver`` is only ever called through it, so every hostname is
        # resolved at most once no matter how many actions check it.
        self._pinner = DnsPinner(resolver, on_pin=audit_pin)
        self._now = now
        self._engagement = engagement
        self._limiter: RateLimiter | None = None
        self._window: object = None
        self._config_error: str | None = None
        try:
            if not isinstance(engagement, Engagement):
                raise ValueError("engagement is missing or not an Engagement")
            self._window = engagement.authorization.window
            problem = window_problem(self._window)
            if problem:
                raise ValueError(problem)
            self._limiter = RateLimiter(engagement.intensity.max_rps, monotonic)
        except Exception as exc:
            self._config_error = f"{type(exc).__name__}: {exc}"

    def check(self, target: object, *, audit: AuditSink) -> GateDecision:
        """Decide, audit, return. Never raises."""
        try:
            decision = self._decide(target)
        except Exception as exc:
            decision = GateDecision(
                _label(target), False,
                f"deny: gate error ({type(exc).__name__})", DENIED_ERROR,
            )
        try:
            audit(decision.target, decision.allowed, decision.reason)
        except Exception:
            return GateDecision(
                decision.target, False, "deny: audit logging failed", DENIED_AUDIT,
                decision.resolved_ips,
            )
        return decision

    def _decide(self, target: object) -> GateDecision:
        label = _label(target)
        if self._config_error is not None or self._limiter is None:
            return GateDecision(
                label, False,
                f"deny: engagement window/rate unusable ({self._config_error})",
                DENIED_LIMITS,
            )

        try:
            now = self._now()
        except Exception as exc:
            return GateDecision(
                label, False, f"deny: clock failed ({type(exc).__name__})", DENIED_WINDOW
            )
        in_window, why = evaluate_window(self._window, now)
        if not in_window:
            return GateDecision(label, False, why, DENIED_WINDOW)

        scope = check_scope(
            target,
            self._engagement.scope,
            resolver=self._pinner.resolve,  # resolve-once: cached per engagement (RC-23)
            audit=lambda t, a, r: None,  # the gate writes the one final entry
        )
        if not scope.allowed:
            return GateDecision(label, False, scope.reason, DENIED_SCOPE, scope.resolved_ips)

        admitted, retry_after = self._limiter.try_acquire()
        if not admitted:
            return GateDecision(
                label, False,
                f"deny: rate cap of {self._limiter.max_rps} rps exceeded "
                f"(retry after {retry_after:.3f}s)",
                DENIED_RATE, scope.resolved_ips, retry_after,
            )
        return GateDecision(
            label, True,
            f"{scope.reason}; {why}; within rate cap of {self._limiter.max_rps} rps",
            ALLOWED, scope.resolved_ips,
        )
