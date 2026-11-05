"""Minimal audit stub (placeholder until RC-11).

RC-11 replaces this with the real, persistent audit log. The only contract the
scope gate depends on is the ``AuditSink`` signature below, so swapping the
implementation does not touch the scope logic.
"""

from __future__ import annotations

import logging
from typing import Callable

# (target, allowed, reason) -> None
AuditSink = Callable[[str, bool, str], None]

logger = logging.getLogger("redcell.audit")


def log_decision(target: str, allowed: bool, reason: str) -> None:
    """Record one scope decision. ``target`` is logged via repr() so hostile
    input (newlines, control characters) cannot forge log lines."""
    logger.log(
        logging.INFO if allowed else logging.WARNING,
        "scope decision=%s target=%s reason=%s",
        "ALLOW" if allowed else "DENY",
        repr(target)[:200],
        reason,
    )
