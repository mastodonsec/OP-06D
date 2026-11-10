# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`

Value-based secret scrubbing shared by the audit log, the evidence store and
the toolbox's parameter redaction. Registered secrets and anything shaped like
an Anthropic API key are replaced with ``REDACTED`` wherever they appear in a
string, at any depth of a dict/list/tuple.
"""

from __future__ import annotations

import re
import threading
from typing import Any

REDACTED = "[REDACTED]"
MIN_SECRET_CHARS = 8

_KEY_SHAPE_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")

_lock = threading.Lock()
_registered: frozenset[str] = frozenset()


def register_secret(value: object) -> None:
    """Add ``value`` to the process-wide set of strings that are always scrubbed."""
    global _registered
    if not isinstance(value, str) or len(value) < MIN_SECRET_CHARS:
        return
    with _lock:
        _registered = _registered | {value}


def clear_registered_secrets() -> None:
    global _registered
    with _lock:
        _registered = frozenset()


def scrub_text(text: str) -> str:
    for secret in sorted(_registered, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, REDACTED)
    return _KEY_SHAPE_RE.sub(REDACTED, text)


def scrub(value: Any, _depth: int = 0) -> Any:
    """A copy of ``value`` with every secret occurrence replaced."""
    if isinstance(value, str):
        return scrub_text(value)
    if _depth > 32:
        return value
    if isinstance(value, dict):
        return {
            (scrub_text(k) if isinstance(k, str) else k): scrub(v, _depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(v, _depth + 1) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub(v, _depth + 1) for v in value)
    return value
