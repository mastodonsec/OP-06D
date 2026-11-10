"""Audit log (RC-11): the liability record.

One append-only JSONL file per engagement, keyed to the engagement ID from the
RC-6 model, so a client's trail is self-contained and handoverable as evidence.
The reporting layer (RC-17) reads it back with ``read_log``.

Each line is one ``AuditEntry``. Entries form a hash chain (``prev_hash`` ->
``hash``), so edits, deletions, reordering or truncation of earlier entries are
detectable with ``read_log`` / ``verify_log``. This is tamper-*evidence*, not
tamper-proofing: someone with write access can still rewrite the whole file.
Copy the log off-host or sign it at handover if that matters.

Fail-closed: any write failure raises ``AuditError`` and poisons the log
object so later writes also fail. The scope gate turns an audit error into a
deny, so an action that cannot be recorded cannot proceed.

Single writer: one ``AuditLog`` per engagement file per process. Concurrent
writers would break the chain, which verification then reports.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, ValidationError

from op06d.engagement import Engagement, is_valid_engagement_id
from op06d.redaction import scrub, scrub_text

# (target, allowed, reason) -> None. The scope gate depends only on this.
AuditSink = Callable[[str, bool, str], None]

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_TARGET_CHARS = 1024

EVENT_LOG_OPENED = "log_opened"
EVENT_GATE_DECISION = "gate_decision"
EVENT_INJECTION_FLAG = "injection_flag"
EVENT_ITERATION = "iteration"  # RC-7: the planner's proposal for one loop iteration
EVENT_APPROVAL = "approval"  # RC-8: operator approved/declined a higher-risk action
EVENT_LOOP_END = "loop_terminated"  # RC-7: why and when the loop stopped
# RC-23: a hostname's first (and only) resolution for this engagement - the
# resolve-once pin. Written once per hostname, never again, even if DNS for
# that name changes later in the same engagement.
EVENT_DNS_PINNED = "dns_pinned"
# RC-40 — LLM planner: wire a real model into the orchestrator and `op06d run`
EVENT_PLANNER_CONFIG = "planner_config"
# Events whose ``allowed`` flag is meaningful (an allow/deny or approve/decline).
_ALLOWED_EVENTS = frozenset({EVENT_GATE_DECISION, EVENT_APPROVAL})
EVENT_ACTION_EXECUTED = "action_executed"


class AuditError(Exception):
    """The audit log could not be written, read or verified."""


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    v: int
    seq: int
    ts: str  # UTC, ISO 8601, millisecond precision
    engagement: str
    event: str
    target: str | None  # repr() of the target, so hostile text cannot forge lines
    tool: str | None
    parameters: dict[str, Any]
    allowed: bool | None
    reason: str | None
    prev_hash: str
    hash: str


def _digest(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _body(entry: AuditEntry) -> dict[str, Any]:
    d = entry.model_dump()
    del d["hash"]
    return d


def read_log(path: str | Path) -> list[AuditEntry]:
    """Parse and verify a log. Raises ``AuditError`` on any malformed line,
    broken hash chain, or sequence gap."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise AuditError(f"cannot read audit log {p}: {exc}") from None
    entries: list[AuditEntry] = []
    prev = GENESIS_HASH
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()  # file ends with the newline after the last entry
    for n, line in enumerate(lines, start=1):
        try:
            entry = AuditEntry.model_validate_json(line)
        except ValidationError as exc:
            raise AuditError(f"{p}: line {n} is not a valid audit entry: {exc}") from None
        if entry.v != SCHEMA_VERSION:
            raise AuditError(f"{p}: line {n} has unsupported schema version {entry.v}")
        if entry.seq != n:
            raise AuditError(f"{p}: line {n} has seq {entry.seq} (entry missing or reordered)")
        if entry.prev_hash != prev:
            raise AuditError(f"{p}: line {n} breaks the hash chain")
        if _digest(_body(entry)) != entry.hash:
            raise AuditError(f"{p}: line {n} was modified (hash mismatch)")
        prev = entry.hash
        entries.append(entry)
    return entries


def verify_log(path: str | Path) -> int:
    """Verify a log's integrity; return the number of entries."""
    return len(read_log(path))


class AuditLog:
    """Append-only audit log for one engagement."""

    def __init__(
        self,
        path: str | Path,
        engagement_id: str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        # Second line of defense (RC-22): same shared rule the RC-6 schema
        # enforces at load, so a hand-built id can't escape the log directory.
        if not is_valid_engagement_id(engagement_id):
            raise AuditError(f"engagement id {engagement_id!r} is not safe to use in a log")
        self.path = Path(path)
        self.engagement_id = engagement_id
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._failed = False
        self._seq = 0
        self._prev = GENESIS_HASH
        if self.path.exists():
            existing = read_log(self.path)  # refuses to extend a corrupt log
            if any(e.engagement != engagement_id for e in existing):
                raise AuditError(f"{self.path} belongs to a different engagement")
            if existing:
                self._seq, self._prev = existing[-1].seq, existing[-1].hash

    @classmethod
    def for_engagement(
        cls,
        engagement: Engagement,
        log_dir: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> AuditLog:
        """Open (or resume) the log for an engagement and record that it was
        opened, with the authorization and scope in force. The file is
        ``<log_dir>/<engagement id>.audit.jsonl``."""
        directory = Path(log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        log = cls(directory / f"{engagement.engagement}.audit.jsonl",
                  engagement.engagement, clock=clock)
        log.record(
            EVENT_LOG_OPENED,
            parameters={
                "authorization": engagement.authorization.model_dump(mode="json"),
                "scope": engagement.scope.model_dump(mode="json"),
                "intensity": engagement.intensity.model_dump(mode="json"),
                "objective": engagement.objective,
            },
        )
        return log

    def record(
        self,
        event: str,
        *,
        target: object = None,
        tool: str | None = None,
        parameters: dict[str, Any] | None = None,
        allowed: bool | None = None,
        reason: str | None = None,
    ) -> AuditEntry:
        """Append one entry durably. Raises ``AuditError`` on any failure."""
        with self._lock:
            if self._failed:
                raise AuditError("audit log is unusable after an earlier write failure")
            try:
                entry = self._build(event, target, tool, parameters, allowed, reason)
                line = entry.model_dump_json().encode("utf-8") + b"\n"
                with open(self.path, "ab") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as exc:
                self._failed = True  # a partial line may exist; do not write past it
                raise AuditError(f"audit write failed: {type(exc).__name__}: {exc}") from None
            self._seq, self._prev = entry.seq, entry.hash
            return entry

    def _build(self, event, target, tool, parameters, allowed, reason) -> AuditEntry:
        # Round-trip through JSON so what is hashed is exactly what is stored.
        params = scrub(json.loads(json.dumps(parameters or {}, default=repr, sort_keys=True)))
        ts = self._clock().astimezone(timezone.utc).isoformat(timespec="milliseconds")
        fields: dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "seq": self._seq + 1,
            "ts": ts.replace("+00:00", "Z"),
            "engagement": self.engagement_id,
            "event": event,
            "target": None if target is None else scrub_text(_safe_repr(target)),
            "tool": scrub_text(tool) if isinstance(tool, str) else tool,
            "parameters": params,
            "allowed": allowed,
            "reason": scrub_text(reason) if isinstance(reason, str) else reason,
            "prev_hash": self._prev,
        }
        return AuditEntry(**fields, hash=_digest(fields))

    def sink(
        self,
        *,
        tool: str,
        parameters: dict[str, Any] | None = None,
        event: str = EVENT_GATE_DECISION,
    ) -> AuditSink:
        """An ``AuditSink`` bound to the action being gated. Pass it as the
        ``audit=`` argument of the gate; the gate never needs to know about
        tools or parameters.

        ``event`` selects the entry type. For gate decisions and approvals the
        ``allowed`` flag is stored; for any other event (e.g. an injection
        flag, RC-12) there is no allow/deny, so it is stored as null."""

        def write(target: str, allowed: bool, reason: str) -> None:
            self.record(
                event,
                target=target,
                tool=tool,
                parameters=parameters,
                allowed=allowed if event in _ALLOWED_EVENTS else None,
                reason=reason,
            )

        return write

    def record_dns_pin(self, hostname: str, resolved_ips: object) -> AuditEntry:
        """Record a hostname's resolve-once pin (RC-23): the first, and only,
        resolution of ``hostname`` for this engagement. Matches the
        ``PinAuditor`` shape ``DnsPinner`` expects, so it can be passed
        straight through as ``Gate(..., audit_pin=log.record_dns_pin)``.
        Raises ``AuditError`` on failure, same as any other write - letting
        that propagate (rather than swallowing it) is what makes an
        unrecorded pin deny the action instead of silently proceeding."""
        ips = list(resolved_ips) if isinstance(resolved_ips, (list, tuple)) else [resolved_ips]
        return self.record(
            EVENT_DNS_PINNED, target=hostname, parameters={"resolved_ips": ips},
            reason=f"pinned {hostname!r} -> {ips}",
        )

    def record_execution(
        self,
        *,
        tool: str,
        target: object,
        parameters: dict[str, Any] | None = None,
        status: str,
        detail: str | None = None,
    ) -> AuditEntry:
        """Record that an allowed action actually ran, and how it ended
        (``status`` e.g. "ok", "error", "timeout")."""
        return self.record(
            EVENT_ACTION_EXECUTED,
            target=target,
            tool=tool,
            parameters=parameters,
            reason=f"{status}: {detail}" if detail else status,
        )


def _safe_repr(value: object) -> str:
    text = repr(value)
    if len(text) > MAX_TARGET_CHARS:
        text = text[:MAX_TARGET_CHARS] + f"...[truncated {len(text) - MAX_TARGET_CHARS} chars]"
    return text
