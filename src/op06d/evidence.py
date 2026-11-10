# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-16: the evidence store - a queryable index for one or more runs.

**Role (read this first).** This is NOT a second source of truth. The RC-11
audit log (``op06d.audit.AuditLog``: append-only, hash-chained JSONL)
remains the tamper-evident liability record. This store only *references*
that log - ``runs.audit_log_path`` / ``runs.audit_log_sha256`` - and is
itself rebuildable from the audit log plus the RC-15 normalized findings. Its
job is reporting-shaped queries: list a run's actions, filter findings by
severity/category, reconstruct a whole run as one nested object for the
report generator (RC-17/18). Nothing here ever supersedes what the audit log
says happened.

Inputs, already built by earlier tickets:

* ``op06d.tools.ExecutionResult`` (RC-7/8) - one action.
* ``op06d.normalize.NormalizedResult`` / ``Finding`` (RC-15) - the
  findings + issues produced from one action's output.
* ``op06d.engagement.Engagement`` (RC-6) - the run's authorization, scope
  and intensity.

Storage: SQLite (stdlib ``sqlite3``), WAL journal mode, ``foreign_keys=ON``,
every write inside a transaction (``BEGIN IMMEDIATE`` so a writer queues
rather than racing another writer). No external dependency.

Redaction: action parameters are stored through the same
``op06d.tools.redact_parameters`` the toolbox and the audit log use - a
secret must never reach this database, including for denied/declined
actions.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel, ConfigDict

from op06d.engagement import Engagement
from op06d.normalize import NormalizedResult
from op06d.redaction import scrub
from op06d.sanitize import sha256_of
from op06d.tools import ExecutionResult, redact_parameters

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id              TEXT PRIMARY KEY,
    engagement          TEXT NOT NULL,
    client              TEXT NOT NULL,
    signed_scope_ref    TEXT NOT NULL,
    authorized_by       TEXT NOT NULL,
    window_start        TEXT NOT NULL,
    window_end          TEXT NOT NULL,
    scope_json          TEXT NOT NULL,
    intensity_json      TEXT NOT NULL,
    objective           TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    status              TEXT NOT NULL,
    tool_versions_json  TEXT NOT NULL,
    audit_log_path      TEXT,
    audit_log_sha256    TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    action_id                  TEXT PRIMARY KEY,
    run_id                     TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    iteration                  INTEGER,
    tool                       TEXT NOT NULL,
    target                     TEXT NOT NULL,
    parameters_redacted_json   TEXT NOT NULL,
    gate_stage                 TEXT NOT NULL,
    gate_allowed               INTEGER NOT NULL,
    gate_reason                TEXT NOT NULL,
    risk                       TEXT,
    outcome                    TEXT NOT NULL,
    status                     TEXT,
    resolved_ips_json          TEXT NOT NULL,
    scanned_ip                 TEXT,
    raw_sha256                 TEXT,
    sanitized_sha256           TEXT,
    executed                   INTEGER NOT NULL,
    observed_at                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id);

CREATE TABLE IF NOT EXISTS findings (
    finding_pk      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    action_id       TEXT NOT NULL REFERENCES actions(action_id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL,
    source_tool     TEXT NOT NULL,
    category        TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    hostname        TEXT,
    ip              TEXT,
    port            INTEGER,
    protocol        TEXT,
    scheme          TEXT,
    description     TEXT,
    evidence_json   TEXT NOT NULL,
    references_json TEXT NOT NULL,
    cve_json        TEXT NOT NULL,
    cvss_score      REAL,
    tags_json       TEXT NOT NULL,
    raw_sha256      TEXT,
    UNIQUE(run_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run_severity ON findings(run_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_run_category ON findings(run_id, category);

CREATE TABLE IF NOT EXISTS issues (
    issue_pk    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    action_id   TEXT REFERENCES actions(action_id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL,
    raw_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_issues_run ON issues(run_id);

CREATE TABLE IF NOT EXISTS run_planner (
    run_id        TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    planner_json  TEXT NOT NULL
);
"""


class EvidenceError(Exception):
    """The evidence store could not be read or written as requested."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _loads(text: str | None, default: object) -> object:
    if text is None:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RunRow(_Frozen):
    run_id: str
    engagement: str
    client: str
    signed_scope_ref: str
    authorized_by: str
    window_start: str
    window_end: str
    scope: dict[str, Any]
    intensity: dict[str, Any]
    objective: str
    started_at: str
    ended_at: str | None = None
    status: str
    tool_versions: dict[str, Any]
    audit_log_path: str | None = None
    audit_log_sha256: str | None = None


class ActionRow(_Frozen):
    action_id: str
    run_id: str
    iteration: int | None = None
    tool: str
    target: str
    parameters_redacted: dict[str, Any]
    gate_stage: str
    gate_allowed: bool
    gate_reason: str
    risk: str | None = None
    outcome: str
    status: str | None = None
    resolved_ips: list[str]
    scanned_ip: str | None = None
    raw_sha256: str | None = None
    sanitized_sha256: str | None = None
    executed: bool
    observed_at: str


class FindingRow(_Frozen):
    finding_pk: int
    run_id: str
    action_id: str
    finding_id: str
    source_tool: str
    category: str
    title: str
    severity: str
    hostname: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    scheme: str | None = None
    description: str | None = None
    evidence: dict[str, Any]
    references: list[str]
    cve: list[str]
    cvss_score: float | None = None
    tags: list[str]
    raw_sha256: str | None = None


class IssueRow(_Frozen):
    issue_pk: int
    run_id: str
    action_id: str | None = None
    kind: str
    detail: str
    raw: Any = None


class ReconstructedRun(_Frozen):
    run: RunRow
    actions: list[ActionRow]
    findings: list[FindingRow]
    issues: list[IssueRow]
    planner: dict[str, Any] | None = None


def _run_row(row: sqlite3.Row) -> RunRow:
    return RunRow(
        run_id=row["run_id"], engagement=row["engagement"], client=row["client"],
        signed_scope_ref=row["signed_scope_ref"], authorized_by=row["authorized_by"],
        window_start=row["window_start"], window_end=row["window_end"],
        scope=_loads(row["scope_json"], {}), intensity=_loads(row["intensity_json"], {}),
        objective=row["objective"], started_at=row["started_at"], ended_at=row["ended_at"],
        status=row["status"], tool_versions=_loads(row["tool_versions_json"], {}),
        audit_log_path=row["audit_log_path"], audit_log_sha256=row["audit_log_sha256"],
    )


def _action_row(row: sqlite3.Row) -> ActionRow:
    return ActionRow(
        action_id=row["action_id"], run_id=row["run_id"], iteration=row["iteration"],
        tool=row["tool"], target=row["target"],
        parameters_redacted=_loads(row["parameters_redacted_json"], {}),
        gate_stage=row["gate_stage"], gate_allowed=bool(row["gate_allowed"]),
        gate_reason=row["gate_reason"], risk=row["risk"], outcome=row["outcome"],
        status=row["status"], resolved_ips=_loads(row["resolved_ips_json"], []),
        scanned_ip=row["scanned_ip"], raw_sha256=row["raw_sha256"],
        sanitized_sha256=row["sanitized_sha256"], executed=bool(row["executed"]),
        observed_at=row["observed_at"],
    )


def _finding_row(row: sqlite3.Row) -> FindingRow:
    return FindingRow(
        finding_pk=row["finding_pk"], run_id=row["run_id"], action_id=row["action_id"],
        finding_id=row["finding_id"], source_tool=row["source_tool"], category=row["category"],
        title=row["title"], severity=row["severity"], hostname=row["hostname"], ip=row["ip"],
        port=row["port"], protocol=row["protocol"], scheme=row["scheme"],
        description=row["description"], evidence=_loads(row["evidence_json"], {}),
        references=_loads(row["references_json"], []), cve=_loads(row["cve_json"], []),
        cvss_score=row["cvss_score"], tags=_loads(row["tags_json"], []),
        raw_sha256=row["raw_sha256"],
    )


def _issue_row(row: sqlite3.Row) -> IssueRow:
    return IssueRow(
        issue_pk=row["issue_pk"], run_id=row["run_id"], action_id=row["action_id"],
        kind=row["kind"], detail=row["detail"], raw=_loads(row["raw_json"], None),
    )


class EvidenceStore:
    """One SQLite file. Every public method opens its own short-lived
    connection (WAL + a busy timeout), so concurrent callers - even from
    different threads - serialize safely on the one writer instead of
    sharing a single ``sqlite3.Connection`` across threads (which the
    ``sqlite3`` module does not make safe on its own)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._ensure_schema()

    @classmethod
    @contextmanager
    def open(cls, path: str | Path) -> Iterator["EvidenceStore"]:
        """Context manager; creates the schema if absent (idempotent)."""
        store = cls(path)
        yield store

    # -- connection management -------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def _ensure_schema(self) -> None:
        # executescript() manages its own transaction (and commits any
        # pending one first), so it runs on a plain connection, not inside
        # our explicit BEGIN IMMEDIATE/COMMIT wrapper in ``_write``.
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    # -- writes ------------------------------------------------------------

    def start_run(
        self,
        engagement: Engagement,
        *,
        audit_log_path: str | Path | None = None,
        tool_versions: dict[str, str] | None = None,
        clock: Any = None,
    ) -> str:
        """Write the run row from the engagement + a fresh uuid. Returns the
        new ``run_id`` (never the engagement id - one engagement may be run
        more than once)."""
        run_id = str(uuid.uuid4())
        started_at = _iso((clock or _utcnow)())
        auth = engagement.authorization
        window_start, window_end = auth.window
        with self._write() as conn:
            conn.execute(
                "INSERT INTO runs (run_id, engagement, client, signed_scope_ref, authorized_by, "
                "window_start, window_end, scope_json, intensity_json, objective, started_at, "
                "ended_at, status, tool_versions_json, audit_log_path, audit_log_sha256) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                scrub((
                    run_id, engagement.engagement, auth.client, auth.signed_scope_ref,
                    auth.authorized_by, _iso(window_start), _iso(window_end),
                    json.dumps(engagement.scope.model_dump(mode="json")),
                    json.dumps(engagement.intensity.model_dump(mode="json")),
                    engagement.objective, started_at, None, "running",
                    json.dumps(tool_versions or {}), str(audit_log_path) if audit_log_path else None,
                    None,
                )),
            )
        return run_id

    def record_action(
        self, run_id: str, result: ExecutionResult, *, iteration: int | None = None,
        observed_at: str | None = None,
    ) -> str:
        """One row per ``ExecutionResult``, allowed or not. Parameters are
        stored only through ``redact_parameters`` - never the raw value."""
        action = getattr(result, "action", None)
        tool = getattr(action, "tool", "") or ""
        target = getattr(action, "target", "") or ""
        parameters = getattr(action, "parameters", None) or {}
        decision = result.decision
        action_id = str(uuid.uuid4())
        observed = observed_at or _iso(_utcnow())
        raw_sha256 = sha256_of(result.raw_output) if result.raw_output is not None else None
        sanitized_sha256 = getattr(result.sanitized, "sha256", None) if result.sanitized is not None else None
        risk = result.risk.name if result.risk is not None else None
        with self._write() as conn:
            conn.execute(
                "INSERT INTO actions (action_id, run_id, iteration, tool, target, "
                "parameters_redacted_json, gate_stage, gate_allowed, gate_reason, risk, outcome, "
                "status, resolved_ips_json, scanned_ip, raw_sha256, sanitized_sha256, executed, "
                "observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                scrub((
                    action_id, run_id, iteration, str(tool), str(target),
                    json.dumps(redact_parameters(parameters), default=repr),
                    decision.stage, int(decision.allowed), decision.reason, risk,
                    result.outcome.value, result.status or None,
                    json.dumps(list(decision.resolved_ips)),
                    decision.resolved_ips[0] if decision.resolved_ips else None,
                    raw_sha256, sanitized_sha256, int(result.executed), observed,
                )),
            )
        return action_id

    def record_findings(self, run_id: str, action_id: str, normalized: NormalizedResult) -> None:
        """Upserts findings on ``(run_id, finding_id)`` (RC-15 ids make this
        safe - re-recording the same logical finding never duplicates it),
        and appends the issues as-is."""
        with self._write() as conn:
            for f in normalized.findings:
                conn.execute(
                    "INSERT INTO findings (run_id, action_id, finding_id, source_tool, category, "
                    "title, severity, hostname, ip, port, protocol, scheme, description, "
                    "evidence_json, references_json, cve_json, cvss_score, tags_json, raw_sha256) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(run_id, finding_id) DO UPDATE SET "
                    "action_id=excluded.action_id, source_tool=excluded.source_tool, "
                    "category=excluded.category, title=excluded.title, severity=excluded.severity, "
                    "hostname=excluded.hostname, ip=excluded.ip, port=excluded.port, "
                    "protocol=excluded.protocol, scheme=excluded.scheme, "
                    "description=excluded.description, evidence_json=excluded.evidence_json, "
                    "references_json=excluded.references_json, cve_json=excluded.cve_json, "
                    "cvss_score=excluded.cvss_score, tags_json=excluded.tags_json, "
                    "raw_sha256=excluded.raw_sha256",
                    scrub((
                        run_id, action_id, f.finding_id, f.source_tool, f.category.value, f.title,
                        f.severity.value, f.asset.hostname, f.asset.ip, f.asset.port,
                        f.asset.protocol, f.asset.scheme, f.description,
                        json.dumps(f.evidence, default=repr), json.dumps(f.references),
                        json.dumps(f.cve), f.cvss_score, json.dumps(f.tags),
                        f.provenance.raw_sha256,
                    )),
                )
            for issue in normalized.issues:
                conn.execute(
                    "INSERT INTO issues (run_id, action_id, kind, detail, raw_json) "
                    "VALUES (?,?,?,?,?)",
                    scrub((
                        run_id, action_id, issue.kind, issue.detail,
                        json.dumps(issue.raw, default=repr) if issue.raw is not None else None,
                    )),
                )

    def record_planner(self, run_id: str, planner: dict[str, Any]) -> None:
        """Store (or replace) the planner metadata for a run."""
        payload = json.dumps(scrub(planner), default=repr, sort_keys=True)
        with self._write() as conn:
            conn.execute(
                "INSERT INTO run_planner (run_id, planner_json) VALUES (?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET planner_json=excluded.planner_json",
                (run_id, payload),
            )

    def get_planner(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT planner_json FROM run_planner WHERE run_id=?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        value = _loads(row["planner_json"], None)
        return value if isinstance(value, dict) else None

    def finish_run(self, run_id: str, *, status: str, audit_log_sha256: str | None = None) -> None:
        ended_at = _iso(_utcnow())
        with self._write() as conn:
            cur = conn.execute(
                "UPDATE runs SET ended_at=?, status=?, "
                "audit_log_sha256=COALESCE(?, audit_log_sha256) WHERE run_id=?",
                (ended_at, status, audit_log_sha256, run_id),
            )
            if cur.rowcount == 0:
                raise EvidenceError(f"no such run {run_id!r}")

    # -- queries -------------------------------------------------------------

    def get_run(self, run_id: str) -> RunRow | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return _run_row(row) if row is not None else None

    def list_runs(self) -> list[RunRow]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY started_at").fetchall()
        return [_run_row(r) for r in rows]

    def list_actions(self, run_id: str) -> list[ActionRow]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE run_id=? ORDER BY observed_at, action_id", (run_id,)
            ).fetchall()
        return [_action_row(r) for r in rows]

    def list_findings(
        self, run_id: str, *, severity: str | None = None, category: str | None = None,
    ) -> list[FindingRow]:
        query = "SELECT * FROM findings WHERE run_id=?"
        params: list[Any] = [run_id]
        if severity is not None:
            query += " AND severity=?"
            params.append(severity)
        if category is not None:
            query += " AND category=?"
            params.append(category)
        query += " ORDER BY finding_pk"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_finding_row(r) for r in rows]

    def list_issues(self, run_id: str) -> list[IssueRow]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM issues WHERE run_id=? ORDER BY issue_pk", (run_id,)).fetchall()
        return [_issue_row(r) for r in rows]

    def reconstruct_run(self, run_id: str) -> ReconstructedRun:
        """The whole run as one nested object: run + every action, finding
        and issue it produced - what the report generator (RC-17/18) reads."""
        run = self.get_run(run_id)
        if run is None:
            raise EvidenceError(f"no such run {run_id!r}")
        return ReconstructedRun(
            run=run, actions=self.list_actions(run_id), findings=self.list_findings(run_id),
            issues=self.list_issues(run_id), planner=self.get_planner(run_id),
        )
