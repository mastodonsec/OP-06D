# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RC-16 (op06d.evidence): round-trip reconstruction, redaction,
concurrency, schema idempotency, and foreign-key cascade."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from op06d.engagement import load_engagement
from op06d.evidence import EvidenceError, EvidenceStore
from op06d.gate import ALLOWED, DENIED_SCOPE, GateDecision
from op06d.normalize import Provenance, normalize_nuclei
from op06d.tools import ExecutionResult, Outcome, Risk, ToolAction

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)
CAPTURES = Path(__file__).parent.parent / "lab" / "captures"


def _allowed_decision(target: str, resolved_ips: tuple[str, ...] = ()) -> GateDecision:
    return GateDecision(target, True, "ok", ALLOWED, resolved_ips)


def _denied_decision(target: str, reason: str = "deny: out of scope") -> GateDecision:
    return GateDecision(target, False, reason, DENIED_SCOPE)


def _executed_result(
    tool: str, target: str, parameters: dict | None = None, *, findings: object = None,
    raw_output: object = "<raw/>", resolved_ips: tuple[str, ...] = (),
) -> ExecutionResult:
    action = ToolAction(tool, target, parameters or {})
    decision = _allowed_decision(target, resolved_ips)
    return ExecutionResult(
        action, Outcome.EXECUTED, decision, True, raw_output, None, "ok", True, findings, Risk.ACTIVE_RECON,
    )


def _denied_result(tool: str, target: str, parameters: dict | None = None) -> ExecutionResult:
    action = ToolAction(tool, target, parameters or {})
    decision = _denied_decision(target)
    return ExecutionResult(action, Outcome.DENIED, decision, False, None, None, "", True, None, None)


def _declined_result(tool: str, target: str) -> ExecutionResult:
    action = ToolAction(tool, target, {})
    decision = GateDecision(target, False, "deny: operator approval not granted", "approval")
    return ExecutionResult(action, Outcome.DECLINED, decision, False, None, None, "", True, None, Risk.INTRUSIVE)


# --- round-trip reconstruction -------------------------------------------------

def test_reconstruct_run_round_trips_allowed_denied_and_declined_actions(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG, audit_log_path="/some/audit.jsonl", tool_versions={"nmap": "7.93"})

        allowed = _executed_result("nmap", "172.31.77.11", {"profile": "service"})
        allowed_id = store.record_action(run_id, allowed, iteration=1)

        denied = _denied_result("nmap", "1.1.1.1")
        denied_id = store.record_action(run_id, denied, iteration=2)

        declined = _declined_result("nuclei", "dvwa.lab")
        declined_id = store.record_action(run_id, declined, iteration=3)

        nuclei_findings = json.loads((CAPTURES / "nuclei_dvwa_default.findings.json").read_text())
        found, issues = normalize_nuclei(
            nuclei_findings, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"),
        )
        from op06d.normalize import NormalizedResult
        store.record_findings(run_id, allowed_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))

        store.finish_run(run_id, status="completed", audit_log_sha256="deadbeef")

        rebuilt = store.reconstruct_run(run_id)

    assert rebuilt.run.run_id == run_id
    assert rebuilt.run.engagement == ENG.engagement
    assert rebuilt.run.status == "completed"
    assert rebuilt.run.audit_log_sha256 == "deadbeef"
    assert rebuilt.run.audit_log_path == "/some/audit.jsonl"
    assert rebuilt.run.tool_versions == {"nmap": "7.93"}

    by_id = {a.action_id: a for a in rebuilt.actions}
    assert set(by_id) == {allowed_id, denied_id, declined_id}
    assert by_id[allowed_id].executed is True
    assert by_id[allowed_id].gate_stage == ALLOWED
    assert by_id[denied_id].executed is False
    assert by_id[denied_id].gate_allowed is False
    assert by_id[denied_id].gate_reason == "deny: out of scope"
    assert by_id[denied_id].outcome == "denied"
    assert by_id[declined_id].executed is False
    assert by_id[declined_id].outcome == "declined"
    assert by_id[declined_id].gate_reason == "deny: operator approval not granted"

    assert len(rebuilt.findings) == 3
    assert all(f.action_id == allowed_id for f in rebuilt.findings)
    assert len(rebuilt.issues) == 0


# --- RC-15 findings recorded + queried by severity/category -------------------

def test_findings_from_real_rc15_output_are_queryable_by_severity_and_category(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        result = _executed_result("nuclei", "juice-shop.lab", resolved_ips=("172.31.77.10",))
        action_id = store.record_action(run_id, result)

        raw = json.loads((CAPTURES / "nuclei_juice-shop_3000.findings.json").read_text())
        found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
        from op06d.normalize import NormalizedResult
        store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))

        all_findings = store.list_findings(run_id)
        assert len(all_findings) == 4

        exposure = store.list_findings(run_id, category="exposure")
        assert {f.finding_id for f in exposure} == {f.finding_id for f in found if f.category.value == "exposure"}

        info = store.list_findings(run_id, severity="info")
        assert len(info) == 4

        none_critical = store.list_findings(run_id, severity="critical")
        assert none_critical == []


# --- redaction ------------------------------------------------------------------

def test_action_parameters_are_redacted_never_the_raw_secret(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        result = _executed_result("nuclei", "dvwa.lab", {"api_token": "sk-super-secret-value"})
        action_id = store.record_action(run_id, result)
        action = store.list_actions(run_id)[0]

    assert action.action_id == action_id
    assert action.parameters_redacted["api_token"] == "[REDACTED]"
    assert "sk-super-secret-value" not in json.dumps(action.parameters_redacted)


def test_denied_action_parameters_are_also_redacted(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        result = _denied_result("nuclei", "1.1.1.1", {"password": "hunter2"})
        store.record_action(run_id, result)
        action = store.list_actions(run_id)[0]

    assert action.parameters_redacted["password"] == "[REDACTED]"


def test_no_secret_reaches_the_raw_sqlite_file(tmp_path):
    db_path = tmp_path / "evidence.db"
    with EvidenceStore.open(db_path) as store:
        run_id = store.start_run(ENG)
        result = _executed_result("nuclei", "dvwa.lab", {"bearer_token": "tok-abc-123-do-not-leak"})
        store.record_action(run_id, result)

    raw_bytes = db_path.read_bytes()
    assert b"tok-abc-123-do-not-leak" not in raw_bytes


# --- concurrency -----------------------------------------------------------------

def test_concurrent_writers_do_not_corrupt_the_store_and_all_rows_land(tmp_path):
    db_path = tmp_path / "evidence.db"
    with EvidenceStore.open(db_path) as store:
        run_id = store.start_run(ENG)

    n_threads = 8
    actions_per_thread = 5
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            store = EvidenceStore(db_path)
            for j in range(actions_per_thread):
                result = _executed_result("nmap", f"172.31.77.{10 + (i % 2)}", {"iter": f"{i}-{j}"})
                store.record_action(run_id, result, iteration=i * 100 + j)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == []
    store = EvidenceStore(db_path)
    actions = store.list_actions(run_id)
    assert len(actions) == n_threads * actions_per_thread
    assert len({a.action_id for a in actions}) == n_threads * actions_per_thread


# --- schema idempotency -----------------------------------------------------------

def test_opening_an_existing_store_twice_is_a_noop_and_keeps_data(tmp_path):
    db_path = tmp_path / "evidence.db"
    with EvidenceStore.open(db_path) as store:
        run_id = store.start_run(ENG)
        store.record_action(run_id, _executed_result("nmap", "172.31.77.11"))

    with EvidenceStore.open(db_path) as store2:
        runs = store2.list_runs()
        actions = store2.list_actions(run_id)

    assert len(runs) == 1
    assert len(actions) == 1


# --- foreign keys / cascade ---------------------------------------------------------

def test_deleting_a_run_cascades_to_actions_findings_and_issues(tmp_path):
    db_path = tmp_path / "evidence.db"
    with EvidenceStore.open(db_path) as store:
        run_id = store.start_run(ENG)
        action_id = store.record_action(run_id, _executed_result("nuclei", "dvwa.lab"))
        raw = json.loads((CAPTURES / "nuclei_dvwa_default.findings.json").read_text())
        found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
        from op06d.normalize import NormalizedResult
        store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))

        with store._connect() as conn:
            conn.execute("DELETE FROM runs WHERE run_id=?", (run_id,))
            conn.commit()

        assert store.get_run(run_id) is None
        assert store.list_actions(run_id) == []
        assert store.list_findings(run_id) == []
        assert store.list_issues(run_id) == []


# --- misc guards -----------------------------------------------------------------

def test_finish_run_on_unknown_run_raises():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        with EvidenceStore.open(Path(d) / "evidence.db") as store:
            with pytest.raises(EvidenceError):
                store.finish_run("does-not-exist", status="completed")


def test_record_findings_upserts_on_run_and_finding_id_not_duplicate(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        action_id = store.record_action(run_id, _executed_result("nuclei", "dvwa.lab"))
        raw = json.loads((CAPTURES / "nuclei_dvwa_default.findings.json").read_text())
        found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
        from op06d.normalize import NormalizedResult
        normalized = NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance)

        store.record_findings(run_id, action_id, normalized)
        store.record_findings(run_id, action_id, normalized)  # re-recording must upsert, not duplicate

        assert len(store.list_findings(run_id)) == len(found)
