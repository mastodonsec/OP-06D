# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RC-17 (op06d.report): build_report + render_markdown against
a real evidence store, covering the empty-run, determinism, redaction and
severity-ordering acceptance criteria."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from op06d.engagement import load_engagement
from op06d.evidence import EvidenceStore
from op06d.gate import ALLOWED, DENIED_SCOPE, GateDecision
from op06d.normalize import NormalizedResult, Provenance, normalize_nuclei
from op06d.report import SEVERITY_ORDER, build_report, render_markdown
from op06d.tools import ExecutionResult, Outcome, Risk, ToolAction

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)
CAPTURES = Path(__file__).parent.parent / "lab" / "captures"


def _allowed_decision(target: str, resolved_ips: tuple[str, ...] = ()) -> GateDecision:
    return GateDecision(target, True, "ok", ALLOWED, resolved_ips)


def _executed_result(
    tool: str, target: str, parameters: dict | None = None, *, resolved_ips: tuple[str, ...] = (),
) -> ExecutionResult:
    action = ToolAction(tool, target, parameters or {})
    decision = _allowed_decision(target, resolved_ips)
    return ExecutionResult(action, Outcome.EXECUTED, decision, True, "<raw/>", None, "ok", True, None, Risk.ACTIVE_RECON)


def _denied_result(tool: str, target: str, *, reason: str = "deny: out of scope") -> ExecutionResult:
    action = ToolAction(tool, target, {})
    decision = GateDecision(target, False, reason, DENIED_SCOPE)
    return ExecutionResult(action, Outcome.DENIED, decision, False, None, None, "", True, None, None)


def _declined_result(tool: str, target: str) -> ExecutionResult:
    action = ToolAction(tool, target, {})
    decision = GateDecision(target, False, "deny: operator approval not granted", "approval")
    return ExecutionResult(action, Outcome.DECLINED, decision, False, None, None, "", True, None, Risk.INTRUSIVE)


def _populate_with_real_findings(store: EvidenceStore) -> str:
    run_id = store.start_run(
        ENG, audit_log_path="/evidence/rc-lab.audit.jsonl",
        tool_versions={"nmap": "7.93", "nuclei": "v3.11.1", "templates_pin": "v10.5.1"},
    )
    allowed = _executed_result("nuclei", "juice-shop.lab", resolved_ips=("172.31.77.10",))
    action_id = store.record_action(run_id, allowed, iteration=1)

    denied = _denied_result("nmap", "1.1.1.1")
    store.record_action(run_id, denied, iteration=2)

    declined = _declined_result("nuclei", "dvwa.lab")
    store.record_action(run_id, declined, iteration=3)

    raw = json.loads((CAPTURES / "nuclei_juice-shop_3000.findings.json").read_text())
    found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
    store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))
    store.finish_run(run_id, status="completed", audit_log_sha256="cafebabe")
    return run_id


# --- populated run -------------------------------------------------------------

def test_report_from_real_findings_has_all_sections_grouped_and_counted(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = _populate_with_real_findings(store)
        reconstructed = store.reconstruct_run(run_id)

    report = build_report(reconstructed)

    assert report.header.engagement == ENG.engagement
    assert report.header.client == ENG.authorization.client
    assert report.executive_summary.total_findings == 4
    assert report.executive_summary.assets_tested == 1  # only the allowed action executed
    counts = {c.severity: c.count for c in report.executive_summary.severity_counts}
    assert counts["info"] == 4
    assert counts["critical"] == 0

    assert report.scope.in_scope == ENG.scope.in_scope
    assert report.scope.out_of_scope == ENG.scope.out_of_scope

    assert "nmap 7.93" in report.methodology.tools
    assert "nuclei v3.11.1 (templates v10.5.1)" in report.methodology.tools

    assert report.findings.total == 4
    assert len(report.findings.groups) == 1
    assert report.findings.groups[0].severity == "info"
    assert len(report.findings.groups[0].findings) == 4

    assert len(report.audit_trail.actions) == 3
    assert report.audit_trail.audit_log_sha256 == "cafebabe"

    markdown = render_markdown(report)
    assert "# Security Assessment Report" in markdown
    assert "## Executive Summary" in markdown
    assert "## Scope" in markdown
    assert "## Methodology" in markdown
    assert "## Findings" in markdown
    assert "## Assessment Activity" in markdown
    assert "## Limitations & Notes" in markdown
    for f in reconstructed.findings:
        assert f.finding_id in markdown
        assert f.title in markdown


# --- empty run -----------------------------------------------------------------

def test_empty_run_still_produces_a_valid_coherent_report(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG, tool_versions={"nmap": "7.93"})
        store.record_action(run_id, _executed_result("nmap", "172.31.77.11"), iteration=1)
        store.record_action(run_id, _denied_result("nmap", "1.1.1.1"), iteration=2)
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    report = build_report(reconstructed)
    assert report.executive_summary.total_findings == 0
    assert report.findings.total == 0
    assert report.findings.groups == []
    assert "no findings" in report.executive_summary.headline.lower()

    markdown = render_markdown(report)
    # every section still renders
    for heading in ("## Executive Summary", "## Scope", "## Methodology", "## Findings",
                     "## Assessment Activity", "## Limitations & Notes"):
        assert heading in markdown
    assert "No findings were recorded" in markdown


# --- an incomplete nmap scan is disclosed (RC-43) --------------------------------

def test_an_nmap_host_timeout_is_listed_under_limitations(tmp_path):
    from op06d.nmap_tool import NmapTool
    from op06d.normalize import normalize_execution_result
    from op06d.tools import ProcessResult

    xml = (Path(__file__).parent / "fixtures" / "nmap_host_timeout.xml").read_bytes()
    tool = NmapTool(5, runner=lambda argv, timeout: ProcessResult(0, xml, b""), which=lambda n: "/usr/bin/nmap")
    out = tool.run("192.0.2.10", {"profile": "service"})
    assert out.status == "host_timeout"
    action = ToolAction("nmap", "192.0.2.10", {"profile": "service"})
    result = ExecutionResult(action, Outcome.TOOL_ERROR, _allowed_decision("192.0.2.10"), True, out.raw, None,
                             out.status, True, out.findings, Risk.ACTIVE_RECON)

    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG, tool_versions={"nmap": "7.93"})
        action_id = store.record_action(run_id, result, iteration=1)
        store.record_findings(run_id, action_id, normalize_execution_result(result, engagement=ENG.engagement))
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    report = build_report(reconstructed)
    assert report.findings.total == 0
    kinds = [i.kind for i in report.limitations.issues]
    assert "nmap_degraded" in kinds and "host_timeout" in kinds

    markdown = render_markdown(report)
    limitations = markdown.split("## Limitations & Notes", 1)[1]
    assert "**nmap_degraded:**" in limitations and "**host_timeout:**" in limitations
    assert "192.0.2.10" in limitations and "host-timeout 710s" in limitations
    assert "the absence of findings does not mean no ports are open" in limitations
    assert "No normalization issues" not in markdown


# --- refused actions appear with reason ----------------------------------------

def test_denied_and_declined_actions_appear_in_audit_trail_with_reason(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        store.record_action(run_id, _denied_result("nmap", "1.1.1.1", reason="deny: out of scope test reason"), iteration=1)
        store.record_action(run_id, _declined_result("nuclei", "dvwa.lab"), iteration=2)
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    report = build_report(reconstructed)
    outcomes = {a.outcome for a in report.audit_trail.actions}
    assert outcomes == {"denied", "declined"}

    markdown = render_markdown(report)
    assert "deny: out of scope test reason" in markdown
    assert "deny: operator approval not granted" in markdown
    assert "denied" in markdown
    assert "declined" in markdown


# --- determinism ----------------------------------------------------------------

def test_rendering_the_same_run_twice_is_byte_identical(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = _populate_with_real_findings(store)
        reconstructed = store.reconstruct_run(run_id)

    report_a = build_report(reconstructed)
    report_b = build_report(reconstructed)
    assert render_markdown(report_a) == render_markdown(report_b)

    # and rendering the same already-built Report object twice
    md1 = render_markdown(report_a)
    md2 = render_markdown(report_a)
    assert md1 == md2


# --- redaction -------------------------------------------------------------------

def test_redacted_secret_never_appears_in_rendered_markdown(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        secret_result = _executed_result("nuclei", "dvwa.lab", {"api_token": "sk-super-secret-value"})
        store.record_action(run_id, secret_result, iteration=1)
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    assert reconstructed.actions[0].parameters_redacted["api_token"] == "[REDACTED]"

    report = build_report(reconstructed)
    markdown = render_markdown(report)
    assert "sk-super-secret-value" not in markdown
    # the report doesn't even surface raw parameters at all
    assert "api_token" not in markdown


# --- severity ordering -----------------------------------------------------------

def _synthetic_finding(template_id: str, severity: str, host: str = "dvwa.lab", ip: str = "172.31.77.11") -> dict:
    return {
        "template_id": template_id, "name": template_id, "host": host,
        "matched_at": f"http://{host}", "ip": ip, "severity": severity, "tags": ["tech"],
    }


def test_findings_are_grouped_and_ordered_critical_to_info(tmp_path):
    raw = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": [
            _synthetic_finding("low-one", "low"),
            _synthetic_finding("critical-one", "critical"),
            _synthetic_finding("info-one", "info"),
            _synthetic_finding("high-one", "high"),
            _synthetic_finding("medium-one", "medium"),
        ],
        "summary": {"findings": 5, "off_target": 0, "unparsed_lines": 0},
    }
    found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))

    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        action_id = store.record_action(run_id, _executed_result("nuclei", "dvwa.lab"), iteration=1)
        store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    report = build_report(reconstructed)
    severities_in_order = [g.severity for g in report.findings.groups]
    assert severities_in_order == [s for s in SEVERITY_ORDER if s in severities_in_order]
    assert severities_in_order == ["critical", "high", "medium", "low", "info"]

    markdown = render_markdown(report)
    assert markdown.index("critical-one") < markdown.index("high-one") < markdown.index(
        "medium-one"
    ) < markdown.index("low-one") < markdown.index("info-one")
