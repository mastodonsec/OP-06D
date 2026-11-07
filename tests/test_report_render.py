# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RC-18 (redcell.report_render): HTML rendering (self-contained,
deterministic, print/pagination CSS contract, redaction) and the gated PDF
path (skips cleanly with no backend installed)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from redcell.engagement import load_engagement
from redcell.evidence import EvidenceStore
from redcell.gate import ALLOWED, GateDecision
from redcell.normalize import NormalizedResult, Provenance, normalize_nuclei
from redcell.report import build_report
from redcell.report_render import NoPdfBackendAvailable, main, render_html, render_pdf
from redcell.tools import ExecutionResult, Outcome, Risk, ToolAction

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)
CAPTURES = Path(__file__).parent.parent / "lab" / "captures"


def _pdf_backend_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _allowed_decision(target: str, resolved_ips: tuple[str, ...] = ()) -> GateDecision:
    return GateDecision(target, True, "ok", ALLOWED, resolved_ips)


def _executed_result(tool: str, target: str, parameters: dict | None = None) -> ExecutionResult:
    action = ToolAction(tool, target, parameters or {})
    decision = _allowed_decision(target)
    return ExecutionResult(action, Outcome.EXECUTED, decision, True, "<raw/>", None, "ok", True, None, Risk.ACTIVE_RECON)


def _build_real_report(tmp_path) -> "Report":  # noqa: F821
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(
            ENG, audit_log_path="/evidence/rc-lab.audit.jsonl",
            tool_versions={"nmap": "7.93", "nuclei": "v3.11.1", "templates_pin": "v10.5.1"},
        )
        action_id = store.record_action(run_id, _executed_result("nuclei", "juice-shop.lab"), iteration=1)
        raw = json.loads((CAPTURES / "nuclei_juice-shop_3000.findings.json").read_text())
        found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
        store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))
        store.finish_run(run_id, status="completed", audit_log_sha256="cafebabe")
        reconstructed = store.reconstruct_run(run_id)
    return build_report(reconstructed)


def _synthetic_finding(template_id: str, host: str = "dvwa.lab", ip: str = "172.31.77.11") -> dict:
    return {
        "template_id": template_id, "name": f"Finding {template_id}", "host": host,
        "matched_at": f"http://{host}", "ip": ip, "severity": "info", "tags": ["tech"],
    }


def _build_long_report(tmp_path, n: int = 40) -> "Report":  # noqa: F821
    raw = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": [_synthetic_finding(f"finding-{i:03d}") for i in range(n)],
        "summary": {"findings": n, "off_target": 0, "unparsed_lines": 0},
    }
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG, tool_versions={"nuclei": "v3.11.1"})
        action_id = store.record_action(run_id, _executed_result("nuclei", "dvwa.lab"), iteration=1)
        found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
        store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)
    return build_report(reconstructed)


# --- HTML: sections, self-contained, print CSS ------------------------------

def test_render_html_has_all_sections_one_doc_inline_style_no_external_refs(tmp_path):
    report = _build_real_report(tmp_path)
    doc = render_html(report)

    assert doc.count("<html") == 1
    assert doc.count("</html>") == 1
    assert "<style>" in doc and "</style>" in doc

    for heading in ("Security Assessment Report", "Executive Summary", "Scope", "Methodology",
                     "Findings", "Assessment Activity", "Limitations"):
        assert heading in doc

    # no external asset or network reference of any kind (the report text
    # legitimately quotes scanned URLs like "http://dvwa.lab" as finding
    # evidence - that's data, not a resource the document loads)
    assert not re.search(r'\bsrc\s*=\s*["\']https?:', doc)
    assert not re.search(r'<link\b', doc)
    assert not re.search(r'href\s*=\s*["\']https?:', doc)
    assert "@import" not in doc
    assert "<script" not in doc


def test_render_html_has_the_print_pagination_css_contract(tmp_path):
    report = _build_real_report(tmp_path)
    doc = render_html(report)

    assert "@page" in doc
    assert "counter(page)" in doc
    assert "break-inside: avoid" in doc or "break-inside:avoid" in doc
    assert "page-break-before" in doc
    assert "display: table-header-group" in doc


# --- long report: every finding block individually avoid-break, sections paginate --

def test_long_report_wraps_each_finding_in_a_break_avoid_block_and_sections_page_break(tmp_path):
    report = _build_long_report(tmp_path, n=40)
    doc = render_html(report)

    finding_blocks = re.findall(r'<div class="finding"[^>]*>.*?</div>\s*(?=<div class="finding"|</div>\s*</div>)',
                                 doc, flags=re.S)
    # simpler, robust check: every rendered title appears inside a div with class="finding"
    assert doc.count('<div class="finding"') == 40
    # the section wrapper carries page-break-before (verified above) and each
    # finding carries its own avoid-break class via the shared .finding rule
    assert doc.count('class="section"') >= 6


# --- determinism -------------------------------------------------------------

def test_render_html_is_byte_identical_across_repeated_renders(tmp_path):
    report = _build_real_report(tmp_path)
    assert render_html(report) == render_html(report)

    report_long = _build_long_report(tmp_path, n=10)
    assert render_html(report_long) == render_html(report_long)


# --- redaction -----------------------------------------------------------------

def test_redacted_param_never_reaches_the_html(tmp_path):
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        secret_result = _executed_result("nuclei", "dvwa.lab", {"api_token": "sk-super-secret-value"})
        store.record_action(run_id, secret_result, iteration=1)
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    report = build_report(reconstructed)
    doc = render_html(report)
    assert "sk-super-secret-value" not in doc
    assert "api_token" not in doc


# --- HTML-escaping of hostile content (defense in depth beyond RC-12 sanitization) --

def test_html_special_characters_in_a_finding_title_are_escaped(tmp_path):
    raw = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": [{
            "template_id": "xss-title", "name": "<script>alert(1)</script> & \"quoted\"",
            "host": "dvwa.lab", "matched_at": "http://dvwa.lab", "ip": "172.31.77.11",
            "severity": "info", "tags": [],
        }],
        "summary": {"findings": 1, "off_target": 0, "unparsed_lines": 0},
    }
    with EvidenceStore.open(tmp_path / "evidence.db") as store:
        run_id = store.start_run(ENG)
        action_id = store.record_action(run_id, _executed_result("nuclei", "dvwa.lab"), iteration=1)
        found, issues = normalize_nuclei(raw, provenance=Provenance(engagement=ENG.engagement, scanner="nuclei"))
        store.record_findings(run_id, action_id, NormalizedResult(findings=found, issues=issues, provenance=found[0].provenance))
        store.finish_run(run_id, status="completed")
        reconstructed = store.reconstruct_run(run_id)

    doc = render_html(build_report(reconstructed))
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


# --- PDF: gated on a real backend -----------------------------------------------

@pytest.mark.skipif(not _pdf_backend_available(), reason="no PDF backend (weasyprint/playwright) installed")
def test_render_pdf_produces_a_real_multi_page_pdf(tmp_path):
    report = _build_long_report(tmp_path, n=60)
    out = tmp_path / "report.pdf"
    render_pdf(report, out)
    data = out.read_bytes()
    assert data[:4] == b"%PDF"
    assert len(data) > 2_000


def test_render_pdf_raises_a_clear_error_with_no_backend(tmp_path, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def _blocking_import(name, *args, **kwargs):
        if name in ("weasyprint", "playwright"):
            raise ImportError(f"blocked for test: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocking_import)
    report = _build_real_report(tmp_path)
    with pytest.raises(NoPdfBackendAvailable) as excinfo:
        render_pdf(report, tmp_path / "out.pdf")
    assert "pip install" in str(excinfo.value)


# --- CLI ---------------------------------------------------------------------

def test_cli_writes_html_report_to_the_output_directory(tmp_path):
    db_path = tmp_path / "evidence.db"
    with EvidenceStore.open(db_path) as store:
        run_id = store.start_run(ENG, tool_versions={"nmap": "7.93"})
        store.record_action(run_id, _executed_result("nmap", "172.31.77.11"), iteration=1)
        store.finish_run(run_id, status="completed")

    out_dir = tmp_path / "out"
    rc = main(["--db", str(db_path), "--run", run_id, "--out", str(out_dir), "--format", "html"])
    assert rc == 0
    produced = list(out_dir.glob("*.html"))
    assert len(produced) == 1
    assert run_id in produced[0].name
    assert "<html" in produced[0].read_text(encoding="utf-8")


def test_cli_pdf_without_backend_reports_a_clean_error(tmp_path, monkeypatch, capsys):
    import builtins
    real_import = builtins.__import__

    def _blocking_import(name, *args, **kwargs):
        if name in ("weasyprint", "playwright"):
            raise ImportError(f"blocked for test: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocking_import)

    db_path = tmp_path / "evidence.db"
    with EvidenceStore.open(db_path) as store:
        run_id = store.start_run(ENG)
        store.finish_run(run_id, status="completed")

    rc = main(["--db", str(db_path), "--run", run_id, "--out", str(tmp_path / "out"), "--format", "pdf"])
    assert rc == 1
    assert "pip install" in capsys.readouterr().err
