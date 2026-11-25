# SPDX-License-Identifier: AGPL-3.0-or-later
"""nuclei template coverage, end to end: the wrapper's coverage_warning ->
normalization issue -> evidence store -> report Limitations, the audit entry,
and `op06d report --db` rebuilding it from the store alone."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from op06d import cli
from op06d.audit import read_log
from op06d.evidence import EvidenceStore
from op06d.normalize import Provenance, normalize_nuclei
from op06d.nuclei_tool import NucleiTool
from op06d.report import build_report
from op06d.tools import ProcessResult, ToolAction

IP = "203.0.113.5"
HOST = "app.example.test"
FULL_STATS = '{"duration":"0:00:05","templates":"2820","total":"2537"}'


class Nuclei:
    """Stands in for the nuclei process: no findings, the given stats on stderr."""

    def __init__(self, stderr: str):
        self.stderr = stderr

    def __call__(self, argv, timeout, *, env=None):
        return ProcessResult(0, b"", self.stderr.encode())


def _tool(stderr: str) -> NucleiTool:
    return NucleiTool(20, runner=Nuclei(stderr), which=lambda n: "/usr/bin/nuclei",
                      isdir=lambda p: True, template_dir="/opt/nuclei-templates")


def _engagement(path: Path, target: str) -> Path:
    now = datetime.now(timezone.utc)
    path.write_text(yaml.safe_dump({
        "engagement": "coverage-test",
        "authorization": {"client": "Test", "signed_scope_ref": "SOW-1", "authorized_by": "t@example.com",
                          "window": [(now - timedelta(hours=1)).isoformat(),
                                     (now + timedelta(hours=1)).isoformat()]},
        "scope": {"in_scope": [target]},
        "intensity": {"max_rps": 20},
        "objective": "test",
    }), encoding="utf-8")
    return path


def _run(tmp_path: Path, stderr: str, target: str = IP):
    eng = _engagement(tmp_path / "engagement.yaml", target)
    summary = cli.run_engagement(
        eng, tmp_path / "out", tools=[_tool(stderr)], resolver=lambda h: [IP], non_interactive=True,
        planner=lambda e: [ToolAction("nuclei", target, {}, reason="recon: default-tag detection")],
        notice=lambda line: None,
    )
    with EvidenceStore.open(summary.evidence_db_path) as store:
        report = build_report(store.reconstruct_run(summary.run_id))
    return summary, report


def _coverage(report):
    return [i for i in report.limitations.issues if i.kind == "nuclei_low_template_coverage"]


def _executed(summary):
    [entry] = [e for e in read_log(summary.audit_log_path) if e.event == "action_executed"]
    return entry


def test_a_zero_template_scan_is_a_limitation_in_the_store_and_the_report(tmp_path):
    summary, report = _run(tmp_path, '{"templates":"0"}')

    assert summary.executed == 1 and summary.severity_counts == {}
    [issue] = _coverage(report)
    assert issue.detail == (
        f'nuclei on {IP} loaded 0 templates. "No findings" from this action does not mean the '
        "target is clean."
    )
    assert issue.raw["templates_loaded"] == 0 and issue.raw["target"] == IP

    html = summary.report_html_path.read_text(encoding="utf-8")
    assert "nuclei_low_template_coverage" in html and f"nuclei on {IP} loaded 0 templates" in html
    assert "templates_loaded=0 coverage_warning" in _executed(summary).reason


def test_op06d_report_rebuilds_the_coverage_limitation_from_the_store_alone(tmp_path):
    summary, _ = _run(tmp_path, '{"templates":"0"}')
    again = tmp_path / "again"
    assert cli.main(["report", "--db", str(summary.evidence_db_path), "--run", summary.run_id,
                     "--out", str(again)]) == 0
    [html] = again.glob("*.html")
    assert f"nuclei on {IP} loaded 0 templates" in html.read_text(encoding="utf-8")


def test_a_normal_scan_has_no_coverage_entry(tmp_path):
    summary, report = _run(tmp_path, FULL_STATS)
    assert _coverage(report) == []
    reason = _executed(summary).reason
    assert "templates_loaded=2820" in reason and "coverage_warning" not in reason


def test_a_zero_template_scan_and_a_clean_scan_read_differently(tmp_path):
    (tmp_path / "zero").mkdir()
    (tmp_path / "clean").mkdir()
    zero, _ = _run(tmp_path / "zero", '{"templates":"0"}')
    clean, _ = _run(tmp_path / "clean", FULL_STATS)

    def limitations(summary):
        html = summary.report_html_path.read_text(encoding="utf-8")
        return html[html.index("<h2>Limitations"):].split("</div>", 1)[0]

    assert "No normalization issues, off-target activity or coverage gaps were recorded" in limitations(clean)
    assert "No normalization issues" not in limitations(zero)
    assert "loaded 0 templates" in limitations(zero)


def test_an_unreadable_template_count_is_reported_as_unknown_coverage(tmp_path):
    summary, report = _run(tmp_path, "")
    [issue] = _coverage(report)
    assert "the number of templates loaded could not be read" in issue.detail
    assert issue.raw["templates_loaded"] is None
    assert "templates_loaded=unknown coverage_warning" in _executed(summary).reason


def test_a_hostname_target_is_named_with_its_pinned_address(tmp_path):
    _, report = _run(tmp_path, '{"templates":"0"}', target=HOST)
    [issue] = _coverage(report)
    assert issue.detail.startswith(f"nuclei on {HOST} ({IP}) loaded 0 templates.")


@pytest.mark.parametrize("loaded, text", [(1, "loaded 1 template."), (0, "loaded 0 templates.")])
def test_the_normalizer_turns_coverage_warning_into_an_issue(loaded, text):
    findings = {"scanner": "nuclei", "findings": [], "coverage_warning": "nuclei reported no templates",
                "summary": {"findings": 0, "off_target": 0, "unparsed_lines": 0, "templates_loaded": loaded}}
    _, issues = normalize_nuclei(findings, provenance=Provenance(engagement="e", scanner="nuclei", target=IP))
    [issue] = [i for i in issues if i.kind == "nuclei_low_template_coverage"]
    assert text in issue.detail


def test_the_normalizer_adds_nothing_without_coverage_warning():
    findings = {"scanner": "nuclei", "findings": [],
                "summary": {"findings": 0, "off_target": 0, "unparsed_lines": 0, "templates_loaded": 2820}}
    _, issues = normalize_nuclei(findings, provenance=Provenance(engagement="e", scanner="nuclei", target=IP))
    assert issues == []
