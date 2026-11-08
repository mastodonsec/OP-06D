# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RC-29 (the `op06d` CLI) + RC-8 (operator approval wiring).

Uses fake nmap/nuclei tools (no real subprocess, no real network) and a
fake DNS resolver (no real DNS lookup) injected into ``run_engagement``, so
this exercises the full wiring - gate, toolbox, audit log, evidence store,
normalizer, report - deterministically and offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from op06d.audit import read_log, verify_log
from op06d.cli import RunSummary, build_parser, main, run_engagement
from op06d.evidence import EvidenceStore
from op06d.tools import Outcome, Risk, ToolAction, ToolOutput

# --- fakes: no subprocess, no network ----------------------------------------


class FakeNmapTool:
    name = "nmap"
    description = "fake nmap for tests"
    risk = Risk.ACTIVE_RECON
    destructive = False
    allowed_parameters = frozenset({"profile", "ports", "scripts"})

    def __init__(self):
        self.calls: list[tuple[str, dict, str | None]] = []

    def risk_for(self, parameters):
        return Risk.INTRUSIVE if parameters.get("profile") == "aggressive" else Risk.ACTIVE_RECON

    def run(self, target, parameters, *, hostname=None):
        self.calls.append((target, dict(parameters), hostname))
        findings = {
            "scanner": "nmap", "version": "7.93",
            "hosts": [{
                "status": "up",
                "addresses": [{"address": target, "type": "ipv4"}],
                "hostnames": [],
                "ports": [{
                    "port": 80, "protocol": "tcp", "state": "open", "reason": "syn-ack",
                    "service": {"name": "http", "product": "FakeHTTP", "version": "1.0",
                                "extrainfo": "", "tunnel": "", "cpe": []},
                }],
            }],
            "summary": {"hosts_up": 1, "hosts_down": 0, "hosts_total": 1, "elapsed_seconds": 0.1},
        }
        if hostname:
            findings["target_hostname"] = hostname
        return ToolOutput(findings, raw="<fake-nmap-xml/>", status="ok")


class FakeNucleiTool:
    name = "nuclei"
    description = "fake nuclei for tests"
    risk = Risk.ACTIVE_RECON
    destructive = False
    allowed_parameters = frozenset({"severity", "tags", "template_ids", "port", "scheme"})

    def __init__(self):
        self.calls: list[tuple[str, dict, str | None]] = []

    def run(self, target, parameters, *, hostname=None):
        self.calls.append((target, dict(parameters), hostname))
        findings = {
            "scanner": "nuclei", "templates_pin": "v10.5.1",
            "selection": {"severity": ["info"], "tags": ["tech"], "template_ids": []},
            "out_of_band": "off",
            "findings": [{
                "template_id": "fake-tech-detect", "name": "Fake Tech Detect", "severity": "info",
                "tags": ["tech"], "description": "", "type": "http", "host": target,
                "matched_at": f"http://{target}", "ip": "203.0.113.5", "matcher_name": "",
                "extracted": [], "references": [], "cve": "", "cvss_score": None,
                "timestamp": "2026-11-07T00:00:00Z",
            }],
            "summary": {"findings": 1, "off_target": 0, "unparsed_lines": 0},
        }
        if hostname:
            findings["target_hostname"] = hostname
        return ToolOutput(findings, raw="{}", status="ok")


def _fake_resolver(host: str) -> list[str]:
    return ["203.0.113.5"]


def _write_engagement(path: Path, *, in_scope: list[str], out_of_scope: list[str] | None = None) -> Path:
    now = datetime.now(timezone.utc)
    data = {
        "engagement": "cli-test-2026-11",
        "authorization": {
            "client": "Test Client",
            "signed_scope_ref": "SOW-TEST-1",
            "authorized_by": "tester@example.com",
            "window": [
                (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            ],
        },
        "scope": {"in_scope": in_scope, "out_of_scope": out_of_scope or []},
        "intensity": {"max_rps": 20, "destructive": False},
        "objective": "CLI end-to-end test",
    }
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# --- end-to-end -----------------------------------------------------------------

def test_run_engagement_end_to_end_produces_report_evidence_and_valid_audit_log(tmp_path):
    eng_path = _write_engagement(tmp_path / "engagement.yaml", in_scope=["app.example.test"])
    out_dir = tmp_path / "out"

    summary = run_engagement(
        eng_path, out_dir,
        tools=[FakeNmapTool(), FakeNucleiTool()],
        resolver=_fake_resolver,
        non_interactive=True,
    )

    assert isinstance(summary, RunSummary)
    assert summary.executed == 2  # nmap + nuclei, both on the one hostname
    assert summary.denied == 0
    assert summary.declined == 0
    assert summary.severity_counts == {"info": 2}  # 1 nmap "service" finding + 1 nuclei finding, both info

    assert summary.report_html_path.exists()
    html = summary.report_html_path.read_text(encoding="utf-8")
    assert "<html" in html
    assert "app.example.test" in html or "203.0.113.5" in html

    assert summary.evidence_db_path.exists()
    store = EvidenceStore(summary.evidence_db_path)
    run_row = store.get_run(summary.run_id)
    assert run_row is not None
    assert run_row.status == "completed"
    assert run_row.audit_log_sha256 is not None

    actions = store.list_actions(summary.run_id)
    assert len(actions) == 2
    findings = store.list_findings(summary.run_id)
    assert len(findings) == 2

    assert summary.audit_log_path.exists()
    assert verify_log(summary.audit_log_path) > 0


def test_audit_pin_fires_for_a_hostname_in_scope(tmp_path):
    eng_path = _write_engagement(tmp_path / "engagement.yaml", in_scope=["app.example.test"])
    out_dir = tmp_path / "out"

    summary = run_engagement(
        eng_path, out_dir, tools=[FakeNmapTool(), FakeNucleiTool()],
        resolver=_fake_resolver, non_interactive=True,
    )

    entries = read_log(summary.audit_log_path)
    pins = [e for e in entries if e.event == "dns_pinned"]
    assert len(pins) == 1
    assert "app.example.test" in pins[0].target


# --- unattended never auto-approves intrusive actions ---------------------------

def test_non_interactive_declines_an_intrusive_action_without_executing_it(tmp_path):
    eng_path = _write_engagement(tmp_path / "engagement.yaml", in_scope=["172.31.77.11"])
    out_dir = tmp_path / "out"
    nmap = FakeNmapTool()

    def intrusive_planner(engagement):
        return [ToolAction("nmap", "172.31.77.11", {"profile": "aggressive"}, reason="test: intrusive")]

    summary = run_engagement(
        eng_path, out_dir, tools=[nmap], planner=intrusive_planner,
        non_interactive=True,  # the acceptance criterion: unattended = deny
    )

    assert summary.executed == 0
    assert summary.declined == 1
    assert nmap.calls == []  # the tool was never actually invoked

    store = EvidenceStore(summary.evidence_db_path)
    actions = store.list_actions(summary.run_id)
    assert len(actions) == 1
    assert actions[0].outcome == "declined"
    assert actions[0].executed is False


def test_non_tty_also_declines_intrusive_action_even_without_non_interactive_flag(tmp_path):
    # Simulates a piped/unattended run that forgot --non-interactive: the
    # tty check alone must still prevent auto-approval.
    eng_path = _write_engagement(tmp_path / "engagement.yaml", in_scope=["172.31.77.11"])
    out_dir = tmp_path / "out"

    def intrusive_planner(engagement):
        return [ToolAction("nmap", "172.31.77.11", {"profile": "aggressive"}, reason="test: intrusive")]

    summary = run_engagement(
        eng_path, out_dir, tools=[FakeNmapTool()], planner=intrusive_planner,
        non_interactive=False, stdin_isatty=False, stdout_isatty=False,
    )
    assert summary.declined == 1
    assert summary.executed == 0


# --- refused (out-of-scope) action recorded -------------------------------------

def test_out_of_scope_action_is_denied_and_recorded_in_store_and_audit(tmp_path):
    eng_path = _write_engagement(
        tmp_path / "engagement.yaml", in_scope=["172.31.77.11"], out_of_scope=["1.1.1.1"],
    )
    out_dir = tmp_path / "out"

    def mixed_planner(engagement):
        return [
            ToolAction("nmap", "172.31.77.11", {"profile": "service"}, reason="in scope"),
            ToolAction("nmap", "1.1.1.1", {"profile": "service"}, reason="test: out of scope"),
        ]

    summary = run_engagement(
        eng_path, out_dir, tools=[FakeNmapTool()], planner=mixed_planner, non_interactive=True,
    )

    assert summary.executed == 1
    assert summary.denied == 1

    store = EvidenceStore(summary.evidence_db_path)
    actions = {a.target: a for a in store.list_actions(summary.run_id)}
    assert actions["1.1.1.1"].outcome == "denied"
    assert actions["1.1.1.1"].executed is False
    assert "deny" in actions["1.1.1.1"].gate_reason.lower()

    entries = read_log(summary.audit_log_path)
    assert any("1.1.1.1" in (e.target or "") and e.allowed is False for e in entries)


# --- CLI exit codes --------------------------------------------------------------

def test_cli_exits_zero_on_success(tmp_path, monkeypatch, capsys):
    eng_path = _write_engagement(tmp_path / "engagement.yaml", in_scope=["172.31.77.11"])
    out_dir = tmp_path / "out"

    # route through run_engagement with injected fakes by monkeypatching the
    # module-level default_tools target is overkill here; instead call main()
    # against a non-interactive run with no --template-dir (nmap only, real
    # NmapTool) would need a real `nmap` binary, so this CLI-level test checks
    # argument wiring and exit codes using plan_recon's own CIDR/host rules
    # against a target that denies cleanly without needing any real binary:
    # an out-of-scope-only engagement still exits 0 (zero actions planned is
    # not an error).
    empty_scope_path = tmp_path / "engagement_minimal.yaml"
    _write_engagement(empty_scope_path, in_scope=["*.example.test"])  # wildcard only -> no actions planned

    rc = main(["run", "--engagement", str(empty_scope_path), "--out", str(out_dir), "--non-interactive"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "run_id:" in out
    assert "findings: none" in out


def test_cli_exits_nonzero_with_clear_message_on_bad_engagement_path(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.yaml"
    rc = main(["run", "--engagement", str(missing), "--out", str(tmp_path / "out"), "--non-interactive"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_build_parser_run_subcommand_defaults():
    parser = build_parser()
    args = parser.parse_args(["run", "--engagement", "e.yaml", "--out", "o"])
    assert args.format == "html"
    assert args.non_interactive is False
    assert args.approval_timeout == 120.0
