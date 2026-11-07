# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-29 + RC-8: the ``redcell`` CLI.

``redcell run --engagement <file> --out <dir>`` takes an engagement file to
a client report in one command, wiring together every finished piece of the
pipeline: the RC-6 engagement loader, the RC-9/10/23 guardrail gate, the
RC-13/14 tool wrappers (via ``GatedToolbox`` only - this module imports no
concrete tool class), the RC-11 audit log, the RC-15 normalizer, the RC-16
evidence store, and the RC-17/18 report renderer.

The console entry point (``pyproject.toml``: ``redcell = "redcell.cli:main"``)
is ``main()`` below.

**Gate is the only door.** Every action here goes through
``GatedToolbox.execute`` - never a tool directly. The deterministic
``plan_recon`` below needs no LLM loop; the RC-7 ``Orchestrator`` remains
the integration point for a future LLM planner, out of scope for this
ticket (an LLM-in-the-loop run also raises an egress question - RC-21
territory).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Sequence

from redcell.approval import ConsoleApprover
from redcell.audit import AuditLog
from redcell.engagement import Engagement, EngagementError, load_engagement
from redcell.evidence import EvidenceStore
from redcell.gate import Gate
from redcell.normalize import normalize_execution_result
from redcell.report import build_report
from redcell.resolve import Resolver, system_resolver
from redcell.report_render import NoPdfBackendAvailable, render_html, render_pdf
from redcell.tools import (
    ApprovalHook,
    DenyAllApprover,
    GatedToolbox,
    Outcome,
    Tool,
    ToolAction,
    default_tools,
)

__all__ = ["plan_recon", "RunSummary", "run_engagement", "build_parser", "main"]


def plan_recon(engagement: Engagement) -> list[ToolAction]:
    """Deterministic recon plan, built from ``engagement.scope.in_scope``:
    per in-scope hostname or IP, an nmap service scan then a nuclei
    default-tag scan; per in-scope CIDR, an nmap service scan of the range
    only - nuclei cannot target a range, so it is skipped for that entry.
    A ``*.`` wildcard entry is a scope *pattern*, not a concrete host, so it
    is not scanned.

    Kept as a standalone pure function (engagement in, actions out) so a
    future LLM planner can replace it without touching the run wiring
    below."""
    actions: list[ToolAction] = []
    for entry in engagement.scope.in_scope:
        if "/" in entry:
            actions.append(ToolAction(
                "nmap", entry, {"profile": "service"}, reason="recon: service scan of in-scope range",
            ))
            continue
        if entry.startswith("*."):
            continue
        actions.append(ToolAction("nmap", entry, {"profile": "service"}, reason="recon: service scan"))
        actions.append(ToolAction("nuclei", entry, {}, reason="recon: default-tag detection"))
    return actions


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    report_html_path: Path
    report_pdf_path: Path | None
    evidence_db_path: Path
    audit_log_path: Path
    executed: int
    denied: int
    declined: int
    tool_errors: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    pdf_warning: str | None = None


def _select_approver(
    *, non_interactive: bool, stdin_isatty: bool, stdout_isatty: bool, timeout: float,
) -> ApprovalHook:
    """SAFETY: an unattended, piped, or explicitly non-interactive run must
    NEVER auto-approve an intrusive action. ``ConsoleApprover`` is reachable
    only when both stdin and stdout are real terminals and the operator did
    not ask for ``--non-interactive``; every other case gets
    ``DenyAllApprover``."""
    if non_interactive or not stdin_isatty or not stdout_isatty:
        return DenyAllApprover()
    return ConsoleApprover(timeout=timeout)


def run_engagement(
    engagement_path: str | Path,
    out_dir: str | Path,
    *,
    template_dir: str | None = None,
    templates_pin: str = "",
    tool_versions: dict[str, str] | None = None,
    formats: Sequence[str] = ("html",),
    non_interactive: bool = False,
    approval_timeout: float = 120.0,
    tools: Iterable[Tool] | None = None,
    approver: ApprovalHook | None = None,
    planner: Callable[[Engagement], list[ToolAction]] = plan_recon,
    clock: Callable[[], datetime] | None = None,
    resolver: Resolver | None = None,
    stdin_isatty: bool | None = None,
    stdout_isatty: bool | None = None,
) -> RunSummary:
    """One engagement file to a client report.

    ``tools``, ``approver``, ``clock``, ``resolver``, ``stdin_isatty``/
    ``stdout_isatty`` are injection points for tests: a fake tool list
    removes the need for any real subprocess or network access, a fake
    resolver removes the need for a real DNS lookup (so a hostname-in-scope
    test can still exercise RC-23's resolve-once ``dns_pinned`` audit entry
    deterministically), a fake approver or clock makes the approval/timing
    behavior deterministic, and the tty overrides let a test exercise the
    interactive-vs-unattended selection without a real terminal. Production
    callers (the CLI) leave all of them ``None`` for the real wiring.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    eng = load_engagement(engagement_path)

    log = AuditLog.for_engagement(eng, out_dir / "audit", clock=clock)
    # RC-23 follow-up: resolve-once DNS, wired in via audit_pin.
    gate = Gate(eng, resolver=resolver or system_resolver, audit_pin=log.record_dns_pin)
    toolset = list(tools) if tools is not None else default_tools(
        eng, nuclei_template_dir=template_dir, nuclei_templates_pin=templates_pin,
    )

    is_tty_in = sys.stdin.isatty() if stdin_isatty is None else stdin_isatty
    is_tty_out = sys.stdout.isatty() if stdout_isatty is None else stdout_isatty
    hook = approver if approver is not None else _select_approver(
        non_interactive=non_interactive, stdin_isatty=is_tty_in, stdout_isatty=is_tty_out,
        timeout=approval_timeout,
    )
    box = GatedToolbox(eng, gate, log, toolset, approver=hook)

    db_path = out_dir / "evidence.db"
    store = EvidenceStore(db_path)
    versions = dict(tool_versions or {})
    if templates_pin:
        versions.setdefault("templates_pin", templates_pin)
    run_id = store.start_run(eng, audit_log_path=str(log.path), tool_versions=versions, clock=clock)

    executed = denied = declined = tool_errors = 0
    severity_counts: dict[str, int] = {}
    for i, action in enumerate(planner(eng), start=1):
        result = box.execute(action, iteration=i)
        action_id = store.record_action(run_id, result, iteration=i)

        if result.outcome is Outcome.TOOL_ERROR:
            tool_errors += 1
        elif result.outcome is Outcome.EXECUTED:
            executed += 1
        elif result.outcome in (Outcome.DENIED, Outcome.RATE_LIMITED):
            denied += 1
        elif result.outcome is Outcome.DECLINED:
            declined += 1

        if result.executed:
            normalized = normalize_execution_result(result, engagement=eng.engagement)
            store.record_findings(run_id, action_id, normalized)
            for f in normalized.findings:
                severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    audit_sha256 = hashlib.sha256(Path(log.path).read_bytes()).hexdigest()
    store.finish_run(run_id, status="completed", audit_log_sha256=audit_sha256)

    report = build_report(store.reconstruct_run(run_id))
    html_path = out_dir / f"{report.header.engagement}-{run_id}.html"
    html_path.write_text(render_html(report), encoding="utf-8")

    pdf_path: Path | None = None
    pdf_warning: str | None = None
    if "pdf" in formats:
        candidate = out_dir / f"{report.header.engagement}-{run_id}.pdf"
        try:
            render_pdf(report, candidate)
            pdf_path = candidate
        except NoPdfBackendAvailable as exc:
            # A missing PDF backend must never fail the whole run - the
            # HTML report above is already written.
            pdf_warning = str(exc)

    return RunSummary(
        run_id=run_id, report_html_path=html_path, report_pdf_path=pdf_path,
        evidence_db_path=db_path, audit_log_path=Path(log.path),
        executed=executed, denied=denied, declined=declined, tool_errors=tool_errors,
        severity_counts=severity_counts, pdf_warning=pdf_warning,
    )


def _print_summary(summary: RunSummary, *, out=None) -> None:
    out = sys.stdout if out is None else out  # resolved at call time, not import time
    print(f"run_id: {summary.run_id}", file=out)
    print(
        f"actions: executed={summary.executed} denied={summary.denied} "
        f"declined={summary.declined} tool_errors={summary.tool_errors}",
        file=out,
    )
    if summary.severity_counts:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(summary.severity_counts.items()))
        print(f"findings by severity: {counts}", file=out)
    else:
        print("findings: none", file=out)
    print(f"report (html): {summary.report_html_path}", file=out)
    if summary.report_pdf_path:
        print(f"report (pdf):  {summary.report_pdf_path}", file=out)
    elif summary.pdf_warning:
        print(f"report (pdf):  not generated - {summary.pdf_warning}", file=out)
    print(f"evidence store: {summary.evidence_db_path}", file=out)
    print(f"audit log:      {summary.audit_log_path}", file=out)


def _cmd_run(args: argparse.Namespace) -> int:
    formats: tuple[str, ...] = ("html", "pdf") if args.format == "both" else (args.format,)
    tool_versions: dict[str, str] = {}
    if args.nmap_version:
        tool_versions["nmap"] = args.nmap_version
    if args.nuclei_version:
        tool_versions["nuclei"] = args.nuclei_version
    try:
        summary = run_engagement(
            args.engagement, args.out,
            template_dir=args.template_dir, templates_pin=args.templates_pin or "",
            tool_versions=tool_versions, formats=formats, non_interactive=args.non_interactive,
            approval_timeout=args.approval_timeout,
        )
    except (EngagementError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_summary(summary)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from redcell.report_render import main as render_main

    return render_main(["--db", args.db, "--run", args.run, "--out", args.out, "--format", args.format])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redcell", description="Red Cell: the model proposes, the gate disposes.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run an engagement end-to-end and produce a client report")
    run_p.add_argument("--engagement", required=True, help="path to the engagement YAML file")
    run_p.add_argument("--out", required=True, help="output directory for the report, evidence store and audit log")
    run_p.add_argument("--template-dir", default=None, help="pinned nuclei template directory (omit to skip nuclei)")
    run_p.add_argument("--templates-pin", default=None, help="label recorded for the nuclei template set")
    run_p.add_argument("--nmap-version", default=None, help="nmap version to record in the report")
    run_p.add_argument("--nuclei-version", default=None, help="nuclei version to record in the report")
    run_p.add_argument("--format", choices=["html", "pdf", "both"], default="html")
    run_p.add_argument(
        "--non-interactive", action="store_true",
        help="never prompt for operator approval; equivalent to a non-TTY run",
    )
    run_p.add_argument(
        "--approval-timeout", type=float, default=120.0,
        help="seconds to wait for an operator approval before denying",
    )
    run_p.set_defaults(func=_cmd_run)

    report_p = sub.add_parser(
        "report", help="render an already-stored run to a report (reuses redcell.report_render)",
    )
    report_p.add_argument("--db", required=True, help="path to the evidence store (.db)")
    report_p.add_argument("--run", required=True, help="run_id to render")
    report_p.add_argument("--out", required=True, help="output directory")
    report_p.add_argument("--format", choices=["html", "pdf", "both"], default="html")
    report_p.set_defaults(func=_cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
