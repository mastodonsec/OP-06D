# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-29 + RC-8: the ``op06d`` CLI.

``op06d run --engagement <file> --out <dir>`` takes an engagement file to
a client report in one command, wiring together every finished piece of the
pipeline: the RC-6 engagement loader, the RC-9/10/23 guardrail gate, the
RC-13/14 tool wrappers (via ``GatedToolbox`` only - this module imports no
concrete tool class), the RC-11 audit log, the RC-15 normalizer, the RC-16
evidence store, and the RC-17/18 report renderer.

The console entry point (``pyproject.toml``: ``op06d = "op06d.cli:main"``)
is ``main()`` below.

**Gate is the only door.** Every action here goes through
``GatedToolbox.execute`` - never a tool directly. ``--planner fixed`` (the
default) runs the deterministic ``plan_recon`` below.

RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`:
``--planner llm`` runs the RC-7 ``Orchestrator`` with a model adapter from
``op06d.llm`` against the same gated toolbox, evidence store and report.
See docs/llm-planner.md.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Sequence

from op06d.approval import ConsoleApprover
from op06d.audit import EVENT_PLANNER_CONFIG, AuditLog
from op06d.engagement import Engagement, EngagementError, load_engagement
from op06d.evidence import EvidenceStore
from op06d.gate import Gate
from op06d.llm import (
    ANTHROPIC_PRICES_PER_MTOK,
    LOCAL_RUNTIMES,
    PROVIDERS,
    LLMConfigError,
    LLMSettings,
    build_llm,
)
from op06d.normalize import normalize_execution_result
from op06d.orchestrator import LLM, Orchestrator, RunLimits, CHARS_PER_TOKEN
from op06d.redaction import scrub_text
from op06d.report import build_report
from op06d.resolve import Resolver, system_resolver
from op06d.report_render import NoPdfBackendAvailable, render_html, render_pdf
from op06d.tools import (
    ApprovalHook,
    DenyAllApprover,
    GatedToolbox,
    Outcome,
    Tool,
    ToolAction,
    default_tools,
)

__all__ = [
    "plan_recon", "RunSummary", "run_engagement", "build_parser", "main", "PlannerPolicyError",
    "PLANNERS", "DEFAULT_LLM_LIMITS",
]

PLANNERS = ("fixed", "llm")
DEFAULT_LLM_LIMITS = dict(
    max_iterations=25, max_actions=20, max_wall_clock_seconds=3_600.0, max_tokens=1_000_000,
)


class PlannerPolicyError(Exception):
    """The requested planner configuration is refused before the run starts."""


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
    planner: str = "fixed"
    termination: str | None = None


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
    planner_mode: str = "fixed",
    llm_settings: LLMSettings | None = None,
    llm: LLM | None = None,
    limits: RunLimits | None = None,
    max_iterations: int = DEFAULT_LLM_LIMITS["max_iterations"],
    orchestrator_options: dict | None = None,
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
    if planner_mode not in PLANNERS:
        raise PlannerPolicyError(f"planner must be one of {PLANNERS}")
    out_dir = Path(out_dir)
    if planner_mode == "fixed":
        out_dir.mkdir(parents=True, exist_ok=True)
    eng = load_engagement(engagement_path)

    settings: LLMSettings | None = None
    if planner_mode == "llm":
        if llm_settings is None:
            raise PlannerPolicyError("--planner llm needs an LLM provider (--llm-provider)")
        if not eng.provider_allowed(llm_settings.provider):
            allowed = (
                f"planner.allowed_providers: {list(eng.planner.allowed_providers)}" if eng.planner
                else "no planner block, so only 'local' is allowed; add it to "
                     "planner.allowed_providers in the engagement file"
            )
            raise PlannerPolicyError(
                f"the engagement does not allow the {llm_settings.provider!r} LLM provider ({allowed})"
            )
        try:
            settings = llm_settings.resolved()
        except LLMConfigError as exc:
            raise PlannerPolicyError(str(exc)) from None

    toolset = list(tools) if tools is not None else default_tools(
        eng, nuclei_template_dir=template_dir, nuclei_templates_pin=templates_pin,
    )
    if settings is not None and llm is None:
        try:
            llm = build_llm(settings, tool_names=[t.name for t in toolset])
        except LLMConfigError as exc:
            raise PlannerPolicyError(scrub_text(str(exc))) from None

    out_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog.for_engagement(eng, out_dir / "audit", clock=clock)
    # RC-23 follow-up: resolve-once DNS, wired in via audit_pin.
    gate = Gate(eng, resolver=resolver or system_resolver, audit_pin=log.record_dns_pin)

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

    def record(result, i: int) -> None:
        nonlocal executed, denied, declined, tool_errors
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

    termination: str | None = None
    if settings is None:
        for i, action in enumerate(planner(eng), start=1):
            record(box.execute(action, iteration=i), i)
    else:
        assert llm is not None
        run_limits = limits or RunLimits(
            max_actions=DEFAULT_LLM_LIMITS["max_actions"],
            max_wall_clock_seconds=DEFAULT_LLM_LIMITS["max_wall_clock_seconds"],
            max_tokens=DEFAULT_LLM_LIMITS["max_tokens"],
            max_output_tokens=settings.max_output_tokens,
        )
        planner_info = {
            "planner": "llm", "provider": settings.provider, "model": settings.model,
            "endpoint_class": settings.endpoint_class, "context_tokens": settings.context_tokens,
            "limits": {"max_iterations": max_iterations, **run_limits.as_dict()},
        }
        if settings.provider == "local":
            planner_info["runtime"] = settings.runtime
        log.record(EVENT_PLANNER_CONFIG, tool="orchestrator", parameters=planner_info,
                   reason=f"llm planner: {settings.provider} ({settings.endpoint_class})")
        try:
            orch = Orchestrator(
                eng, llm, box, log, max_iterations=max_iterations, limits=run_limits,
                context_budget_chars=settings.context_tokens * CHARS_PER_TOKEN,
                **(orchestrator_options or {}),
            )
        except ValueError as exc:
            store.finish_run(run_id, status="refused")
            raise PlannerPolicyError(str(exc)) from None
        outcome = orch.run()
        for step in outcome.steps:
            if step.result is not None:
                record(step.result, step.iteration)
        termination = outcome.termination.value
        store.record_planner(run_id, {
            **planner_info, "iterations": outcome.iterations, "actions": outcome.actions,
            "termination": termination, "input_tokens": outcome.input_tokens,
            "output_tokens": outcome.output_tokens,
            **({"failure_cause": outcome.failure} if outcome.failure else {}),
            **({"output_mode": llm.output_mode} if hasattr(llm, "output_mode") else {}),
        })

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
        planner=planner_mode, termination=termination,
    )


def _print_summary(summary: RunSummary, *, out=None) -> None:
    out = sys.stdout if out is None else out  # resolved at call time, not import time
    print(f"run_id: {summary.run_id}", file=out)
    if summary.termination:
        print(f"planner: {summary.planner} (termination: {summary.termination})", file=out)
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
    llm_kwargs: dict = {}
    try:
        if args.planner == "llm":
            llm_kwargs = _llm_options(args)
        elif any(getattr(args, a) is not None for a in _LLM_ONLY_ARGS):
            raise PlannerPolicyError("LLM options need --planner llm")
        summary = run_engagement(
            args.engagement, args.out,
            template_dir=args.template_dir, templates_pin=args.templates_pin or "",
            tool_versions=tool_versions, formats=formats, non_interactive=args.non_interactive,
            approval_timeout=args.approval_timeout, planner_mode=args.planner, **llm_kwargs,
        )
    except (EngagementError, PlannerPolicyError, OSError) as exc:
        print(f"error: {scrub_text(str(exc))}", file=sys.stderr)
        return 2
    _print_summary(summary)
    return 0


_LLM_ONLY_ARGS = (
    "llm_provider", "model", "llm_endpoint", "llm_runtime", "llm_allow_private", "context_tokens",
    "max_output_tokens", "llm_timeout", "max_iterations", "max_actions", "max_wall_clock",
    "max_tokens", "max_cost_usd", "price_input_per_mtok", "price_output_per_mtok",
)


def _llm_options(args: argparse.Namespace) -> dict:
    if args.llm_provider is None:
        raise PlannerPolicyError("--planner llm needs --llm-provider {anthropic,local}")
    if args.llm_provider == "anthropic" and (args.llm_runtime or args.llm_allow_private):
        raise PlannerPolicyError("--llm-runtime/--llm-allow-private apply to the local provider only")
    settings = LLMSettings(
        provider=args.llm_provider, model=args.model, endpoint=args.llm_endpoint,
        runtime=args.llm_runtime or "ollama", context_tokens=args.context_tokens,
        max_output_tokens=args.max_output_tokens, timeout=args.llm_timeout,
        allowed_private=tuple(args.llm_allow_private or ()),
    )
    try:
        resolved = settings.resolved()
    except LLMConfigError as exc:
        raise PlannerPolicyError(str(exc)) from None
    price_in, price_out = args.price_input_per_mtok, args.price_output_per_mtok
    if resolved.provider == "local":
        price_in = 0.0 if price_in is None else price_in
        price_out = 0.0 if price_out is None else price_out
    elif price_in is None and price_out is None and resolved.model in ANTHROPIC_PRICES_PER_MTOK:
        price_in, price_out = ANTHROPIC_PRICES_PER_MTOK[resolved.model]
    try:
        limits = RunLimits(
            max_actions=args.max_actions or DEFAULT_LLM_LIMITS["max_actions"],
            max_wall_clock_seconds=args.max_wall_clock or DEFAULT_LLM_LIMITS["max_wall_clock_seconds"],
            max_tokens=args.max_tokens or DEFAULT_LLM_LIMITS["max_tokens"],
            max_cost_usd=args.max_cost_usd,
            price_input_per_mtok=price_in, price_output_per_mtok=price_out,
            max_output_tokens=resolved.max_output_tokens,
        )
    except ValueError as exc:
        raise PlannerPolicyError(str(exc)) from None
    max_iterations = args.max_iterations or DEFAULT_LLM_LIMITS["max_iterations"]
    return dict(llm_settings=settings, limits=limits, max_iterations=max_iterations)


def _cmd_report(args: argparse.Namespace) -> int:
    from op06d.report_render import main as render_main

    return render_main(["--db", args.db, "--run", args.run, "--out", args.out, "--format", args.format])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="op06d", description="OP-06D: the model proposes, the gate disposes.",
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
    plan = run_p.add_argument_group("planner (RC-40; see docs/llm-planner.md)")
    plan.add_argument("--planner", choices=PLANNERS, default="fixed",
                      help="fixed: deterministic recon plan (default); llm: model-driven orchestrator")
    plan.add_argument("--llm-provider", choices=PROVIDERS, default=None,
                      help="anthropic (hosted; key from ANTHROPIC_API_KEY) or local")
    plan.add_argument("--model", default=None, help="model name (provider default if omitted)")
    plan.add_argument("--llm-endpoint", default=None,
                      help="local provider base URL; loopback unless --llm-allow-private lists the IP")
    plan.add_argument("--llm-runtime", choices=LOCAL_RUNTIMES, default=None,
                      help="local server type for constrained output (default: ollama)")
    plan.add_argument("--llm-allow-private", action="append", default=None, metavar="IP",
                      help="private IP address the local endpoint may use (repeatable)")
    plan.add_argument("--context-tokens", type=int, default=None,
                      help="context size of the model in tokens (provider default if omitted)")
    plan.add_argument("--max-output-tokens", type=int, default=None,
                      help="per-reply output token cap")
    plan.add_argument("--llm-timeout", type=float, default=None, help="per-request timeout, seconds")
    limits_g = run_p.add_argument_group("llm run limits")
    limits_g.add_argument("--max-iterations", type=int, default=None,
                          help=f"default {DEFAULT_LLM_LIMITS['max_iterations']}")
    limits_g.add_argument("--max-actions", type=int, default=None,
                          help=f"tool invocations per run, default {DEFAULT_LLM_LIMITS['max_actions']}")
    limits_g.add_argument("--max-wall-clock", type=float, default=None,
                          help=f"seconds, default {DEFAULT_LLM_LIMITS['max_wall_clock_seconds']:.0f}")
    limits_g.add_argument("--max-tokens", type=int, default=None,
                          help=f"input+output tokens per run, default {DEFAULT_LLM_LIMITS['max_tokens']}")
    limits_g.add_argument("--max-cost-usd", type=float, default=None, help="cost cap per run (USD)")
    limits_g.add_argument("--price-input-per-mtok", type=float, default=None,
                          help="USD per million input tokens (built in for known Anthropic models)")
    limits_g.add_argument("--price-output-per-mtok", type=float, default=None,
                          help="USD per million output tokens")
    run_p.set_defaults(func=_cmd_run)

    report_p = sub.add_parser(
        "report", help="render an already-stored run to a report (reuses op06d.report_render)",
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
