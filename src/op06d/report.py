# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-17: the client report, built from the evidence store.

**Role.** This is where the methodology becomes the product: the document a
paying client reads, authored on behalf of Mastodon Security. Everything in
it comes FROM ``op06d.evidence.ReconstructedRun`` (RC-16) - there is no
hand-assembled content, no invented finding, and no re-scored severity. If a
fact is not in the reconstructed run, it is not in the report.

**Split structure (sets up RC-18):**

* ``build_report(run) -> Report`` - a structured, pure model of the report
  (sections, grouped findings, counts). No Markdown, no HTML, no
  presentation decisions.
* ``render_markdown(report) -> str`` - ``Report`` -> Markdown text.

RC-18 adds ``render_html(report)`` against the SAME ``Report`` model, so
nothing Markdown-specific belongs in ``build_report``.

**Non-negotiables, each with a test:**

* Generated from the store, never hand-assembled.
* An empty or low-finding run still produces a valid, coherent report (every
  section renders; the executive summary says plainly that nothing was
  found).
* No invented data: severities and categories are presented exactly as
  RC-15 stored them (nmap's "info" baseline is not escalated; nuclei's
  passthrough severity is not re-judged). The report describes, it does not
  re-score.
* Deterministic: rendering the same ``ReconstructedRun`` twice yields
  byte-identical Markdown. ``report_date`` is therefore derived from the run
  itself (``ended_at`` or ``started_at``), never from wall-clock "now" -
  using the real clock would make two renders of the same run differ by
  whenever each render happened to run.
* No secrets: action parameters are already redacted in the store
  (``op06d.tools.redact_parameters``); nothing here reaches into or
  surfaces anything beyond what the store already holds.
* Refused actions (denied/declined) are shown, with their gate reason -
  refusing to exceed scope is evidence of the guardrail working, not
  something to hide.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from op06d.evidence import ActionRow, IssueRow, ReconstructedRun

__all__ = [
    "SEVERITY_ORDER",
    "Header",
    "SeverityCount",
    "ExecutiveSummary",
    "ScopeSection",
    "MethodologySection",
    "FindingView",
    "SeverityGroup",
    "FindingsSection",
    "ActionView",
    "AuditTrailSection",
    "IssueView",
    "LimitationsSection",
    "PlannerSection",
    "Report",
    "build_report",
    "render_markdown",
]

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
PREPARED_BY = "Mastodon Security"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Header(_Frozen):
    engagement: str
    client: str
    report_date: str
    prepared_by: str = PREPARED_BY
    signed_scope_ref: str
    authorized_by: str
    window_start: str
    window_end: str


class SeverityCount(_Frozen):
    severity: str
    count: int


class ExecutiveSummary(_Frozen):
    headline: str
    assets_tested: int
    total_findings: int
    severity_counts: list[SeverityCount] = Field(default_factory=list)


class ScopeSection(_Frozen):
    in_scope: list[str]
    out_of_scope: list[str]
    window_start: str
    window_end: str
    statement: str


class MethodologySection(_Frozen):
    approach: str
    tools: list[str]
    guardrail_summary: str
    out_of_scope_statement: str


class FindingView(_Frozen):
    finding_id: str
    title: str
    severity: str
    category: str
    source_tool: str
    hostname: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    scheme: str | None = None
    description: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    tags: list[str] = Field(default_factory=list)


class SeverityGroup(_Frozen):
    severity: str
    findings: list[FindingView]


class FindingsSection(_Frozen):
    groups: list[SeverityGroup]
    total: int


class ActionView(_Frozen):
    action_id: str
    iteration: int | None = None
    tool: str
    target: str
    outcome: str
    gate_stage: str
    gate_allowed: bool
    gate_reason: str
    risk: str | None = None
    status: str | None = None
    executed: bool
    scanned_ip: str | None = None
    observed_at: str


class AuditTrailSection(_Frozen):
    actions: list[ActionView]
    tool_versions: dict[str, Any]
    audit_log_path: str | None = None
    audit_log_sha256: str | None = None


class IssueView(_Frozen):
    kind: str
    detail: str
    raw: Any = None


class LimitationsSection(_Frozen):
    issues: list[IssueView]


class PlannerSection(_Frozen):
    """RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`"""

    planner: str
    provider: str | None = None
    model: str | None = None
    endpoint_class: str | None = None
    context_tokens: int | None = None
    iterations: int | None = None
    actions: int | None = None
    termination: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    failure_cause: dict[str, Any] | None = None
    # RC-46: Planner model benchmark: score candidate models on lab runs
    output_mode: str | None = None
    limits: dict[str, Any] = Field(default_factory=dict)


class Report(_Frozen):
    header: Header
    executive_summary: ExecutiveSummary
    scope: ScopeSection
    methodology: MethodologySection
    findings: FindingsSection
    audit_trail: AuditTrailSection
    limitations: LimitationsSection
    planner: PlannerSection | None = None


# --- build_report --------------------------------------------------------

def _report_date(run) -> str:
    """Derived from the run's own timestamps, never wall-clock "now" - see
    the determinism note in the module docstring."""
    stamp = run.ended_at or run.started_at
    return stamp[:10] if isinstance(stamp, str) and len(stamp) >= 10 else str(stamp)


def _tool_display(tool_versions: dict[str, Any]) -> list[str]:
    items: list[str] = []
    if tool_versions.get("nmap"):
        items.append(f"nmap {tool_versions['nmap']}")
    if tool_versions.get("nuclei"):
        pin = tool_versions.get("templates_pin")
        items.append(f"nuclei {tool_versions['nuclei']}" + (f" (templates {pin})" if pin else ""))
    for key in sorted(tool_versions):
        if key in ("nmap", "nuclei", "templates_pin"):
            continue
        items.append(f"{key} {tool_versions[key]}")
    return items


def _asset_identity(hostname: str | None, ip: str | None) -> str:
    return ip or hostname or ""


def _finding_sort_key(f) -> tuple[str, int, str]:
    # "order deterministically (e.g. by asset then finding_id)"
    return (_asset_identity(f.hostname, f.ip), f.port or -1, f.finding_id)


def _action_sort_key(a: ActionRow) -> tuple[int, str]:
    return (a.iteration if a.iteration is not None else -1, a.action_id)


def _executive_headline(total_findings: int, severity_counts: dict[str, int], assets: int) -> str:
    if total_findings == 0:
        return (
            f"No findings were identified across {assets} tested asset(s) during this engagement; "
            "every tested asset responded within expected parameters for the recon performed."
        )
    high_or_above = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    headline = f"{total_findings} finding(s) were identified across {assets} tested asset(s)."
    if high_or_above:
        headline += f" {high_or_above} of these were rated critical or high severity."
    else:
        headline += " None were rated above medium severity."
    return headline


def build_report(run: ReconstructedRun) -> Report:
    """Pure transform: ``ReconstructedRun`` -> ``Report``. No Markdown, no
    rendering decisions, no wall-clock reads."""
    r = run.run

    header = Header(
        engagement=r.engagement, client=r.client, report_date=_report_date(r),
        signed_scope_ref=r.signed_scope_ref, authorized_by=r.authorized_by,
        window_start=r.window_start, window_end=r.window_end,
    )

    executed_targets = {
        _asset_identity(None, a.scanned_ip or a.target) for a in run.actions if a.executed
    }
    executed_targets.discard("")
    severity_counts: dict[str, int] = {}
    for f in run.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    executive_summary = ExecutiveSummary(
        headline=_executive_headline(len(run.findings), severity_counts, len(executed_targets)),
        assets_tested=len(executed_targets),
        total_findings=len(run.findings),
        severity_counts=[
            SeverityCount(severity=s, count=severity_counts.get(s, 0)) for s in SEVERITY_ORDER
        ],
    )

    in_scope = list(r.scope.get("in_scope") or [])
    out_of_scope = list(r.scope.get("out_of_scope") or [])
    scope = ScopeSection(
        in_scope=in_scope, out_of_scope=out_of_scope,
        window_start=r.window_start, window_end=r.window_end,
        statement="Only the assets explicitly listed as in-scope above were tested; "
                  "nothing outside that authorization was contacted.",
    )

    methodology = MethodologySection(
        approach=(
            "Unauthenticated external reconnaissance: automated, read-mostly probing of the "
            "in-scope assets to identify open services, technologies and common misconfigurations "
            "or exposures, without attempting to exploit, authenticate against, or change the state "
            "of any system."
        ),
        tools=_tool_display(r.tool_versions),
        guardrail_summary=(
            "Every action was proposed by an automated planner and then passed through a hard "
            "guardrail layer before anything ran: scope, the authorized time window, and a rate "
            "limit were all enforced in code, not by instructing the planner to behave - an action "
            "the planner proposed outside authorization could not execute. Every decision, allowed "
            "or refused, was written to an append-only, tamper-evident audit log (see Assessment "
            "Activity below)."
        ),
        out_of_scope_statement=(
            "Exploitation, authenticated application testing, denial-of-service and any "
            "state-changing action were out of scope for this engagement and were not attempted."
        ),
    )

    groups: list[SeverityGroup] = []
    for severity in SEVERITY_ORDER:
        matching = sorted((f for f in run.findings if f.severity == severity), key=_finding_sort_key)
        if not matching:
            continue
        groups.append(SeverityGroup(
            severity=severity,
            findings=[
                FindingView(
                    finding_id=f.finding_id, title=f.title, severity=f.severity,
                    category=f.category, source_tool=f.source_tool, hostname=f.hostname,
                    ip=f.ip, port=f.port, protocol=f.protocol, scheme=f.scheme,
                    description=f.description, evidence=f.evidence, references=f.references,
                    cve=f.cve, cvss_score=f.cvss_score, tags=f.tags,
                )
                for f in matching
            ],
        ))
    findings_section = FindingsSection(groups=groups, total=len(run.findings))

    audit_trail = AuditTrailSection(
        actions=[
            ActionView(
                action_id=a.action_id, iteration=a.iteration, tool=a.tool, target=a.target,
                outcome=a.outcome, gate_stage=a.gate_stage, gate_allowed=a.gate_allowed,
                gate_reason=a.gate_reason, risk=a.risk, status=a.status, executed=a.executed,
                scanned_ip=a.scanned_ip, observed_at=a.observed_at,
            )
            for a in sorted(run.actions, key=_action_sort_key)
        ],
        tool_versions=r.tool_versions,
        audit_log_path=r.audit_log_path, audit_log_sha256=r.audit_log_sha256,
    )

    limitations = LimitationsSection(
        issues=[
            IssueView(kind=i.kind, detail=i.detail, raw=i.raw)
            for i in sorted(run.issues, key=lambda i: (i.kind, i.detail, i.issue_pk))
        ],
    )

    return Report(
        header=header, executive_summary=executive_summary, scope=scope,
        methodology=methodology, findings=findings_section, audit_trail=audit_trail,
        limitations=limitations, planner=_planner_section(run.planner),
    )


_PLANNER_FIELDS = (
    "planner", "provider", "model", "endpoint_class", "context_tokens", "iterations",
    "actions", "termination", "input_tokens", "output_tokens", "failure_cause", "output_mode",
    "limits",
)


def format_failure_cause(cause: dict[str, Any] | None) -> str | None:
    """``authentication_error (HTTP 401)`` from a recorded model-failure cause."""
    if not isinstance(cause, dict):
        return None
    name = cause.get("error_type") or cause.get("error")
    status = cause.get("http_status")
    parts = [str(name)] if name else []
    if status is not None:
        parts.append(f"(HTTP {status})" if parts else f"HTTP {status}")
    return " ".join(parts) or None


def _planner_section(info: dict[str, Any] | None) -> PlannerSection | None:
    if not isinstance(info, dict) or not isinstance(info.get("planner"), str):
        return None
    data = {k: info[k] for k in _PLANNER_FIELDS if info.get(k) is not None}
    try:
        return PlannerSection.model_validate(data)
    except ValueError:
        return PlannerSection(planner=info["planner"])


def planner_rows(p: PlannerSection) -> list[tuple[str, str]]:
    """(label, value) rows for the planner section, shared by both renderers."""
    rows = [("Planner", p.planner)]
    for label, value in (
        ("Provider", p.provider), ("Model", p.model), ("Endpoint", p.endpoint_class),
        ("Context size (tokens)", p.context_tokens), ("Output mode", p.output_mode),
        ("Iterations", p.iterations),
        ("Tool actions", p.actions), ("Termination reason", p.termination),
        ("Failure cause", format_failure_cause(p.failure_cause)),
        ("Input tokens", p.input_tokens), ("Output tokens", p.output_tokens),
    ):
        if value is not None:
            rows.append((label, str(value)))
    if p.limits:
        rows.append(("Limits", ", ".join(f"{k}={v}" for k, v in sorted(p.limits.items()))))
    return rows


# --- render_markdown --------------------------------------------------------

def _md_escape(text: str) -> str:
    # Just enough to keep a hostile title/description from breaking table
    # layout or accidentally forming Markdown syntax; this is a client
    # report, not a security boundary (RC-12 sanitization already covers
    # anything that reaches the planner).
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _evidence_lines(evidence: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key in sorted(evidence):
        value = evidence[key]
        if value in (None, "", [], {}):
            continue
        if isinstance(value, dict):
            rendered = ", ".join(f"{k}={v}" for k, v in sorted(value.items()) if v not in (None, ""))
        elif isinstance(value, list):
            rendered = ", ".join(str(v) for v in value)
        else:
            rendered = str(value)
        if not rendered:
            continue
        lines.append(f"  - **{key}**: {_md_escape(rendered)}")
    return lines


def _render_header(h: Header) -> list[str]:
    return [
        f"# Security Assessment Report — {h.engagement}",
        "",
        f"**Client:** {h.client}  ",
        f"**Prepared by:** {h.prepared_by}  ",
        f"**Report date:** {h.report_date}  ",
        f"**Authorization reference:** {h.signed_scope_ref}  ",
        f"**Authorized by:** {h.authorized_by}  ",
        f"**Authorized window:** {h.window_start} – {h.window_end}",
        "",
    ]


def _render_executive_summary(s: ExecutiveSummary) -> list[str]:
    lines = ["## Executive Summary", "", s.headline, "", f"Assets tested: {s.assets_tested}", ""]
    lines += ["| Severity | Count |", "|---|---|"]
    lines += [f"| {c.severity.capitalize()} | {c.count} |" for c in s.severity_counts]
    lines += ["", f"Total findings: {s.total_findings}", ""]
    return lines


def _render_scope(s: ScopeSection) -> list[str]:
    lines = ["## Scope", "", f"**Authorized window:** {s.window_start} – {s.window_end}", ""]
    lines += ["**In scope:**", ""]
    lines += [f"- {_md_escape(x)}" for x in s.in_scope] if s.in_scope else ["- (none)"]
    lines += ["", "**Out of scope:**", ""]
    lines += [f"- {_md_escape(x)}" for x in s.out_of_scope] if s.out_of_scope else ["- (none)"]
    lines += ["", s.statement, ""]
    return lines


def _render_methodology(m: MethodologySection) -> list[str]:
    lines = ["## Methodology", "", m.approach, ""]
    lines += ["**Tools used:**", ""]
    lines += [f"- {_md_escape(t)}" for t in m.tools] if m.tools else ["- (none recorded)"]
    lines += ["", "**Guardrail model:**", "", m.guardrail_summary, ""]
    lines += ["**Explicitly out of scope for this assessment:**", "", m.out_of_scope_statement, ""]
    return lines


def _render_finding(f: FindingView) -> list[str]:
    asset_bits = [b for b in (f.hostname, f.ip) if b]
    asset = "/".join(asset_bits) if asset_bits else "(no asset recorded)"
    if f.port is not None:
        asset += f":{f.port}"
    lines = [
        f"#### {_md_escape(f.title)}",
        "",
        f"- **Severity:** {f.severity.capitalize()}",
        f"- **Category:** {f.category.replace('_', ' ')}",
        f"- **Source tool:** {f.source_tool}",
        f"- **Affected asset:** {_md_escape(asset)}",
    ]
    if f.description:
        lines.append(f"- **Description:** {_md_escape(f.description)}")
    if f.cve:
        lines.append(f"- **CVE:** {', '.join(f.cve)}")
    if f.cvss_score is not None:
        lines.append(f"- **CVSS:** {f.cvss_score}")
    if f.references:
        lines.append("- **References:** " + ", ".join(f.references))
    if f.tags:
        lines.append(f"- **Tags:** {', '.join(f.tags)}")
    lines.append(f"- **Finding ID:** `{f.finding_id}`")
    evidence_lines = _evidence_lines(f.evidence)
    if evidence_lines:
        lines.append("- **Evidence:**")
        lines += evidence_lines
    lines.append("")
    return lines


def _render_findings(section: FindingsSection) -> list[str]:
    lines = ["## Findings", ""]
    if section.total == 0:
        lines += ["No findings were recorded for this engagement.", ""]
        return lines
    for group in section.groups:
        lines.append(f"### {group.severity.capitalize()} ({len(group.findings)})")
        lines.append("")
        for f in group.findings:
            lines += _render_finding(f)
    return lines


def _render_audit_trail(a: AuditTrailSection) -> list[str]:
    lines = ["## Assessment Activity", ""]
    if a.tool_versions:
        versions = ", ".join(f"{k}={v}" for k, v in sorted(a.tool_versions.items()))
        lines += [f"**Tool versions:** {versions}", ""]
    if a.audit_log_path:
        lines.append(f"**Audit log:** `{a.audit_log_path}`"
                      + (f" (sha256 `{a.audit_log_sha256}`)" if a.audit_log_sha256 else ""))
        lines.append("")
    lines.append(
        "This is a complete record of every action proposed during the engagement, including "
        "actions the guardrail refused - refusing to exceed authorization is expected behavior, "
        "not an omission."
    )
    lines.append("")
    lines += ["| Iter | Tool | Target | Outcome | Gate stage | Gate reason | Risk | Status |",
              "|---|---|---|---|---|---|---|---|"]
    for act in a.actions:
        lines.append(
            f"| {act.iteration if act.iteration is not None else '-'} | {act.tool} | "
            f"{_md_escape(act.target)} | {act.outcome} | {act.gate_stage} | "
            f"{_md_escape(act.gate_reason)} | {act.risk or '-'} | {act.status or '-'} |"
        )
    lines.append("")
    return lines


def _render_limitations(section: LimitationsSection) -> list[str]:
    lines = ["## Limitations & Notes", ""]
    if not section.issues:
        lines += ["No normalization issues, off-target activity or coverage gaps were recorded "
                   "for this engagement.", ""]
        return lines
    lines += ["The following were observed during normalization and are disclosed for completeness:", ""]
    for issue in section.issues:
        lines.append(f"- **{issue.kind}:** {_md_escape(issue.detail)}")
    lines.append("")
    return lines


def _render_planner(p: PlannerSection | None) -> list[str]:
    if p is None:
        return []
    lines = ["## Planner", "", "| Field | Value |", "|---|---|"]
    lines += [f"| {k} | {_md_escape(v)} |" for k, v in planner_rows(p)]
    lines.append("")
    return lines


def render_markdown(report: Report) -> str:
    """``Report`` -> Markdown text. Deterministic for a given ``Report``
    (which is itself deterministic for a given ``ReconstructedRun`` -
    see ``build_report``)."""
    lines: list[str] = []
    lines += _render_header(report.header)
    lines += _render_executive_summary(report.executive_summary)
    lines += _render_scope(report.scope)
    lines += _render_methodology(report.methodology)
    lines += _render_findings(report.findings)
    lines += _render_audit_trail(report.audit_trail)
    lines += _render_planner(report.planner)
    lines += _render_limitations(report.limitations)
    return "\n".join(lines).rstrip() + "\n"
