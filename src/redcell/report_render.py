# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-18: render the RC-17 ``Report`` model to a self-contained HTML
document, and (optionally) to PDF.

**Builds on the model, not the Markdown.** RC-17 split the report into a
pure ``Report`` model (``redcell.report.build_report``) and
``render_markdown``. This module renders that SAME model to HTML -
``render_html`` never reparses or depends on the Markdown text, so the two
renderers can never drift from each other in a way that isn't also a drift
in the underlying model.

**HTML.** ``render_html`` produces one self-contained document: every style
is inline in a single ``<style>`` block, and nothing references an external
URL (no ``http(s)://`` asset, no CDN font, no remote stylesheet) - the file
opens correctly offline, as a client deliverable should. It carries print
CSS (``@page``, page-break rules, a repeating table header) so a long report
paginates correctly when printed or converted to PDF.

**PDF.** ``render_pdf`` renders the HTML and converts it with whichever
backend is importable, in order: `weasyprint`, then `playwright` (+
Chromium). Neither import happens unless ``render_pdf`` is actually called,
so the HTML path (and the default test suite) never needs either installed.
Enable PDF with ``pip install 'redcell[report-pdf]'`` (weasyprint) or by
installing Playwright and its Chromium browser yourself - see
``NoPdfBackendAvailable``'s message for exact instructions.

**CLI.** ``python -m redcell.report_render --db <evidence.db> --run <run_id>
--out <dir> --format html|pdf|both`` - one repeatable command, no manual
editing of generated output.
"""

from __future__ import annotations

import argparse
import html as _html
import sys
from pathlib import Path

from redcell.evidence import EvidenceStore
from redcell.report import (
    ActionView,
    FindingView,
    MethodologySection,
    Report,
    ScopeSection,
    build_report,
)

__all__ = [
    "render_html",
    "render_pdf",
    "NoPdfBackendAvailable",
    "main",
]

_SEVERITY_COLORS = {
    "critical": ("#7f1d1d", "#fee2e2"),
    "high": ("#9a3412", "#ffedd5"),
    "medium": ("#854d0e", "#fef9c3"),
    "low": ("#1e40af", "#dbeafe"),
    "info": ("#374151", "#f3f4f6"),
}


def _e(text: object) -> str:
    """HTML-escape. Every piece of text in this document - including
    anything originating from a scanned target's banners/output via the
    RC-16 store - goes through this before it reaches the page."""
    return _html.escape("" if text is None else str(text), quote=True)


_STYLE = """
:root {
  --ink: #1f2937;
  --muted: #6b7280;
  --border: #d1d5db;
  --accent: #0f172a;
}
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", Helvetica, Arial, sans-serif;
  color: var(--ink);
  background: #ffffff;
  margin: 0;
  padding: 2rem 2.5rem;
  line-height: 1.5;
  font-size: 11pt;
}
h1, h2, h3, h4 { color: var(--accent); line-height: 1.25; }
h1 { font-size: 20pt; margin: 0 0 0.25rem 0; }
h2 {
  font-size: 15pt;
  margin-top: 2rem;
  padding-bottom: 0.25rem;
  border-bottom: 2px solid var(--border);
}
h3 { font-size: 12.5pt; margin-top: 1.25rem; }
h4 { font-size: 11.5pt; margin-top: 1rem; margin-bottom: 0.4rem; }
.header-block {
  border-bottom: 3px solid var(--accent);
  padding-bottom: 1rem;
  margin-bottom: 1.5rem;
}
.header-block .prepared-by { color: var(--muted); font-weight: 600; }
.meta-table { margin-top: 0.75rem; border-collapse: collapse; }
.meta-table td { padding: 0.15rem 0.75rem 0.15rem 0; vertical-align: top; }
.meta-table td.label { color: var(--muted); white-space: nowrap; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.75rem 0;
}
thead { display: table-header-group; }
th, td {
  border: 1px solid var(--border);
  padding: 0.4rem 0.6rem;
  text-align: left;
  font-size: 10pt;
}
th { background: #f3f4f6; }
tr { break-inside: avoid; page-break-inside: avoid; }
.badge {
  display: inline-block;
  padding: 0.1rem 0.6rem;
  border-radius: 999px;
  font-size: 9.5pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.02em;
}
.finding {
  border: 1px solid var(--border);
  border-left: 5px solid var(--border);
  border-radius: 4px;
  padding: 0.75rem 1rem;
  margin: 0.75rem 0;
  break-inside: avoid;
  page-break-inside: avoid;
}
.finding dl { margin: 0.4rem 0 0 0; }
.finding dt { font-weight: 600; color: var(--muted); float: left; clear: left; width: 9.5rem; }
.finding dd { margin: 0 0 0.15rem 9.5rem; }
.evidence {
  margin-top: 0.4rem;
  background: #f9fafb;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.5rem 0.75rem;
  font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
  font-size: 9.5pt;
}
.evidence div { margin: 0.1rem 0; }
.section { page-break-before: always; break-before: page; }
.section:first-of-type { page-break-before: auto; break-before: auto; }
code { font-family: "Consolas", "SFMono-Regular", Menlo, monospace; font-size: 9.5pt; }
.statement { color: var(--muted); font-style: italic; }
@page {
  size: A4;
  margin: 2.2cm 1.8cm 2.6cm 1.8cm;
  @bottom-center {
    content: "Page " counter(page) " of " counter(pages);
    font-size: 9pt;
    color: #6b7280;
  }
}
"""


def _severity_badge(severity: str) -> str:
    fg, bg = _SEVERITY_COLORS.get(severity, _SEVERITY_COLORS["info"])
    return f'<span class="badge" style="color:{fg};background:{bg};">{_e(severity)}</span>'


def _render_header(report: Report) -> str:
    h = report.header
    return f"""
<div class="header-block">
  <h1>Security Assessment Report &mdash; {_e(h.engagement)}</h1>
  <div class="prepared-by">Prepared by {_e(h.prepared_by)}</div>
  <table class="meta-table">
    <tr><td class="label">Client</td><td>{_e(h.client)}</td></tr>
    <tr><td class="label">Report date</td><td>{_e(h.report_date)}</td></tr>
    <tr><td class="label">Authorization reference</td><td>{_e(h.signed_scope_ref)}</td></tr>
    <tr><td class="label">Authorized by</td><td>{_e(h.authorized_by)}</td></tr>
    <tr><td class="label">Authorized window</td><td>{_e(h.window_start)} &ndash; {_e(h.window_end)}</td></tr>
  </table>
</div>
""".strip()


def _render_executive_summary(report: Report) -> str:
    s = report.executive_summary
    rows = "".join(
        f"<tr><td>{_severity_badge(c.severity)}</td><td>{c.count}</td></tr>" for c in s.severity_counts
    )
    return f"""
<div class="section">
  <h2>Executive Summary</h2>
  <p>{_e(s.headline)}</p>
  <p>Assets tested: <strong>{s.assets_tested}</strong></p>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <p>Total findings: <strong>{s.total_findings}</strong></p>
</div>
""".strip()


def _render_scope(scope: ScopeSection) -> str:
    def _list(items: list[str]) -> str:
        if not items:
            return "<li>(none)</li>"
        return "".join(f"<li><code>{_e(x)}</code></li>" for x in items)

    return f"""
<div class="section">
  <h2>Scope</h2>
  <p>Authorized window: <strong>{_e(scope.window_start)} &ndash; {_e(scope.window_end)}</strong></p>
  <h3>In scope</h3>
  <ul>{_list(scope.in_scope)}</ul>
  <h3>Out of scope</h3>
  <ul>{_list(scope.out_of_scope)}</ul>
  <p class="statement">{_e(scope.statement)}</p>
</div>
""".strip()


def _render_methodology(m: MethodologySection) -> str:
    tools = "".join(f"<li>{_e(t)}</li>" for t in m.tools) if m.tools else "<li>(none recorded)</li>"
    return f"""
<div class="section">
  <h2>Methodology</h2>
  <p>{_e(m.approach)}</p>
  <h3>Tools used</h3>
  <ul>{tools}</ul>
  <h3>Guardrail model</h3>
  <p>{_e(m.guardrail_summary)}</p>
  <h3>Explicitly out of scope for this assessment</h3>
  <p>{_e(m.out_of_scope_statement)}</p>
</div>
""".strip()


def _evidence_html(evidence: dict) -> str:
    rows = []
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
        rows.append(f"<div><strong>{_e(key)}:</strong> {_e(rendered)}</div>")
    return "".join(rows)


def _render_finding(f: FindingView) -> str:
    asset_bits = [b for b in (f.hostname, f.ip) if b]
    asset = "/".join(asset_bits) if asset_bits else "(no asset recorded)"
    if f.port is not None:
        asset += f":{f.port}"

    rows = [
        ("Severity", _severity_badge(f.severity)),
        ("Category", _e(f.category.replace("_", " "))),
        ("Source tool", _e(f.source_tool)),
        ("Affected asset", f"<code>{_e(asset)}</code>"),
    ]
    if f.description:
        rows.append(("Description", _e(f.description)))
    if f.cve:
        rows.append(("CVE", _e(", ".join(f.cve))))
    if f.cvss_score is not None:
        rows.append(("CVSS", _e(f.cvss_score)))
    if f.references:
        rows.append(("References", _e(", ".join(f.references))))
    if f.tags:
        rows.append(("Tags", _e(", ".join(f.tags))))
    rows.append(("Finding ID", f"<code>{_e(f.finding_id)}</code>"))

    dl = "".join(f"<dt>{_e(label)}</dt><dd>{value}</dd>" for label, value in rows)
    evidence_html = _evidence_html(f.evidence)
    evidence_block = f'<div class="evidence">{evidence_html}</div>' if evidence_html else ""
    border = _SEVERITY_COLORS.get(f.severity, _SEVERITY_COLORS["info"])[0]
    return (
        f'<div class="finding" style="border-left-color:{border};">'
        f"<h4>{_e(f.title)}</h4><dl>{dl}</dl>{evidence_block}</div>"
    )


def _render_findings(report: Report) -> str:
    section = report.findings
    if section.total == 0:
        body = "<p>No findings were recorded for this engagement.</p>"
    else:
        parts = []
        for group in section.groups:
            findings_html = "".join(_render_finding(f) for f in group.findings)
            parts.append(f"<h3>{_e(group.severity.capitalize())} ({len(group.findings)})</h3>{findings_html}")
        body = "".join(parts)
    return f'<div class="section"><h2>Findings</h2>{body}</div>'


def _render_audit_trail(report: Report) -> str:
    a = report.audit_trail
    version_line = ""
    if a.tool_versions:
        versions = ", ".join(f"{_e(k)}={_e(v)}" for k, v in sorted(a.tool_versions.items()))
        version_line = f"<p><strong>Tool versions:</strong> {versions}</p>"
    audit_line = ""
    if a.audit_log_path:
        sha = f" (sha256 <code>{_e(a.audit_log_sha256)}</code>)" if a.audit_log_sha256 else ""
        audit_line = f"<p><strong>Audit log:</strong> <code>{_e(a.audit_log_path)}</code>{sha}</p>"

    def _row(act: ActionView) -> str:
        return (
            "<tr>"
            f"<td>{act.iteration if act.iteration is not None else '-'}</td>"
            f"<td>{_e(act.tool)}</td><td><code>{_e(act.target)}</code></td>"
            f"<td>{_e(act.outcome)}</td><td>{_e(act.gate_stage)}</td>"
            f"<td>{_e(act.gate_reason)}</td><td>{_e(act.risk or '-')}</td>"
            f"<td>{_e(act.status or '-')}</td></tr>"
        )

    rows = "".join(_row(a) for a in a.actions)
    return f"""
<div class="section">
  <h2>Assessment Activity</h2>
  {version_line}
  {audit_line}
  <p>This is a complete record of every action proposed during the engagement, including actions
  the guardrail refused &mdash; refusing to exceed authorization is expected behavior, not an omission.</p>
  <table>
    <thead><tr><th>Iter</th><th>Tool</th><th>Target</th><th>Outcome</th><th>Gate stage</th>
    <th>Gate reason</th><th>Risk</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
""".strip()


def _render_limitations(report: Report) -> str:
    section = report.limitations
    if not section.issues:
        body = (
            "<p>No normalization issues, off-target activity or coverage gaps were recorded "
            "for this engagement.</p>"
        )
    else:
        items = "".join(
            f"<li><strong>{_e(i.kind)}:</strong> {_e(i.detail)}</li>" for i in section.issues
        )
        body = (
            "<p>The following were observed during normalization and are disclosed for "
            f"completeness:</p><ul>{items}</ul>"
        )
    return f'<div class="section"><h2>Limitations &amp; Notes</h2>{body}</div>'


def render_html(report: Report) -> str:
    """``Report`` -> a single self-contained HTML document. Deterministic
    for a given ``Report`` (which is itself deterministic for a given
    ``ReconstructedRun`` - see ``redcell.report.build_report``). No external
    reference of any kind: every style is inlined, nothing points at a URL."""
    body = "".join([
        _render_header(report),
        _render_executive_summary(report),
        _render_scope(report.scope),
        _render_methodology(report.methodology),
        _render_findings(report),
        _render_audit_trail(report),
        _render_limitations(report),
    ])
    title = _e(f"Security Assessment Report - {report.header.engagement}")
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f"<title>{title}</title>\n"
        f"<style>{_STYLE}</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


# --- PDF ----------------------------------------------------------------

class NoPdfBackendAvailable(RuntimeError):
    """Neither weasyprint nor Playwright+Chromium is importable/installed."""

    def __init__(self) -> None:
        super().__init__(
            "No PDF rendering backend is available. Enable one of:\n"
            "  pip install 'redcell[report-pdf]'   # weasyprint (recommended, pure Python deps)\n"
            "  pip install playwright && playwright install chromium   # alternative backend\n"
            "The HTML report (render_html) needs neither and always works."
        )


def _pdf_via_weasyprint(html_text: str, out_path: Path) -> None:
    import weasyprint  # noqa: PLC0415 - imported lazily, only when this backend is chosen

    weasyprint.HTML(string=html_text, base_url=str(out_path.parent)).write_pdf(str(out_path))


def _pdf_via_playwright(html_text: str, out_path: Path) -> None:
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            page.set_content(html_text, wait_until="load")
            page.pdf(path=str(out_path), format="A4", print_background=True, display_header_footer=False)
        finally:
            browser.close()


def render_pdf(report: Report, out_path: str | Path) -> Path:
    """Render ``report`` to HTML, then convert it to a PDF at ``out_path``
    using the first available backend (weasyprint, then Playwright+
    Chromium). Raises ``NoPdfBackendAvailable`` naming exactly what to
    install if neither is importable. Never imports a backend unless it is
    actually used."""
    out_path = Path(out_path)
    html_text = render_html(report)

    try:
        import weasyprint  # noqa: F401
    except ImportError:
        pass
    else:
        _pdf_via_weasyprint(html_text, out_path)
        return out_path

    try:
        import playwright  # noqa: F401
    except ImportError:
        pass
    else:
        _pdf_via_playwright(html_text, out_path)
        return out_path

    raise NoPdfBackendAvailable()


# --- CLI ------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a stored Red Cell run to a client report (RC-17/18)."
    )
    parser.add_argument("--db", required=True, help="path to the evidence store (.db)")
    parser.add_argument("--run", required=True, help="run_id to render")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--format", choices=["html", "pdf", "both"], default="html")
    args = parser.parse_args(argv)

    store = EvidenceStore(args.db)
    reconstructed = store.reconstruct_run(args.run)
    report = build_report(reconstructed)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{report.header.engagement}-{args.run}"

    if args.format in ("html", "both"):
        html_path = out_dir / f"{stem}.html"
        html_path.write_text(render_html(report), encoding="utf-8")
        print(f"wrote {html_path}")

    if args.format in ("pdf", "both"):
        pdf_path = out_dir / f"{stem}.pdf"
        try:
            render_pdf(report, pdf_path)
        except NoPdfBackendAvailable as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"wrote {pdf_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
