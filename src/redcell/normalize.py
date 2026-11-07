# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-15: normalize nmap and nuclei output into one findings schema.

Input is the already-STRUCTURED ``ToolOutput.findings`` dict each wrapper
produces (``parse_nmap_xml`` / ``parse_nuclei_jsonl`` output), not raw
XML/JSONL. This module is pure: no I/O, no evidence-store coupling (RC-16
consumes the ``Finding`` model; it isn't built here), and it never imports
the concrete tool modules (``nmap_tool``/``nuclei_tool``) - only ``tools.py``
does that (RC-21's import-boundary test covers this).

Design rules, each load-bearing:

* **Deterministic ``finding_id``.** Hashes ``(source_tool, asset.ip or
  asset.hostname, asset.port, category, a stable key)`` - never a timestamp
  or anything else that varies run to run - so re-running a scan or
  deduplicating across runs is possible (RC-20's repeatability check and
  RC-16's evidence store both depend on this).
* **No cross-tool reconciliation.** nmap and nuclei disagreeing about a
  service's identity (PLANTED_VULNS correction C-1: nmap calls port 3000
  `ppp`, nuclei says `http`) is real and reported as-is, as two findings.
  Correlating/reconciling tool identities is a later ticket.
* **Severity is not invented.** nuclei's severity is a direct passthrough;
  nmap-derived findings get the "info" baseline. Escalation rules are a
  later concern.
* **Nothing is silently dropped.** Anything that cannot be mapped - a
  malformed dict, a host reported down, an off-target nuclei hit, unparsed
  lines - becomes a ``NormalizationIssue`` carrying the raw snippet, never a
  silent drop and never a crash.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Category",
    "Severity",
    "Asset",
    "Provenance",
    "Finding",
    "NormalizationIssue",
    "NormalizedResult",
    "normalize_nmap",
    "normalize_nuclei",
    "normalize",
    "normalize_execution_result",
]


class Category(str, Enum):
    OPEN_PORT = "open_port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    EXPOSURE = "exposure"
    MISCONFIGURATION = "misconfiguration"
    VULNERABILITY = "vulnerability"
    SCRIPT_OUTPUT = "script_output"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Asset(_Frozen):
    hostname: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    scheme: str | None = None


class Provenance(_Frozen):
    engagement: str
    scanner: str
    scanner_version: str | None = None
    templates_pin: str | None = None
    raw_sha256: str | None = None
    scanned_ip: str | None = None
    observed_at: str | None = None


class Finding(_Frozen):
    finding_id: str
    source_tool: str
    category: Category
    title: str
    severity: Severity
    asset: Asset
    description: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    tags: list[str] = Field(default_factory=list)
    provenance: Provenance


class NormalizationIssue(_Frozen):
    kind: str
    detail: str
    raw: Any = None


class NormalizedResult(_Frozen):
    findings: list[Finding] = Field(default_factory=list)
    issues: list[NormalizationIssue] = Field(default_factory=list)
    provenance: Provenance


# --- shared helpers ----------------------------------------------------------

def _finding_id(source_tool: str, asset: Asset, category: Category, key: str) -> str:
    """16 hex chars, stable across runs: no timestamp, no raw text, nothing
    that varies between two normalizations of the same logical finding."""
    ident = asset.ip or asset.hostname or ""
    canonical = "\x1f".join((
        source_tool, ident, "" if asset.port is None else str(asset.port),
        category.value, key or "",
    ))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _finding(
    source_tool: str, category: Category, title: str, severity: Severity, asset: Asset,
    description: str | None, evidence: dict[str, Any], references: list[str], cve: list[str],
    cvss_score: float | None, tags: list[str], provenance: Provenance, *, key: str,
) -> Finding:
    return Finding(
        finding_id=_finding_id(source_tool, asset, category, key),
        source_tool=source_tool, category=category, title=title, severity=severity,
        asset=asset, description=description or None, evidence=evidence,
        references=list(references), cve=list(cve), cvss_score=cvss_score,
        tags=list(tags), provenance=provenance,
    )


def _malformed(kind: str, detail: str, raw: object) -> NormalizationIssue:
    return NormalizationIssue(kind=kind, detail=detail, raw=raw)


# --- nmap ---------------------------------------------------------------------

_MISCONFIG_SCRIPT_MARKERS = ("security-headers", "cors")


def _nmap_port_title(port: dict[str, Any], svc: dict[str, Any] | None) -> str:
    base = f"Open {port.get('port')}/{port.get('protocol')}"
    if not svc:
        return base
    name_part = " ".join(b for b in (svc.get("product") or "", svc.get("version") or "") if b).strip()
    extra = svc.get("extrainfo") or ""
    if extra:
        name_part = f"{name_part} {extra}".strip() if name_part else extra
    return f"{base} - {name_part}" if name_part else base


def _nmap_script_finding(script: dict[str, Any], asset: Asset, provenance: Provenance) -> Finding:
    script_id = str(script.get("id") or "")
    category = (
        Category.MISCONFIGURATION
        if any(marker in script_id for marker in _MISCONFIG_SCRIPT_MARKERS)
        else Category.SCRIPT_OUTPUT
    )
    return _finding(
        "nmap", category, f"nmap script {script_id}", Severity.INFO, asset,
        None, {"output": script.get("output")}, [], [], None, [], provenance, key=script_id,
    )


def normalize_nmap(
    findings: object, *, provenance: Provenance,
) -> tuple[list[Finding], list[NormalizationIssue]]:
    """Map one nmap ``ToolOutput.findings`` dict into ``Finding``s. Never
    raises: anything unmappable becomes a ``NormalizationIssue``."""
    issues: list[NormalizationIssue] = []
    if not isinstance(findings, dict):
        issues.append(_malformed("malformed_nmap_output", "findings is not a dict", findings))
        return [], issues

    if findings.get("status") == "error":
        err = findings.get("error") if isinstance(findings.get("error"), dict) else {}
        issues.append(_malformed(
            str(err.get("code") or "nmap_error"),
            str(err.get("message") or "nmap reported an error"),
            err or findings,
        ))

    hosts = findings.get("hosts")
    if not isinstance(hosts, list):
        if "hosts" in findings:
            issues.append(_malformed("malformed_nmap_hosts", "'hosts' is not a list", findings.get("hosts")))
        hosts = []

    target_hostname = findings.get("target_hostname")
    out: list[Finding] = []
    for host in hosts:
        if not isinstance(host, dict):
            issues.append(_malformed("malformed_nmap_host", "a host entry is not a dict", host))
            continue
        if host.get("status") != "up":
            issues.append(_malformed("nmap_host_down", f"host status={host.get('status')!r}", host))
            continue

        ip = next(
            (a.get("address") for a in host.get("addresses", []) or []
             if isinstance(a, dict) and a.get("type") == "ipv4"),
            None,
        )

        for port in host.get("ports", []) or []:
            if not isinstance(port, dict):
                issues.append(_malformed("malformed_nmap_port", "a port entry is not a dict", port))
                continue
            svc = port.get("service") if isinstance(port.get("service"), dict) else None
            port_asset = Asset(hostname=target_hostname, ip=ip, port=port.get("port"),
                                protocol=port.get("protocol"), scheme=None)
            if port.get("state") == "open":
                category = Category.SERVICE if (svc and svc.get("product")) else Category.OPEN_PORT
                title = _nmap_port_title(port, svc)
                evidence: dict[str, Any] = {"reason": port.get("reason")}
                if svc:
                    evidence["service"] = svc
                out.append(_finding(
                    "nmap", category, title, Severity.INFO, port_asset,
                    None, evidence, [], [], None, [], provenance, key=title,
                ))
            for script in port.get("scripts", []) or []:
                if not isinstance(script, dict):
                    issues.append(_malformed("malformed_nmap_script", "a script entry is not a dict", script))
                    continue
                out.append(_nmap_script_finding(script, port_asset, provenance))

        host_asset = Asset(hostname=target_hostname, ip=ip, port=None, protocol=None, scheme=None)
        for script in host.get("host_scripts", []) or []:
            if not isinstance(script, dict):
                issues.append(_malformed("malformed_nmap_host_script", "a host_script entry is not a dict", script))
                continue
            out.append(_nmap_script_finding(script, host_asset, provenance))

    for warning in findings.get("warnings") or []:
        issues.append(_malformed("nmap_warning", str(warning), warning))

    return out, issues


# --- nuclei -------------------------------------------------------------------

def _nuclei_category(tags: set[str]) -> Category:
    if tags & {"cve", "kev", "vuln"}:
        return Category.VULNERABILITY
    if "exposure" in tags:
        return Category.EXPOSURE
    if tags & {"misconfig", "config"}:
        return Category.MISCONFIGURATION
    if "tech" in tags:
        return Category.TECHNOLOGY
    return Category.OTHER


def _nuclei_severity(value: object, issues: list[NormalizationIssue]) -> Severity:
    if isinstance(value, str):
        try:
            return Severity(value.strip().lower())
        except ValueError:
            pass
    issues.append(_malformed(
        "nuclei_unknown_severity", f"unrecognized severity {value!r}; defaulted to info", value,
    ))
    return Severity.INFO


def _nuclei_scheme_port(matched_at: object) -> tuple[str | None, int | None]:
    if not isinstance(matched_at, str) or not matched_at:
        return None, None
    try:
        parts = urlsplit(matched_at)
        return parts.scheme or None, parts.port
    except ValueError:
        return None, None


def _cve_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _nuclei_finding(
    f: dict[str, Any], hostname: str | None, provenance: Provenance, issues: list[NormalizationIssue],
) -> Finding:
    tags = {str(t).strip().lower() for t in (f.get("tags") or []) if str(t).strip()}
    category = _nuclei_category(tags)
    severity = _nuclei_severity(f.get("severity"), issues)
    scheme, port = _nuclei_scheme_port(f.get("matched_at"))
    asset = Asset(hostname=hostname, ip=f.get("ip") or None, port=port,
                  protocol="tcp" if port else None, scheme=scheme)
    template_id = f.get("template_id") or ""
    title = f.get("name") or template_id or "nuclei finding"
    evidence = {
        "matched_at": f.get("matched_at"),
        "matcher_name": f.get("matcher_name") or None,
        "extracted": list(f.get("extracted") or []),
        "template_id": template_id,
    }
    return _finding(
        "nuclei", category, title, severity, asset, f.get("description"), evidence,
        list(f.get("references") or []), _cve_list(f.get("cve")), f.get("cvss_score"),
        sorted(tags), provenance, key=template_id or title,
    )


def normalize_nuclei(
    findings: object, *, provenance: Provenance,
) -> tuple[list[Finding], list[NormalizationIssue]]:
    """Map one nuclei ``ToolOutput.findings`` dict into ``Finding``s. Never
    raises: anything unmappable becomes a ``NormalizationIssue``. Off-target
    hits are never emitted as findings (the wrapper already excludes them
    from ``findings``); their presence is reported as an issue instead."""
    issues: list[NormalizationIssue] = []
    if not isinstance(findings, dict):
        issues.append(_malformed("malformed_nuclei_output", "findings is not a dict", findings))
        return [], issues

    if findings.get("status") == "error":
        err = findings.get("error") if isinstance(findings.get("error"), dict) else {}
        code = str(err.get("code") or "nuclei_error")
        raw = findings.get("off_target_hosts") if code == "off_target_activity" else (err or findings)
        issues.append(_malformed(code, str(err.get("message") or "nuclei reported an error"), raw))

    summary = findings.get("summary") if isinstance(findings.get("summary"), dict) else {}
    unparsed = summary.get("unparsed_lines")
    if isinstance(unparsed, int) and unparsed > 0:
        issues.append(_malformed("nuclei_unparsed_lines", f"{unparsed} unparsed output line(s)", None))

    raw_findings = findings.get("findings")
    if not isinstance(raw_findings, list):
        if "findings" in findings:
            issues.append(_malformed("malformed_nuclei_findings", "'findings' is not a list", raw_findings))
        raw_findings = []

    hostname = findings.get("target_hostname")
    out: list[Finding] = []
    for f in raw_findings:
        if not isinstance(f, dict):
            issues.append(_malformed("malformed_nuclei_finding", "a finding entry is not a dict", f))
            continue
        out.append(_nuclei_finding(f, hostname, provenance, issues))

    return out, issues


# --- dispatch -------------------------------------------------------------

_NORMALIZERS = {"nmap": normalize_nmap, "nuclei": normalize_nuclei}


def normalize(tool: str, findings: object, *, provenance: Provenance) -> NormalizedResult:
    """Dispatch on ``tool`` ("nmap"/"nuclei"). An unknown tool is reported as
    an issue, never a crash - the same "never silently drop" guarantee as
    everything else here."""
    normalizer = _NORMALIZERS.get(tool)
    if normalizer is None:
        return NormalizedResult(
            findings=[],
            issues=[_malformed("unknown_tool", f"no normalizer for tool {tool!r}", findings)],
            provenance=provenance,
        )
    found, issues = normalizer(findings, provenance=provenance)
    return NormalizedResult(findings=found, issues=issues, provenance=provenance)


def normalize_execution_result(result: object, *, engagement: str, observed_at: str | None = None) -> NormalizedResult:
    """Convenience: build a ``NormalizedResult`` straight from a
    ``redcell.tools.ExecutionResult`` (RC-7/RC-8 produce these). Takes
    ``result`` as ``object`` rather than importing ``ExecutionResult`` by
    name to keep this module's import surface minimal; any object with the
    same shape (duck-typed) works, which is what the tests exercise."""
    from redcell.sanitize import sha256_of

    tool = getattr(getattr(result, "action", None), "tool", None)
    tool = tool if isinstance(tool, str) else "unknown"

    findings_obj = getattr(result, "findings", None)
    findings_dict = findings_obj if isinstance(findings_obj, dict) else None
    scanner_version = findings_dict.get("version") if findings_dict else None
    templates_pin = findings_dict.get("templates_pin") if findings_dict else None

    raw_output = getattr(result, "raw_output", None)
    raw_sha256 = sha256_of(raw_output) if raw_output is not None else None

    decision = getattr(result, "decision", None)
    resolved_ips = getattr(decision, "resolved_ips", ()) or ()
    scanned_ip = resolved_ips[0] if resolved_ips else None

    provenance = Provenance(
        engagement=engagement, scanner=tool, scanner_version=scanner_version,
        templates_pin=templates_pin, raw_sha256=raw_sha256, scanned_ip=scanned_ip,
        observed_at=observed_at,
    )

    if not getattr(result, "executed", False):
        reason = getattr(decision, "reason", None) or "action was not executed"
        return NormalizedResult(
            findings=[], issues=[_malformed("not_executed", str(reason), None)], provenance=provenance,
        )

    return normalize(tool, findings_dict if findings_dict is not None else {}, provenance=provenance)
