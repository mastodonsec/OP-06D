# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RC-15 (redcell.normalize), exercised against the frozen RC-20
real captures in lab/captures/*.findings.json so the schema is proven
against actual tool output, not just hand-written samples."""

from __future__ import annotations

import json
import pathlib

import pytest

from redcell.normalize import (
    Category,
    NormalizedResult,
    Provenance,
    Severity,
    normalize,
    normalize_execution_result,
    normalize_nmap,
    normalize_nuclei,
)

CAPTURES = pathlib.Path(__file__).parent.parent / "lab" / "captures"


def _load(name: str) -> dict:
    return json.loads((CAPTURES / name).read_text(encoding="utf-8"))


def _provenance(**overrides) -> Provenance:
    base = dict(engagement="rc-lab-2026-11", scanner="test")
    base.update(overrides)
    return Provenance(**base)


# --- nmap, real captures -----------------------------------------------------

def test_dvwa_service_scan_yields_one_service_finding():
    findings, issues = normalize_nmap(_load("nmap_dvwa_service.findings.json"), provenance=_provenance())
    assert issues == []
    assert len(findings) == 1
    f = findings[0]
    assert f.category == Category.SERVICE
    assert f.severity == Severity.INFO
    assert f.title == "Open 80/tcp - Apache httpd 2.4.25 (Debian)"
    assert f.asset.ip == "172.31.77.11"
    assert f.asset.port == 80
    assert f.asset.protocol == "tcp"
    assert f.evidence["service"]["product"] == "Apache httpd"


def test_juice_shop_port_with_no_product_is_open_port_not_service():
    findings, issues = normalize_nmap(_load("nmap_juice-shop_service.findings.json"), provenance=_provenance())
    assert issues == []
    assert len(findings) == 1
    f = findings[0]
    assert f.category == Category.OPEN_PORT
    assert f.title == "Open 3000/tcp"
    assert f.asset.ip == "172.31.77.10"


def test_dvwa_default_profile_port_with_empty_service_is_open_port():
    findings, issues = normalize_nmap(_load("nmap_dvwa_default.findings.json"), provenance=_provenance())
    assert issues == []
    assert len(findings) == 1
    assert findings[0].category == Category.OPEN_PORT


def test_safe_scripts_run_produces_port_plus_script_findings():
    findings, issues = normalize_nmap(_load("nmap_dvwa_safe_scripts.findings.json"), provenance=_provenance())
    assert issues == []
    by_category = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)
    assert len(by_category[Category.SERVICE]) == 1
    # one port finding + 18 port scripts + 7 host scripts, per the frozen capture
    assert sum(len(v) for v in by_category.values()) == 1 + 18 + 7
    security_headers = [f for f in findings if "security-headers" in f.title]
    assert len(security_headers) == 1
    assert security_headers[0].category == Category.MISCONFIGURATION
    assert security_headers[0].evidence["output"] == ""


# --- nuclei, real captures ----------------------------------------------------

def test_juice_shop_nuclei_findings_categorize_as_exposure_and_technology():
    findings, issues = normalize_nuclei(_load("nuclei_juice-shop_3000.findings.json"), provenance=_provenance())
    assert issues == []
    assert len(findings) == 4
    by_id = {f.evidence["template_id"]: f for f in findings}
    assert by_id["swagger-api"].category == Category.EXPOSURE
    assert by_id["owasp-juice-shop-detect"].category == Category.TECHNOLOGY
    assert by_id["fingerprinthub-web-fingerprints"].category == Category.TECHNOLOGY
    assert by_id["tech-detect"].category == Category.TECHNOLOGY
    for f in findings:
        assert f.severity == Severity.INFO
        # this frozen capture predates RC-23's target_hostname field, so the
        # hostname is legitimately absent here; see the dedicated test below
        # for the case where target_hostname is present.
        assert f.asset.hostname is None
        assert f.asset.ip == "172.31.77.10"
        assert f.asset.port == 3000
        assert f.asset.scheme == "http"


def test_hostname_target_populates_asset_hostname_when_present():
    # RC-23 adds target_hostname only for hostname-targeted actions (the
    # frozen RC-20 captures above predate it); confirm it flows into asset.
    data = {
        "scanner": "nuclei", "out_of_band": "off", "target_hostname": "dvwa.lab",
        "findings": [{"template_id": "php-detect", "host": "dvwa.lab", "matched_at": "http://172.31.77.11",
                      "ip": "172.31.77.11", "severity": "info", "tags": ["tech"]}],
        "summary": {"findings": 1, "off_target": 0, "unparsed_lines": 0},
    }
    findings, issues = normalize_nuclei(data, provenance=_provenance())
    assert issues == []
    assert findings[0].asset.hostname == "dvwa.lab"
    assert findings[0].asset.ip == "172.31.77.11"


def test_dvwa_nuclei_findings_all_technology():
    findings, issues = normalize_nuclei(_load("nuclei_dvwa_default.findings.json"), provenance=_provenance())
    assert issues == []
    assert {f.category for f in findings} == {Category.TECHNOLOGY}
    assert {f.evidence["template_id"] for f in findings} == {"php-detect", "waf-detect", "tech-detect"}


def test_dvwa_exposure_run_matches_same_template_ids_as_default_run():
    # RC-23/RC-20: the IP+Host substitution must not change what matches.
    a, _ = normalize_nuclei(_load("nuclei_dvwa_default.findings.json"), provenance=_provenance())
    b, _ = normalize_nuclei(_load("nuclei_dvwa_exposure.findings.json"), provenance=_provenance())
    assert {f.evidence["template_id"] for f in a} == {f.evidence["template_id"] for f in b}


# --- the nmap-vs-nuclei identity disagreement (PLANTED_VULNS C-1) is kept, not reconciled ----

def test_nmap_and_nuclei_disagreement_on_port_3000_both_surface_as_separate_findings():
    nmap_findings, _ = normalize_nmap(_load("nmap_juice-shop_service.findings.json"), provenance=_provenance())
    nuclei_findings, _ = normalize_nuclei(_load("nuclei_juice-shop_3000.findings.json"), provenance=_provenance())
    assert nmap_findings[0].title == "Open 3000/tcp"  # nmap has no idea it's HTTP
    assert any("juice" in f.title.lower() or "juice" in f.evidence.get("template_id", "") for f in nuclei_findings)
    # Both stand on their own; nothing here merges or drops either one.
    assert len(nmap_findings) == 1
    assert len(nuclei_findings) == 4


# --- finding_id determinism ---------------------------------------------------

def test_finding_id_is_stable_across_repeated_normalization():
    raw = _load("nuclei_juice-shop_3000.findings.json")
    first, _ = normalize_nuclei(raw, provenance=_provenance())
    second, _ = normalize_nuclei(raw, provenance=_provenance())
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    # ids don't depend on the per-finding timestamp, which does vary
    assert len(raw["findings"][0]["timestamp"]) > 0  # sanity: the fixture does carry one


def test_finding_id_is_16_hex_chars_and_distinct_per_finding():
    findings, _ = normalize_nmap(_load("nmap_dvwa_safe_scripts.findings.json"), provenance=_provenance())
    ids = [f.finding_id for f in findings]
    assert all(len(i) == 16 and all(c in "0123456789abcdef" for c in i) for i in ids)
    assert len(set(ids)) == len(ids)


def test_finding_id_unaffected_by_provenance_fields():
    raw = _load("nmap_dvwa_service.findings.json")
    a, _ = normalize_nmap(raw, provenance=_provenance(raw_sha256="aaa", scanned_ip="9.9.9.9"))
    b, _ = normalize_nmap(raw, provenance=_provenance(raw_sha256="bbb", scanned_ip="1.1.1.1"))
    assert a[0].finding_id == b[0].finding_id


# --- malformed / missing / error input: issues, never a crash, never a silent drop ----

@pytest.mark.parametrize("bad", [None, "not a dict", 42, [], {"hosts": "not a list"}])
def test_normalize_nmap_never_raises_on_malformed_input(bad):
    findings, issues = normalize_nmap(bad, provenance=_provenance())
    assert findings == []
    assert len(issues) >= 1


@pytest.mark.parametrize("bad", [None, "not a dict", 42, [], {"findings": "not a list"}])
def test_normalize_nuclei_never_raises_on_malformed_input(bad):
    findings, issues = normalize_nuclei(bad, provenance=_provenance())
    assert findings == []
    assert len(issues) >= 1


def test_nmap_host_down_is_an_issue_not_a_phantom_finding():
    data = {"scanner": "nmap", "hosts": [{"status": "down", "addresses": [], "hostnames": [], "ports": []}]}
    findings, issues = normalize_nmap(data, provenance=_provenance())
    assert findings == []
    assert any(i.kind == "nmap_host_down" for i in issues)


def test_nmap_host_unreachable_status_error_is_an_issue_not_a_finding():
    data = {
        "scanner": "nmap", "hosts": [{"status": "down", "addresses": [], "hostnames": [], "ports": []}],
        "status": "error", "error": {"code": "host_unreachable", "message": "no host responded"},
    }
    findings, issues = normalize_nmap(data, provenance=_provenance())
    assert findings == []
    assert {i.kind for i in issues} == {"host_unreachable", "nmap_host_down"}


def test_nmap_tool_error_result_with_no_hosts_key_is_an_issue():
    data = {"status": "error", "error": {"code": "nmap_failed", "message": "exit 1"}}
    findings, issues = normalize_nmap(data, provenance=_provenance())
    assert findings == []
    assert issues[0].kind == "nmap_failed"


def test_nuclei_unparsed_lines_is_an_issue():
    data = {
        "scanner": "nuclei", "findings": [], "out_of_band": "off",
        "summary": {"findings": 0, "off_target": 0, "unparsed_lines": 3},
    }
    findings, issues = normalize_nuclei(data, provenance=_provenance())
    assert findings == []
    assert any(i.kind == "nuclei_unparsed_lines" and "3" in i.detail for i in issues)


def test_nuclei_off_target_activity_is_an_issue_and_hits_are_not_findings():
    data = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": [{"template_id": "ok-one", "host": "dvwa.lab", "matched_at": "http://dvwa.lab",
                      "ip": "172.31.77.11", "severity": "info", "tags": ["tech"]}],
        "summary": {"findings": 1, "off_target": 1, "unparsed_lines": 0},
        "status": "error",
        "error": {"code": "off_target_activity", "message": "off target"},
        "off_target_hosts": ["http://evil.example/"],
    }
    findings, issues = normalize_nuclei(data, provenance=_provenance())
    assert len(findings) == 1  # the on-target hit still normalizes
    assert findings[0].evidence["template_id"] == "ok-one"
    assert any(i.kind == "off_target_activity" for i in issues)
    off_target_issue = next(i for i in issues if i.kind == "off_target_activity")
    assert off_target_issue.raw == ["http://evil.example/"]


def test_unrecognized_nuclei_severity_defaults_to_info_and_is_flagged():
    data = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": [{"template_id": "weird", "host": "dvwa.lab", "matched_at": "http://dvwa.lab",
                      "ip": "172.31.77.11", "severity": "apocalyptic", "tags": ["tech"]}],
        "summary": {"findings": 1, "off_target": 0, "unparsed_lines": 0},
    }
    findings, issues = normalize_nuclei(data, provenance=_provenance())
    assert findings[0].severity == Severity.INFO
    assert any(i.kind == "nuclei_unknown_severity" for i in issues)


def test_a_malformed_finding_entry_is_an_issue_not_a_crash():
    data = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": ["not a dict", {"template_id": "ok", "host": "dvwa.lab", "matched_at": "http://dvwa.lab",
                                     "ip": "172.31.77.11", "severity": "info", "tags": []}],
        "summary": {"findings": 2, "off_target": 0, "unparsed_lines": 0},
    }
    findings, issues = normalize_nuclei(data, provenance=_provenance())
    assert len(findings) == 1
    assert any(i.kind == "malformed_nuclei_finding" for i in issues)


# --- cve normalization ---------------------------------------------------------

@pytest.mark.parametrize("raw_cve,expected", [
    ("", []),
    ("CVE-2021-1234", ["CVE-2021-1234"]),
    ("CVE-2021-1234,CVE-2021-5678", ["CVE-2021-1234", "CVE-2021-5678"]),
    (["CVE-2021-1234", "CVE-2021-5678"], ["CVE-2021-1234", "CVE-2021-5678"]),
    (None, []),
])
def test_cve_normalizes_single_csv_and_list_forms(raw_cve, expected):
    data = {
        "scanner": "nuclei", "out_of_band": "off",
        "findings": [{"template_id": "x", "host": "dvwa.lab", "matched_at": "http://dvwa.lab",
                      "ip": "172.31.77.11", "severity": "info", "tags": [], "cve": raw_cve,
                      "cvss_score": 7.5}],
        "summary": {"findings": 1, "off_target": 0, "unparsed_lines": 0},
    }
    findings, issues = normalize_nuclei(data, provenance=_provenance())
    assert issues == []
    assert findings[0].cve == expected
    assert findings[0].cvss_score == 7.5


# --- dispatch + convenience ----------------------------------------------------

def test_normalize_dispatches_by_tool_name():
    result = normalize("nmap", _load("nmap_dvwa_service.findings.json"), provenance=_provenance())
    assert isinstance(result, NormalizedResult)
    assert len(result.findings) == 1
    assert result.findings[0].source_tool == "nmap"


def test_normalize_unknown_tool_is_an_issue_not_a_crash():
    result = normalize("masscan", {"anything": True}, provenance=_provenance())
    assert result.findings == []
    assert result.issues[0].kind == "unknown_tool"


class _FakeAction:
    def __init__(self, tool):
        self.tool = tool


class _FakeDecision:
    def __init__(self, resolved_ips=(), reason="deny: out of scope"):
        self.resolved_ips = resolved_ips
        self.reason = reason


class _FakeExecutionResult:
    def __init__(self, *, tool, findings, raw_output, executed, resolved_ips=(), reason=""):
        self.action = _FakeAction(tool)
        self.findings = findings
        self.raw_output = raw_output
        self.executed = executed
        self.decision = _FakeDecision(resolved_ips, reason)


def test_normalize_execution_result_carries_provenance_through():
    nmap_findings = _load("nmap_dvwa_service.findings.json")
    result = _FakeExecutionResult(
        tool="nmap", findings=nmap_findings, raw_output="<nmaprun>...</nmaprun>",
        executed=True, resolved_ips=("172.31.77.11",),
    )
    normalized = normalize_execution_result(result, engagement="rc-lab-2026-11", observed_at="2026-11-06T00:00:00Z")
    assert len(normalized.findings) == 1
    assert normalized.provenance.engagement == "rc-lab-2026-11"
    assert normalized.provenance.scanner == "nmap"
    assert normalized.provenance.scanner_version == "7.93"
    assert normalized.provenance.scanned_ip == "172.31.77.11"
    assert normalized.provenance.observed_at == "2026-11-06T00:00:00Z"
    assert normalized.provenance.raw_sha256 is not None
    assert normalized.findings[0].provenance.scanned_ip == "172.31.77.11"


def test_normalize_execution_result_not_executed_is_an_issue_not_a_crash():
    result = _FakeExecutionResult(
        tool="nmap", findings=None, raw_output=None, executed=False, reason="deny: out of scope",
    )
    normalized = normalize_execution_result(result, engagement="rc-lab-2026-11")
    assert normalized.findings == []
    assert normalized.issues[0].kind == "not_executed"
    assert "out of scope" in normalized.issues[0].detail


def test_normalize_execution_result_nuclei_captures_templates_pin():
    nuclei_findings = _load("nuclei_dvwa_default.findings.json")
    result = _FakeExecutionResult(
        tool="nuclei", findings=nuclei_findings, raw_output="{}", executed=True, resolved_ips=("172.31.77.11",),
    )
    normalized = normalize_execution_result(result, engagement="rc-lab-2026-11")
    assert normalized.provenance.templates_pin == "v10.5.1"
    assert len(normalized.findings) == 3
