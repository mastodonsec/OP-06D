# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-24: Lab runbook polish + validation harness

Docker-free tests of lab/validation_harness.py's pure decision logic: an
isolation failure short-circuits the whole run, a NEEDS-REVIEW step never
turns into a clean PASS, a findings step never auto-passes, and the run
skips (exit 3) without OP06D_LAB=1."""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import lab_asserts  # noqa: E402
import validation_harness as vh  # noqa: E402

BASELINE = lab_asserts.load_baseline()


def _all(status: str) -> list[vh.StepResult]:
    return [vh.StepResult(k, n, status) for k, n in vh.STEPS]


# -- isolation gate: fail-closed --------------------------------------------

@pytest.mark.parametrize("internal,exit_code", [
    ("false", 0), ("true", 1), ("true", 2), ("<inspect failed>", 0), ("", 0), ("True", 0),
])
def test_isolation_anything_but_clean_pass_fails(internal, exit_code):
    assert vh.classify_isolation(internal, exit_code).status == vh.FAIL


def test_isolation_clean_pass():
    assert vh.classify_isolation("true", 0).status == vh.PASS


def test_isolation_fail_short_circuits_overall_to_fail_even_if_everything_else_passed():
    results = _all(vh.PASS)
    results[0] = vh.StepResult("4", "isolation", vh.FAIL, "not internal")
    code, line = vh.overall(results)
    assert code == vh.EXIT_ISOLATION
    assert line.startswith("RESULT: FAIL")


def test_missing_isolation_step_is_a_fail():
    code, _ = vh.overall([r for r in _all(vh.PASS) if r.step != "4"])
    assert code == vh.EXIT_ISOLATION


def test_isolation_abort_skips_every_other_step():
    rest = vh.skipped("gate failed")
    assert {r.step for r in rest} == {k for k, _ in vh.STEPS} - {"4"}
    assert all(r.status == vh.SKIP for r in rest)


# -- overall result ----------------------------------------------------------

def test_needs_review_does_not_become_a_clean_pass():
    results = _all(vh.PASS)
    for r in results:
        if r.step in vh.REVIEW_STEPS:
            r.status = vh.NEEDS_REVIEW
    code, line = vh.overall(results)
    assert code == vh.EXIT_OK
    assert line != "RESULT: PASS"
    assert "review" in line and "10" in line and "11" in line


def test_any_fail_fails_the_run():
    results = _all(vh.PASS)
    results[5].status = vh.FAIL
    code, line = vh.overall(results)
    assert code == vh.EXIT_FAIL and "FAIL" in line


def test_skip_without_fail_is_not_a_pass():
    results = _all(vh.PASS)
    results[3].status = vh.SKIP
    assert vh.overall(results)[0] == vh.EXIT_FAIL


def test_report_lists_every_step_and_the_final_line():
    results = _all(vh.PASS)
    code, line = vh.overall(results)
    text = vh.format_report(results, "2026-11-09T23:50:00Z", line)
    assert text.splitlines()[-1] == line
    assert "Step 4  isolation" in text and "Step 13 e2e" in text


# -- findings steps never auto-pass -----------------------------------------

def test_tag_audit_is_needs_review_when_clean():
    audit = {"templates_scanned": 14104, "non_get": [{"id": "x", "methods": ["POST"]}] * 52,
             "write_method": [], "write_method_unexcluded": []}
    r = vh.classify_tag_audit(audit)
    assert r.status == vh.NEEDS_REVIEW and "52 non-GET" in r.detail


def test_tag_audit_with_nothing_found_is_still_needs_review():
    r = vh.classify_tag_audit({"templates_scanned": 10, "non_get": [], "write_method": [],
                               "write_method_unexcluded": []})
    assert r.status == vh.NEEDS_REVIEW


def test_tag_audit_fails_on_uncovered_write_method_or_empty_scan():
    assert vh.classify_tag_audit({"templates_scanned": 10, "write_method_unexcluded": ["evil"]}).status == vh.FAIL
    assert vh.classify_tag_audit({"templates_scanned": 0}).status == vh.FAIL


CLEAN_WRAPPER = {"status": "ok", "probe_hit": True, "redirect_followed": False,
                 "hostile_header_sent": False, "oast_contacted": False, "out_of_band": "off"}


def test_ambient_clean_wrapper_is_needs_review_not_pass():
    r = vh.classify_ambient({"wrapper": CLEAN_WRAPPER, "control": {"redirect_followed": True},
                             "hostile_config_removed": True})
    assert r.status == vh.NEEDS_REVIEW


@pytest.mark.parametrize("key,value", [
    ("redirect_followed", True), ("hostile_header_sent", True), ("oast_contacted", True),
    ("status", "nuclei_failed"), ("probe_hit", False), ("out_of_band", "on"),
])
def test_ambient_dirty_wrapper_fails(key, value):
    r = vh.classify_ambient({"wrapper": {**CLEAN_WRAPPER, key: value}, "hostile_config_removed": True})
    assert r.status == vh.FAIL


def test_ambient_subcheck_the_control_never_showed_is_inconclusive_not_clean():
    """Control followed the redirect and sent the header but never
    reached OAST. OAST must read INCONCLUSIVE on its own,
    not be folded into "wrapper clean"."""
    result = {"wrapper": CLEAN_WRAPPER, "hostile_config_removed": True,
              "control": {"redirect_followed": True, "hostile_header_sent": True, "oast_contacted": False}}
    subs = vh.ambient_subchecks(result)
    assert subs["redirect"].startswith(vh.CLEAN) and subs["header"].startswith(vh.CLEAN)
    assert subs["OAST"] == "INCONCLUSIVE (control did not reach OAST - detection not proven)"
    r = vh.classify_ambient(result)
    assert r.status == vh.NEEDS_REVIEW
    assert "OAST: INCONCLUSIVE" in r.detail and "wrapper-as-built clean" not in r.detail


def test_ambient_subchecks_all_clean_only_when_control_detected_each():
    result = {"wrapper": CLEAN_WRAPPER, "hostile_config_removed": True,
              "control": {"redirect_followed": True, "hostile_header_sent": True, "oast_contacted": True}}
    assert all(v.startswith(vh.CLEAN) for v in vh.ambient_subchecks(result).values())
    assert vh.classify_ambient(result).status == vh.NEEDS_REVIEW  # still a human read


def test_ambient_lingering_hostile_config_fails():
    r = vh.classify_ambient({"wrapper": CLEAN_WRAPPER, "hostile_config_removed": False})
    assert r.status == vh.FAIL


def test_review_step_classifiers_never_return_pass():
    """Exhaustive-ish: whatever goes in, steps 10/11 never come out PASS."""
    audits = [{}, {"templates_scanned": 1}, {"templates_scanned": 1, "write_method_unexcluded": ["a"]}]
    ambients = [{}, {"wrapper": CLEAN_WRAPPER, "hostile_config_removed": True}, {"wrapper": {}}]
    assert all(vh.classify_tag_audit(a).status != vh.PASS for a in audits)
    assert all(vh.classify_ambient(a).status != vh.PASS for a in ambients)


# -- other classifiers -------------------------------------------------------

def test_window():
    s, e = dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc), dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
    assert vh.classify_window(dt.datetime(2026, 11, 9, tzinfo=dt.timezone.utc), s, e).status == vh.PASS
    assert vh.classify_window(e, s, e).status == vh.FAIL
    assert vh.classify_window(dt.datetime(2026, 11, 4, tzinfo=dt.timezone.utc), s, e).status == vh.FAIL


LAB_VERSIONS = "nmap=7.93+dfsg1-1\nnuclei=3.11.1\nnuclei-templates=v10.5.1\nbase=debian\n"
NMAP_OUT = "Nmap version 7.93 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\n"
NUCLEI_OUT = "[INF] Nuclei Engine Version: v3.11.1\n"


def test_versions_match_pins():
    found = vh.parse_versions(LAB_VERSIONS, NMAP_OUT, NUCLEI_OUT)
    assert vh.classify_versions(found, BASELINE["pins"], "ab" * 32).status == vh.PASS


def test_versions_mismatch_or_missing_hash_fails():
    found = vh.parse_versions(LAB_VERSIONS, "Nmap version 7.94\n", NUCLEI_OUT)
    assert vh.classify_versions(found, BASELINE["pins"], "ab" * 32).status == vh.FAIL
    found = vh.parse_versions(LAB_VERSIONS, NMAP_OUT, NUCLEI_OUT)
    assert vh.classify_versions(found, BASELINE["pins"], None).status == vh.FAIL


def _argvs():
    from op06d.nmap_tool import PROFILES, NmapTool
    from op06d.nuclei_tool import NucleiTool
    nm = NmapTool(50)
    out = [nm.build_argv("/usr/bin/nmap", "172.31.77.11", {"profile": p}) for p in PROFILES]
    out.append(nm.build_argv("/usr/bin/nmap", "172.31.77.11", {"profile": "service", "ports": "80,443"}))
    out.append(nm.build_argv("/usr/bin/nmap", "172.31.77.11",
                             {"scripts": ["safe", "default", "discovery", "version", "vuln"]}))
    nu = NucleiTool(50, template_dir="/opt/nuclei-templates")
    out.append(nu.build_argv("/usr/local/bin/nuclei", "dvwa.lab", {}))
    out.append(nu.build_argv("/usr/local/bin/nuclei", "dvwa.lab", {"tags": ["tech", "cve"], "severity": ["info", "high"]}))
    return out


def test_flags_pass_on_the_real_wrapper_argvs():
    """The expected-flag lists match what the wrappers actually build today."""
    r = vh.classify_flags(_argvs())
    assert r.status == vh.PASS, r.detail


def test_flags_fail_when_one_is_dropped():
    argvs = _argvs()
    argvs[-1] = [a for a in argvs[-1] if a != "-disable-redirects"]
    r = vh.classify_flags(argvs)
    assert r.status == vh.FAIL and "-disable-redirects" in r.detail


def test_parsers():
    assert vh.classify_parsers([{"file": "a.xml", "ok": True, "unparsed": 0}]).status == vh.PASS
    assert vh.classify_parsers([{"file": "a.jsonl", "ok": True, "unparsed": 1}]).status == vh.FAIL
    assert vh.classify_parsers([{"file": "a.xml", "ok": False, "unparsed": 0}]).status == vh.FAIL
    assert vh.classify_parsers([]).status == vh.FAIL


def test_priv():
    good = {"root": [{"profile": "ping", "status": "ok"}], "scanner": [{"profile": "ping", "status": "ok"}]}
    assert vh.classify_priv(good, ["ping"], []).status == vh.PASS
    assert vh.classify_priv(good, ["ping", "full"], []).status == vh.FAIL  # a profile never reported
    assert vh.classify_priv(good, ["ping"], ["scanner"]).status == vh.FAIL
    bad = {"root": [{"profile": "ping", "status": "wrapper_error"}]}
    assert vh.classify_priv(bad, ["ping"], []).status == vh.FAIL


E2E_OK = {"termination": "objective_met", "audit_verified": 17,
          "steps": [{"kind": k} for k in ["executed", "executed", "denied", "declined", "done"]],
          "denied_out_of_scope": True, "executed_out_of_scope": False,
          "dns_pinned": ["dvwa.lab"], "planner_view_wrapped": True,
          "planner_view_has_raw_xml": False}


def test_e2e_pass_and_each_failure_mode():
    assert vh.classify_e2e(E2E_OK).status == vh.PASS
    for bad in ({"termination": "max_iterations"}, {"executed_out_of_scope": True},
                {"denied_out_of_scope": False}, {"dns_pinned": ["dvwa.lab", "dvwa.lab"]},
                {"dns_pinned": ["dvwa.lab", "1.1.1.1"]}, {"planner_view_wrapped": False}, {"planner_view_has_raw_xml": True},
                {"steps": [{"kind": "executed"}] * 4}, {"audit_verified": 0}):
        assert vh.classify_e2e({**E2E_OK, **bad}).status == vh.FAIL, bad


def test_scans_use_the_shared_baseline_asserts():
    """Step 8 reuses lab_asserts (shared with test_lab_rc20.py): a summary
    missing a baseline row fails, it is never re-implemented here."""
    summary = {"runs": [], "audit_entries": 3, "dns_pinned": {}, "action_executed": []}
    r = vh.classify_scans(summary, BASELINE)
    assert r.status == vh.FAIL and "missing" in r.detail


def test_skip_reason_without_op06d_lab(monkeypatch):
    monkeypatch.delenv("OP06D_LAB", raising=False)
    assert "OP06D_LAB=1" in vh.skip_reason()


def test_main_skips_cleanly_without_the_lab(monkeypatch, capsys):
    monkeypatch.delenv("OP06D_LAB", raising=False)
    assert vh.main([]) == vh.EXIT_SKIPPED == 3
    assert "RESULT: SKIPPED" in capsys.readouterr().out
