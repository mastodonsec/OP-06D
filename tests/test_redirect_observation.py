# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-44: Recon: report redirects to hostnames outside scope instead of going quiet"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from op06d.audit import EVENT_ACTION_EXECUTED, EVENT_GATE_DECISION, read_log
from op06d.cli import run_engagement
from op06d.engagement import Scope
from op06d.evidence import EvidenceStore
from op06d.llm import LLMSettings
from op06d.nmap_tool import PROFILES, NmapTool, parse_nmap_xml
from op06d.normalize import Category, Provenance, Severity, host_in_scope, normalize_nmap
from op06d.report import build_report, render_markdown
from op06d.tools import ProcessResult, Risk, ToolAction

FIXTURES = Path(__file__).parent / "fixtures"
CROSS = (FIXTURES / "nmap_http_title_cross_host_redirect.xml").read_text(encoding="utf-8")
SAME = (FIXTURES / "nmap_http_title_same_host_redirect.xml").read_text(encoding="utf-8")
NONE = (FIXTURES / "nmap_http_title_no_redirect.xml").read_text(encoding="utf-8")

IP = "172.31.77.12"
LOCATION = "http://site-outside.lab/"
OUTSIDE = "site-outside.lab"
NMAP_PATH = "/usr/bin/nmap"
PROV = Provenance(engagement="rc44-test", scanner="nmap")


def _http_title(xml: str) -> dict:
    (port,) = parse_nmap_xml(xml)["hosts"][0]["ports"]
    return next(s for s in port["scripts"] if s["id"] == "http-title")


def _normalize(xml: str, in_scope=None, hostname: str | None = None):
    findings = parse_nmap_xml(xml)
    if hostname:
        findings["target_hostname"] = hostname
    return normalize_nmap(findings, provenance=PROV, in_scope=in_scope)


def _redirects(found):
    return [f for f in found if "http-redirect" in f.tags]


def _not_assessed(issues):
    return [i for i in issues if i.kind == "redirect_target_not_assessed"]


# --- parsing the http-title redirect_url elem ----------------------------------------

def test_cross_host_redirect_url_is_parsed_from_the_elem():
    script = _http_title(CROSS)
    assert script["output"] == f"Did not follow redirect to {LOCATION}"
    assert script["redirect_url"] == LOCATION


def test_same_host_redirect_keeps_the_relative_redirect_url():
    script = _http_title(SAME)
    assert script["redirect_url"] == "/login.php"


def test_no_redirect_has_no_redirect_url():
    assert "redirect_url" not in _http_title(NONE)


def test_redirect_url_comes_from_the_elem_not_the_output_text():
    xml = CROSS.replace(f"<elem key=\"redirect_url\">{LOCATION}</elem>", "")
    assert "redirect_url" not in _http_title(xml)
    xml = CROSS.replace(f'output="Did not follow redirect to {LOCATION}"', 'output="x"')
    assert _http_title(xml)["redirect_url"] == LOCATION


# --- findings and limitations ----------------------------------------------------------

def test_cross_host_redirect_out_of_scope_gives_finding_and_limitation():
    found, issues = _normalize(CROSS, in_scope=lambda host: False)
    (f,) = _redirects(found)
    assert f.severity is Severity.INFO and f.category is Category.OTHER
    assert (f.asset.ip, f.asset.port) == (IP, 80)
    assert LOCATION in f.title and f"{IP}:80" in f.title
    assert f.evidence["location"] == LOCATION
    assert f.evidence["redirecting_asset"] == f"{IP}:80"
    assert f.evidence["redirect_host"] == OUTSIDE
    assert not [x for x in found if x.title == "nmap script http-title"]  # replaced, not duplicated
    (issue,) = _not_assessed(issues)
    assert issue.detail.startswith(f"The site at {OUTSIDE} was not assessed")
    assert issue.detail.endswith(
        f"If {OUTSIDE} belongs to the client and is covered by the signed authorization, "
        f"add it to the engagement scope to cover it.")
    assert issue.raw == {"location": LOCATION, "redirect_host": OUTSIDE, "redirecting_asset": f"{IP}:80"}


def test_cross_host_redirect_in_scope_gives_finding_but_no_limitation():
    asked = []
    found, issues = _normalize(CROSS, in_scope=lambda host: asked.append(host) or True)
    assert len(_redirects(found)) == 1
    assert _not_assessed(issues) == []
    assert asked == [OUTSIDE]


def test_without_a_scope_check_the_target_is_reported_as_not_assessed():
    found, issues = _normalize(CROSS)
    assert len(_redirects(found)) == 1 and len(_not_assessed(issues)) == 1


@pytest.mark.parametrize("xml", [SAME, NONE], ids=["same-host", "no-redirect"])
def test_same_host_or_no_redirect_gives_no_redirect_finding(xml):
    found, issues = _normalize(xml, in_scope=lambda host: False)
    assert _redirects(found) == [] and _not_assessed(issues) == []
    assert [f.title for f in found if f.title == "nmap script http-title"] == ["nmap script http-title"]


@pytest.mark.parametrize("location", [
    f"http://{IP}:8443/",            # same host, other port: http-title does not follow it either
    f"https://{IP}/",
    "HTTP://REDIRECT.LAB./x",        # the scanned hostname, any case, trailing dot
    "/relative/path",
    "relative",
])
def test_absolute_same_host_and_relative_redirects_give_no_redirect_finding(location):
    xml = CROSS.replace(LOCATION, location)
    found, issues = _normalize(xml, in_scope=lambda host: False, hostname="redirect.lab")
    assert _redirects(found) == [] and _not_assessed(issues) == []


def test_scheme_relative_redirect_to_another_host_is_reported():
    found, _ = _normalize(CROSS.replace(LOCATION, "//other.example/"), in_scope=lambda h: False)
    (f,) = _redirects(found)
    assert f.evidence["redirect_host"] == "other.example"


def test_redirect_finding_id_is_stable():
    a, _ = _normalize(CROSS)
    b, _ = _normalize(CROSS)
    assert [f.finding_id for f in _redirects(a)] == [f.finding_id for f in _redirects(b)]


@pytest.mark.parametrize("in_scope, out_of_scope, host, expected", [
    (["site-outside.lab"], [], OUTSIDE, True),
    (["*.site-outside.lab"], [], "www.site-outside.lab", True),
    (["*.site-outside.lab"], ["www.site-outside.lab"], "www.site-outside.lab", False),
    (["*.site-outside.lab"], [], OUTSIDE, False),  # a wildcard does not cover the bare name
    ([IP], [], OUTSIDE, False),
    (["10.0.0.0/8"], [], OUTSIDE, False),
    (["10.0.0.0/8"], [], "10.1.2.3", True),
])
def test_host_in_scope_uses_the_engagement_scope_matching(in_scope, out_of_scope, host, expected):
    check = host_in_scope(Scope(in_scope=in_scope, out_of_scope=out_of_scope))
    assert check(host) is expected


# --- argv: the fixed http-title addition ----------------------------------------------

def _argv(params):
    return NmapTool(50).build_argv(NMAP_PATH, IP, params)


def _script_args(argv):
    return [a for a in argv if a.startswith("--script")]


@pytest.mark.parametrize("profile", ["service", "full"])
def test_sv_profiles_add_http_title(profile):
    assert _script_args(_argv({"profile": profile})) == ["--script=http-title"]


def test_planner_categories_are_combined_into_one_script_value():
    argv = _argv({"profile": "service", "scripts": ["vuln", "safe"]})
    assert _script_args(argv) == ["--script=safe,vuln,http-title"]
    assert argv[-2:] == ["--", IP]


@pytest.mark.parametrize("profile", ["ping", "quick", "default", "aggressive"])
def test_other_profiles_do_not_add_http_title(profile):
    assert not any("http-title" in a for a in _argv({"profile": profile}))
    if profile != "ping":
        assert _script_args(_argv({"profile": profile, "scripts": ["safe"]})) == ["--script=safe"]


def test_aggressive_already_runs_the_default_category():
    assert "-A" in PROFILES["aggressive"][0]


@pytest.mark.parametrize("profile", ["service", "full"])
def test_risk_tier_of_sv_profiles_is_unchanged(profile):
    assert NmapTool(50).risk_for({"profile": profile}) is Risk.ACTIVE_RECON


@pytest.mark.parametrize("scripts", [["http-title"], ["safe", "http-title"], ["http-*"]])
def test_planner_cannot_pass_a_script_name(scripts):
    assert NmapTool(50).validate_parameters({"profile": "service", "scripts": scripts})


# --- end to end: finding and limitation in the report; the gate denies the redirect host --

class FixtureRunner:
    def __init__(self, xml: str):
        self.xml, self.calls = xml, []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        return ProcessResult(0, self.xml.encode(), b"")


def _engagement(tmp_path: Path) -> Path:
    now = datetime.now(timezone.utc)
    data = {
        "engagement": "rc44-test",
        "authorization": {
            "client": "Test Client", "signed_scope_ref": "SOW-1", "authorized_by": "ops@example.com",
            "window": [(now - timedelta(hours=1)).isoformat(), (now + timedelta(hours=2)).isoformat()],
        },
        "scope": {"in_scope": [IP], "out_of_scope": []},
        "intensity": {"max_rps": 50, "destructive": False},
        "objective": "recon",
    }
    path = tmp_path / "engagement.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


class ScriptLLM:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def complete(self, system, messages):
        self.calls.append([dict(m) for m in messages])
        return self.replies.pop(0)


def _act(tool, target, **params):
    return json.dumps({"type": "action", "tool": tool, "target": target, "parameters": params,
                       "reason": "recon"})


def _run(tmp_path, **kw):
    runner = FixtureRunner(CROSS)
    resolved = []
    nmap = NmapTool(50, runner=runner, which=lambda n: NMAP_PATH)
    summary = run_engagement(
        _engagement(tmp_path), tmp_path / "out", tools=[nmap], non_interactive=True,
        resolver=lambda host: resolved.append(host) or [IP], **kw,
    )
    return summary, runner, resolved


def _report(summary) -> str:
    return render_markdown(build_report(EvidenceStore(summary.evidence_db_path).reconstruct_run(summary.run_id)))


def test_fixed_run_reports_the_redirect_finding_and_the_limitation(tmp_path):
    summary, runner, resolved = _run(
        tmp_path, planner=lambda eng: [ToolAction("nmap", IP, {"profile": "service"}, reason="recon")],
    )
    assert summary.executed == 1 and len(runner.calls) == 1
    assert "--script=http-title" in runner.calls[0] and runner.calls[0][-1] == IP
    md = _report(summary)
    assert f"HTTP redirect to another host: {IP}:80 -> {LOCATION}" in md
    assert (f"**redirect_target_not_assessed:** The site at {OUTSIDE} was not assessed" in md
            and f"If {OUTSIDE} belongs to the client and is covered by the signed authorization, "
            f"add it to the engagement scope to cover it." in md)
    assert resolved == []
    assert not any(OUTSIDE in " ".join(argv) for argv in runner.calls)


def test_planner_proposing_the_redirect_host_is_denied_by_the_gate(tmp_path):
    llm = ScriptLLM([
        _act("nmap", IP, profile="service"),
        _act("nmap", OUTSIDE, profile="service"),
        json.dumps({"type": "done", "summary": "finished"}),
    ])
    summary, runner, resolved = _run(tmp_path, planner_mode="llm", llm_settings=LLMSettings("local"), llm=llm)

    # The planner saw the redirect in the first tool result before proposing the host.
    assert any(OUTSIDE in json.dumps(m) for m in llm.calls[1])
    assert summary.executed == 1 and summary.denied == 1
    assert [argv[-1] for argv in runner.calls] == [IP]
    assert OUTSIDE not in resolved  # denied on the name, never resolved

    log = read_log(summary.audit_log_path)
    about_outside = [e for e in log if OUTSIDE in (e.target or "")]
    decisions = [e for e in about_outside if e.event == EVENT_GATE_DECISION]
    assert decisions and all(e.allowed is False for e in decisions)
    assert any("no in-scope host entry" in (e.reason or "") for e in decisions)
    assert [e for e in about_outside if e.event == EVENT_ACTION_EXECUTED] == []
    executed = [e for e in log if e.event == EVENT_ACTION_EXECUTED]
    assert len(executed) == 1 and IP in (executed[0].target or "")
