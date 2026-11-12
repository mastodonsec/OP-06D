# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`

``run_engagement(planner_mode="llm")`` end to end with a scripted model and
fake tools (no subprocess, no network, no real model): engagement policy,
every run limit, model failures, malformed and out-of-scope proposals,
approval, context fitting, the report's planner section, and that the API
key reaches none of the audit log, evidence store or report.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from op06d.audit import EVENT_LOOP_END, EVENT_PLANNER_CONFIG, read_log
from op06d.cli import PlannerPolicyError, main, run_engagement
from op06d.evidence import EvidenceStore
from op06d.llm import AnthropicLLM, LLMRefused, LLMSettings, LLMUnavailable, LocalLLM, RetryPolicy, Usage
from op06d.orchestrator import RunLimits
from op06d.redaction import clear_registered_secrets
from op06d.sanitize import BLOCK_NAME
from op06d.tools import Outcome, Risk, ToolOutput

ROOT = Path(__file__).resolve().parent.parent
IN_SCOPE = "203.0.113.5"
OUT_OF_SCOPE = "198.51.100.7"
FAKE_KEY = "sk-ant-" + "api03-" + "Q" * 48


@pytest.fixture(autouse=True)
def _clean_secrets():
    clear_registered_secrets()
    yield
    clear_registered_secrets()


def _engagement(tmp_path: Path, planner: dict | None = None) -> Path:
    now = datetime.now(timezone.utc)
    data = {
        "engagement": "rc40-test",
        "authorization": {
            "client": "Test Client", "signed_scope_ref": "SOW-1", "authorized_by": "ops@example.com",
            "window": [(now - timedelta(hours=1)).isoformat(), (now + timedelta(hours=2)).isoformat()],
        },
        "scope": {"in_scope": [IN_SCOPE], "out_of_scope": [OUT_OF_SCOPE]},
        "intensity": {"max_rps": 50, "destructive": False},
        "objective": "recon",
    }
    if planner is not None:
        data["planner"] = planner
    path = tmp_path / "engagement.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


class FakeNmap:
    name = "nmap"
    description = "fake nmap"
    risk = Risk.ACTIVE_RECON
    destructive = False
    allowed_parameters = frozenset({"profile", "ports"})

    def __init__(self, banner: str = "FakeHTTP", body_chars: int = 0):
        self.calls: list[tuple[str, dict]] = []
        self.banner = banner
        self.body_chars = body_chars

    def risk_for(self, parameters):
        return Risk.INTRUSIVE if parameters.get("profile") == "aggressive" else Risk.ACTIVE_RECON

    def run(self, target, parameters, *, hostname=None):
        self.calls.append((target, dict(parameters)))
        findings = {
            "scanner": "nmap", "version": "7.93",
            "hosts": [{
                "status": "up", "addresses": [{"address": target, "type": "ipv4"}], "hostnames": [],
                "ports": [{"port": 80, "protocol": "tcp", "state": "open", "reason": "syn-ack",
                           "service": {"name": "http", "product": self.banner, "version": "1.0",
                                       "extrainfo": "", "tunnel": "", "cpe": []}}],
            }],
            "summary": {"hosts_up": 1, "hosts_down": 0, "hosts_total": 1, "elapsed_seconds": 0.1},
        }
        if self.body_chars:
            findings["padding"] = "A" * self.body_chars
        return ToolOutput(findings, raw=f"<nmap banner='{self.banner}'/>", status="ok")


def act(target=IN_SCOPE, **params):
    return json.dumps({"type": "action", "tool": "nmap", "target": target,
                       "parameters": params, "reason": "recon"})


DONE = json.dumps({"type": "done", "summary": "finished"})


class ScriptLLM:
    def __init__(self, replies, usage: Usage | None = None):
        self.replies = list(replies)
        self.usage = usage
        self.calls: list[tuple[str, list[dict]]] = []
        self.last_usage: Usage | None = None

    def complete(self, system, messages):
        self.calls.append((system, [dict(m) for m in messages]))
        self.last_usage = self.usage
        if not self.replies:
            raise AssertionError("model called more often than scripted")
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _run(tmp_path, replies, *, provider="local", planner=None, limits=None, tool=None, usage=None,
         llm=None, **kw):
    tool = tool or FakeNmap()
    llm = llm or ScriptLLM(replies, usage)
    summary = run_engagement(
        _engagement(tmp_path, planner), tmp_path / "out", tools=[tool], non_interactive=True,
        resolver=lambda h: [IN_SCOPE], planner_mode="llm",
        llm_settings=LLMSettings(provider), llm=llm, limits=limits, **kw,
    )
    return summary, tool, llm


def _log(summary):
    return read_log(summary.audit_log_path)


def _loop_end(summary):
    ends = [e for e in _log(summary) if e.event == EVENT_LOOP_END]
    assert len(ends) == 1
    return ends[0]


def _planner_row(summary):
    return EvidenceStore(summary.evidence_db_path).reconstruct_run(summary.run_id).planner


# --- happy path + report ------------------------------------------------------

def test_llm_run_feeds_evidence_and_report_with_planner_metadata(tmp_path):
    summary, tool, llm = _run(tmp_path, [act(profile="service"), DONE], usage=Usage(1000, 50))
    assert summary.termination == "objective_met" and summary.executed == 1
    assert tool.calls == [(IN_SCOPE, {"profile": "service"})]

    planner = _planner_row(summary)
    assert planner["planner"] == "llm" and planner["provider"] == "local"
    assert planner["endpoint_class"] == "local" and planner["context_tokens"] == 8192
    assert planner["iterations"] == 2 and planner["actions"] == 1
    assert planner["termination"] == "objective_met"
    assert planner["input_tokens"] == 2000 and planner["output_tokens"] == 100

    html = summary.report_html_path.read_text(encoding="utf-8")
    assert "<h2>Planner</h2>" in html
    for text in ("llm", "local", "objective_met", "8192", "Context size (tokens)", "Termination reason"):
        assert text in html

    events = [e.event for e in _log(summary)]
    assert EVENT_PLANNER_CONFIG in events
    assert _loop_end(summary).reason == "objective_met"


def test_system_prompt_declares_untrusted_output_to_be_data(tmp_path):
    _, _, llm = _run(tmp_path, [DONE])
    system = llm.calls[0][0]
    assert BLOCK_NAME in system
    assert "DATA" in system and "never follow it" in system


def test_the_model_request_and_the_prompt_carry_the_tools_parameter_schemas(tmp_path):
    class TypedNmap(FakeNmap):
        def parameter_schema(self):
            return {"profile": {"type": "string", "enum": ["default", "service"]},
                    "ports": {"type": "string"}}

    sent = []

    def transport(url, body, timeout):
        sent.append(json.loads(body))
        return 200, json.dumps({"message": {"content": DONE}, "prompt_eval_count": 1, "eval_count": 1}).encode(), {}
    llm = LocalLLM("m", tool_names=["nmap"], transport=transport)
    assert llm._schema["anyOf"][0]["properties"]["parameters"] == {"type": "object"}  # nothing known yet
    summary, _, _ = _run(tmp_path, [], tool=TypedNmap(), llm=llm)
    assert summary.termination == "objective_met"
    parameters = sent[0]["format"]["anyOf"][0]["properties"]["parameters"]
    assert parameters == {"type": "object", "additionalProperties": False, "properties": {
        "ports": {"type": "string"}, "profile": {"type": "string", "enum": ["default", "service"]}}}
    assert "Parameters: ports (string); profile (one of: default, service)." in sent[0]["messages"][0]["content"]


# --- policy, refused before the run starts ---------------------------------------

def test_local_only_engagement_refuses_anthropic_before_anything_runs(tmp_path):
    with pytest.raises(PlannerPolicyError, match="anthropic"):
        _run(tmp_path, [DONE], provider="anthropic", planner={"allowed_providers": ["local"]})
    assert not (tmp_path / "out").exists()


def test_engagement_without_a_planner_block_refuses_anthropic(tmp_path):
    with pytest.raises(PlannerPolicyError, match="no planner block"):
        _run(tmp_path, [DONE], provider="anthropic")
    assert not (tmp_path / "out").exists()


def test_anthropic_runs_when_explicitly_allowed(tmp_path):
    summary, _, _ = _run(tmp_path, [DONE], provider="anthropic",
                         planner={"allowed_providers": ["anthropic"]})
    assert summary.termination == "objective_met"
    assert _planner_row(summary)["endpoint_class"] == "hosted"


def test_local_only_engagement_allows_local(tmp_path):
    summary, _, _ = _run(tmp_path, [DONE], planner={"allowed_providers": ["local"]})
    assert summary.termination == "objective_met"


def test_unknown_provider_in_policy_fails_engagement_validation(tmp_path):
    from op06d.engagement import EngagementError
    with pytest.raises(EngagementError):
        _run(tmp_path, [DONE], planner={"allowed_providers": ["openai"]})


def test_cli_refuses_a_public_local_endpoint(tmp_path, capsys):
    code = main(["run", "--engagement", str(_engagement(tmp_path)), "--out", str(tmp_path / "o"),
                 "--planner", "llm", "--llm-provider", "local", "--llm-endpoint", "http://8.8.8.8:11434"])
    assert code == 2 and "not loopback" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


def test_cli_refuses_anthropic_for_a_local_only_engagement(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    eng = _engagement(tmp_path, {"allowed_providers": ["local"]})
    code = main(["run", "--engagement", str(eng), "--out", str(tmp_path / "o"),
                 "--planner", "llm", "--llm-provider", "anthropic"])
    err = capsys.readouterr().err
    assert code == 2 and "does not allow" in err and FAKE_KEY not in err


def test_cli_refuses_anthropic_when_the_engagement_has_no_planner_block(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    code = main(["run", "--engagement", str(_engagement(tmp_path)), "--out", str(tmp_path / "o"),
                 "--planner", "llm", "--llm-provider", "anthropic"])
    err = capsys.readouterr().err
    assert code == 2 and "only 'local' is allowed" in err and FAKE_KEY not in err
    assert not (tmp_path / "o").exists()


def test_cli_llm_options_require_planner_llm(tmp_path, capsys):
    code = main(["run", "--engagement", str(_engagement(tmp_path)), "--out", str(tmp_path / "o"),
                 "--llm-provider", "local"])
    assert code == 2 and "--planner llm" in capsys.readouterr().err


def test_cli_anthropic_without_key_is_refused(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    eng = _engagement(tmp_path, {"allowed_providers": ["anthropic"]})
    code = main(["run", "--engagement", str(eng), "--out", str(tmp_path / "o"),
                 "--planner", "llm", "--llm-provider", "anthropic"])
    assert code == 2 and "ANTHROPIC_API_KEY" in capsys.readouterr().err


# --- limits ------------------------------------------------------------------------

def test_max_iterations_ends_the_run(tmp_path):
    summary, tool, _ = _run(tmp_path, [act(), act(ports="80")], max_iterations=2)
    assert summary.termination == "max_iterations"
    assert _loop_end(summary).reason == "max_iterations"
    assert len(tool.calls) == 2


def test_max_actions_ends_the_run(tmp_path):
    summary, tool, llm = _run(tmp_path, [act(), act(ports="80")], limits=RunLimits(max_actions=1))
    assert summary.termination == "max_actions" and len(tool.calls) == 1 and len(llm.calls) == 1
    assert _planner_row(summary)["termination"] == "max_actions"


def test_wall_clock_limit_ends_the_run(tmp_path):
    ticks = iter([0.0, 10.0, 200.0, 400.0, 600.0])
    summary, tool, llm = _run(
        tmp_path, [act(), act(ports="80")], limits=RunLimits(max_wall_clock_seconds=150.0),
        orchestrator_options={"monotonic": lambda: next(ticks)},
    )
    assert summary.termination == "max_wall_clock"
    assert len(llm.calls) == 1 and tool.calls == []
    assert _loop_end(summary).reason == "max_wall_clock"


def test_token_limit_ends_the_run_on_the_reply_that_crosses_it(tmp_path):
    summary, tool, llm = _run(tmp_path, [act(), act(ports="80"), DONE], usage=Usage(1500, 100),
                              limits=RunLimits(max_tokens=3000, max_output_tokens=100))
    assert summary.termination == "max_tokens"
    assert len(llm.calls) == 2 and len(tool.calls) == 1  # the crossing reply is never acted on
    end = _loop_end(summary)
    assert end.reason == "max_tokens" and end.parameters["input_tokens"] == 3000


def test_token_limit_refuses_a_call_whose_estimate_cannot_fit(tmp_path):
    summary, _, llm = _run(tmp_path, [DONE], limits=RunLimits(max_tokens=300, max_output_tokens=100))
    assert summary.termination == "max_tokens" and llm.calls == []


class CapLLM(ScriptLLM):
    def __init__(self, replies, usage):
        super().__init__(replies, usage)
        self.caps: list[int | None] = []
        self._cap: int | None = None

    def set_output_cap(self, cap):
        self._cap = cap

    def complete(self, system, messages):
        self.caps.append(self._cap)
        return super().complete(system, messages)


def test_each_request_is_capped_to_the_remaining_token_budget(tmp_path):
    llm = CapLLM([act(), act(ports="80"), DONE], Usage(7_000, 100))
    limits = RunLimits(max_tokens=10_000, max_output_tokens=2_000)
    summary, _, _ = _run(tmp_path, [], llm=llm, limits=limits)
    assert llm.caps[0] == 2_000              # plenty of budget: the configured maximum
    assert 256 <= llm.caps[1] < 2_000        # then what is left after the input estimate
    assert 7_100 + llm.caps[1] < 10_000
    assert summary.termination == "max_tokens" and len(llm.calls) == 2


def test_no_cap_is_pushed_to_the_adapter_without_a_token_limit(tmp_path):
    llm = CapLLM([DONE], Usage(10, 10))
    _run(tmp_path, [], llm=llm, limits=RunLimits(max_actions=5))
    assert llm.caps == [None]


def test_cost_limit_ends_the_run(tmp_path):
    limits = RunLimits(max_cost_usd=0.002, price_input_per_mtok=1.0, price_output_per_mtok=1.0,
                       max_output_tokens=100)
    summary, _, llm = _run(tmp_path, [act(), act(ports="80"), DONE], usage=Usage(1500, 100), limits=limits)
    assert summary.termination == "max_cost" and len(llm.calls) == 1
    assert _planner_row(summary)["termination"] == "max_cost"


def test_cost_limit_without_prices_is_rejected():
    with pytest.raises(ValueError):
        RunLimits(max_cost_usd=1.0)


# --- failures are recorded/ended, never executed --------------------------------

def test_api_failure_ends_the_run_cleanly_and_nothing_runs(tmp_path):
    summary, tool, _ = _run(tmp_path, [LLMUnavailable("local model: gave up after 4 attempts")])
    assert summary.termination == "model_failure" and tool.calls == []
    reasons = [e.reason or "" for e in _log(summary)]
    assert any("model failure: LLMUnavailable" in r for r in reasons)
    assert summary.report_html_path.exists()


def test_model_failure_cause_is_in_the_audit_log_the_evidence_store_and_the_report(tmp_path):
    exc = LLMUnavailable(f"model API error: AuthenticationError (HTTP 401) {FAKE_KEY}")
    exc.with_cause(401, "authentication_error")
    summary, tool, _ = _run(tmp_path, [exc])
    assert summary.termination == "model_failure" and tool.calls == []
    cause = {"error": "LLMUnavailable", "http_status": 401, "error_type": "authentication_error"}
    assert _loop_end(summary).parameters["cause"] == cause
    noted = [e for e in _log(summary) if (e.reason or "").startswith("model failure")]
    assert len(noted) == 1 and noted[0].parameters["cause"] == cause
    assert _planner_row(summary)["failure_cause"] == cause
    html = summary.report_html_path.read_text(encoding="utf-8")
    assert "Failure cause" in html and "authentication_error (HTTP 401)" in html
    for p in sorted((tmp_path / "out").rglob("*")):
        if p.is_file():
            assert FAKE_KEY.encode() not in p.read_bytes(), p


def test_a_failure_without_a_known_status_records_the_error_class_only(tmp_path):
    summary, _, _ = _run(tmp_path, [LLMUnavailable("local model: gave up after 4 attempts")])
    assert _loop_end(summary).parameters["cause"] == {"error": "LLMUnavailable"}
    assert "Failure cause" in summary.report_html_path.read_text(encoding="utf-8")


def test_the_report_planner_section_shows_the_output_mode_from_the_run_record(tmp_path):
    # RC-46: Planner model benchmark: score candidate models on lab runs
    llm = ScriptLLM([DONE])
    llm.output_mode = "json_schema"
    summary, _, _ = _run(tmp_path, [], llm=llm)
    assert _planner_row(summary)["output_mode"] == "json_schema"
    html = summary.report_html_path.read_text(encoding="utf-8")
    assert "<th>Output mode</th><td>json_schema</td>" in html
    from op06d.report import build_report, render_markdown
    store = EvidenceStore(summary.evidence_db_path)
    assert "| Output mode | json_schema |" in render_markdown(build_report(store.reconstruct_run(summary.run_id)))


def test_a_run_without_an_output_mode_has_no_output_mode_row(tmp_path):
    summary, _, _ = _run(tmp_path, [DONE])
    assert "output_mode" not in _planner_row(summary)
    assert "Output mode" not in summary.report_html_path.read_text(encoding="utf-8")


def test_a_run_that_does_not_fail_records_no_failure_cause(tmp_path):
    summary, _, _ = _run(tmp_path, [DONE])
    assert "cause" not in _loop_end(summary).parameters
    assert "failure_cause" not in _planner_row(summary)
    assert "Failure cause" not in summary.report_html_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("bad", ["x", "sk-ant-" + "short", "plain-" + "a" * 60])
def test_cli_anthropic_with_an_implausible_key_is_refused_before_anything_is_created(
        tmp_path, capsys, monkeypatch, bad):
    monkeypatch.setenv("ANTHROPIC_API_KEY", bad)
    eng = _engagement(tmp_path, {"allowed_providers": ["anthropic"]})
    code = main(["run", "--engagement", str(eng), "--out", str(tmp_path / "o"),
                 "--planner", "llm", "--llm-provider", "anthropic"])
    err = capsys.readouterr().err
    assert code == 2 and "does not look like an Anthropic API key" in err
    assert f"{len(bad)} character(s) long" in err
    assert not (tmp_path / "o").exists()


def test_refusal_ends_the_run_as_model_refused_in_audit_log_and_report(tmp_path):
    summary, tool, llm = _run(tmp_path, [act(), LLMRefused("model declined the request (stop_reason=refusal)")])
    assert summary.termination == "model_refused" and len(tool.calls) == 1 and len(llm.calls) == 2
    assert _loop_end(summary).reason == "model_refused"
    reasons = [e.reason or "" for e in _log(summary)]
    assert any(r.startswith("model refused: LLMRefused") for r in reasons)
    assert not any(r.startswith("model failure") for r in reasons)
    assert _planner_row(summary)["termination"] == "model_refused"
    html = summary.report_html_path.read_text(encoding="utf-8")
    assert "model_refused" in html and "model_failure" not in html


def test_anthropic_refusal_end_to_end_is_model_refused(tmp_path):
    class Msgs:
        def create(self, **kw):
            return SimpleNamespace(content=[], stop_reason="refusal",
                                   usage=SimpleNamespace(input_tokens=40, output_tokens=0))

    llm = AnthropicLLM(client=SimpleNamespace(messages=Msgs()), environ={},
                       retry=RetryPolicy(attempts=1, sleep=lambda s: None))
    summary, tool, _ = _run(tmp_path, [], provider="anthropic", llm=llm,
                            planner={"allowed_providers": ["anthropic"]})
    assert summary.termination == "model_refused" and tool.calls == []
    assert _planner_row(summary)["input_tokens"] == 40


def test_malformed_output_is_recorded_retried_bounded_and_never_executed(tmp_path):
    bad = ['{"type": "action", "tool": "nmap"', "sure! here you go", act()[:-1] + ', "extra": 1}']
    summary, tool, llm = _run(tmp_path, bad)
    assert summary.termination == "planner_failure" and tool.calls == [] and len(llm.calls) == 3
    invalid = [e for e in _log(summary) if (e.reason or "").startswith("invalid planner reply")]
    assert len(invalid) == 3


def test_out_of_scope_proposal_is_denied_and_recorded(tmp_path):
    summary, tool, _ = _run(tmp_path, [act(OUT_OF_SCOPE), DONE])
    assert tool.calls == [] and summary.denied == 1
    run = EvidenceStore(summary.evidence_db_path).reconstruct_run(summary.run_id)
    assert [(a.target, a.outcome) for a in run.actions] == [(OUT_OF_SCOPE, Outcome.DENIED.value)]


def test_intrusive_action_is_declined_when_non_interactive(tmp_path):
    summary, tool, _ = _run(tmp_path, [act(profile="aggressive"), DONE])
    assert tool.calls == [] and summary.declined == 1


# --- context management ---------------------------------------------------------------

def test_oversized_tool_output_is_truncated_with_the_wrapper_intact(tmp_path):
    tool = FakeNmap(body_chars=200_000)
    summary, _, llm = _run(tmp_path, [act(), DONE], tool=tool)
    observation = llm.calls[1][1][-1]["content"]
    assert len(observation) < 20_000
    assert f"<<<{BLOCK_NAME} id=" in observation
    assert f"<<<END_{BLOCK_NAME} id=" in observation.splitlines()[-1]
    assert "elided to fit the context budget" in observation
    assert summary.termination == "objective_met"


# --- fixed planner is unchanged ----------------------------------------------------------

def test_fixed_planner_records_no_planner_metadata(tmp_path):
    tool = FakeNmap()
    summary = run_engagement(_engagement(tmp_path), tmp_path / "out", tools=[tool],
                             non_interactive=True, resolver=lambda h: [IN_SCOPE])
    assert summary.planner == "fixed" and summary.termination is None
    assert tool.calls == [(IN_SCOPE, {"profile": "service"})]
    assert _planner_row(summary) is None
    assert "<h2>Planner</h2>" not in summary.report_html_path.read_text(encoding="utf-8")
    assert EVENT_PLANNER_CONFIG not in [e.event for e in _log(summary)]


# --- secrets ---------------------------------------------------------------------------

def test_api_key_never_reaches_audit_log_evidence_or_report(tmp_path):
    leaky_action = json.dumps({"type": "action", "tool": "nmap", "target": IN_SCOPE,
                               "parameters": {"ports": f"80 {FAKE_KEY}"},
                               "reason": f"key is {FAKE_KEY}"})
    leaky_done = json.dumps({"type": "done", "summary": f"done {FAKE_KEY}"})

    class Msgs:
        def __init__(self):
            self.replies = [leaky_action, leaky_done]

        def create(self, **kw):
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.replies.pop(0))],
                                   stop_reason="end_turn",
                                   usage=SimpleNamespace(input_tokens=10, output_tokens=5))

    msgs = Msgs()
    client = SimpleNamespace(messages=msgs)
    llm = AnthropicLLM(client=client, environ={"ANTHROPIC_API_KEY": FAKE_KEY},
                       retry=RetryPolicy(attempts=1, sleep=lambda s: None))
    tool = FakeNmap(banner=f"Server {FAKE_KEY}")
    summary, _, _ = _run(tmp_path, [], provider="anthropic", llm=llm, tool=tool,
                         planner={"allowed_providers": ["anthropic"]})

    out = tmp_path / "out"
    files = [p for p in out.rglob("*") if p.is_file()]
    assert summary.audit_log_path in files and summary.report_html_path in files
    assert any(p.name.startswith("evidence.db") for p in files)
    for p in files:
        assert FAKE_KEY.encode() not in p.read_bytes(), p
        assert b"sk-ant-" not in p.read_bytes(), p


def test_no_api_key_is_committed_to_the_repository():
    try:
        tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                                 check=True).stdout.split(b"\0")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git is not available")
    pattern = b"sk-ant-" + b"api"
    hits = []
    for name in filter(None, tracked):
        path = ROOT / name.decode()
        if path.is_file() and pattern in path.read_bytes():
            hits.append(name.decode())
    assert hits == []
