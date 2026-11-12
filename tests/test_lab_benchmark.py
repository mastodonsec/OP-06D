# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-46: Planner model benchmark: score candidate models on lab runs

Default-suite tests for lab/benchmark.py and lab/benchmark_metrics.py. No
docker, no Ollama, no model: metrics are computed from audit logs and evidence
stores written by ``run_engagement`` with a scripted model and a fake tool (or
by ``AuditLog`` directly), and the harness runs against a stub launcher.
"""

from __future__ import annotations

import csv
import json
import pathlib
import signal
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import benchmark as bench  # noqa: E402
import benchmark_metrics as bm  # noqa: E402
import model_relay as relay  # noqa: E402
from op06d.audit import EVENT_ITERATION, EVENT_LOOP_END, AuditLog, read_log  # noqa: E402
from op06d.cli import run_engagement  # noqa: E402
from op06d.llm import (  # noqa: E402
    DEFAULT_ANTHROPIC_MODEL, DEFAULT_LOCAL_MODEL, LLMSettings, LLMUnavailable, Usage,
)
from op06d.orchestrator import RunLimits  # noqa: E402
from op06d.redaction import clear_registered_secrets  # noqa: E402
from op06d.tools import Risk, ToolOutput  # noqa: E402

IN_SCOPE = "203.0.113.5"
OUT_OF_SCOPE = "198.51.100.7"
FAKE_KEY = "sk-ant-" + "api03-" + "B" * 48  # built in pieces: never a key-shaped literal in the tree
DEFAULT_CONFIG = ROOT / "lab" / "benchmark.default.yaml"
# Actions the --planner fixed baseline executes on the lab: nmap + nuclei on each of
# the 4 in-scope targets (the RC-46 smoke run, default-20261111T235813Z).
LAB_BASELINE_ACTIONS = 8


@pytest.fixture(autouse=True)
def _clean_secrets():
    clear_registered_secrets()
    yield
    clear_registered_secrets()


# --- a run to measure -----------------------------------------------------------------------

def _engagement(tmp_path: pathlib.Path) -> pathlib.Path:
    now = datetime.now(timezone.utc)
    path = tmp_path / "engagement.yaml"
    path.write_text(yaml.safe_dump({
        "engagement": "rc46-test",
        "authorization": {
            "client": "Test Client", "signed_scope_ref": "SOW-1", "authorized_by": "ops@example.com",
            "window": [(now - timedelta(hours=1)).isoformat(), (now + timedelta(hours=2)).isoformat()],
        },
        "scope": {"in_scope": [IN_SCOPE], "out_of_scope": [OUT_OF_SCOPE]},
        "intensity": {"max_rps": 50, "destructive": False},
        "objective": "recon",
    }), encoding="utf-8")
    return path


class FakeNmap:
    name = "nmap"
    description = "fake nmap"
    risk = Risk.ACTIVE_RECON
    destructive = False
    allowed_parameters = frozenset({"profile", "ports"})

    def run(self, target, parameters, *, hostname=None):
        ports = [int(p) for p in str(parameters.get("ports") or "80").split(",")]
        return ToolOutput({
            "scanner": "nmap", "version": "7.93",
            "hosts": [{
                "status": "up", "addresses": [{"address": target, "type": "ipv4"}], "hostnames": [],
                "ports": [{"port": p, "protocol": "tcp", "state": "open", "reason": "syn-ack",
                           "service": {"name": "http", "product": "FakeHTTP", "version": "1.0",
                                       "extrainfo": "", "tunnel": "", "cpe": []}} for p in ports],
            }],
            "summary": {"hosts_up": 1, "hosts_down": 0, "hosts_total": 1, "elapsed_seconds": 0.1},
        }, raw="<nmap/>", status="ok")


class ScriptLLM:
    def __init__(self, replies, usage=None):
        self.replies, self.usage, self.last_usage = list(replies), usage, None

    def complete(self, system, messages):
        self.last_usage = self.usage
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def act(target=IN_SCOPE, **params):
    return json.dumps({"type": "action", "tool": "nmap", "target": target, "parameters": params, "reason": "recon"})


DONE = json.dumps({"type": "done", "summary": "finished"})


def _llm_run(tmp_path, replies, *, usage=None, baseline=None, **kw) -> bm.RunMetrics:
    out = tmp_path / "out"
    run_engagement(_engagement(tmp_path), out, tools=[FakeNmap()], non_interactive=True, planner_mode="llm",
                   llm_settings=LLMSettings("local"), llm=ScriptLLM(replies, usage), **kw)
    return bm.collect_run(out, baseline)


def _fixed_run(tmp_path) -> bm.RunMetrics:
    out = tmp_path / "baseline"
    run_engagement(_engagement(tmp_path), out, tools=[FakeNmap()], non_interactive=True)
    return bm.collect_run(out)


def _synthetic_log(tmp_path, write) -> list:
    """An audit log written entry by entry, with a clock that advances 1.5 s per entry."""
    ticks = iter(datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=1.5 * i) for i in range(1000))
    log = AuditLog(tmp_path / "synthetic.audit.jsonl", "rc46-synthetic", clock=lambda: next(ticks))
    write(log)
    return read_log(log.path)


# --- metrics --------------------------------------------------------------------------------

def test_a_mixed_run_is_scored_from_its_audit_log_and_evidence_store(tmp_path):
    baseline = _fixed_run(tmp_path)
    assert baseline.findings >= 1 and baseline.planner == "fixed"
    m = _llm_run(tmp_path, [
        act(profile="service"),           # executed
        act(OUT_OF_SCOPE),                # denied by the gate: scope
        act(OUT_OF_SCOPE),                # repeat of a refused action: not re-submitted
        act(profile="service"),           # executed again: redundant
        "not json at all",                # invalid, re-asked
        act(profile="service", ports="81"),  # executed, different profile: not redundant
        DONE,
    ], usage=Usage(1000, 50), baseline=baseline.finding_ids)
    assert m.model_turns == 7 and m.well_formed_actions == 5 and m.done_replies == 1
    assert m.invalid_replies == 1 and m.repeat_refused == 1 and m.failed_calls == 0
    assert m.valid_action_rate == pytest.approx(6 / 7)
    assert m.out_of_scope_denied == 1 and m.denied_by_stage == {"scope": 1} and m.tool_rejected == 0
    assert m.executed_actions == 3 and m.redundant_actions == 1
    assert m.input_tokens == 7000 and m.output_tokens == 350 and m.total_tokens == 7350
    assert m.termination == "objective_met" and m.failure_cause is None and m.planner == "llm"
    assert m.wall_clock_seconds is not None and m.wall_clock_seconds >= 0
    # the fixed baseline found port 80; this run found it too, plus port 81
    assert m.baseline_findings == baseline.findings and m.coverage == 1.0 and m.extra_findings >= 1


def test_a_fixed_planner_run_has_no_model_turns_and_no_rate(tmp_path):
    m = _fixed_run(tmp_path)
    assert m.model_turns == 0 and m.valid_action_rate is None
    assert m.termination is None and m.total_tokens == 0 and m.output_mode is None
    assert m.executed_actions == 1  # nmap; nuclei is not registered here, so that proposal is refused
    assert m.denied_by_stage == {"tool": 1} and m.out_of_scope_denied == 0 and m.tool_rejected == 1
    assert m.coverage is None and m.baseline_findings is None


def test_a_well_formed_proposal_the_tool_rejects_is_counted_apart_from_the_rate(tmp_path):
    # Schema-valid replies can still carry parameters the tool will not take (the
    # RC-46 smoke run: nuclei with an empty severity list). The rate stays 1.0; the
    # refusal shows up in tool_rejected, and the action never executes.
    m = _llm_run(tmp_path, [
        act(profile="service", bogus="x"),  # well formed, refused by the tool layer
        act(profile="service"),             # executed
        DONE,
    ])
    assert m.model_turns == 3 and m.well_formed_actions == 2 and m.done_replies == 1
    assert m.valid_action_rate == 1.0
    assert m.tool_rejected == 1 and m.denied_by_stage == {"tool": 1} and m.out_of_scope_denied == 0
    assert m.executed_actions == 1


def test_a_loop_that_ended_before_the_first_turn_has_zero_turns(tmp_path):
    entries = _synthetic_log(tmp_path, lambda log: log.record(
        EVENT_LOOP_END, tool="orchestrator", parameters={"iteration": 0, "summary": ""}, reason="window_not_open"))
    m = bm.compute_metrics(entries, [], [], {"planner": "llm"}, ["a"])
    assert m.model_turns == 0 and m.valid_action_rate is None and m.termination == "window_not_open"
    assert m.coverage == 0.0 and m.baseline_covered == 0


def test_a_run_of_nothing_but_invalid_replies_scores_zero(tmp_path):
    m = _llm_run(tmp_path, ["nope", "{", "[1, 2]"])
    assert m.termination == "planner_failure"
    assert m.model_turns == 3 and m.invalid_replies == 3 and m.valid_action_rate == 0.0
    assert m.executed_actions == 0 and m.findings == 0


def test_model_failure_counts_the_failed_call_as_a_turn_and_keeps_the_cause(tmp_path):
    exc = LLMUnavailable(f"model API error (HTTP 401) {FAKE_KEY}")
    exc.with_cause(401, "authentication_error")
    m = _llm_run(tmp_path, [act(profile="service"), exc], usage=Usage(100, 10))
    assert m.termination == "model_failure" and m.model_turns == 2
    assert m.well_formed_actions == 1 and m.failed_calls == 1 and m.valid_action_rate == 0.5
    assert m.failure_cause == {"error": "LLMUnavailable", "http_status": 401, "error_type": "authentication_error"}
    assert FAKE_KEY not in json.dumps(m.as_dict())


def test_max_iterations_and_max_actions_runs_are_scored(tmp_path):
    (tmp_path / "a").mkdir()
    a = _llm_run(tmp_path / "a", [act(profile="service"), act(profile="service", ports="81")], max_iterations=2)
    assert a.termination == "max_iterations" and a.model_turns == 2 and a.valid_action_rate == 1.0
    (tmp_path / "b").mkdir()
    b = _llm_run(tmp_path / "b", [act(profile="service")], limits=RunLimits(max_actions=1))
    assert b.termination == "max_actions" and b.model_turns == 1 and b.executed_actions == 1


def test_a_reply_discarded_for_the_token_budget_is_a_turn_that_is_not_valid(tmp_path):
    m = _llm_run(tmp_path, [act(profile="service")], usage=Usage(9000, 10), limits=RunLimits(max_tokens=8000))
    assert m.termination == "max_tokens"
    assert m.model_turns == 1 and m.discarded_replies == 1 and m.well_formed_actions == 0
    assert m.valid_action_rate == 0.0 and m.executed_actions == 0 and m.total_tokens == 9010


def test_a_budget_stop_before_the_next_call_adds_no_turn(tmp_path):
    def write(log):
        log.record(EVENT_ITERATION, target=IN_SCOPE, tool="nmap", parameters={"iteration": 1}, reason="planned: x")
        log.record(EVENT_LOOP_END, tool="orchestrator", parameters={"iteration": 1}, reason="max_tokens")
    stats = bm.turn_stats(_synthetic_log(tmp_path, write))
    assert stats.model_turns == 1 and stats.discarded_replies == 0 and stats.valid_action_rate == 1.0


def test_redundant_means_same_tool_target_and_profile_already_executed(tmp_path):
    def write(log):
        for target, params in [("a.lab", {"profile": "service"}), ("a.lab", {"profile": "service"}),
                               ("a.lab", {"profile": "default"}), ("b.lab", {"profile": "service"}),
                               ("a.lab", {"profile": "service"})]:
            log.record_execution(tool="nmap", target=target, parameters={"iteration": 1, "params": params}, status="ok")
        log.record_execution(tool="nuclei", target="a.lab", parameters={"iteration": 2, "params": {}}, status="ok")
        log.record_execution(tool="nuclei", target="a.lab", parameters={"iteration": 3, "params": {}}, status="error")
    assert bm.executed_and_redundant(_synthetic_log(tmp_path, write)) == (7, 3)
    assert bm.executed_and_redundant([]) == (0, 0)


def test_coverage_is_the_share_of_baseline_finding_ids_the_run_reproduced():
    assert bm.coverage(["a", "b", "x"], ["a", "b", "c", "d"]) == (2, 0.5, 1)
    assert bm.coverage([], ["a"]) == (0, 0.0, 0)
    assert bm.coverage(["a"], []) == (0, None, 1)      # empty baseline: no coverage to speak of
    assert bm.coverage(["a"], None) == (None, None, None)


def test_wall_clock_is_first_audit_entry_to_last(tmp_path):
    def write(log):
        for _ in range(5):
            log.record(EVENT_ITERATION, tool="orchestrator", parameters={"iteration": 1}, reason="x")
    assert bm.wall_clock_seconds(_synthetic_log(tmp_path, write)) == 6.0
    assert bm.wall_clock_seconds([]) is None


def test_a_directory_without_a_run_cannot_be_scored(tmp_path):
    with pytest.raises(bm.MetricsError, match="no evidence store"):
        bm.collect_run(tmp_path)


# --- config ---------------------------------------------------------------------------------

def _config(**over) -> dict:
    data = {
        "benchmark": "t",
        "hosted_budget": {"max_tokens": 100_000},
        "candidates": [
            {"name": "small", "provider": "local", "model": "m:8b", "quantization": "q5", "context_tokens": 8192, "runs": 2},
            {"name": "hosted", "provider": "anthropic", "context_tokens": 200_000, "runs": 2},
            {"name": "big", "provider": "local", "model": "m:14b", "quantization": "q4", "context_tokens": 8192, "runs": 1},
        ],
    }
    data.update(over)
    return data


def test_the_default_config_is_the_shortlist():
    cfg = bench.load_config(DEFAULT_CONFIG)
    local = [c for c in cfg.candidates if c.provider == "local"]
    hosted = [c for c in cfg.candidates if c.provider == "anthropic"]
    assert len(local) == 4 and len(hosted) == 1
    assert local[0].model == DEFAULT_LOCAL_MODEL
    assert sum("qwen" in c.model for c in local) == 3 and any("30b" in c.model for c in local)
    assert all(c.quantization.startswith("q") and c.context_tokens >= 8192 for c in local)
    assert hosted[0].model == DEFAULT_ANTHROPIC_MODEL and hosted[0].runs < min(c.runs for c in local)
    assert cfg.budget_max_tokens and cfg.budget_max_cost_usd
    assert cfg.engagements == {"local": "lab/engagement.yaml", "anthropic": "lab/engagement-llm-hosted.yaml"}
    # RC-47's limits, except the action cap: the lab's --planner fixed baseline
    # executes 8 actions, and a lower cap would make coverage measure the cap.
    assert set(cfg.limits) == set(relay.ACCEPTANCE_LIMITS)
    assert cfg.limits["max_actions"] >= LAB_BASELINE_ACTIONS + 2
    assert cfg.limits["max_iterations"] > cfg.limits["max_actions"]
    for k in ("max_wall_clock", "max_tokens"):
        assert cfg.limits[k] == relay.ACCEPTANCE_LIMITS[k]


def test_an_unknown_provider_is_refused():
    data = _config()
    data["candidates"][0]["provider"] = "openai"
    with pytest.raises(bench.ConfigError, match="unknown provider 'openai'"):
        bench.parse_config(data)


def test_a_hosted_candidate_without_a_budget_is_refused():
    with pytest.raises(bench.ConfigError, match="hosted_budget"):
        bench.parse_config(_config(hosted_budget=None))
    with pytest.raises(bench.ConfigError, match="hosted_budget"):
        bench.parse_config(_config(hosted_budget={}))
    local_only = _config(hosted_budget=None)
    del local_only["candidates"][1]
    assert bench.parse_config(local_only).budget_max_tokens is None


def test_a_cost_budget_needs_a_price_for_the_model():
    data = _config(hosted_budget={"max_cost_usd": 2.0})
    assert bench.parse_config(data).budget_max_cost_usd == 2.0  # the default hosted model has a built-in price
    data["candidates"][1]["model"] = "claude-unpriced-9"
    with pytest.raises(bench.ConfigError, match="needs a price"):
        bench.parse_config(data)
    data["candidates"][1].update(price_input_per_mtok=1.0, price_output_per_mtok=5.0)
    assert bench.parse_config(data).candidates[1].prices() == (1.0, 5.0)


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d.update(extra=1), "unknown top-level"),
    (lambda d: d["candidates"][0].update(temperature=0.2), "unknown key"),
    (lambda d: d["candidates"][0].update(runs=0), "runs must be a positive integer"),
    (lambda d: d["candidates"][0].update(runs=True), "runs must be a positive integer"),
    (lambda d: d["candidates"][0].update(context_tokens="8k"), "context_tokens"),
    (lambda d: d["candidates"][0].pop("model"), "model must be a model name"),
    (lambda d: d["candidates"][0].pop("quantization"), "quantization label"),
    (lambda d: d["candidates"][0].update(name="../x"), "names a directory"),
    (lambda d: d["candidates"][2].update(name="small"), "duplicate candidate"),
    (lambda d: d.update(candidates=[]), "non-empty list"),
    (lambda d: d.update(limits={"max_turns": 3}), "unknown limit"),
    (lambda d: d.update(hosted_budget={"max_tokens": -1}), "positive integer"),
    (lambda d: d.update(engagements={"openai": "lab/x.yaml"}), "engagements"),
])
def test_malformed_configs_are_refused(mutate, message):
    data = _config()
    mutate(data)
    with pytest.raises(bench.ConfigError, match=message):
        bench.parse_config(data)


def test_hosted_candidates_need_the_explicit_opt_in():
    cfg = bench.parse_config(_config())
    with pytest.raises(bench.ConfigError, match="--allow-hosted"):
        bench.select(cfg)
    assert [c.name for c in bench.select(cfg, providers=["local"])] == ["small", "big"]
    assert [c.name for c in bench.select(cfg, allow_hosted=True)] == ["small", "hosted", "big"]
    assert [c.runs for c in bench.select(cfg, names=["small"], runs=1)] == [1]
    with pytest.raises(bench.ConfigError, match="no such candidate"):
        bench.select(cfg, names=["nope"])
    with pytest.raises(bench.ConfigError, match="--allow-hosted"):
        bench.select(cfg, names=["hosted"])


# --- harness, with a stub launcher --------------------------------------------------------------

def _metrics(**over) -> bm.RunMetrics:
    base = dict(
        model_turns=4, well_formed_actions=3, done_replies=1, invalid_replies=0, failed_calls=0,
        discarded_replies=0, repeat_refused=0, valid_action_rate=1.0, tool_rejected=0, out_of_scope_denied=0,
        denied_by_stage={},
        executed_actions=3, redundant_actions=0, findings=2, baseline_findings=2, baseline_covered=2, coverage=1.0,
        extra_findings=0, input_tokens=29_000, output_tokens=1_000, total_tokens=30_000, wall_clock_seconds=12.5,
        termination="objective_met", failure_cause=None, planner="llm", output_mode="json_schema",
        finding_ids=("f1", "f2"),
    )
    base.update(over)
    return bm.RunMetrics(**base)


class StubLauncher:
    def __init__(self, tmp_path, *, models=("m:8b", "m:14b"), check_exit=0, fail_run_at=None):
        self.tmp, self.models, self.check_exit, self.fail_run_at = tmp_path, set(models), check_exit, fail_run_at
        self.calls: list[tuple] = []
        self.requests: list[bench.RunRequest] = []

    def check_policy(self, mode, engagement):
        self.calls.append(("policy", mode, engagement))

    def require_key(self, mode):
        self.calls.append(("key", mode))

    def has_model(self, model):
        return model in self.models

    def up(self, mode, engagement):
        self.calls.append(("up", mode, engagement))

    def check(self, mode):
        self.calls.append(("check", mode))
        report = relay.CheckReport()
        report.ok("fine") if self.check_exit == 0 else report.fail("scanner reached the internet")
        return report

    def down(self):
        self.calls.append(("down",))

    def run(self, request):
        self.requests.append(request)
        self.calls.append(("run", request.mode, request.planner, request.out_rel.split("/", 1)[1]))
        if self.fail_run_at is not None and len(self.requests) == self.fail_run_at[0]:
            raise self.fail_run_at[1]
        return bench.RunArtifacts(0, self.tmp / request.out_rel / "run")

    def host_environment(self):
        return {"gpu": [{"name": "NVIDIA GeForce RTX 3080", "vram_mib": 10240}], "ollama_version": "0.12.3",
                "platform": "test"}

    def model_placement(self, model):
        return {"model_bytes": 6_000_000_000, "model_bytes_on_gpu": 6_000_000_000}

    def steps(self):
        return [c for c in self.calls if c[0] in ("up", "check", "run", "down")]


def _collect(run_dir, baseline_ids):
    if run_dir.parent.name == bench.BASELINE_NAME:
        return _metrics(planner="fixed", model_turns=0, valid_action_rate=None, termination=None, total_tokens=0,
                        input_tokens=0, output_tokens=0, output_mode=None, coverage=None, baseline_findings=None)
    assert list(baseline_ids) == ["f1", "f2"]  # every candidate run is scored against the baseline
    return _metrics()


def _bench(tmp_path, launcher, *, cfg=None, collect=_collect, say=lambda _: None, **select):
    cfg = cfg or bench.parse_config(_config())
    chosen = bench.select(cfg, allow_hosted=True, **select)
    return bench.run_benchmark(cfg, chosen, launcher, results_root=tmp_path / "results", collect=collect,
                               bench_id="t-1", say=say)


def test_candidates_are_grouped_into_one_stack_per_provider_with_one_baseline(tmp_path):
    launcher = StubLauncher(tmp_path)
    results, results_dir = _bench(tmp_path, launcher)
    assert launcher.steps() == [
        ("down",), ("up", "local", "lab/engagement.yaml"), ("check", "local"),
        ("run", "local", "fixed", "baseline-fixed"),
        ("run", "local", "llm", "small/run-01"), ("run", "local", "llm", "small/run-02"),
        ("run", "local", "llm", "big/run-01"),
        ("down",), ("up", "anthropic", "lab/engagement-llm-hosted.yaml"), ("check", "anthropic"),
        ("run", "anthropic", "llm", "hosted/run-01"), ("run", "anthropic", "llm", "hosted/run-02"),
        ("down",),
    ]
    assert [(r.model, r.context_tokens) for r in launcher.requests[1:4]] == [("m:8b", 8192)] * 2 + [("m:14b", 8192)]
    assert launcher.requests[0].model is None and launcher.requests[-1].model == DEFAULT_ANTHROPIC_MODEL
    assert results["status"] == "completed" and len(results["runs"]) == 5
    assert results["baseline"]["metrics"]["planner"] == "fixed"
    env = results["runs"][0]["environment"]
    assert env == {"gpu": [{"name": "NVIDIA GeForce RTX 3080", "vram_mib": 10240}], "quantization": "q5",
                   "context_tokens": 8192, "output_mode": "json_schema", "runtime": "ollama",
                   "runtime_version": "0.12.3", "model_bytes": 6_000_000_000, "model_bytes_on_gpu": 6_000_000_000}
    assert results["runs"][-1]["environment"]["runtime"] == "anthropic api"
    assert results_dir == tmp_path / "results" / "t-1"


def test_results_are_written_as_json_csv_and_a_markdown_table(tmp_path):
    _, results_dir = _bench(tmp_path, StubLauncher(tmp_path), providers=["local"])
    data = json.loads((results_dir / "results.json").read_text(encoding="utf-8"))
    assert data["ticket"] == bench.TICKET and data["finding_identity"] == bm.FINDING_IDENTITY
    small = data["summary"][0]
    assert small["candidate"] == "small" and small["n"] == 2 and small["failures"] == 0
    assert small["valid_action_rate"] == {"n": 2, "mean": 1.0, "stdev": 0.0, "min": 1.0, "max": 1.0}
    assert data["summary"][1]["coverage"]["stdev"] is None  # one run: no spread
    with (results_dir / "results.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["candidate"] for r in rows] == ["baseline-fixed", "small", "small", "big"]
    assert rows[1]["gpu"] == "NVIDIA GeForce RTX 3080" and rows[1]["vram_mib"] == "10240"
    assert rows[1]["quantization"] == "q5" and rows[1]["output_mode"] == "json_schema"
    assert rows[1]["total_tokens"] == "30000" and rows[1]["termination"] == "objective_met"
    assert rows[1]["tool_rejected"] == "0"
    md = (results_dir / "summary.md").read_text(encoding="utf-8")
    assert "| small | local: m:8b | q5 | 8192 | 2 | 0 | 1.00 ± 0.00 (1.00 to 1.00) |" in md
    assert "| big | local: m:14b | q4 | 8192 | 1 | 0 | 1.00 |" in md
    assert "NVIDIA GeForce RTX 3080 (10240 MiB)" in md and bm.FINDING_IDENTITY in md


def test_failures_and_spread_show_in_the_summary():
    runs = [
        {"candidate": "c", "provider": "local", "model": "m", "quantization": "q", "context_tokens": 1, "status": "ok",
         "metrics": _metrics(valid_action_rate=0.5, coverage=0.5, tool_rejected=2).as_dict()},
        {"candidate": "c", "status": "ok", "metrics": _metrics(
            termination="model_failure", failure_cause={"error": "LLMUnavailable", "error_type": "overloaded_error"},
            valid_action_rate=1.0, coverage=None).as_dict()},
        {"candidate": "c", "status": "error", "metrics": None},
        {"candidate": "c", "status": "skipped_budget", "metrics": None},
    ]
    (row,) = bm.summarize(runs)
    assert row["n"] == 2 and row["failures"] == 2 and row["errors"] == 1 and row["skipped"] == 1
    assert row["valid_action_rate"]["mean"] == 0.75 and row["valid_action_rate"]["min"] == 0.5
    assert row["coverage"] == {"n": 1, "mean": 0.5, "stdev": None, "min": 0.5, "max": 0.5}
    assert row["terminations"] == {"model_failure": 1, "objective_met": 1}
    assert row["failure_causes"] == {"overloaded_error": 1}
    assert row["tool_rejected"]["mean"] == 1.0 and row["tool_rejected"]["max"] == 2
    md = bm.render_markdown({"summary": [row], "benchmark": "x"})
    assert "2 (overloaded_error x1); 1 skipped (budget)" in md
    assert "| Valid-action rate | Rejected by tool | Out-of-scope denied |" in md
    assert "| 0.75 ± 0.35 (0.50 to 1.00) | 1.0 ± 1.4 (0.0 to 2.0) | 0.0 ± 0.0 (0.0 to 0.0) |" in md


def test_no_run_starts_unless_the_isolation_check_passes(tmp_path):
    launcher = StubLauncher(tmp_path, check_exit=1)
    with pytest.raises(bench.BenchmarkError, match="isolation check did not PASS"):
        _bench(tmp_path, launcher)
    assert launcher.steps() == [("down",), ("up", "local", "lab/engagement.yaml"), ("check", "local"), ("down",)]
    data = json.loads((tmp_path / "results" / "t-1" / "results.json").read_text(encoding="utf-8"))
    assert data["status"] == "aborted" and "isolation" in data["error"] and data["runs"] == []


@pytest.mark.parametrize("boom", [RuntimeError("docker fell over"), KeyboardInterrupt()])
def test_down_is_called_when_a_run_blows_up_or_the_operator_interrupts(tmp_path, boom):
    launcher = StubLauncher(tmp_path, fail_run_at=(3, boom))
    with pytest.raises(type(boom)):
        _bench(tmp_path, launcher)
    assert launcher.steps()[-1] == ("down",) and ("up", "anthropic", "lab/engagement-llm-hosted.yaml") not in launcher.calls
    data = json.loads((tmp_path / "results" / "t-1" / "results.json").read_text(encoding="utf-8"))
    assert data["status"] == "aborted" and len(data["runs"]) == 1  # the run before the failure is kept


class TeardownStub(StubLauncher):
    """Records what is on disk, and the SIGINT handler, when the teardown
    ``down`` is called (the one after a stack was brought up), then raises
    ``boom`` if there is one."""

    def __init__(self, tmp_path, *, boom=None, results_dir=None, **kw):
        super().__init__(tmp_path, **kw)
        self.boom, self.results_dir = boom, results_dir or tmp_path / "results" / "t-1"
        self.files_at_teardown = self.on_disk = self.sigint = None

    def down(self):
        super().down()
        if not any(c[0] == "up" for c in self.calls):
            return  # the down before the first up
        found = sorted(self.results_dir.glob("**/*.*"))
        self.files_at_teardown = [p.name for p in found]
        for p in found:
            if p.name == "results.json":
                self.on_disk = json.loads(p.read_text(encoding="utf-8"))
        self.sigint = signal.getsignal(signal.SIGINT)
        if self.boom is not None:
            raise self.boom


def test_the_results_are_on_disk_before_the_teardown_and_rewritten_after_it(tmp_path):
    said: list[str] = []
    launcher = TeardownStub(tmp_path)
    before = signal.getsignal(signal.SIGINT)
    results, results_dir = _bench(tmp_path, launcher, providers=["local"], say=said.append)
    assert launcher.files_at_teardown == ["results.csv", "results.json", "summary.md"]
    assert launcher.on_disk["status"] == "completed" and len(launcher.on_disk["runs"]) == 3
    assert launcher.on_disk["teardown"] == "pending" and launcher.on_disk["finished_at"] is None
    data = json.loads((results_dir / "results.json").read_text(encoding="utf-8"))
    assert data["status"] == "completed" and data["teardown"] == "ok" and data["finished_at"]
    # Ctrl+C is ignored for the teardown and the previous handler is back afterwards
    assert launcher.sigint is signal.SIG_IGN and signal.getsignal(signal.SIGINT) is before
    assert said[-1] == "[local] tearing down the stack (this can take a minute)"


def test_a_second_ctrl_c_during_the_teardown_cannot_skip_the_results(tmp_path):
    said: list[str] = []
    launcher = TeardownStub(tmp_path, fail_run_at=(3, KeyboardInterrupt()), boom=KeyboardInterrupt())
    before = signal.getsignal(signal.SIGINT)
    with pytest.raises(KeyboardInterrupt):
        _bench(tmp_path, launcher, say=said.append)
    assert signal.getsignal(signal.SIGINT) is before
    # written before the teardown: aborted, with the run that had completed
    assert launcher.on_disk["status"] == "aborted" and launcher.on_disk["error"] == "interrupted"
    assert len(launcher.on_disk["runs"]) == 1 and launcher.on_disk["teardown"] == "pending"
    # and still there, with the teardown outcome, after the second interrupt
    data = json.loads((tmp_path / "results" / "t-1" / "results.json").read_text(encoding="utf-8"))
    assert data["status"] == "aborted" and data["error"] == "interrupted; teardown_failed: interrupted"
    assert data["teardown"] == "failed" and data["finished_at"]
    assert [r["candidate"] for r in data["runs"]] == ["small"] and data["baseline"]["status"] == "ok"
    assert sorted(p.name for p in (tmp_path / "results" / "t-1").iterdir()) == [
        "results.csv", "results.json", "summary.md"]
    assert f"partial results (aborted): {tmp_path / 'results' / 't-1'}" in said
    assert "[local] tearing down the stack (this can take a minute; do not press Ctrl+C again)" in said
    assert said[-1].startswith("WARNING: teardown failed") and "uv run python lab/model_relay.py down" in said[-1]


def test_a_teardown_that_fails_still_leaves_results_and_warns(tmp_path):
    said: list[str] = []
    launcher = TeardownStub(tmp_path, boom=bench.BenchmarkError("docker compose down failed (exit 1)"))
    with pytest.raises(bench.BenchmarkError, match="teardown failed: docker compose down failed"):
        _bench(tmp_path, launcher, providers=["local"], say=said.append)
    data = json.loads((tmp_path / "results" / "t-1" / "results.json").read_text(encoding="utf-8"))
    assert data["status"] == "aborted" and data["teardown"] == "failed" and len(data["runs"]) == 3
    assert data["error"] == "teardown_failed: docker compose down failed (exit 1)"
    assert said[-1].startswith("WARNING: teardown failed") and "uv run python lab/model_relay.py down" in said[-1]
    # after an earlier failure, that failure is what is raised, and both are in the results
    said.clear()
    launcher = TeardownStub(tmp_path, fail_run_at=(2, RuntimeError("docker fell over")),
                            boom=subprocess.TimeoutExpired("docker", 300))
    with pytest.raises(RuntimeError, match="docker fell over"):
        _bench(tmp_path, launcher, providers=["local"], say=said.append)
    data = json.loads((tmp_path / "results" / "t-1" / "results.json").read_text(encoding="utf-8"))
    assert data["status"] == "aborted" and data["teardown"] == "failed"
    assert data["error"].startswith("RuntimeError: docker fell over; teardown_failed: ")
    assert any(line.startswith("WARNING: teardown failed") for line in said)


def test_the_cli_exits_130_with_results_on_disk_after_two_interrupts(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(bench.bm, "collect_run", _collect)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(_config()), encoding="utf-8")
    launcher = TeardownStub(tmp_path, results_dir=tmp_path / "r", fail_run_at=(2, KeyboardInterrupt()),
                            boom=KeyboardInterrupt())
    code = bench.main(["run", "--config", str(cfg), "--candidate", "small", "--results-dir", str(tmp_path / "r")],
                      launcher=launcher)
    out = capsys.readouterr()
    assert code == 130 and "interrupted" in out.err
    assert "do not press Ctrl+C again" in out.out and "WARNING: teardown failed" in out.out
    (written,) = (tmp_path / "r").glob("*/results.json")
    data = json.loads(written.read_text(encoding="utf-8"))
    assert data["status"] == "aborted" and data["baseline"]["status"] == "ok" and data["runs"] == []


def test_a_failed_run_is_recorded_and_the_benchmark_goes_on(tmp_path):
    launcher = StubLauncher(tmp_path, fail_run_at=(2, subprocess.TimeoutExpired("docker", 5)))
    results, _ = _bench(tmp_path, launcher, providers=["local"])
    assert [r["status"] for r in results["runs"]] == ["error", "ok", "ok"]
    assert "time limit" in results["runs"][0]["error"] and results["status"] == "completed"
    assert results["summary"][0]["failures"] == 1 and results["summary"][0]["n"] == 1


def test_a_failed_baseline_stops_the_benchmark(tmp_path):
    def collect(run_dir, baseline_ids):
        raise bm.MetricsError("no evidence store")
    launcher = StubLauncher(tmp_path)
    with pytest.raises(bench.BenchmarkError, match="baseline failed"):
        _bench(tmp_path, launcher, collect=collect)
    assert [c for c in launcher.steps() if c[0] == "run"] == [("run", "local", "fixed", "baseline-fixed")]
    assert launcher.steps()[-1] == ("down",)


def test_the_hosted_group_stops_cleanly_when_the_budget_is_reached(tmp_path):
    data = _config(hosted_budget={"max_tokens": 50_000})
    data["candidates"][1]["runs"] = 4
    launcher = StubLauncher(tmp_path)
    results, _ = _bench(tmp_path, launcher, cfg=bench.parse_config(data), providers=["anthropic"])
    hosted = [r for r in launcher.requests if r.planner == "llm"]
    # 30k tokens per run: the first run may use the whole 50k, the second only the 20k left, then stop
    assert [r.limits["max_tokens"] for r in hosted] == [50_000, 20_000]
    assert [r["status"] for r in results["runs"]] == ["ok", "ok", "skipped_budget", "skipped_budget"]
    assert results["hosted_budget"] == {"max_tokens": 50_000, "max_cost_usd": None, "spent_tokens": 60_000,
                                        "spent_cost_usd": pytest.approx(0.272), "stopped": True, "skipped_runs": 2}
    assert results["status"] == "completed" and launcher.steps()[-1] == ("down",)
    assert results["summary"][0]["n"] == 2 and results["summary"][0]["skipped"] == 2


def test_a_cost_budget_caps_each_hosted_run_and_stops_the_group(tmp_path):
    data = _config(hosted_budget={"max_cost_usd": 0.20})
    data["candidates"][1]["runs"] = 3
    launcher = StubLauncher(tmp_path)
    results, _ = _bench(tmp_path, launcher, cfg=bench.parse_config(data), providers=["anthropic"])
    hosted = [r for r in launcher.requests if r.planner == "llm"]
    # one run costs 29k x $4/M + 1k x $20/M = $0.136, leaving $0.064 for the second
    assert [round(r.max_cost_usd, 3) for r in hosted] == [0.2, 0.064]
    assert all(r.prices == (4.0, 20.0) for r in hosted)
    assert [r["status"] for r in results["runs"]] == ["ok", "ok", "skipped_budget"]


def test_a_hosted_run_that_left_no_record_is_charged_its_whole_grant(tmp_path):
    def collect(run_dir, baseline_ids):
        if run_dir.parent.name == bench.BASELINE_NAME:
            return _collect(run_dir, baseline_ids)
        raise bm.MetricsError("no evidence store")
    data = _config(hosted_budget={"max_tokens": 310_000})
    results, _ = _bench(tmp_path, StubLauncher(tmp_path), cfg=bench.parse_config(data), providers=["anthropic"],
                        collect=collect)
    assert [r["status"] for r in results["runs"]] == ["error", "skipped_budget"]
    assert results["hosted_budget"]["spent_tokens"] == 300_000


def test_a_model_that_is_not_pulled_refuses_the_benchmark_before_any_stack(tmp_path):
    launcher = StubLauncher(tmp_path, models=("m:8b",))
    with pytest.raises(bench.Refused, match=r"does not have 'm:14b'[\s\S]*ollama pull m:14b"):
        _bench(tmp_path, launcher, providers=["local"])
    assert launcher.steps() == [] and not (tmp_path / "results").exists()


def test_the_cli_refuses_hosted_candidates_without_the_flag_and_starts_nothing(tmp_path, capsys):
    launcher = StubLauncher(tmp_path)
    code = bench.main(["run", "--config", str(DEFAULT_CONFIG), "--results-dir", str(tmp_path / "r")], launcher=launcher)
    assert code == 2 and "--allow-hosted" in capsys.readouterr().err
    assert launcher.calls == [] and not (tmp_path / "r").exists()


def test_the_cli_validates_and_lists_models_without_starting_anything(tmp_path, capsys):
    launcher = StubLauncher(tmp_path, models=(DEFAULT_LOCAL_MODEL,))
    assert bench.main(["validate", "--config", str(DEFAULT_CONFIG), "--provider", "local"], launcher=launcher) == 0
    assert "config OK" in capsys.readouterr().out
    assert bench.main(["models", "--config", str(DEFAULT_CONFIG)], launcher=launcher) == 0
    out = capsys.readouterr().out
    assert f"{DEFAULT_LOCAL_MODEL}: present" in out and out.count("MISSING  ->  ollama pull ") == 3
    assert launcher.steps() == []


def test_the_cli_runs_a_selected_candidate_and_reports_an_interrupt(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(bench.bm, "collect_run", _collect)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(yaml.safe_dump(_config()), encoding="utf-8")
    argv = ["run", "--config", str(cfg), "--candidate", "small", "--runs", "1", "--results-dir", str(tmp_path / "r")]
    launcher = StubLauncher(tmp_path)
    assert bench.main(argv, launcher=launcher) == 0
    assert "| small | local: m:8b |" in capsys.readouterr().out
    assert [c for c in launcher.steps() if c[0] == "run"] == [
        ("run", "local", "fixed", "baseline-fixed"), ("run", "local", "llm", "small/run-01")]
    interrupted = StubLauncher(tmp_path, fail_run_at=(1, KeyboardInterrupt()))
    assert bench.main(argv, launcher=interrupted) == 130
    assert interrupted.steps()[-1] == ("down",) and "interrupted" in capsys.readouterr().err


# --- no key material in the results -----------------------------------------------------------------

def test_key_material_in_the_results_fails_the_benchmark_and_removes_the_file(tmp_path):
    def collect(run_dir, baseline_ids):
        m = _collect(run_dir, baseline_ids)
        return m if m.planner == "fixed" else replace(m, termination=FAKE_KEY)  # a leak nothing scrubbed
    with pytest.raises(bench.BenchmarkError, match="API key material was found") as err:
        _bench(tmp_path, StubLauncher(tmp_path), providers=["local"], collect=collect)
    assert FAKE_KEY not in str(err.value)
    assert list((tmp_path / "results" / "t-1").iterdir()) == []


def test_the_results_written_before_the_teardown_are_scanned_too(tmp_path):
    def collect(run_dir, baseline_ids):
        m = _collect(run_dir, baseline_ids)
        return m if m.planner == "fixed" else replace(m, termination=FAKE_KEY)
    launcher = TeardownStub(tmp_path, fail_run_at=(3, KeyboardInterrupt()), boom=KeyboardInterrupt())
    with pytest.raises(bench.BenchmarkError, match="API key material was found") as err:
        _bench(tmp_path, launcher, providers=["local"], collect=collect)
    assert isinstance(err.value.__cause__, KeyboardInterrupt) and FAKE_KEY not in str(err.value)
    assert launcher.files_at_teardown == []  # deleted before the teardown started, not only after it
    assert list((tmp_path / "results" / "t-1").iterdir()) == []


def test_the_results_scan_finds_the_key_and_key_shaped_values(tmp_path):
    (tmp_path / "clean.json").write_text('{"ok": true, "env": "ANTHROPIC_API_KEY"}', encoding="utf-8")
    (tmp_path / "shape.csv").write_text("x," + "sk-ant-" + "zzzzzzzzzzzz", encoding="utf-8")
    (tmp_path / "exact.md").write_text("value " + "opaque-" * 6, encoding="utf-8")
    assert bench.scan_for_key_material(tmp_path, "opaque-" * 6) == ["exact.md", "shape.csv"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["clean.json"]
    # a value too short to search for is not searched for (it would match by chance); the shape scan still runs
    assert bench.scan_for_key_material(tmp_path, "o") == []


def test_error_text_from_a_run_is_scrubbed_and_bounded(tmp_path):
    launcher = StubLauncher(tmp_path, fail_run_at=(2, relay.RelayError(f"boom {FAKE_KEY} " + "x" * 2000)))
    results, results_dir = _bench(tmp_path, launcher, providers=["local"])
    assert results["runs"][0]["status"] == "error" and len(results["runs"][0]["error"]) <= 500
    for p in results_dir.iterdir():
        assert FAKE_KEY.encode() not in p.read_bytes()


# --- the real launcher's commands, with a fake runner ---------------------------------------------

class FakeDocker:
    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        if argv[0] == "nvidia-smi":
            return subprocess.CompletedProcess(argv, 0, "NVIDIA GeForce RTX 4080 Laptop GPU, 12282\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_the_baseline_command_has_no_model_options_and_a_candidate_run_carries_its_own():
    fixed = bench.op06d_argv(bench.RunRequest("local", "lab/engagement.yaml", "b/x", "fixed"), "/c/e.yaml", "/c/run")
    assert fixed[:4] == ["python3", "-m", "op06d.cli", "run"] and fixed[-1] == "--non-interactive"
    assert "--template-dir" in fixed and not any(a.startswith(("--planner", "--llm", "--model", "--max-")) for a in fixed)
    llm = bench.op06d_argv(bench.RunRequest(
        "local", "lab/engagement.yaml", "b/x", "llm", model="m:14b", context_tokens=16384,
        limits={"max_tokens": 1234}), "/c/e.yaml", "/c/run")
    joined = " ".join(llm)
    assert "--planner llm --llm-provider local" in joined and "--model m:14b" in joined
    assert "--context-tokens 16384" in joined and "--max-tokens 1234" in joined and "--max-cost-usd" not in joined
    assert f"--llm-endpoint http://{relay.RELAY_IP}:11434" in joined
    hosted = " ".join(bench.op06d_argv(bench.RunRequest(
        "anthropic", "lab/engagement-llm-hosted.yaml", "b/x", "llm", model="claude-x", context_tokens=200_000,
        max_cost_usd=1.5, prices=(4.0, 20.0)), "/c/e.yaml", "/c/run"))
    assert "--max-cost-usd 1.5000 --price-input-per-mtok 4.0 --price-output-per-mtok 20.0" in hosted
    assert "--llm-endpoint" not in hosted


def test_the_launcher_writes_each_run_to_its_own_capture_directory_and_passes_the_key_by_name_only(monkeypatch):
    monkeypatch.setenv(relay.KEY_ENV, FAKE_KEY)
    docker = FakeDocker()
    launcher = bench.RelayLauncher(docker)
    out = launcher.run(bench.RunRequest("anthropic", "lab/engagement-llm-hosted.yaml", "id/hosted/run-01", "llm",
                                        model="claude-x", context_tokens=200_000))
    assert out.run_dir == ROOT / "lab" / "captures" / "_rc46_benchmark" / "id" / "hosted" / "run-01" / "run"
    mkdir, gen, run = docker.calls
    assert mkdir[-3:] == ["mkdir", "-p", "/captures/_rc46_benchmark/id/hosted/run-01"]
    assert gen[-3:] == ["/captures/_rc46_benchmark/id/hosted/run-01/engagement.yaml", "--template",
                        "/lab/engagement-llm-hosted.yaml"]
    assert run[run.index("exec"):run.index("scanner")] == ["exec", "-T", "-e", "ANTHROPIC_API_KEY"]
    assert "/captures/_rc46_benchmark/id/hosted/run-01/run" in run
    docker.calls.clear()
    launcher.run(bench.RunRequest("anthropic", "lab/engagement-llm-hosted.yaml", "id/baseline-fixed", "fixed"))
    launcher.run(bench.RunRequest("local", "lab/engagement.yaml", "id/small/run-01", "llm", model="m:8b"))
    assert not any("-e" in call for call in docker.calls)  # the baseline and local runs never get the key
    assert FAKE_KEY not in json.dumps(docker.calls)
    assert all(str(relay.OVERLAYS["anthropic"]) in c for c in docker.calls[:3])


def test_the_host_environment_reads_the_gpu_from_nvidia_smi_and_falls_back_to_unknown():
    tags = {"/api/version": {"version": "0.12.3"},
            "/api/ps": {"models": [{"name": "m:30b", "size": 19_000_000_000, "size_vram": 9_500_000_000}]}}
    launcher = bench.RelayLauncher(FakeDocker(), fetch=lambda url: tags[url.split("11434")[1]])
    env = launcher.host_environment()
    assert env["gpu"] == [{"name": "NVIDIA GeForce RTX 4080 Laptop GPU", "vram_mib": 12282}]
    assert env["ollama_version"] == "0.12.3"
    assert launcher.model_placement("m:30b") == {"model_bytes": 19_000_000_000, "model_bytes_on_gpu": 9_500_000_000}
    assert launcher.model_placement("other") == {}

    def no_nvidia(argv, timeout):
        raise FileNotFoundError("nvidia-smi")

    def no_ollama(url):
        raise OSError("connection refused")
    bare = bench.RelayLauncher(no_nvidia, fetch=no_ollama).host_environment()
    assert bare["gpu"] == "unknown" and bare["ollama_version"] == "unknown"
    assert bench.RelayLauncher(no_nvidia, fetch=no_ollama).model_placement("m") == {}
    assert bench.parse_nvidia_smi("A, 10240\nB, [N/A]\n\n") == [
        {"name": "A", "vram_mib": 10240}, {"name": "B", "vram_mib": "unknown"}]


# --- repository hygiene -------------------------------------------------------------------------------

def test_benchmark_output_directories_are_git_ignored_and_apart_from_the_evidence():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "benchmark-results/" in ignore and "lab/captures/_rc46_benchmark/" in ignore
    assert bench.DEFAULT_RESULTS_DIR == ROOT / "benchmark-results"
    assert (ROOT / "lab" / "captures") not in bench.DEFAULT_RESULTS_DIR.parents


def test_down_goes_through_the_teardown_runner_which_detaches_the_child_from_ctrl_c(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, **kw)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(bench.subprocess, "run", fake_run)
    bench.RelayLauncher().down()
    assert seen["argv"][:2] == ["docker", "compose"] and seen["argv"][-2:] == ["down", "--remove-orphans"]
    assert seen["encoding"] == "utf-8" and seen["capture_output"] and seen["check"] is False and seen["timeout"] == 300
    if sys.platform == "win32":
        assert seen["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        assert seen["start_new_session"] is True
    # a launcher given its own runner never reaches the real one, for down either
    seen.clear()
    docker = FakeDocker()
    bench.RelayLauncher(docker).down()
    assert seen == {} and docker.calls[0][-2:] == ["down", "--remove-orphans"]

    def failing(argv, timeout):
        return subprocess.CompletedProcess(argv, 1, "", "no such network")
    with pytest.raises(bench.BenchmarkError, match="docker compose down failed"):
        bench.RelayLauncher(docker, down_run=failing).down()


def test_the_harness_starts_no_process_of_its_own_except_the_teardown():
    import ast

    for name in ("benchmark.py", "benchmark_metrics.py"):
        tree = ast.parse((ROOT / "lab" / name).read_text(encoding="utf-8"))

        def starts(node):
            return [n for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and isinstance(n.func.value, ast.Name) and n.func.value.id in ("subprocess", "os")
                    and n.func.attr in ("run", "Popen", "call", "check_output", "check_call", "system", "popen")]
        # docker and nvidia-smi go through model_relay.default_runner (UTF-8 capture); the one
        # exception is benchmark.teardown_runner, used for `docker compose down` only
        allowed = [c for fn in tree.body if isinstance(fn, ast.FunctionDef) and fn.name == "teardown_runner"
                   for c in starts(fn)] if name == "benchmark.py" else []
        assert len(allowed) == (1 if name == "benchmark.py" else 0), name
        assert starts(tree) == allowed, name
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not {m for m in imported if m and m.startswith(("op06d.tools", "op06d.nmap", "op06d.nuclei"))}, name
