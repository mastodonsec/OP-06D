# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-46: Planner model benchmark: score candidate models on lab runs

Opt-in harness: runs ``op06d run --planner llm`` N times per candidate model
in the sealed lab, through the RC-47 model relay, and scores each run from its
audit log and evidence store (lab/benchmark_metrics.py). Run from the
repository root with the project venv:

    uv run python lab/benchmark.py validate --config lab/benchmark.default.yaml
    uv run python lab/benchmark.py models   --config lab/benchmark.default.yaml
    uv run python lab/benchmark.py run      --config lab/benchmark.default.yaml --provider local
    uv run python lab/benchmark.py run      --config lab/benchmark.default.yaml --provider anthropic --allow-hosted

What ``run`` does, in order:

* refuses before any docker call if the selection has a hosted candidate
  without ``--allow-hosted``, the engagement does not allow a provider, the
  API key is implausible (hosted), or a local model is not pulled in host
  Ollama (it never pulls);
* per provider (``local`` first), one stack through lab/model_relay.py:
  ``down``, ``up``, then ``check``, which must PASS before any run;
* one ``--planner fixed`` baseline run, once per benchmark, in the first
  stack: its findings are the reference set for coverage;
* N runs per candidate; local candidates share the ``local`` stack and differ
  by ``--model`` / ``--context-tokens``;
* hosted runs draw on one per-benchmark budget (tokens and/or USD). Each run
  is capped to what is left, and the hosted group stops when it is used up;
* ``down`` at the end, always: on success, on an error and on Ctrl+C.

Run output (reports, evidence stores, audit logs) goes under
``lab/captures/_rc46_benchmark/<id>/``; results (``results.json``,
``results.csv``, ``summary.md``) go under ``benchmark-results/<id>/``. Both are
git-ignored. The results directory is scanned for API-key material before the
command returns.

The launcher is injectable (``Launcher``), so tests/test_lab_benchmark.py
drives the orchestration without docker, Ollama or a model. This module starts
no process itself: every docker call goes through lab/model_relay.py's runner.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, Sequence

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(LAB))

import benchmark_metrics as bm  # noqa: E402
import model_relay as relay  # noqa: E402
from op06d.llm import ANTHROPIC_PRICES_PER_MTOK, DEFAULT_ANTHROPIC_MODEL  # noqa: E402
from op06d.redaction import scrub_text  # noqa: E402

TICKET = "RC-46: Planner model benchmark: score candidate models on lab runs"
CAPTURE_SUBDIR = "_rc46_benchmark"
DEFAULT_RESULTS_DIR = ROOT / "benchmark-results"
PROVIDER_ORDER = ("local", "anthropic")
DEFAULT_ENGAGEMENTS = {"local": "lab/engagement.yaml", "anthropic": "lab/engagement-llm-hosted.yaml"}
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_RUNS = 50
# Below this many tokens left, a hosted run could not finish a useful loop: stop the group.
MIN_HOSTED_RUN_TOKENS = 20_000
MIN_HOSTED_RUN_USD = 0.05
BASELINE_TIMEOUT = 3_600.0
BASELINE_NAME = "baseline-fixed"

_TOP_KEYS = frozenset({"benchmark", "limits", "engagements", "hosted_budget", "candidates"})
_CANDIDATE_KEYS = frozenset({
    "name", "provider", "model", "quantization", "context_tokens", "runs", "limits", "notes",
    "price_input_per_mtok", "price_output_per_mtok",
})
_BUDGET_KEYS = frozenset({"max_tokens", "max_cost_usd"})


class BenchmarkError(RuntimeError):
    """The benchmark refuses to start, or cannot go on."""


class Refused(BenchmarkError):
    """Refused before anything was started."""


class ConfigError(Refused):
    """The benchmark config, or the selection made from it, is not usable."""


# --- config ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class Candidate:
    name: str
    provider: str
    model: str
    quantization: str
    context_tokens: int
    runs: int
    limits: dict[str, int] = field(default_factory=dict)
    notes: str = ""
    price_input_per_mtok: float | None = None
    price_output_per_mtok: float | None = None

    @property
    def hosted(self) -> bool:
        return self.provider != "local"

    def prices(self) -> tuple[float, float] | None:
        if self.price_input_per_mtok is not None and self.price_output_per_mtok is not None:
            return self.price_input_per_mtok, self.price_output_per_mtok
        return ANTHROPIC_PRICES_PER_MTOK.get(self.model)


@dataclass(frozen=True)
class BenchmarkConfig:
    name: str
    limits: dict[str, int]
    engagements: dict[str, str]
    candidates: tuple[Candidate, ...]
    budget_max_tokens: int | None = None
    budget_max_cost_usd: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.name, "limits": dict(self.limits), "engagements": dict(self.engagements),
            "hosted_budget": {"max_tokens": self.budget_max_tokens, "max_cost_usd": self.budget_max_cost_usd},
            "candidates": [
                {"name": c.name, "provider": c.provider, "model": c.model, "quantization": c.quantization,
                 "context_tokens": c.context_tokens, "runs": c.runs, "limits": dict(c.limits), "notes": c.notes}
                for c in self.candidates
            ],
        }


def _positive_int(value: object, what: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(f"{what} must be a positive integer, got {value!r}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{what} must be at most {maximum}, got {value}")
    return value


def _positive_number(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise ConfigError(f"{what} must be a positive number, got {value!r}")
    return float(value)


def _limits(raw: object, what: str) -> dict[str, int]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{what} must be a mapping")
    unknown = sorted(set(raw) - set(relay.ACCEPTANCE_LIMITS))
    if unknown:
        raise ConfigError(f"{what}: unknown limit(s) {unknown}; known: {sorted(relay.ACCEPTANCE_LIMITS)}")
    return {k: _positive_int(v, f"{what}.{k}") for k, v in raw.items()}


def _candidate(raw: object, index: int) -> Candidate:
    where = f"candidates[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping")
    unknown = sorted(set(raw) - _CANDIDATE_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {unknown}")
    provider = raw.get("provider")
    if provider not in relay.MODES:
        raise ConfigError(f"{where}: unknown provider {provider!r}; the lab relay has {list(relay.MODES)}")
    model = raw.get("model")
    if model is None and provider == "anthropic":
        model = DEFAULT_ANTHROPIC_MODEL
    if not isinstance(model, str) or not model.strip() or model != model.strip():
        raise ConfigError(f"{where}: model must be a model name" +
                          (" (a local candidate has no default)" if provider == "local" else ""))
    name = raw.get("name") or re.sub(r"[^A-Za-z0-9._-]+", "-", model).strip("-.")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ConfigError(f"{where}: name {name!r} must match {NAME_RE.pattern} (it names a directory)")
    if name == BASELINE_NAME:
        raise ConfigError(f"{where}: the name {BASELINE_NAME!r} is reserved for the fixed-planner baseline")
    quant = raw.get("quantization", "n/a" if provider != "local" else None)
    if not isinstance(quant, str) or not quant:
        raise ConfigError(f"{where}: quantization label is required for a local model (e.g. q5_K_M)")
    prices = [raw.get("price_input_per_mtok"), raw.get("price_output_per_mtok")]
    if (prices[0] is None) != (prices[1] is None):
        raise ConfigError(f"{where}: give both price_input_per_mtok and price_output_per_mtok, or neither")
    return Candidate(
        name=name, provider=provider, model=model, quantization=quant,
        context_tokens=_positive_int(raw.get("context_tokens"), f"{where}.context_tokens"),
        runs=_positive_int(raw.get("runs"), f"{where}.runs", MAX_RUNS),
        limits=_limits(raw.get("limits"), f"{where}.limits"), notes=str(raw.get("notes") or ""),
        price_input_per_mtok=None if prices[0] is None else _positive_number(prices[0], f"{where}.price_input_per_mtok"),
        price_output_per_mtok=None if prices[1] is None else _positive_number(prices[1], f"{where}.price_output_per_mtok"),
    )


def parse_config(data: object) -> BenchmarkConfig:
    if not isinstance(data, dict):
        raise ConfigError("the benchmark config must be a YAML mapping")
    unknown = sorted(set(data) - _TOP_KEYS)
    if unknown:
        raise ConfigError(f"unknown top-level key(s) {unknown}")
    name = data.get("benchmark") or "benchmark"
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ConfigError(f"benchmark name {name!r} must match {NAME_RE.pattern}")
    raw_candidates = data.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise ConfigError("candidates must be a non-empty list")
    candidates = tuple(_candidate(c, i) for i, c in enumerate(raw_candidates))
    names = [c.name for c in candidates]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ConfigError(f"duplicate candidate name(s) {dupes}")

    engagements = dict(DEFAULT_ENGAGEMENTS)
    raw_eng = data.get("engagements") or {}
    if not isinstance(raw_eng, dict) or set(raw_eng) - set(relay.MODES):
        raise ConfigError(f"engagements must map provider ({list(relay.MODES)}) to a lab/ engagement file")
    for mode, path in raw_eng.items():
        if not isinstance(path, str) or not path:
            raise ConfigError(f"engagements.{mode} must be a path under lab/")
        engagements[mode] = path

    budget = data.get("hosted_budget")
    max_tokens = max_cost = None
    if budget is not None:
        if not isinstance(budget, dict) or set(budget) - _BUDGET_KEYS:
            raise ConfigError(f"hosted_budget takes only {sorted(_BUDGET_KEYS)}")
        if budget.get("max_tokens") is not None:
            max_tokens = _positive_int(budget["max_tokens"], "hosted_budget.max_tokens")
        if budget.get("max_cost_usd") is not None:
            max_cost = _positive_number(budget["max_cost_usd"], "hosted_budget.max_cost_usd")
    hosted = [c for c in candidates if c.hosted]
    if hosted and max_tokens is None and max_cost is None:
        raise ConfigError(
            f"hosted candidate(s) {[c.name for c in hosted]} need a hosted_budget with max_tokens "
            "and/or max_cost_usd: a hosted benchmark without a budget is refused")
    if max_cost is not None:
        unpriced = [c.name for c in hosted if c.prices() is None]
        if unpriced:
            raise ConfigError(
                f"hosted_budget.max_cost_usd needs a price for {unpriced}: the model is not in the built-in "
                "price table, so give price_input_per_mtok and price_output_per_mtok on the candidate")
    return BenchmarkConfig(
        name=name, limits={**relay.ACCEPTANCE_LIMITS, **_limits(data.get("limits"), "limits")},
        engagements=engagements, candidates=candidates,
        budget_max_tokens=max_tokens, budget_max_cost_usd=max_cost,
    )


def load_config(path: str | os.PathLike) -> BenchmarkConfig:
    try:
        data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from None
    return parse_config(data)


def select(config: BenchmarkConfig, *, providers: Sequence[str] | None = None,
           names: Sequence[str] | None = None, runs: int | None = None,
           allow_hosted: bool = False) -> list[Candidate]:
    """The candidates this invocation will run. Hosted ones need the opt-in."""
    chosen = list(config.candidates)
    if providers:
        chosen = [c for c in chosen if c.provider in providers]
    if names:
        known = {c.name for c in config.candidates}
        missing = sorted(set(names) - known)
        if missing:
            raise ConfigError(f"no such candidate(s) {missing}; the config has {sorted(known)}")
        chosen = [c for c in chosen if c.name in names]
    if not chosen:
        raise ConfigError("the selection is empty: no candidate matches --provider / --candidate")
    hosted = [c.name for c in chosen if c.hosted]
    if hosted and not allow_hosted:
        raise ConfigError(
            f"hosted candidate(s) {hosted} are selected and hosted runs cost money: pass --allow-hosted "
            "to run them, or --provider local to leave them out")
    if runs is not None:
        _positive_int(runs, "--runs", MAX_RUNS)
        chosen = [replace(c, runs=runs) for c in chosen]
    return chosen


# --- launcher ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class RunRequest:
    mode: str  # which stack the run executes in
    engagement: str
    out_rel: str  # under lab/captures/_rc46_benchmark/
    planner: str  # "fixed" or "llm"
    model: str | None = None
    context_tokens: int | None = None
    limits: dict[str, int] = field(default_factory=dict)
    max_cost_usd: float | None = None
    prices: tuple[float, float] | None = None


@dataclass(frozen=True)
class RunArtifacts:
    returncode: int
    run_dir: pathlib.Path
    stderr: str = ""


class Launcher(Protocol):
    def check_policy(self, mode: str, engagement: str) -> None: ...
    def require_key(self, mode: str) -> None: ...
    def has_model(self, model: str) -> bool: ...
    def up(self, mode: str, engagement: str) -> None: ...
    def check(self, mode: str) -> relay.CheckReport: ...
    def down(self) -> None: ...
    def run(self, request: RunRequest) -> RunArtifacts: ...
    def host_environment(self) -> dict[str, Any]: ...
    def model_placement(self, model: str) -> dict[str, Any]: ...


def _get_json(url: str, timeout: float = 5.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - loopback Ollama only
        return json.load(resp)


def parse_nvidia_smi(text: str) -> list[dict[str, Any]]:
    """``name, memory.total`` rows of ``--format=csv,noheader,nounits``."""
    gpus = []
    for line in text.splitlines():
        name, _, mem = line.rpartition(",")
        if not name.strip():
            continue
        try:
            vram: int | str = int(mem.strip())
        except ValueError:
            vram = "unknown"
        gpus.append({"name": name.strip(), "vram_mib": vram})
    return gpus


def op06d_argv(request: RunRequest, engagement_in_scanner: str, out_in_scanner: str) -> list[str]:
    """The ``op06d run`` command for one benchmark run, built on the RC-47
    acceptance command so the tool pins cannot drift from it."""
    limits = {**relay.ACCEPTANCE_LIMITS, **request.limits}
    llm_mode = request.mode
    argv = relay.op06d_run_argv(llm_mode, engagement_in_scanner, out_in_scanner, model=request.model, limits=limits)
    if request.planner == "fixed":
        return argv[:argv.index("--planner")]  # engagement, output, tool pins, --non-interactive
    if request.context_tokens is not None:
        argv += ["--context-tokens", str(request.context_tokens)]
    if request.max_cost_usd is not None:
        argv += ["--max-cost-usd", f"{request.max_cost_usd:.4f}"]
        if request.prices is not None:
            argv += ["--price-input-per-mtok", str(request.prices[0]),
                     "--price-output-per-mtok", str(request.prices[1])]
    return argv


class RelayLauncher:
    """The real thing: every step is a lab/model_relay.py call or a docker
    compose command through its (UTF-8, return-code) runner."""

    def __init__(self, run: relay.Runner = relay.default_runner, *,
                 fetch: Callable[[str], Any] = _get_json) -> None:
        self._run = run
        self._fetch = fetch

    def check_policy(self, mode: str, engagement: str) -> None:
        relay.check_policy(mode, engagement)

    def require_key(self, mode: str) -> None:
        relay.require_key(mode)

    def has_model(self, model: str) -> bool:
        return relay.ollama_has_model(model)

    def up(self, mode: str, engagement: str) -> None:
        relay.up(mode, engagement, self._run)

    def check(self, mode: str) -> relay.CheckReport:
        return relay.check(mode, self._run)

    def down(self) -> None:
        cp = relay.down(self._run)
        if cp.returncode != 0:
            raise BenchmarkError(f"docker compose down failed (exit {cp.returncode}):\n{cp.stdout}\n{cp.stderr}")

    def run(self, request: RunRequest) -> RunArtifacts:
        path, _ = relay.check_policy(request.mode, request.engagement)
        base = f"/captures/{CAPTURE_SUBDIR}/{request.out_rel}"
        scanner = ("exec", "-T", "scanner")
        relay._ok(self._run(relay.compose_argv(request.mode, *scanner, "mkdir", "-p", base), 60),
                  "preparing the run directory")
        gen = f"{base}/engagement.yaml"
        relay._ok(self._run(relay.compose_argv(request.mode, *scanner, "python3", "/lab/make_lab_engagement.py",
                                               gen, "--template", relay.container_path(path)), 120),
                  "generating the run engagement")
        with_key = request.planner == "llm" and request.mode == "anthropic"
        exec_args = ["exec", "-T"] + (["-e", relay.KEY_ENV] if with_key else []) + ["scanner"]
        limits = {**relay.ACCEPTANCE_LIMITS, **request.limits}
        timeout = BASELINE_TIMEOUT if request.planner == "fixed" else float(limits["max_wall_clock"]) + 600
        cp = self._run(relay.compose_argv(request.mode, *exec_args, *op06d_argv(request, gen, f"{base}/run")),
                       timeout)
        run_dir = LAB / "captures" / CAPTURE_SUBDIR / pathlib.PurePosixPath(request.out_rel) / "run"
        return RunArtifacts(cp.returncode, run_dir, cp.stderr or "")

    def host_environment(self) -> dict[str, Any]:
        gpu: list[dict[str, Any]] | str = "unknown"
        try:
            cp = self._run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"], 30)
            if cp.returncode == 0:
                gpu = parse_nvidia_smi(cp.stdout or "") or "unknown"
        except (OSError, subprocess.SubprocessError):
            pass  # no nvidia-smi on this host
        version = "unknown"
        try:
            found = self._fetch(f"{relay.HOST_OLLAMA}/api/version").get("version")
            version = found if isinstance(found, str) and found else "unknown"
        except (OSError, urllib.error.URLError, ValueError, AttributeError):
            pass
        return {"gpu": gpu, "ollama_version": version, "platform": platform.platform()}

    def model_placement(self, model: str) -> dict[str, Any]:
        """How much of a loaded model sits on the GPU (Ollama ``/api/ps``),
        which is what tells a fully offloaded model from a partly offloaded one."""
        try:
            for m in self._fetch(f"{relay.HOST_OLLAMA}/api/ps").get("models", []):
                if m.get("name") in (model, f"{model}:latest") or m.get("model") == model:
                    return {"model_bytes": m.get("size"), "model_bytes_on_gpu": m.get("size_vram")}
        except (OSError, urllib.error.URLError, ValueError, AttributeError):
            pass
        return {}


# --- hosted budget ------------------------------------------------------------------------------

@dataclass
class HostedBudget:
    max_tokens: int | None
    max_cost_usd: float | None
    spent_tokens: int = 0
    spent_cost_usd: float = 0.0
    stopped: bool = False
    skipped_runs: int = 0

    def grant(self, run_max_tokens: int) -> tuple[int, float | None] | None:
        """(token cap, cost cap) for the next hosted run, or None when what is
        left of the budget is too small to start one."""
        tokens = run_max_tokens
        if self.max_tokens is not None:
            left = self.max_tokens - self.spent_tokens
            if left < MIN_HOSTED_RUN_TOKENS:
                return None
            tokens = min(tokens, left)
        cost = None
        if self.max_cost_usd is not None:
            cost = self.max_cost_usd - self.spent_cost_usd
            if cost < MIN_HOSTED_RUN_USD:
                return None
        return tokens, cost

    def charge(self, input_tokens: int, output_tokens: int, prices: tuple[float, float] | None) -> None:
        self.spent_tokens += input_tokens + output_tokens
        if prices is not None:
            self.spent_cost_usd += (input_tokens * prices[0] + output_tokens * prices[1]) / 1_000_000

    def as_dict(self) -> dict[str, Any]:
        return {"max_tokens": self.max_tokens, "max_cost_usd": self.max_cost_usd,
                "spent_tokens": self.spent_tokens, "spent_cost_usd": round(self.spent_cost_usd, 6),
                "stopped": self.stopped, "skipped_runs": self.skipped_runs}


# --- the benchmark --------------------------------------------------------------------------------

Collector = Callable[[pathlib.Path, Sequence[str] | None], bm.RunMetrics]


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _error_text(text: str) -> str:
    return scrub_text(text.strip())[-500:]


def preflight(config: BenchmarkConfig, candidates: Sequence[Candidate], launcher: Launcher) -> None:
    """Everything that can refuse the benchmark, before any stack exists."""
    for mode in sorted({c.provider for c in candidates}):
        launcher.check_policy(mode, config.engagements[mode])
        launcher.require_key(mode)
    missing = []
    for model in dict.fromkeys(c.model for c in candidates if c.provider == "local"):
        if not launcher.has_model(model):
            missing.append(model)
    if missing:
        raise Refused(
            "host Ollama does not have " + ", ".join(repr(m) for m in missing)
            + ". Nothing was started and nothing is pulled for you; run:\n"
            + "\n".join(f"  ollama pull {m}" for m in missing))


def _measure(launcher: Launcher, collect: Collector, request: RunRequest,
             baseline_ids: Sequence[str] | None) -> tuple[dict[str, Any], bm.RunMetrics | None]:
    record: dict[str, Any] = {"status": "ok", "error": None, "metrics": None,
                              "evidence_dir": f"lab/captures/{CAPTURE_SUBDIR}/{request.out_rel}"}
    try:
        artifacts = launcher.run(request)
    except subprocess.TimeoutExpired:
        record.update(status="error", error="op06d run did not finish within its time limit")
        return record, None
    except relay.RelayError as exc:
        record.update(status="error", error=_error_text(str(exc)))
        return record, None
    try:
        metrics = collect(artifacts.run_dir, baseline_ids)
    except bm.MetricsError as exc:
        detail = f"op06d run exited {artifacts.returncode}; " if artifacts.returncode else ""
        record.update(status="error", error=_error_text(f"{detail}{exc}. {artifacts.stderr}"))
        return record, None
    if artifacts.returncode != 0:
        record.update(status="error", error=_error_text(f"op06d run exited {artifacts.returncode}: {artifacts.stderr}"))
    record["metrics"] = metrics.as_dict()
    return record, metrics


def run_benchmark(config: BenchmarkConfig, candidates: Sequence[Candidate], launcher: Launcher, *,
                  results_root: pathlib.Path = DEFAULT_RESULTS_DIR, collect: Collector | None = None,
                  bench_id: str | None = None, secret: str | None = None,
                  say: Callable[[str], None] = print) -> tuple[dict[str, Any], pathlib.Path]:
    """Run the selected candidates. Returns (results, results directory).

    The results files are written whatever happens after the first stack is
    asked for (a partial benchmark is marked ``aborted``), ``down`` is always
    called, and the exception that stopped the benchmark is re-raised."""
    preflight(config, candidates, launcher)
    collect = collect or bm.collect_run
    bench_id =bench_id or f"{config.name}-{_utc():%Y%m%dT%H%M%SZ}"
    results_dir = results_root / bench_id
    budget = HostedBudget(config.budget_max_tokens, config.budget_max_cost_usd)
    any_hosted = any(c.hosted for c in candidates)
    results: dict[str, Any] = {
        "ticket": TICKET, "benchmark": config.name, "bench_id": bench_id, "status": "aborted", "error": None,
        "started_at": _utc().isoformat(timespec="seconds"), "finished_at": None,
        "config": config.as_dict(), "selected": [c.name for c in candidates],
        "finding_identity": bm.FINDING_IDENTITY, "host": {}, "baseline": None, "runs": [], "summary": [],
        "hosted_budget": None,
    }
    baseline_ids: list[str] | None = None
    stopped: BaseException | None = None
    try:
        results["host"] = launcher.host_environment()
        for mode in [m for m in PROVIDER_ORDER if any(c.provider == m for c in candidates)]:
            engagement = config.engagements[mode]
            say(f"[{mode}] bringing the stack up")
            launcher.down()  # a relay left over from an earlier run, of either mode
            launcher.up(mode, engagement)
            report = launcher.check(mode)
            if report.exit_code != 0:
                raise BenchmarkError(
                    f"the {mode} relay isolation check did not PASS (exit {report.exit_code}); "
                    "no run was started in this stack:\n" + "\n".join(report.lines))
            say(f"[{mode}] isolation check PASS")

            if baseline_ids is None:
                say("[baseline] --planner fixed")
                record, metrics = _measure(launcher, collect, RunRequest(
                    mode, engagement, f"{bench_id}/{BASELINE_NAME}", "fixed"), None)
                results["baseline"] = {
                    "candidate": BASELINE_NAME, "provider": "none", "model": "none", "quantization": "n/a",
                    "context_tokens": None, "run_index": 1, "environment": {}, **record}
                if metrics is None or record["status"] != "ok":
                    raise BenchmarkError(f"the fixed-planner baseline failed, so coverage has no reference: "
                                         f"{record['error']}")
                baseline_ids = list(metrics.finding_ids)
                say(f"[baseline] {len(baseline_ids)} reference findings")

            for cand in [c for c in candidates if c.provider == mode]:
                limits = {**config.limits, **cand.limits}
                for index in range(1, cand.runs + 1):
                    run: dict[str, Any] = {
                        "candidate": cand.name, "provider": cand.provider, "model": cand.model,
                        "quantization": cand.quantization, "context_tokens": cand.context_tokens,
                        "run_index": index, "limits": dict(limits),
                    }
                    cost_cap = None
                    granted = limits["max_tokens"]
                    if cand.hosted:
                        grant = None if budget.stopped else budget.grant(limits["max_tokens"])
                        if grant is None:
                            if not budget.stopped:
                                say(f"[{mode}] hosted budget reached: skipping the remaining hosted runs")
                            budget.stopped = True
                            budget.skipped_runs += 1
                            results["runs"].append({**run, "status": "skipped_budget", "metrics": None,
                                                    "error": "hosted budget reached", "environment": {}})
                            continue
                        granted, cost_cap = grant
                    say(f"[{mode}] {cand.name} run {index}/{cand.runs}")
                    record, metrics = _measure(launcher, collect, RunRequest(
                        mode, engagement, f"{bench_id}/{cand.name}/run-{index:02d}", "llm",
                        model=cand.model, context_tokens=cand.context_tokens,
                        limits={**limits, "max_tokens": granted}, max_cost_usd=cost_cap,
                        prices=cand.prices() if cost_cap is not None else None), baseline_ids)
                    if cand.hosted:
                        if metrics is not None:
                            budget.charge(metrics.input_tokens, metrics.output_tokens, cand.prices())
                        else:  # nothing to read the spend from: assume the whole grant was used
                            budget.charge(granted, 0, cand.prices())
                    env: dict[str, Any] = {
                        "gpu": results["host"].get("gpu", "unknown"), "quantization": cand.quantization,
                        "context_tokens": cand.context_tokens,
                        "output_mode": metrics.output_mode if metrics is not None else None,
                    }
                    if cand.hosted:
                        env.update(runtime="anthropic api", runtime_version="n/a")
                    else:
                        env.update(runtime="ollama", runtime_version=results["host"].get("ollama_version", "unknown"),
                                   **launcher.model_placement(cand.model))
                    results["runs"].append({**run, **record, "environment": env})
        results["status"] = "completed"
    except BaseException as exc:  # noqa: BLE001 - KeyboardInterrupt included: tear down, write, re-raise
        stopped = exc
        results["error"] = ("interrupted" if isinstance(exc, KeyboardInterrupt)
                            else _error_text(f"{type(exc).__name__}: {exc}"))
    finally:
        try:
            launcher.down()
        except Exception as exc:  # noqa: BLE001 - never hide what stopped the benchmark
            say(f"WARNING: teardown failed, the lab may still be running "
                f"(`uv run python lab/model_relay.py down`): {_error_text(str(exc))}")
            if stopped is None:
                stopped = BenchmarkError(f"teardown failed: {exc}")
                results.update(status="aborted", error=_error_text(str(stopped)))
        results["finished_at"] = _utc().isoformat(timespec="seconds")
        results["summary"] = bm.summarize(results["runs"])
        if any_hosted:
            results["hosted_budget"] = budget.as_dict()
        bm.write_results(results_dir, results)
        leaks = scan_for_key_material(results_dir, secret)
    if leaks:
        raise BenchmarkError(
            "API key material was found in the benchmark results; the file(s) were deleted: "
            + ", ".join(leaks) + ". The run output under lab/captures/ needs the same look") from stopped
    if stopped is not None:
        raise stopped
    return results, results_dir


def scan_for_key_material(results_dir: pathlib.Path, secret: str | None) -> list[str]:
    """The RC-47 leak check, on the results directory: the key-shape pattern,
    and the key itself when there is one long enough to search for. A file
    that matches is deleted and named."""
    if secret is not None and len(secret) < relay.LEAK_SCAN_MIN_SECRET_CHARS:
        secret = None  # too short to search for honestly; the shape scan still runs
    hits = []
    for path in sorted(results_dir.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if (secret and secret.encode() in data) or relay.KEY_SHAPE.search(data):
            path.unlink()
            hits.append(path.name)
    return hits


# --- CLI --------------------------------------------------------------------------------------------

def _print_plan(config: BenchmarkConfig, candidates: Sequence[Candidate]) -> None:
    print(f"benchmark {config.name}: {len(candidates)} candidate(s), "
          f"{sum(c.runs for c in candidates)} run(s) + 1 fixed-planner baseline")
    for c in candidates:
        print(f"  {c.name}: {c.provider} {c.model} ({c.quantization}, context {c.context_tokens}) x{c.runs}")
    if any(c.hosted for c in candidates):
        print(f"  hosted budget: max_tokens={config.budget_max_tokens} max_cost_usd={config.budget_max_cost_usd}")


def main(argv: list[str] | None = None, *, launcher: Launcher | None = None) -> int:
    p = argparse.ArgumentParser(prog="benchmark.py", description=TICKET)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "models", "run"):
        sp = sub.add_parser(name)
        sp.add_argument("--config", required=True, help="benchmark config (YAML), e.g. lab/benchmark.default.yaml")
        sp.add_argument("--provider", action="append", choices=relay.MODES, help="only these providers (repeatable)")
        sp.add_argument("--candidate", action="append", help="only these candidates, by name (repeatable)")
        if name != "models":
            sp.add_argument("--runs", type=int, default=None, help="override N for every selected candidate")
            sp.add_argument("--allow-hosted", action="store_true",
                            help="allow hosted (paid) candidates; they still need the hosted engagement, "
                                 "the key and the config's hosted_budget")
        if name == "run":
            sp.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR),
                            help="where results.json / results.csv / summary.md go (default: benchmark-results/)")
    args = p.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.cmd == "models":
            chosen = select(config, providers=args.provider, names=args.candidate, allow_hosted=True)
            live = launcher or RelayLauncher()
            for model in dict.fromkeys(c.model for c in chosen if c.provider == "local"):
                state = "present" if live.has_model(model) else f"MISSING  ->  ollama pull {model}"
                print(f"{model}: {state}")
            return 0
        chosen = select(config, providers=args.provider, names=args.candidate, runs=args.runs,
                        allow_hosted=args.allow_hosted)
        _print_plan(config, chosen)
        if args.cmd == "validate":
            print("config OK (nothing was started)")
            return 0
        started = time.monotonic()
        results, results_dir = run_benchmark(
            config, chosen, launcher or RelayLauncher(), results_root=pathlib.Path(args.results_dir),
            secret=os.environ.get(relay.KEY_ENV) or None)
    except KeyboardInterrupt:
        print("interrupted: the stack was torn down and partial results were written", file=sys.stderr)
        return 130
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except relay.NotReady as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    except relay.RelayError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except BenchmarkError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    print((results_dir / "summary.md").read_text(encoding="utf-8"))
    print(f"results: {results_dir} ({time.monotonic() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
