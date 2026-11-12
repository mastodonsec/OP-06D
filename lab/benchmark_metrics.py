# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-46: Planner model benchmark: score candidate models on lab runs

Metrics for one finished ``op06d run``, read from the run's audit log and
evidence store (never from stdout), plus the per-candidate aggregation and the
JSON / CSV / Markdown writers used by lab/benchmark.py. No docker, no network,
no subprocess: everything here is a function of files a run left behind.

Definitions
-----------

model turn
    One call to the model in the orchestrator loop. Counted from the audit
    log: every distinct iteration number that has an ``iteration`` entry, plus
    the final iteration of a run that stopped on ``max_tokens`` / ``max_cost``
    after the reply came back (that reply is discarded before it is logged; it
    is a turn, and not a valid one). Re-asks after an invalid reply are turns,
    so retries are counted. Transport retries inside the adapter are not in the
    audit log and are not counted.

valid-action rate
    ``(well-formed actions + well-formed "done" replies) / model turns``. A
    reply is well formed when the orchestrator parsed it against the action
    schema (audit reason ``planned...`` or ``planner reports objective met``).
    ``done`` is counted because it is the one valid way to end a run; the raw
    counts are reported next to the rate. ``None`` when there were no turns.
    It measures the reply's shape only: with schema-constrained output
    (``output_mode`` ``json_schema``) nearly every reply is well formed, so read
    it together with ``tool_rejected``.

rejected by the tool layer (``tool_rejected``)
    Evidence-store actions refused at stage ``tool``: well-formed proposals the
    tool layer turned down before the gate (unknown tool, a parameter the tool
    does not take, a parameter value it rejects). This is where planners differ
    once the output is schema-constrained. Counted like the scope denials: a
    repeat of a refused action is not re-submitted, so it is counted once.

out-of-scope proposals denied by the gate
    Evidence-store actions refused at gate stage ``scope``. A repeat of a
    refused action is never re-submitted to the gate, so it is not counted
    again (``repeat_refused`` counts those).

redundant action
    An executed action whose (tool, target, profile) was already executed
    earlier in the same run. "Profile" is the action's whole parameter set as
    recorded (nmap: profile/ports/scripts; nuclei: severity/tags/...), and the
    target is the literal string proposed, so ``juice-shop.lab`` and its IP are
    different targets.

finding identity (for coverage)
    The RC-15 ``finding_id``: the first 16 hex characters of the SHA-256 of
    ``(source_tool, asset IP or else hostname, port, category, stable key)``,
    where the key is the nuclei template id or the nmap finding title / script
    id. It contains no timestamp and no run id, and a hostname target is
    keyed by the IP that was scanned, so the same observation has the same
    identity in every run. Two limits follow from the key: an nmap port found
    without version detection has a different title, hence a different
    identity, from the same port with a detected product; and nmap and nuclei
    reporting the same service are two findings.

coverage
    ``|run findings ∩ baseline findings| / |baseline findings|`` with the
    baseline being one ``--planner fixed`` run in the same benchmark. ``None``
    when the baseline has no findings. Findings outside the baseline are
    reported as ``extra_findings`` and do not change coverage.
"""

from __future__ import annotations

import csv
import json
import pathlib
import re
import statistics
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Sequence

from op06d.audit import EVENT_ACTION_EXECUTED, EVENT_ITERATION, EVENT_LOOP_END, AuditEntry, read_log
from op06d.evidence import EvidenceStore

FINDING_IDENTITY = (
    "RC-15 finding_id = sha256(source_tool, asset IP or else hostname, port, category, "
    "nuclei template id | nmap finding title | nmap script id)[:16]"
)
BUDGET_TERMINATIONS = frozenset({"max_tokens", "max_cost"})
# A run that ended one of these ways did not do its job, whatever its other numbers say.
FAILURE_TERMINATIONS = frozenset({
    "model_failure", "model_refused", "planner_failure", "audit_failure", "gate_unusable",
    "window_expired", "window_not_open", "operator_stop",
})
STAGE_SCOPE, STAGE_TOOL = "scope", "tool"  # op06d.tools gate stages
STAT_FIELDS = (
    "valid_action_rate", "tool_rejected", "out_of_scope_denied", "redundant_actions", "coverage",
    "executed_actions", "total_tokens", "wall_clock_seconds",
)


class MetricsError(RuntimeError):
    """The run left nothing that can be measured."""


@dataclass(frozen=True)
class TurnStats:
    model_turns: int = 0
    well_formed_actions: int = 0
    done_replies: int = 0
    invalid_replies: int = 0
    failed_calls: int = 0
    discarded_replies: int = 0
    repeat_refused: int = 0

    @property
    def valid_action_rate(self) -> float | None:
        if self.model_turns == 0:
            return None
        return (self.well_formed_actions + self.done_replies) / self.model_turns


@dataclass(frozen=True)
class RunMetrics:
    model_turns: int
    well_formed_actions: int
    done_replies: int
    invalid_replies: int
    failed_calls: int
    discarded_replies: int
    repeat_refused: int
    valid_action_rate: float | None
    tool_rejected: int
    out_of_scope_denied: int
    denied_by_stage: dict[str, int]
    executed_actions: int
    redundant_actions: int
    findings: int
    baseline_findings: int | None
    baseline_covered: int | None
    coverage: float | None
    extra_findings: int | None
    input_tokens: int
    output_tokens: int
    total_tokens: int
    wall_clock_seconds: float | None
    termination: str | None
    failure_cause: dict[str, Any] | None
    planner: str
    output_mode: str | None
    finding_ids: tuple[str, ...] = field(default=(), repr=False)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["finding_ids"] = list(self.finding_ids)
        return data


# --- one metric each, over audit entries / evidence rows ---------------------------------

def _iteration_of(entry: AuditEntry) -> int | None:
    n = entry.parameters.get("iteration")
    return n if isinstance(n, int) and not isinstance(n, bool) else None


def turn_stats(entries: Sequence[AuditEntry]) -> TurnStats:
    """Model turns and what became of each reply (see the module docstring)."""
    turns: set[int] = set()
    actions = done = invalid = failed = discarded = repeats = 0
    for e in entries:
        n = _iteration_of(e)
        if e.event == EVENT_ITERATION:
            reason = e.reason or ""
            if reason == "planned" or reason.startswith("planned: "):
                actions += 1
            elif reason.startswith("planner reports objective met"):
                done += 1
            elif reason.startswith("invalid planner reply"):
                invalid += 1
            elif reason.startswith(("model failure", "model refused", "planner call failed")):
                failed += 1
            elif reason.startswith("repeat of a refused action"):
                repeats += 1  # second entry of a turn already counted as an action
            if n is not None:
                turns.add(n)
        elif e.event == EVENT_LOOP_END and e.reason in BUDGET_TERMINATIONS:
            if n is not None and n > 0 and n not in turns:
                turns.add(n)
                discarded += 1
    return TurnStats(len(turns), actions, done, invalid, failed, discarded, repeats)


def denied_by_stage(actions: Iterable[Any]) -> dict[str, int]:
    """Refused proposals by the stage that refused them (evidence-store actions)."""
    counts: Counter[str] = Counter()
    for a in actions:
        if not a.gate_allowed:
            counts[str(a.gate_stage)] += 1
    return dict(sorted(counts.items()))


def out_of_scope_denied(actions: Iterable[Any]) -> int:
    return denied_by_stage(actions).get(STAGE_SCOPE, 0)


def tool_rejected(actions: Iterable[Any]) -> int:
    return denied_by_stage(actions).get(STAGE_TOOL, 0)


def _action_key(entry: AuditEntry) -> str:
    params = entry.parameters.get("params")
    return json.dumps([entry.tool, entry.target, params if isinstance(params, dict) else {}],
                      sort_keys=True, default=repr)


def executed_and_redundant(entries: Sequence[AuditEntry]) -> tuple[int, int]:
    """(actions executed, of which a repeat of an earlier tool + target + profile)."""
    seen: set[str] = set()
    executed = redundant = 0
    for e in entries:
        if e.event != EVENT_ACTION_EXECUTED:
            continue
        executed += 1
        key = _action_key(e)
        if key in seen:
            redundant += 1
        seen.add(key)
    return executed, redundant


def coverage(run_ids: Iterable[str], baseline_ids: Iterable[str] | None) -> tuple[int | None, float | None, int | None]:
    """(baseline findings covered, coverage, findings not in the baseline)."""
    if baseline_ids is None:
        return None, None, None
    base, mine = set(baseline_ids), set(run_ids)
    covered = len(base & mine)
    return covered, (covered / len(base) if base else None), len(mine - base)


def _ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def wall_clock_seconds(entries: Sequence[AuditEntry]) -> float | None:
    """First audit entry to last. ``None`` for an empty log."""
    if not entries:
        return None
    try:
        return round((_ts(entries[-1].ts) - _ts(entries[0].ts)).total_seconds(), 3)
    except ValueError:
        return None


def loop_end(entries: Sequence[AuditEntry]) -> AuditEntry | None:
    ends = [e for e in entries if e.event == EVENT_LOOP_END]
    return ends[-1] if ends else None


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def compute_metrics(entries: Sequence[AuditEntry], actions: Sequence[Any], finding_ids: Iterable[str],
                    planner: dict[str, Any] | None, baseline_ids: Iterable[str] | None) -> RunMetrics:
    ids = tuple(sorted(set(finding_ids)))
    turns = turn_stats(entries)
    executed, redundant = executed_and_redundant(entries)
    stages = denied_by_stage(actions)
    covered, cov, extra = coverage(ids, baseline_ids)
    end = loop_end(entries)
    end_params = end.parameters if end is not None else {}
    cause = end_params.get("cause")
    tokens_in, tokens_out = _int(end_params.get("input_tokens")), _int(end_params.get("output_tokens"))
    info = planner or {}
    return RunMetrics(
        model_turns=turns.model_turns, well_formed_actions=turns.well_formed_actions,
        done_replies=turns.done_replies, invalid_replies=turns.invalid_replies,
        failed_calls=turns.failed_calls, discarded_replies=turns.discarded_replies,
        repeat_refused=turns.repeat_refused, valid_action_rate=turns.valid_action_rate,
        tool_rejected=stages.get(STAGE_TOOL, 0),
        out_of_scope_denied=stages.get(STAGE_SCOPE, 0), denied_by_stage=stages,
        executed_actions=executed, redundant_actions=redundant,
        findings=len(ids), baseline_findings=None if baseline_ids is None else len(set(baseline_ids)),
        baseline_covered=covered, coverage=cov, extra_findings=extra,
        input_tokens=tokens_in, output_tokens=tokens_out, total_tokens=tokens_in + tokens_out,
        wall_clock_seconds=wall_clock_seconds(entries),
        termination=end.reason if end is not None else None,
        failure_cause=cause if isinstance(cause, dict) else None,
        planner=str(info.get("planner") or "fixed"),
        output_mode=info.get("output_mode") if isinstance(info.get("output_mode"), str) else None,
        finding_ids=ids,
    )


def collect_run(run_dir: pathlib.Path, baseline_ids: Iterable[str] | None = None) -> RunMetrics:
    """Metrics for the run stored under ``run_dir`` (``evidence.db`` + ``audit/``)."""
    db = run_dir / "evidence.db"
    if not db.is_file():
        raise MetricsError(f"no evidence store in {run_dir}")
    store = EvidenceStore(db)
    runs = store.list_runs()
    if not runs:
        raise MetricsError(f"the evidence store in {run_dir} has no run")
    recon = store.reconstruct_run(runs[-1].run_id)
    if not recon.run.audit_log_path:
        raise MetricsError("the run record names no audit log")
    # The path was written inside the scanner (POSIX) or by a host run (either separator).
    audit = run_dir / "audit" / re.split(r"[\\/]", recon.run.audit_log_path)[-1]
    try:
        entries = read_log(audit)
    except Exception as exc:  # noqa: BLE001 - an unverifiable log cannot be scored
        raise MetricsError(f"audit log does not verify: {type(exc).__name__}: {exc}") from None
    return compute_metrics(entries, recon.actions, [f.finding_id for f in recon.findings],
                           recon.planner, baseline_ids)


# --- aggregation ---------------------------------------------------------------------------

def _stat(values: Sequence[float]) -> dict[str, float | int] | None:
    if not values:
        return None
    return {
        "n": len(values), "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else None,
        "min": min(values), "max": max(values),
    }


def is_failure(run: dict[str, Any]) -> bool:
    if run.get("status") == "error":
        return True
    return (run.get("metrics") or {}).get("termination") in FAILURE_TERMINATIONS


def summarize(runs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per candidate, in first-seen order. ``n`` is the number of runs
    that left a measurable record; means and spread are over those runs,
    failed ones included, and ``failures`` says how many there were. Runs the
    hosted budget skipped are counted in ``skipped`` only."""
    order: list[str] = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for r in runs:
        name = r["candidate"]
        if name not in grouped:
            order.append(name)
            grouped[name] = []
        grouped[name].append(r)
    rows = []
    for name in order:
        group = grouped[name]
        measured = [r for r in group if r.get("metrics")]
        first = group[0]
        terminations = Counter(str(r["metrics"].get("termination")) for r in measured)
        causes = Counter(
            str((r["metrics"]["failure_cause"] or {}).get("error_type")
                or (r["metrics"]["failure_cause"] or {}).get("error"))
            for r in measured if r["metrics"].get("failure_cause"))
        row: dict[str, Any] = {
            "candidate": name, "provider": first.get("provider"), "model": first.get("model"),
            "quantization": first.get("quantization"), "context_tokens": first.get("context_tokens"),
            "n": len(measured), "failures": sum(1 for r in group if is_failure(r)),
            "errors": sum(1 for r in group if r.get("status") == "error"),
            "skipped": sum(1 for r in group if r.get("status") == "skipped_budget"),
            "terminations": dict(sorted(terminations.items())),
            "failure_causes": dict(sorted(causes.items())),
        }
        for f in STAT_FIELDS:
            row[f] = _stat([r["metrics"][f] for r in measured if r["metrics"].get(f) is not None])
        rows.append(row)
    return rows


# --- writers ------------------------------------------------------------------------------------

CSV_FIELDS = (
    "candidate", "provider", "model", "quantization", "context_tokens", "run_index", "status", "error",
    "planner", "termination", "failure_cause", "model_turns", "well_formed_actions", "done_replies",
    "invalid_replies", "failed_calls", "discarded_replies", "repeat_refused", "valid_action_rate",
    "tool_rejected", "out_of_scope_denied", "denied_by_stage", "executed_actions", "redundant_actions", "findings",
    "baseline_findings", "baseline_covered", "coverage", "extra_findings", "input_tokens",
    "output_tokens", "total_tokens", "wall_clock_seconds", "output_mode", "gpu", "vram_mib",
    "runtime", "runtime_version", "model_bytes", "model_bytes_on_gpu", "placement_source", "evidence_dir",
)


def _cell(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return value


def csv_row(run: dict[str, Any]) -> dict[str, object]:
    env = run.get("environment") or {}
    gpus = env.get("gpu") if isinstance(env.get("gpu"), list) else []
    flat = {**run, **(run.get("metrics") or {})}
    flat.update(
        gpu="; ".join(str(g.get("name")) for g in gpus) or "unknown",
        vram_mib="; ".join(str(g.get("vram_mib")) for g in gpus) or "unknown",
        runtime=env.get("runtime"), runtime_version=env.get("runtime_version"),
        output_mode=env.get("output_mode"), model_bytes=env.get("model_bytes"),
        model_bytes_on_gpu=env.get("model_bytes_on_gpu"), placement_source=env.get("placement_source"),
    )
    return {k: _cell(flat.get(k)) for k in CSV_FIELDS}


def _fmt(stat: dict[str, Any] | None, digits: int) -> str:
    if not stat:
        return "n/a"
    text = f"{stat['mean']:.{digits}f}"
    if stat.get("stdev") is not None:
        text += f" ± {stat['stdev']:.{digits}f} ({stat['min']:.{digits}f} to {stat['max']:.{digits}f})"
    return text


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(results: dict[str, Any]) -> str:
    base = (results.get("baseline") or {}).get("metrics") or {}
    host = results.get("host") or {}
    gpus = host.get("gpu") if isinstance(host.get("gpu"), list) else []
    gpu = ", ".join(f"{g.get('name')} ({g.get('vram_mib')} MiB)" for g in gpus) or "unknown"
    lines = [
        f"# Planner model benchmark: {_md(results.get('benchmark'))}",
        "",
        "RC-46: Planner model benchmark: score candidate models on lab runs",
        "",
        f"- Benchmark id: `{results.get('bench_id')}` ({results.get('status')})",
        f"- Started / finished (UTC): {results.get('started_at')} / {results.get('finished_at')}",
        f"- Host GPU: {_md(gpu)}; Ollama: {_md(host.get('ollama_version', 'unknown'))}",
        f"- Baseline (`--planner fixed`): {base.get('findings', 'n/a')} findings from "
        f"{base.get('executed_actions', 'n/a')} executed actions",
        f"- Finding identity: {FINDING_IDENTITY}",
    ]
    if results.get("error"):
        lines.append(f"- **Stopped early:** {_md(results['error'])}")
    budget = results.get("hosted_budget")
    if budget:
        lines.append(
            f"- Hosted budget: {budget.get('spent_tokens')} of {budget.get('max_tokens') or 'no limit'} tokens, "
            f"${budget.get('spent_cost_usd', 0):.4f} of {budget.get('max_cost_usd') or 'no limit'} USD"
            + (f"; **budget reached, {budget.get('skipped_runs')} run(s) skipped**" if budget.get("stopped") else ""))
    lines += [
        "",
        "Mean ± sample standard deviation (min to max) over the N runs that left a record; "
        "a single run shows the value alone.",
        "",
        "| Candidate | Model | Quant. | Context | N | Failures | Valid-action rate | Rejected by tool "
        "| Out-of-scope denied | Redundant actions | Baseline coverage | Tokens | Wall clock (s) | Terminations |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in results.get("summary") or []:
        failures = str(row["failures"])
        if row.get("failure_causes"):
            failures += " (" + ", ".join(f"{k} x{v}" for k, v in row["failure_causes"].items()) + ")"
        if row.get("skipped"):
            failures += f"; {row['skipped']} skipped (budget)"
        terms = ", ".join(f"{k} x{v}" for k, v in row["terminations"].items()) or "n/a"
        lines.append("| " + " | ".join(_md(c) for c in (
            row["candidate"], f"{row['provider']}: {row['model']}", row["quantization"], row["context_tokens"],
            row["n"], failures, _fmt(row["valid_action_rate"], 2), _fmt(row.get("tool_rejected"), 1),
            _fmt(row["out_of_scope_denied"], 1),
            _fmt(row["redundant_actions"], 1), _fmt(row["coverage"], 2), _fmt(row["total_tokens"], 0),
            _fmt(row["wall_clock_seconds"], 0), terms,
        )) + " |")
    lines += placement_lines(results.get("runs") or [])
    return "\n".join(lines) + "\n"


def placement_lines(runs: Iterable[dict[str, Any]]) -> list[str]:
    """Per local candidate: the share of the model's bytes that was on the
    GPU, and the runs for which there is no reading."""
    by_candidate: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        if (run.get("environment") or {}).get("runtime") == "ollama":
            by_candidate.setdefault(str(run.get("candidate")), []).append(run)
    if not by_candidate:
        return []
    lines = ["", "Model placement (Ollama `/api/ps`): share of the model's bytes on the GPU, read while the run "
                 "executed unless noted.", ""]
    for name, group in by_candidate.items():
        shares, after, missing = [], 0, []
        for run in group:
            env = run["environment"]
            size, on_gpu = env.get("model_bytes"), env.get("model_bytes_on_gpu")
            if not isinstance(size, int) or not isinstance(on_gpu, int) or size <= 0:
                missing.append(str(run.get("run_index")))
                continue
            shares.append(round(100 * on_gpu / size))
            after += env.get("placement_source") == "after_run"
        parts = []
        if shares:
            span = f"{min(shares)}%" if min(shares) == max(shares) else f"{min(shares)}% to {max(shares)}%"
            parts.append(f"{span} on the GPU ({len(shares)} of {len(group)} run(s)"
                         + (f", {after} read after the run" if after else "") + ")")
        if missing:
            parts.append(f"**placement unavailable for run(s) {', '.join(missing)}** "
                         "(the model was not loaded when Ollama was asked)")
        lines.append(f"- {_md(name)}: " + "; ".join(parts))
    return lines


def write_results(results_dir: pathlib.Path, results: dict[str, Any]) -> list[pathlib.Path]:
    """results.json, results.csv (one row per run) and summary.md."""
    results_dir.mkdir(parents=True, exist_ok=True)
    out_json, out_csv, out_md = (results_dir / n for n in ("results.json", "results.csv", "summary.md"))
    out_json.write_text(json.dumps(results, indent=2, sort_keys=True, default=repr) + "\n", encoding="utf-8")
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for run in [results["baseline"], *results["runs"]] if results.get("baseline") else results["runs"]:
            writer.writerow(csv_row(run))
    out_md.write_text(render_markdown(results), encoding="utf-8")
    return [out_json, out_csv, out_md]
