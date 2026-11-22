# Planner model benchmark (OPT-IN)

The opt-in benchmark that compares planner models through the
[model relay](model-relay.md), on the lab of [RUNBOOK.md](RUNBOOK.md) and a host
prepared as in [hosts.md](hosts.md).

`lab/benchmark.py` runs `op06d run --planner llm` N times per candidate model
through the [model relay](model-relay.md) and scores every run from its audit log and
evidence store. It is long, it tears the `rc-lab` stack down and up, and
hosted candidates cost money, so nothing runs it for you.

The candidates are in a YAML config; `lab/benchmark.default.yaml` is the
shortlist (provider, model, quantization label, context size, N, per-run
limits, and the hosted budget). The harness never pulls a model:

PowerShell 7 or bash / zsh:

```bash
uv run python lab/benchmark.py models --config lab/benchmark.default.yaml   # present / MISSING per local model
```

The pulls are safe to paste together:

PowerShell 7 or bash / zsh:

```bash
ollama pull llama3.1:8b-instruct-q5_K_M
ollama pull qwen2.5:7b-instruct-q5_K_M
ollama pull qwen2.5:14b-instruct-q4_K_M
ollama pull qwen3:30b-a3b-q4_K_M
```

PowerShell 7 or bash / zsh:

```bash
uv run python lab/model_relay.py build local    # once, if the overlay images are not built
```

Smoke: one local model, one run:

PowerShell 7 or bash / zsh:

```bash
uv run python lab/benchmark.py run --config lab/benchmark.default.yaml --candidate llama3.1-8b-q5 --runs 1
```

Every local candidate:

PowerShell 7 or bash / zsh:

```bash
uv run python lab/benchmark.py run --config lab/benchmark.default.yaml --provider local
```

Hosted reference (paid): needs the flag, the key and the config's `hosted_budget`:

PowerShell 7:

```powershell
$env:ANTHROPIC_API_KEY = Read-Host -MaskInput "Anthropic API key"   # paste with right-click, check .Length
```

bash / zsh:

```bash
printf 'Anthropic API key: '; read -rs ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
```

PowerShell 7 or bash / zsh:

```bash
uv run python lab/benchmark.py run --config lab/benchmark.default.yaml --provider anthropic --allow-hosted
```

PowerShell 7:

```powershell
Remove-Item Env:ANTHROPIC_API_KEY
```

bash / zsh:

```bash
unset ANTHROPIC_API_KEY
```

`validate` instead of `run` checks the config and the selection and starts
nothing. Exit codes: 0 done, 1 failed, 2 refused before anything started,
130 interrupted.

What `run` does:

- Refuses before any docker call when a hosted candidate is selected without
  `--allow-hosted`, the engagement does not allow the provider, the key is
  implausible, or a local model is not in host Ollama (it prints the
  `ollama pull` lines).
- One stack per provider, `local` first: `down`, `up`, then `check`, which
  must PASS or no run starts. Local candidates share the `local` stack and
  differ by `--model` and `--context-tokens`.
- One `--planner fixed` run first, once per benchmark: its findings are the
  reference set for coverage.
- Hosted runs share one budget (`hosted_budget.max_tokens` and/or
  `max_cost_usd`). Each run's `--max-tokens` / `--max-cost-usd` is capped to
  what is left; when less than 20 000 tokens or $0.05 is left the remaining
  hosted runs are recorded as `skipped_budget` and the benchmark finishes
  normally. A hosted run that left no record is charged its whole grant.
- `down` at the end, also after an error or Ctrl+C. The results files are
  written before that teardown starts (`teardown: pending`) and again after
  it (`teardown: ok` or `failed`, and `finished_at`); a partial benchmark is
  marked `aborted`.

Stopping a benchmark: press Ctrl+C **once**. It prints where the partial
results are, then `tearing down the stack (this can take a minute; do not
press Ctrl+C again)`, and `docker compose down` runs with no output for 30
seconds or more. Ctrl+C is ignored during the teardown, and the docker child
is started outside the console's Ctrl+C, so a second press does nothing. The
command exits 130. If it prints `WARNING: teardown failed`, or the process
was killed some other way (Ctrl+Break, a closed terminal), the stack may
still be up, and `results.json` has `teardown_failed` in `error` or still
says `teardown: pending`: run `uv run python lab/model_relay.py down`.

Metrics per run (definitions in `lab/benchmark_metrics.py`):

| Metric | From | Definition |
|---|---|---|
| Valid-action rate | audit log | (well-formed actions + well-formed `done`) / model turns. Re-asks after an invalid reply are turns. Shape only: with `output_mode` `json_schema` it is near 1.00 for every model, so read it with the next column. |
| Rejected by tool | evidence store | well-formed proposals the tool layer refused (stage `tool`: unknown tool, a parameter the tool does not take, a value it rejects); they never execute |
| Out-of-scope denied | evidence store | proposals the gate refused at stage `scope` |
| Redundant actions | audit log | executed actions whose tool + target + parameter set was already executed in the run |
| Baseline coverage | evidence store | share of the fixed-planner run's findings this run also produced |
| Tokens, wall clock, termination, failure cause | audit log | loop-end entry; first to last entry |

**Finding identity** (what "the same finding" means for coverage): the normalizer's
`finding_id`, i.e. the first 16 hex characters of SHA-256 over (source tool,
asset IP or else hostname, port, category, key), where the key is the nuclei
template id or the nmap finding title / script id. It has no timestamp or run
id, and a hostname target is keyed by the IP that was scanned. Consequences:
an nmap port found without version detection is a different finding from the
same port with a detected product, and nmap and nuclei reporting the same
service are two findings.

Each run also records its environment: GPU name and VRAM (`nvidia-smi` on the
host, else `unknown`), quantization label, context size, Ollama version,
`output_mode`, and how many of the model's bytes were on the GPU
(`model_bytes`, `model_bytes_on_gpu`), which is what shows a partly offloaded
model.

The placement comes from host Ollama's `GET /api/ps`, read every 15 seconds
while a local-model run executes (read-only; nothing is loaded and
`keep_alive` is untouched). Ollama unloads an idle model after its
`keep_alive`, 5 minutes by default, so a reading taken only after a run that
ended in long scans would find nothing. `placement_source` in the run's
environment says where the reading is from:

- `during_run`: the last reading taken while the run executed;
- `after_run`: none was taken during the run (for example a run shorter than
  one reading), and the model was still loaded just after it;
- `unavailable`: the model was not loaded either time; the byte counts are
  absent.

`summary.md` ends with a "Model placement" list, one line per local
candidate, which names the runs whose placement is unavailable. Hosted runs
have no placement and no `placement_source`.

Output, both git-ignored:

- run output (report, evidence store, audit log per run):
  `lab/captures/_benchmark/<id>/<candidate>/run-NN/run/`
- results: `benchmark-results/<id>/results.json`, `results.csv` (one row per
  run) and `summary.md` (per candidate: N, failures, mean ± sample standard
  deviation and min to max). The results directory is scanned for API-key
  material before the command returns; a file that matches is deleted and the
  command fails.
