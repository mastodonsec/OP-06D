# LLM planner (`op06d run --planner llm`)

RC-40 — LLM planner: wire a real model into the orchestrator and `op06d run`

`op06d run` has two planners:

| `--planner` | What decides the next action |
|---|---|
| `fixed` (default, unchanged) | `plan_recon()`: an nmap service scan and a nuclei default-tag scan per in-scope entry |
| `llm` | the RC-7 `Orchestrator`, driven by a model through an adapter in `op06d.llm` |

Both planners use the same `GatedToolbox`, audit log, evidence store and report.
The model proposes one action at a time, and every proposal goes through
`GatedToolbox.execute()` (validate, `Gate.check`, operator approval, run,
sanitize, record). The model has no other way to reach a tool. Nothing it emits
can widen scope, extend the window, raise the rate or skip approval.

## Quick start

Hosted (Anthropic). Install the extra and put the key in the environment. There
is no flag or config field for the key.

```sh
pip install 'op06d[llm-anthropic]'
export ANTHROPIC_API_KEY=...            # read from the environment only
op06d run --engagement eng.yaml --out out/ --planner llm --llm-provider anthropic
```

Local (Ollama on the same host, listening on loopback):

```sh
ollama pull llama3.1:8b-instruct-q5_K_M
op06d run --engagement eng.yaml --out out/ --planner llm --llm-provider local \
  --model llama3.1:8b-instruct-q5_K_M --context-tokens 8192
```

Other local runtimes speak the OpenAI-compatible chat API:

```sh
# llama.cpp server (constrained by a GBNF grammar)
op06d run ... --planner llm --llm-provider local --llm-runtime llamacpp \
  --llm-endpoint http://127.0.0.1:8080 --model <name>
# LM Studio / vLLM (constrained by response_format json_schema)
op06d run ... --planner llm --llm-provider local --llm-runtime openai \
  --llm-endpoint http://127.0.0.1:1234/v1 --model <name>
```

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--planner {fixed,llm}` | `fixed` | the LLM flags below are refused unless this is `llm` |
| `--llm-provider {anthropic,local}` | required for `llm` | |
| `--model` | `claude-opus-5-5` / `llama3.1:8b-instruct-q5_K_M` | |
| `--llm-endpoint` | local: `http://127.0.0.1:11434` | local only; the anthropic provider always uses `https://api.anthropic.com` |
| `--llm-runtime {ollama,llamacpp,openai}` | `ollama` | local only; selects the constrained-output mechanism |
| `--llm-allow-private IP` | none | local only, repeatable; see the endpoint rule below |
| `--context-tokens` | anthropic 200000, local 8192 | set it to the context size the model is actually served with |
| `--max-output-tokens` | anthropic 16000, local 1024 | per-reply cap |
| `--llm-timeout` | anthropic 120 s, local 300 s | per request |
| `--max-iterations` | 25 | planner calls |
| `--max-actions` | 20 | tool invocations, meaning executed actions plus tool errors |
| `--max-wall-clock` | 3600 s | |
| `--max-tokens` | 1000000 | input plus output tokens across the whole run |
| `--max-cost-usd` | off | needs prices. These are built in for `claude-opus-5-5`, `claude-sonnet-5-5` and `claude-haiku-5-5`; otherwise pass `--price-input-per-mtok` / `--price-output-per-mtok`. Local runs are priced at 0. |

Every limit is enforced in code by the orchestrator. Hitting one ends the run
cleanly: the reason is written to the audit log (`loop_terminated`), the
evidence store and the report, and the HTML report is still produced.

| Termination | Meaning |
|---|---|
| `objective_met` | the model replied `{"type": "done", ...}` |
| `max_iterations`, `max_actions`, `max_wall_clock` | that limit was reached |
| `max_tokens`, `max_cost` | the next call could not fit the remaining budget, by estimate (characters / 3 plus the output cap), or the reported usage crossed it. A reply that crosses the budget is never acted on. |
| `model_failure` | non-retryable API error, retries exhausted, or a refusal |
| `planner_failure` | 3 consecutive malformed replies |
| `window_expired`, `window_not_open`, `operator_stop`, `gate_unusable`, `audit_failure` | as in [orchestrator.md](orchestrator.md) |

## Engagement policy

The engagement file can restrict which providers may plan it:

```yaml
planner:
  allowed_providers: [local]   # anthropic | local, at least one
```

A disallowed provider is refused before anything runs: no output directory,
no audit log, no evidence. Without a `planner:` block, both providers are
allowed.

## Egress and data handling

### Hosted (`--llm-provider anthropic`)

- **Egress:** HTTPS to `api.anthropic.com` only. The endpoint cannot be
  overridden. Standard `HTTPS_PROXY` settings are honoured.
- **What leaves the host:** the system prompt (engagement ID, objective,
  in-scope and out-of-scope lists, window, rate cap, tool list) and every
  observation. Observations are the sanitized tool findings, such as open
  ports, service banners and nuclei matches, wrapped as
  `UNTRUSTED_TOOL_OUTPUT`. **Findings about the client's systems are sent to the
  provider** and handled under the provider's data-retention terms. Raw tool
  output is not sent; it stays local as evidence.
- Use `planner.allowed_providers: [local]` for any engagement whose
  authorization does not allow third-party processing.
- Server-side refusal fallbacks (`fallbacks: "default"`, beta
  `server-side-fallback-2026-07-01`) are enabled. If the request is declined
  on policy grounds, the API may answer with a fallback model. A refusal
  that is not rescued ends the run as `model_failure`.

### Local (`--llm-provider local`)

- **Egress:** none beyond the endpoint, which must be `localhost`, a loopback
  IP, or a private IP literal you list with `--llm-allow-private`. Any other
  endpoint is refused, including DNS names, public addresses and
  `0.0.0.0`. The adapter ignores proxy environment variables and does not
  follow redirects.
- **Data stays on the host:** Ollama runs on the host and listens on
  loopback. The orchestrator runs on the same host and reaches the tools only
  through the gated toolbox. Findings never leave the machine.
- **Constrained output:** Ollama gets the action JSON schema as `format`,
  llama.cpp gets an equivalent GBNF grammar, and OpenAI-compatible servers get
  `response_format: json_schema`. The tool name is restricted to the
  registered tools. The reply is still parsed strictly; see below.
- Ollama receives `num_ctx = --context-tokens`. For llama.cpp, LM Studio and
  vLLM, the context size is set when the server is launched, so pass the same
  value as `--context-tokens`.

### Where op06d actually runs

- **Operator host (product deployment):** op06d, nmap and nuclei run on the
  host. The modes behave as described above.
- **The sealed lab:** op06d and the tools run *inside* the scanner container on
  `labnet`. That network is `internal: true`, with no route to the host or the
  internet, so a lab LLM run can reach neither host-loopback Ollama nor
  `api.anthropic.com`. The chosen lab design is an opt-in **model-relay
  overlay**, built in RC-47. It adds a second internal network that joins only
  the scanner and a relay container, and the relay forwards to exactly one
  upstream: host Ollama, or `api.anthropic.com:443` as TLS passthrough. The
  targets are not on that network, and the base `lab/docker-compose.yml` and
  its no-egress isolation are unchanged. Until RC-47 lands, `--planner llm`
  is not wired into the lab.

## Replies, failures and context

- **Strict validation:** a reply must be exactly one JSON object that matches
  the action schema, `{"type":"action","tool","target","parameters","reason"}`
  or `{"type":"done","summary"}`, with no other keys. Malformed or partial
  JSON is recorded in the audit log (`invalid planner reply: ...`) and is
  never executed. The model is told and asked again, up to 3 consecutive
  failures (`planner_failure`).
- **Transient API errors** (408, 409, 425, 429, 5xx, 529, connection errors and
  timeouts) are retried with exponential backoff and jitter, honouring
  `retry-after` up to 60 s. There are 4 attempts. The SDK's own retries are
  disabled, so this is the only retry layer. Anything else, or exhausted
  retries, ends the run as `model_failure`. A failure never bypasses the gate,
  because the model has no path to the tools except `GatedToolbox.execute()`.
- **Context budget:** `--context-tokens` × 3 characters, minus the system
  prompt and the output reserve, bounds the message history. Each tool
  observation is capped at a third of that budget. When an observation is cut,
  the `UNTRUSTED_TOOL_OUTPUT` header, data notice and END marker are kept and
  the cut is marked (`[... N characters elided to fit the context budget ...]`).
  Older observations are elided when the history no longer fits.

## Secrets

- `ANTHROPIC_API_KEY` is read from the environment only. It is never accepted
  as a flag, never written to the engagement or config, and never logged.
- The key is registered with `op06d.redaction`, which scrubs it from every
  audit entry, from every evidence-store row (and therefore from the report)
  and from CLI error output. Anything shaped like an Anthropic key
  (`sk-ant-...`) is scrubbed whether or not it was registered.
- Tests assert that the key appears in none of the audit log, the evidence
  store files or the report, and that no key-shaped string is committed to the
  repository.

## Report

LLM runs add a **Planner** section: planner, provider, model, endpoint class
(hosted or local), configured context size, iterations, tool actions,
termination reason, input and output tokens, and the limits in force. The
audit log carries the same configuration as a `planner_config` entry.
`--planner fixed` reports are unchanged.

## Model choice

- Hosted default: `claude-opus-5-5`.
- Local dev default: an ~8B instruct model with strong tool calling,
  quantized Q4/Q5, for example `llama3.1:8b-instruct-q5_K_M` on Ollama, with
  `--context-tokens 8192`. Larger contexts need more VRAM; whatever you pass
  to `--context-tokens` is what the server is asked for.
