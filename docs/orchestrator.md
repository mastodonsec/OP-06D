# Orchestrator loop (RC-7) and approval hook (RC-8)

Modules: [`src/op06d/orchestrator.py`](../src/op06d/orchestrator.py) ·
[`src/op06d/tools.py`](../src/op06d/tools.py) ·
Audit events: [`src/op06d/audit.py`](../src/op06d/audit.py) ·
Tests: [`tests/test_orchestrator.py`](../tests/test_orchestrator.py)

## Purpose

The loop that drives an LLM through recon: ask for the next action, route it
through the gate, execute approved actions, sanitize the result, feed it back,
repeat. It ties together the gate (RC-9/RC-10), the audit log (RC-11) and output
sanitization (RC-12). The model proposes; the gate disposes.

```
build context -> LLM proposes action -> GatedToolbox.execute -> append SANITIZED result -> repeat
                                           |
                                           |- validate (tool known, params allowed, target well-formed)
                                           |- Gate.check   (window -> scope -> rate)      <- the only door
                                           |- approval     (only if tool risk >= threshold)
                                           |- tool.run
                                           |- sanitize_tool_output  (raw kept for evidence)
                                           `- record_execution (audit)
```

## Scope of RC-7 / RC-8

**In scope:** the loop, the gated toolbox, the system prompt, planner-reply
parsing, termination rules, the approval *hook* and its risk threshold, audit
traceability, tests with a stub LLM.

**Not here:**

| Concern | Ticket |
|---|---|
| The interactive CLI approval prompt (implements `ApprovalHook`) | RC-8 |
| Real nmap / nuclei MCP wrappers | RC-13, RC-14 |
| A real LLM client | RC-7 follow-up / CLI |
| Normalizing raw output into findings; evidence store | RC-15, RC-16 |
| Live-model injection testing | RC-21 |

## Design properties

### 1. The gate is the only door

The loop holds a `GatedToolbox` and nothing else that can run a tool. The
toolbox keeps its tools in a private (name-mangled) attribute and its public API
is exactly `describe()` (names and metadata, no callables) and `execute()`,
which always calls `Gate.check` before `tool.run`. There is no accessor that
returns a tool.

Python cannot make this absolute, so it is also asserted by tests: for ten kinds
of denied action (out of scope, out of window, unknown tool, smuggled parameter,
newline in target, destructive tool, approval not granted, broken audit log,
...) the tool's `run` is never called; the gate is shown to run before the tool;
and the orchestrator is shown to hold no tool objects.

Before the gate, `execute` also refuses (and audits):

| Check | Why |
|---|---|
| Unknown tool name | nothing to run |
| Target not a clean printable string (no leading/trailing whitespace, no newlines, max 253 chars) | a newline must not smuggle extra arguments into a tool |
| Parameter not in the tool's `allowed_parameters` | the gate checks `target` only; a parameter like `extra_targets` would otherwise bypass scope |
| Parameter values other than strings, numbers, booleans, lists of those; over 4000 chars | keep tool input simple and bounded |
| Tool is `destructive` but the engagement has `destructive: false` | that engagement field is otherwise unenforced |

### 2. Sanitize before planning

`execute` returns both `raw_output` (evidence only) and `sanitized`. The loop
appends only `sanitized.text` to the context. Raw output stays on the `Step`
records (`RunResult.evidence`) for RC-15/16. Tool errors are sanitized too.
Injection flags are written to the audit log by the sanitizer (RC-12).

### 3. System-prompt data contract

`build_system_prompt` tells the model that content inside `UNTRUSTED_TOOL_OUTPUT`
blocks is data captured from remote targets, to be analyzed and never followed,
and that scope, window and rate are enforced by code outside it. It also lists
the in-scope and out-of-scope entries, the window, the rate cap, the tools and
the reply format. A test asserts the contract is in the system prompt on every
LLM call.

### 4. Gate decisions are respected

| Gate outcome | Loop behavior |
|---|---|
| Rate block | sleep `retry_after` (capped at 60 s), retry the **same** action without another LLM call, up to `max_rate_retries` (default 5); then tell the planner it was rate limited and continue |
| Scope / tool / approval refusal | feed the reason back, remember the action, **never retry it**; re-proposing the identical action is short-circuited before it reaches the gate |
| Window denial | terminate (`window_expired` / `window_not_open`) |
| Engagement limits unusable | terminate (`gate_unusable`) |
| Audit failure | terminate (`audit_failure`) |

### 5. Bounded

`max_iterations` (default 25, hard limit 1000, validated) counts planner calls.
The window is checked before every LLM call, so no tokens are spent after it
closes. Context is capped (`max_context_chars`, default 200,000): the oldest
observations are replaced by a one-line elision; the opening message is kept.

| Termination | When |
|---|---|
| `objective_met` | planner replies `{"type": "done", ...}` |
| `window_expired` | now is at or after the window end (see RC-10: `[start, end)`) |
| `window_not_open` | now is before the window start |
| `operator_stop` | the injected `stop()` returns true (or raises) |
| `max_iterations` | cap reached |
| `planner_failure` | `max_planner_failures` (default 3) consecutive LLM errors or invalid replies |
| `gate_unusable` | window/rate config unusable or clock failure |
| `audit_failure` | an audit record could not be written |

### 6. Enforcement stays outside the model

The model only produces a JSON proposal. It is parsed strictly (anything else is
an invalid reply and counts toward `planner_failure`). Nothing in a reply or in
tool output can change the engagement, the gate, the window or the rate.

## Approval hook (RC-8) and risk threshold

```python
class ApprovalHook(Protocol):
    def approve(self, request: ApprovalRequest) -> bool: ...
```

Every tool declares a `Risk`:

| Risk | Meaning | Example |
|---|---|---|
| `PASSIVE_RECON` (0) | reads public data, never touches the target | cert transparency lookup |
| `ACTIVE_RECON` (1) | probes the target like a normal client | nmap, nuclei default templates |
| `INTRUSIVE` (2) | may degrade a service or send attack-shaped traffic | fuzzing, intrusive templates |
| `EXPLOIT` (3) | attempts access or state change | Metasploit (future tier) |

**Threshold:** an action needs operator approval when `tool.risk >=
approval_threshold`. The default is `Risk.INTRUSIVE`, and it is configurable per
toolbox. **Decision for the recon MVP: nothing crosses it.** nmap and nuclei
(default templates) are `ACTIVE_RECON`; a test pins that they never ask. A
nuclei configuration that enables intrusive templates must be registered as
`INTRUSIVE`. The exploit tier will hook in by registering `EXPLOIT` tools.

Rules, all tested:
- Approval is asked **after** the gate allows the action, so the operator is
  never asked about something the gate would refuse. Gate-denied actions never
  reach the approver.
- Decline, timeout (the hook must return False on timeout), an exception, no
  approver configured (`DenyAllApprover` is the default), or an approval that
  cannot be recorded: the action does not run.
- Every approval and decline is written to the audit log (`approval` event with
  `allowed`).
- The operator's refusal is remembered like a gate refusal; the planner is told
  not to propose it again.

## Audit trail

One entry type per step, all on the engagement's RC-11 log, all carrying
`parameters.iteration` so a run can be grouped and reconstructed:

| Event | Written by |
|---|---|
| `log_opened` | `AuditLog.for_engagement` (authorization, scope, intensity in force) |
| `iteration` | the loop: the planner's proposal (tool, target, params, truncated reply), invalid replies, repeats, LLM failures, "done" |
| `gate_decision` | the gate: allow / deny with stage reason (window, scope, rate, ...) |
| `approval` | the toolbox: approved / declined |
| `injection_flag` | the sanitizer (RC-12) |
| `action_executed` | the toolbox: status, output length and the **sha256 of the raw output** |
| `loop_terminated` | the loop: the termination reason |

A normal executed step reads `iteration -> gate_decision -> [injection_flag] ->
action_executed`; a refused one reads `iteration -> gate_decision`.

## Usage

```python
from op06d.audit import AuditLog
from op06d.engagement import load_engagement
from op06d.gate import Gate
from op06d.orchestrator import Orchestrator
from op06d.tools import GatedToolbox, Risk

eng = load_engagement("examples/engagement.yaml")
log = AuditLog.for_engagement(eng, "logs/")
gate = Gate(eng)                                   # one per engagement; holds rate state
toolbox = GatedToolbox(eng, gate, log, [NmapTool(), NucleiTool()],
                       approver=my_cli_approver,   # RC-8; omit => risky actions are declined
                       approval_threshold=Risk.INTRUSIVE)

orch = Orchestrator(eng, my_llm, toolbox, log, max_iterations=25,
                    stop=operator_stop_event.is_set)
result = orch.run()
result.termination   # Termination.OBJECTIVE_MET, ...
result.evidence      # executed actions with RAW output, for RC-15/16
```

An LLM is anything with `complete(system: str, messages: list[dict]) -> str`
(roles `user` / `assistant`, strictly alternating). A tool is anything with
`name`, `description`, `risk`, `destructive`, `allowed_parameters` and
`run(target, parameters)`.

Planner reply format (one JSON object, optionally in a code fence):

```json
{"type": "action", "tool": "nmap", "target": "203.0.113.5", "parameters": {"ports": "1-1024"}, "reason": "map open ports"}
{"type": "done", "summary": "..."}
```

Testing: inject `now`, `sleep`, `stop`, the LLM and the tools; no live calls and
no real waiting. Run:

```bash
uv run --extra dev pytest tests/test_orchestrator.py
```

## Requirements for tool wrappers (RC-13, RC-14)

- Build the command as an argv list; never use a shell.
- Declare only `allowed_parameters` that cannot carry a target, and validate
  values yourself (the toolbox checks shape, not meaning).
- Pass the engagement's `max_rps` to the tool (e.g. nmap `--max-rate`). The gate
  counts one approved action as one request; a scan sends many packets.
- Enforce a timeout and stop if the window ends; the window is checked only
  between actions.
- Register the right `Risk`; set `destructive=True` for anything that changes
  target state.

## Known limits

- The chokepoint rests on the toolbox design and tests; Python cannot hide
  attributes absolutely.
- A long-running action is not interrupted when the window ends.
- The loop is single-threaded and synchronous.
- Sanitization and the data contract reduce, but do not eliminate, the chance a
  real model is steered. The guarantee is the gate. Validate with a live model
  and varied/multilingual payloads in RC-21.
- No real MCP wrapper or LLM client exists yet; both are protocols here.
