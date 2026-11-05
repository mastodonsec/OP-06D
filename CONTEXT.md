# Red Cell — project context

Primer for anyone (human or AI assistant) picking up this repo. It captures the
plan so a dev session can start with full context. The living plan lives in two
places: the **Red Cell MVP architecture doc** and the **RC Jira board**
(Mastodonsec site). This file is the in-repo summary.

## What this is

An AI-driven security validation tool. An LLM orchestrator plans actions and
drives real security tools against *authorized* targets, enforced by a hard
guardrail layer, and produces a client-grade report.

Business context: built to assess paid clients' posture, and potentially to sell
or license later. Operated solo for now (consultancy mode), productized later.

**Guiding principle: own the orchestration, rent the attack content.** The LLM is
a planner that drives real tools — not the thing doing the hacking. Community-
maintained engines (attack libraries, vuln templates) are borrowed so one person
can maintain the tool. The orchestration loop and the guardrail layer are the
only fully hand-owned parts; that's where the value and the safety live.

## MVP scope

One command, one engagement file, one report, against authorized targets, with
the gate enforcing scope. **Recon only** for the MVP.

**In scope:** engagement-file parser, guardrail gate, recon tools (nmap + nuclei),
evidence store, report generation, lab validation.

**Explicitly out of the MVP** (later iterations):
- Exploitation tier (Metasploit) — highest blast radius, added last
- BAS / CALDERA — iteration two
- Cloud posture module (Prowler/ScoutSuite) — later
- Authenticated app testing — unauthenticated external recon first
- Any UI — config file + CLI only

## Architecture

```
Operator + scope file  ->  Orchestrator (LLM loop)  ->  [ Guardrail gate ]  ->  Tool layer (MCP-wrapped)  ->  Targets
                                                              |                         (nmap, nuclei)
                                                              v
                                                   Evidence store  ->  Reporting (client deliverable)
```

Four components that cannot be cut:

1. **Orchestrator loop** — reads the engagement file, asks the LLM to plan the
   next action, executes it *through the gate*, feeds results back, repeats.
2. **Guardrail gate** — every action passes through one enforcement point:
   scope allowlist, rate cap, time window. Logs everything. Sanitizes tool
   output before it re-enters the planning prompt.
3. **Tool layer** — each real tool wrapped as an MCP tool. MVP: nmap + nuclei.
4. **Evidence store + report** — every action and finding persisted, then
   rendered to the client deliverable.

### Guardrail rules (non-negotiable)

- **Enforce scope in code, not in the prompt.** The LLM is *asked*; the gate
  *decides*. Scope enforcement lives outside the model and cannot be altered by
  model output.
- **Treat tool output as hostile input.** Banners, HTTP bodies, and file
  contents are attacker-controllable and can carry prompt injection. Sanitize
  before they re-enter the planning context; keep scope enforcement independent
  of anything in tool output.
- **Audit everything.** The log is the liability record, the report evidence,
  and the debugging trail.

## Stack

- **Python.** The project is orchestration and glue; the bottleneck is network
  I/O to the LLM and tool runtimes, so language speed is irrelevant. The
  security-tooling ecosystem is Python.
- **pydantic** for the engagement-file schema and evidence records — the config
  is the safety boundary, so it is schema-validated on load.
- **asyncio** — mostly I/O-bound; concurrency later.
- **MCP** to wrap each tool, so tools and the LLM are swappable.
- Docker for the lab and eventual packaging.

## Build order (RC board)

Build in thin vertical slices; test each against a lab you own (host-only
network, nothing routable out). The guardrail epic (RC-2) leads the backlog.

Start here, in order:

1. **RC-6 — engagement-file parser.** Pure Python, no network. Define the
   pydantic models (scope in/out, authorization, intensity, window), load YAML,
   validate. This is the spine everything hangs off; the gate reads from it.
2. **RC-9 — scope allowlist enforcement.** The `is_in_scope(target)` function.
   The single most important function in the codebase. Trivially unit-testable.
3. **RC-11 — audit log.** Stand up early; the gate and loop write to it from day
   one. Retrofitting logging is painful.

That gives a testable safety core (config -> scope check -> audit) before any
code touches a network.

Then: orchestrator loop (RC-7), human approval prompt (RC-8), rate/window
(RC-10), output sanitization (RC-12), tool wrappers (RC-13 nmap, RC-14 nuclei),
normalization (RC-15), evidence store (RC-16), report (RC-17), HTML/PDF (RC-18),
lab (RC-19), functional/repeatability tests (RC-20), adversarial gate tests
(RC-21).

### Jira epics

- **RC-2 Guardrail gate** (leads) — RC-9 scope allowlist, RC-10 rate/window,
  RC-11 audit log, RC-12 output sanitization
- **RC-1 Orchestrator loop** — RC-6 engagement parser, RC-7 plan-act-observe
  loop, RC-8 human approval prompt
- **RC-3 Tool layer (recon MVP)** — RC-13 nmap, RC-14 nuclei, RC-15 normalization
- **RC-4 Evidence store & reporting** — RC-16 store, RC-17 Markdown report,
  RC-18 HTML/PDF
- **RC-5 Lab validation & hardening** — RC-19 lab, RC-20 functional/repeatability,
  RC-21 adversarial gate testing

Reference commits and branches by issue key (e.g. `RC-6: add engagement schema`,
branch `RC-6-engagement-parser`) so work links back to the board.

## Engagement file shape (reference)

```yaml
engagement: acme-saas-external-2026-11
authorization:
  client: "Acme Corp"
  signed_scope_ref: "SOW-2026-114"
  authorized_by: "jane.doe@acme.com"
  window: ["2026-11-10T02:00Z", "2026-11-10T06:00Z"]
scope:
  in_scope:
    - app.acme.com
    - 203.0.113.0/28
  out_of_scope:
    - "*.stripe.com"
    - billing.acme.com
intensity:
  max_rps: 20
  destructive: false
objective: "External attack surface recon"
```

## Operating rules (safety and legal)

- Never run against a target not in a signed, authorized scope.
- Secrets are never committed — use references (e.g. a vault path), not inline
  values. Get `.gitignore` and secrets scanning in place before there's anything
  sensitive.
- Cloud targets have provider-specific pentest policies; confirm them per
  engagement. "Client authorized it" does not override the provider's terms.
- Repo is private. License decision deferred (consultancy vs. product).
