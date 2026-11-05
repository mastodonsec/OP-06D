# Red Cell — project context

Primer for anyone (human or AI assistant) picking up this repo — including a fresh
Claude Code session. It captures where the project stands so a dev session can start
with full context. The **authoritative, live state is the RC Jira board** (Mastodonsec
site); this file is the in-repo summary, and the **Red Cell MVP architecture doc** has
the narrative.

> Repo lives on a **local drive** (`Z:\git\RedCell`), not Google Drive. This matters:
> Docker bind mounts can't read Google Drive File Stream, so the lab must run from a
> local or WSL path. Back up via GitHub, not a cloud-synced drive.

## What this is

An AI-driven security validation tool. An LLM *plans* reconnaissance actions and drives
real security tools (nmap, nuclei) against **authorized** targets, with every action
forced through a hard guardrail layer, and produces a client-grade report.

**Guiding principle: own the orchestration, rent the attack content.** The LLM is a
planner, not the thing doing the hacking. Community-maintained engines are borrowed; the
orchestration loop and the guardrail gate are the only hand-owned parts — that's where
the value and the safety live.

**The guarantee: the model proposes, the gate disposes.** Nothing the model emits (or
anything a scanned target says back) can widen scope, exceed the rate, run outside the
window, or escape the audit trail. Enforcement is in code, outside the model.

Business context: built to assess paid clients' posture, and potentially to sell/license
later. Solo, consultancy-mode now; productized later.

## Status (2026-11)

**Built, tested, committed:**
- RC-6 engagement-file parser (pydantic; the authorization boundary)
- RC-9 scope allowlist (deny-wins, fail-closed, host+IP)
- RC-11 audit log (append-only, hash-chained, per-engagement)
- RC-10 rate cap + time window — unified behind `Gate.check()`
- RC-12 tool-output sanitization (prompt-injection defense)
- RC-7 orchestrator loop (plan-act-observe; gate is the only door)
- RC-13 nmap wrapper; RC-14 nuclei wrapper

**In progress:**
- RC-19 lab stand-up + validating the wrappers against real tools. Lab is up and
  **isolation gate passes** (host-side + inside-scanner). Next: run scans, capture real
  output, replace hand-written fixtures, freeze the RC-20 baseline.

**Remaining (MVP):** RC-8 (only the operator CLI prompt remains; hook/threshold done),
RC-15 (normalize nmap+nuclei output to one schema), RC-16 (evidence store), RC-17/18
(report → HTML/PDF), RC-20 (functional/repeatability), RC-21 (adversarial gate testing).

**Open follow-ups / must-fix:**
- **RC-23 (must-fix before any live client engagement):** resolve-once DNS. The gate
  resolves a hostname and the tool re-resolves it independently — a TOCTOU/rebinding gap.
  Fix: gate returns approved IP(s); tools scan that IP with resolution disabled (`-n`).
- **RC-14 ambient-config hardening:** a `~/.config/nuclei` config could override the
  wrapper's security flags; wrapper must control the config environment.
- **RC-22:** move engagement-ID charset validation into the RC-6 schema.

## Architecture

```
Operator + scope file
        │
        ▼
Orchestrator (LLM loop)      plan → act → observe → repeat
        │
        ▼
   ┌───────────┐
   │   GATE    │   scope · rate · window · audit · sanitize   (the only door)
   └───────────┘
        │
        ▼
Tool layer (nmap, nuclei)    argv only, no shell; rate-limited; risk-classified
        │
        ▼
     Targets  (authorized scope only)
        └──────────▶  Evidence store  ──▶  Report (client deliverable)
```

### Key design facts (learned during build)
- **`GatedToolbox` is the only door.** Tools are reachable only via `execute()`
  (validate → `Gate.check` → approval → run → sanitize → record). The orchestrator holds
  no tool objects. Proven by tests across 10 denial kinds. (Protect this over time:
  nothing outside `tools.py` should import the concrete tool classes — RC-21 adds an
  architectural test for it.)
- **Risk tiers:** passive-recon / active-recon / intrusive / exploit. Approval required
  at **intrusive+** (configurable). nmap/nuclei defaults are active-recon, so recon
  trips no approval. `dos`/`exploit` need `destructive: true`. Risk is derived from the
  actual scan profile/templates, not a flat per-tool constant.
- **Audit event** is `gate_decision` (covers scope + rate + window). Each gate decision
  writes exactly one audit entry; secrets are redacted (incl. in refused actions).
- **Sanitizer** wraps tool output in an `UNTRUSTED_TOOL_OUTPUT` block. The orchestrator
  system prompt MUST declare that block is data, never instructions (RC-7 criterion).
  Sanitization is defense-in-depth; the gate is what actually blocks a bad action.

### Guardrail rules (non-negotiable)
- Enforce scope in code, not the prompt. Deny-wins; empty allowlist = deny-all.
- Treat tool output as hostile input. Sanitize before it re-enters planning; keep
  enforcement independent of anything in tool output.
- Audit everything: the log is the liability record and the report evidence.

## Stack
- **Python** (orchestration/glue; bottleneck is I/O, not CPU). pydantic for the
  engagement schema and records. MCP to wrap tools. Docker for the lab.
- Tools run **argv-only, never shell**; each wrapped as a `Tool` imported only via
  `default_tools()`.

## The lab (`lab/`)
- `docker-compose.yml`: Juice Shop (:3000) + DVWA (:80) + a scanner, all on ONE
  `internal: true` network (no egress). Pinned by digest. No published ports.
- `scanner/Dockerfile`: pinned nmap 7.93, nuclei v3.11.1, nuclei-templates v10.5.1
  (sha256-verified, templates read-only).
- `check_isolation.ps1` (host-side) + `check_isolation.sh` (inside-scanner): the
  two-layer isolation gate. **Must PASS before any scan.** Run:
  `powershell -ExecutionPolicy Bypass -File ".\lab\check_isolation.ps1"`
- `engagement.yaml`: scoped to the two targets; scanner explicitly out-of-scope.
- `PLANTED_VULNS.md`: provisional RC-20 benchmark (incl. G-1..G-9 negative/guardrail
  expectations). Freeze after the first real captures.
- `RUNBOOK.md`: ordered steps; isolation gate is the blocking step before any scan.

**Lab run scope:** tools run directly in the scanner, **no LLM** — the scanner is sealed
(no egress), so the orchestrator can't reach the LLM API from inside. A full
LLM-in-the-loop end-to-end is a separate, deliberately egress-controlled step (RC-21
territory), not part of the sealed-lab run.

## Build order / Jira epics
- **RC-2 Guardrail gate** (done): RC-9 scope, RC-10 rate/window, RC-11 audit, RC-12 sanitize
- **RC-1 Orchestrator loop**: RC-6 parser (done), RC-7 loop (done), RC-8 approval (hook done, CLI pending)
- **RC-3 Tool layer**: RC-13 nmap (done), RC-14 nuclei (done, port/scheme fixed; ambient-config
  hardening still open), RC-15 normalization
- **RC-4 Evidence & reporting**: RC-16 store, RC-17 report, RC-18 HTML/PDF
- **RC-5 Lab & hardening**: RC-19 lab (in progress), RC-20 functional/repeatability, RC-21 adversarial
- Bugs/tasks: RC-22 (engagement-id in schema), RC-23 (resolve-once DNS, must-fix before live)

Reference commits/branches by issue key (`RC-15: ...`) so work links to the board.

## Engagement file shape (reference)

```yaml
engagement: acme-saas-external-2026-11
authorization:
  client: "Acme Corp"
  signed_scope_ref: "SOW-2026-114"
  authorized_by: "jane.doe@acme.com"
  window: ["2026-11-10T02:00Z", "2026-11-10T06:00Z"]
scope:
  in_scope: [app.acme.com, 203.0.113.0/28]
  out_of_scope: ["*.stripe.com", billing.acme.com]
intensity:
  max_rps: 20
  destructive: false
# interactsh_server: https://your-self-hosted   # optional; public OOB is refused
objective: "External attack surface recon"
```
Scope entries are exact: `acme.com` ≠ its subdomains; `*.acme.com` ≠ the apex.

## Operating rules (safety and legal)
- Never run against a target not in a signed, authorized scope.
- No secrets in the repo — references only. `.gitignore` + secrets discipline before
  anything sensitive exists.
- **No live client engagement** until: lab validation complete, RC-23 (resolve-once DNS)
  fixed, and RC-21 adversarial testing done.
- Cloud targets have provider pentest policies; a client scope doesn't override them.
- Repo is private; license decision deferred (consultancy vs. product).

## Deliberately out of the MVP
Exploitation tier (Metasploit), BAS (CALDERA), cloud posture auditing, authenticated app
testing, any web UI. Config-file + CLI only for now.
