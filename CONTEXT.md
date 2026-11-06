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

## Status (2026-11-06)

**Built, tested, committed:**
- RC-6 engagement-file parser (pydantic; the authorization boundary)
- RC-9 scope allowlist (deny-wins, fail-closed, host+IP)
- RC-11 audit log (append-only, hash-chained, per-engagement)
- RC-10 rate cap + time window — unified behind `Gate.check()`
- RC-12 tool-output sanitization (prompt-injection defense)
- RC-7 orchestrator loop (plan-act-observe; gate is the only door)
- RC-13 nmap wrapper; RC-14 nuclei wrapper

**Done (2026-11-06):**
- **RC-19 lab stand-up + wrapper validation against real tools — COMPLETE.** Lab is up,
  isolation gate passes (host-side + inside-scanner), both wrappers ran against real
  nmap 7.93 / nuclei v3.11.1 / templates v10.5.1, and the full chain ran end-to-end
  (scripted planner, no LLM). Scope denial, approval denial, sanitization, and audit
  hash-chain integrity all demonstrated live. The **RC-20 baseline is frozen** in
  `lab/PLANTED_VULNS.md` and committed with the `lab/captures/*.findings.json` set.

**Remaining (MVP):** RC-8 (only the operator CLI prompt remains; hook/threshold done),
RC-15 (normalize nmap+nuclei output to one schema — now has real fixtures to target),
RC-16 (evidence store), RC-17/18 (report → HTML/PDF), RC-20 (functional/repeatability
harness + template-set hash), RC-21 (adversarial gate testing).

**Open follow-ups / must-fix (all before any live client engagement):**
- **RC-23 (must-fix):** resolve-once DNS. The gate resolves a hostname and the tool
  re-resolves it independently — a TOCTOU/rebinding gap. Fix: gate returns approved
  IP(s); tools scan that IP with resolution disabled (`-n`).
- **RC-26 (nuclei coverage, medium):** the misconfig/exposure templates advertised in
  `selection.tags` produced no findings in the first real run (only tech/discovery +
  swagger surfaced). The capture doesn't record how many templates nuclei loaded, so we
  can't tell "loaded and matched nothing" from "never loaded." Capture
  `templates_loaded`; confirm the default set actually runs misconfig/exposure; fix the
  selection or document the coverage limit. Could move J-9/J-10/D-8 to FOUND.
- **RC-14 follow-up 1 (ambient-config hardening):** nuclei reads `~/.config/nuclei`;
  the as-built wrapper crashes on a redirect-conflict config (DOS risk) and leaves a
  header vector undefended. Fix validated in lab: always pass a controlled `-config`
  and a controlled `HOME`.
- **RC-14 follow-up 2 (method backstop):** risk tiering is tag-dependent; add an
  HTTP-method backstop so a mis-tagged write-method template can't slip through.
- **RC-25 (nmap privilege, low):** unprivileged `aggressive` silently degrades (skips
  OS detection) and still reports `status=ok`. Surface a `degraded`/skipped-capability
  flag so a privilege-reduced scan isn't reported as complete.
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
  no tool objects. Proven by tests across 10 denial kinds, and confirmed live in the
  RC-19 end-to-end run (out-of-scope `1.1.1.1` denied at the gate with no
  `action_executed`; an INTRUSIVE nuclei action passed the scope gate but was stopped by
  the separate approval hook — the two enforcement layers are provably independent).
  (Protect this over time: nothing outside `tools.py` should import the concrete tool
  classes — RC-21 adds an architectural test for it.)
- **Risk tiers:** passive-recon / active-recon / intrusive / exploit. Approval required
  at **intrusive+** (configurable). nmap/nuclei defaults are active-recon, so recon
  trips no approval. `dos`/`exploit` need `destructive: true`. Risk is derived from the
  actual scan profile/templates, not a flat per-tool constant.
- **Audit event** is `gate_decision` (covers scope + rate + window). Each gate decision
  writes exactly one audit entry; secrets are redacted (incl. in refused actions). The
  sha256 the planner is fed matches the sha256 recorded in `action_executed` — the
  evidence chain is tamper-evident end to end.
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
  (sha256-verified, templates read-only). **The scanner container runs as root by
  default** (hence SYN scans); dropping to the unprivileged `scanner` user forces
  connect scans — see RC-25.
- `check_isolation.ps1` (host-side) + `check_isolation.sh` (inside-scanner): the
  two-layer isolation gate. **Must PASS before any scan.** Run:
  `powershell -ExecutionPolicy Bypass -File ".\lab\check_isolation.ps1"`
- `engagement.yaml`: scoped to the two targets; scanner explicitly out-of-scope.
- `PLANTED_VULNS.md`: **FROZEN RC-20 baseline** (reconciled against the first real
  captures; incl. G-1..G-9 negative/guardrail expectations, all HELD). Corrections
  C-1..C-4 record the real-run deviations (nmap mislabels port 3000 as `ppp`;
  misconfig/exposure templates didn't fire → RC-26; aggressive degrades unprivileged →
  RC-25; DVWA baselined uninitialized).
- `captures/*.findings.json`: the seven frozen baseline captures. These are tracked
  (force-added past the scan-artifact `.gitignore` rule); routine scan output stays
  ignored.
- `RUNBOOK.md`: ordered steps; isolation gate is the blocking step before any scan.
  (Header still references an old `R:\My Drive` path — ignore; repo is `Z:\git\RedCell`.
  Step 12 expected result corrected per RC-25: aggressive degrades, it doesn't fail.)

**Lab run scope:** tools run directly in the scanner, **no LLM** — the scanner is sealed
(no egress), so the orchestrator can't reach the LLM API from inside. The RC-19
end-to-end used a **scripted planner** in place of the LLM. A full LLM-in-the-loop
end-to-end is a separate, deliberately egress-controlled step (RC-21 territory), not
part of the sealed-lab run.

## Tests / fixtures
- Hand-written fixtures cover edge cases (malformed XML, XXE, optional `matcher_name`,
  unparsed lines) — keep them.
- `tests/fixtures/real/` holds the frozen RC-19 captures as **golden schema fixtures**
  (these are already-normalized wrapper output, not raw re-parse inputs). If raw nmap
  XML / nuclei JSONL was also saved, it goes under `tests/fixtures/real/raw/` with a
  round-trip test feeding it through `parse_nmap_xml` / `parse_nuclei_jsonl`.

## Build order / Jira epics
- **RC-2 Guardrail gate** (done): RC-9 scope, RC-10 rate/window, RC-11 audit, RC-12 sanitize
- **RC-1 Orchestrator loop**: RC-6 parser (done), RC-7 loop (done), RC-8 approval (hook done, CLI pending)
- **RC-3 Tool layer**: RC-13 nmap (done), RC-14 nuclei (done, +config/method follow-ups), RC-15 normalization
- **RC-4 Evidence & reporting**: RC-16 store, RC-17 report, RC-18 HTML/PDF
- **RC-5 Lab & hardening**: RC-19 lab (DONE), RC-20 functional/repeatability, RC-21 adversarial
- Bugs/tasks: RC-22 (engagement-id in schema), RC-23 (resolve-once DNS, must-fix before live),
  RC-25 (nmap privilege-degradation surfacing), RC-26 (nuclei template coverage + instrumentation)

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
- **No live client engagement** until: RC-23 (resolve-once DNS) fixed, RC-14 config/method
  follow-ups done, and RC-21 adversarial testing done. (Lab validation is complete.)
- Cloud targets have provider pentest policies; a client scope doesn't override them.
- Repo is private; license decision deferred (consultancy vs. product).

## Deliberately out of the MVP
Exploitation tier (Metasploit), BAS (CALDERA), cloud posture auditing, authenticated app
testing, any web UI. Config-file + CLI only for now.
