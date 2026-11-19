![alt text](OP-06D-v2.png)
# OP-06D

An AI-driven security validation tool. A fixed recon plan or an LLM planner chooses
reconnaissance actions and drives real security tools against **authorized** targets, with every action forced through a
hard guardrail layer, and produces a client-grade report.

> **OP-06D runs reconnaissance with nmap and nuclei, driven by a fixed or an LLM planner,
> and is validated against the pinned tools in an isolated lab.** Authorized use only:
> run it only against systems you own or hold signed authorization to test.

---

## ⚠️ Authorized use only

OP-06D runs reconnaissance tooling against networks and applications. Run it **only**
against systems you own or have **explicit, written authorization** to test.

- Every engagement requires a scope file naming the authorized targets and referencing
  the signed authorization. The tool refuses to act outside that scope.
- "I had a tool that let me" is not authorization. Unauthorized scanning is illegal in
  most jurisdictions, and a signed client scope does not override a cloud provider's or
  third party's own testing policies.
- You are responsible for operating within your authorization. The guardrails reduce the
  chance of a mistake; they do not transfer that responsibility.

To report a vulnerability in OP-06D itself, see [`SECURITY.md`](SECURITY.md).

---

## What it is

OP-06D's design principle is **own the orchestration, rent the attack content.** The
LLM is a *planner* that decides what to do next; the actual work is done by established,
community-maintained tools (nmap, nuclei). The parts that are uniquely OP-06D's — and
the parts that matter for safety — are the orchestration loop and the guardrail gate.

The guarantee the tool is built around: **the model proposes, the gate disposes.** Nothing
the LLM emits can widen scope, exceed the authorized rate, run outside the booked window,
or escape the audit trail. Enforcement lives in code, outside the model, and cannot be
altered by model output or by anything a scanned target says back.

## Architecture

```
Operator + scope file
        │
        ▼
Orchestrator (LLM loop)         plan → act → observe → repeat
        │
        ▼
   ┌───────────┐
   │   GATE    │   scope allowlist · rate cap · time window · audit · sanitize
   └───────────┘   every action passes through here; there is no other door
        │
        ▼
Tool layer (nmap, nuclei)       argv only, no shell; rate-limited; risk-classified
        │
        ▼
     Targets  (authorized scope only)

        └──────────────▶  Evidence store  ──▶  Report (client deliverable)
```

### The guardrail gate

Every action the planner proposes is checked by a single enforcement point before any
tool runs:

- **Scope allowlist** — the target must match the engagement's in-scope list (host and
  resolved IP) and match no out-of-scope entry. Deny wins; an empty allowlist denies
  everything (fail-closed); anything malformed or ambiguous is denied.
- **Rate cap** — actions are throttled to the engagement's `max_rps`, and each tool is
  also invoked with its own rate limit so the *actual* packet/request rate is bounded.
- **Time window** — actions outside the authorized window are refused.
- **Audit log** — every decision (allow and deny) is written to an append-only,
  hash-chained, per-engagement log. This is the liability record and the report evidence.
- **Output sanitization** — tool output (banners, HTTP bodies) is treated as hostile and
  wrapped as untrusted data before it re-enters the planning context, so a scanned target
  cannot prompt-inject the planner. The gate still blocks any bad action even if an
  injection slips through — sanitization is defense-in-depth, not the wall.

## Requirements

- Python 3.11+
- [`uv`](https://github.com/astral-sh/uv) (or pip)
- `nmap` and `nuclei` on `PATH` to run real scans (not needed for the unit tests or the
  gate demo, which mock or avoid the tools)
- Docker (for the isolated test lab)

## Install

```bash
git clone https://github.com/mastodonsec/OP-06D.git
cd OP-06D
uv sync
```

## Usage

OP-06D is driven by a single declarative **engagement file** and one command. The
engagement file *is* the authorization boundary — it names the authorized targets, the
rate cap, and the window, and the gate enforces exactly what it says.

```bash
uv run op06d run --engagement examples/engagement.yaml --out out/
```

`--out` (required) is the directory for the HTML report, the evidence store and the
audit log. The default **fixed planner** runs, per in-scope host or IP, an nmap service
scan and a nuclei default-tag scan, and per in-scope CIDR an nmap service scan; nuclei
runs only when `--template-dir` points at a pinned nuclei template directory, and is
otherwise refused as an unknown tool. The example's window (2026-11-10, 02:00 to 06:00
UTC) has passed, so this command scans nothing: every action is refused at the gate
and the report records that. For a real engagement, write your own engagement file.

```
run_id: 9ff1686f-3ffe-405c-84af-140d7fe7c88d
actions: executed=0 denied=3 declined=0 tool_errors=0
findings: none
report (html): out\acme-saas-external-2026-11-9ff1686f-3ffe-405c-84af-140d7fe7c88d.html
evidence store: out\evidence.db
audit log:      out\audit\acme-saas-external-2026-11.audit.jsonl
```

To let a model propose the actions instead (through the same gate), add
`--planner llm --llm-provider local` (or `anthropic`); see
[docs/llm-planner.md](docs/llm-planner.md).

### Engagement file

```yaml
engagement: acme-saas-external-2026-11
authorization:
  client: "Acme Corp"
  signed_scope_ref: "SOW-2026-114"     # your authorization paper trail
  authorized_by: "jane.doe@acme.com"
  window: ["2026-11-10T02:00Z", "2026-11-10T06:00Z"]   # off-hours only
scope:
  in_scope:
    - app.acme.com
    - 203.0.113.0/28
  out_of_scope:
    - "*.stripe.com"      # third-party SaaS they don't own
    - billing.acme.com    # explicitly excluded by the client
intensity:
  max_rps: 20
  destructive: false      # destructive actions require this to be true
objective: "External attack surface recon"
planner:                  # optional; without it only the local LLM provider may plan
  allowed_providers: [local]   # local and/or anthropic (hosted: findings leave the host)
```

The `planner:` block is not in `examples/engagement.yaml`; `--planner fixed` ignores
it. All fields are documented in [docs/engagement-parser.md](docs/engagement-parser.md).

Scope rules worth knowing:

- Plain entries are **exact**: `acme.com` does **not** cover subdomains, and `*.acme.com`
  does **not** cover the apex `acme.com`. List what you mean.
- An explicit `out_of_scope` entry always wins over any `in_scope` match.

## Limitations

- Before a live engagement you need a signed, authorized scope, referenced in the
  engagement file.
- Not supported: exploitation, breach-and-attack simulation, cloud posture auditing,
  authenticated app testing, and a web UI.

## Demo

[`examples/demo_gate.py`](examples/demo_gate.py) shows the scope check making
allow/deny decisions **without running any scan or touching the network** (DNS is
faked). It loads `examples/engagement.yaml`, widens its scope with `*.acme.com` and an
excluded `203.0.113.8/29` so the deny-wins cases can be shown, runs eight targets
through the scope check (`op06d.scope.check_scope`), records every decision in a
hash-chained audit log in a temporary directory, and verifies that log. The
window and rate checks of the full gate are not part of this demo.

```bash
uv run python examples/demo_gate.py
```

Real output (the timestamp and hashes in the last line differ on every run):

```
[ok ] ALLOW '203.0.113.5'        allow: IP in in-scope 203.0.113.0/28
[ok ] DENY  '203.0.113.9'        deny: IP is in out-of-scope 203.0.113.8/29
[ok ] ALLOW 'app.acme.com'       allow: host in scope
[ok ] DENY  'billing.acme.com'   deny: host matches out-of-scope entry 'billing.acme.com'
[ok ] DENY  'www.acme.com'       deny: resolved 203.0.113.9 is in out-of-scope 203.0.113.8/29
[ok ] DENY  'evil.example.net'   deny: host matches no in-scope host entry
[ok ] DENY  '127.1'              deny: malformed target (ambiguous numeric hostname '127.1')
[ok ] DENY  None                 deny: malformed target (target has unexpected type NoneType)

Audit log verified: 9 entries -> acme-saas-external-2026-11.audit.jsonl
Last entry as stored:
  {"v":1,"seq":9,"ts":"2026-11-19T00:06:33.424Z","engagement":"acme-saas-external-2026-11","event":"gate_decision","target":"'<NoneType>'","tool":"demo","parameters":{"note":"manual test"},"allowed":false,"reason":"deny: malformed target (target has unexpected type NoneType)","prev_hash":"4be40b81b4f69f86cd37b1b4aa66f543f4fc8f02cccf0780022eae957fdb5bcd","hash":"522d72b074ffff29c491b5d2912955ac649b72faacefdae0b2ffdf1c33bcbf19"}
```

## Running the tests

```bash
uv run --extra dev pytest -q
```

The unit suite mocks all subprocesses — **no test starts a real scanner or touches a real
host.** Real-tool behavior is validated separately in the isolated lab
([`lab/RUNBOOK.md`](lab/RUNBOOK.md)). The lab-gated integration tests are deselected
by default (they need `-m lab`, `OP06D_LAB=1` and the lab), and the live-model test
is skipped unless `OP06D_LIVE_MODEL=1`.

## Project layout

```
src/op06d/
  __init__.py            package marker
  approval.py            interactive operator approval prompt (default deny, timeout)
  audit.py               append-only, hash-chained per-engagement audit log
  cli.py                 the op06d command: run (engagement to report) and report (re-render a stored run)
  engagement.py          engagement-file schema and loader (the authorization boundary)
  evidence.py            SQLite evidence store: runs, actions and findings, for the report
  gate.py                the single enforcement point (window · scope · rate), one audit entry per decision
  limits.py              time-window and rate-cap primitives used by the gate
  llm.py                 LLM planner adapters: hosted Anthropic, local Ollama / llama.cpp / OpenAI-compatible
  nmap_tool.py           nmap wrapper (argv only, rate-limited, risk-classified, sized host timeouts)
  normalize.py           maps nmap and nuclei output to one findings schema
  nuclei_method_audit.py finds nuclei templates that declare an HTTP write method
  nuclei_tool.py         nuclei wrapper (curated templates, no out-of-band, no redirects, write-method backstop)
  nuclei_write_method_exclusions.json  bundled write-method template ids for the pinned template set
  orchestrator.py        the plan-act-observe loop and its run limits
  redaction.py           secret scrubbing for the audit log, evidence store and CLI errors
  report.py              client report model and Markdown rendering
  report_render.py       self-contained HTML report, optional PDF
  resolve.py             resolve-once DNS pinning (the only place DNS lookups happen)
  sanitize.py            tool-output sanitization against prompt injection
  scope.py               scope decision logic (deny wins, fail closed)
  tools.py               GatedToolbox (tools reachable only through the gate) and default_tools
examples/
  demo_gate.py           the scope-check demo above
  engagement.yaml        example engagement file
scripts/
  generate_nuclei_write_method_exclusions.py   regenerates the write-method list on a template re-pin
docs/                    design notes per component
tests/                   unit suite; tests/integration/ holds the lab-gated tests
lab/                     isolated Docker lab for live validation (see lab/RUNBOOK.md):
                         - targets: OWASP Juice Shop and DVWA, plus an nginx redirector
                         - scanner image with the pinned nmap, nuclei and templates
                         - isolation gate: check_isolation.py (Windows, Linux, macOS)
                         - validation_harness.py: one-command run of the RUNBOOK checks
                         - model relay overlay for --planner llm runs (model_relay.py)
                         - planner model benchmark (benchmark.py)
                         - PLANTED_VULNS.md: the frozen baseline; captures/: frozen evidence
```

## License

OP-06D is licensed under the **GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later)** — see [`LICENSE`](LICENSE). In short: you are free to use,
study, modify, and redistribute it, but any modified version you distribute **or
run as a network service** must be made available under the same license. If you
run a modified OP-06D as a service for others, you must offer them its source.

Copyright (c) 2026 Thomas Pavan / Mastodon Security.

For how the project is run, see [`CONTRIBUTING.md`](CONTRIBUTING.md). Read
[`NOTICE`](NOTICE) before running the tool — it is for authorized testing only.