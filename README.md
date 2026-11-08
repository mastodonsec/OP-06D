![alt text](Redcell2-1.png)
# OP-06D

An AI-driven security validation tool. An LLM plans reconnaissance actions and drives
real security tools against **authorized** targets, with every action forced through a
hard guardrail layer, and produces a client-grade report.

> **Status: active development — recon MVP.** The core engine (engagement parser,
> guardrail gate, orchestrator loop) and two tool wrappers (nmap, nuclei) are built and
> unit-tested. Live validation against real tools in an isolated lab is in progress.
> **Not for use against live client targets yet** — see [Project status](#project-status).

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
git clone <your-repo-url> OP-06D
cd OP-06D
uv sync
```

## Usage

OP-06D is driven by a single declarative **engagement file** and one command. The
engagement file *is* the authorization boundary — it names the authorized targets, the
rate cap, and the window, and the gate enforces exactly what it says.

```bash
uv run op06d run --engagement engagement.yaml
```

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
```

Scope rules worth knowing:

- Plain entries are **exact**: `acme.com` does **not** cover subdomains, and `*.acme.com`
  does **not** cover the apex `acme.com`. List what you mean.
- An explicit `out_of_scope` entry always wins over any `in_scope` match.

## Demo

`examples/demo_gate.py` shows the guardrail gate making allow/deny decisions **without
running any real scan** — it's the safest way to see the safety core work. It loads an
engagement, runs a set of targets through the gate, and prints each decision with its
reason.

```python
# examples/demo_gate.py
"""
OP-06D — guardrail gate demo.

Shows the scope gate allowing and denying targets against an engagement scope,
with the reason for each decision. Runs NO real scan and touches NO network beyond
the DNS resolution the gate itself performs. Safe to run anywhere.

    uv run python examples/demo_gate.py
"""
from op06d.engagement import load_engagement
from op06d.gate import Gate
from op06d.audit import open_audit_log   # per-engagement audit sink

# A tiny inline engagement for the demo (normally this is your engagement.yaml).
DEMO_ENGAGEMENT = {
    "engagement": "demo-local",
    "authorization": {
        "client": "Demo",
        "signed_scope_ref": "DEMO-000",
        "authorized_by": "demo@example.com",
        # Wide-open window so the demo focuses on scope decisions.
        "window": ["2000-01-01T00:00Z", "2100-01-01T00:00Z"],
    },
    "scope": {
        "in_scope": ["203.0.113.0/28", "app.acme.com"],
        "out_of_scope": ["203.0.113.8/29", "billing.acme.com"],
    },
    "intensity": {"max_rps": 20, "destructive": False},
    "objective": "Gate demo",
}

# Targets to run through the gate: (target, what we expect, why it matters)
CASES = [
    ("203.0.113.5",      "ALLOW", "IP inside the in-scope /28"),
    ("203.0.113.9",      "DENY",  "IP inside an out-of-scope /29 — deny wins"),
    ("app.acme.com",     "ALLOW", "host is in scope"),
    ("billing.acme.com", "DENY",  "host explicitly excluded"),
    ("evil.example.net", "DENY",  "host matches no in-scope entry (fail-closed)"),
    ("127.1",            "DENY",  "malformed/ambiguous target"),
    (None,               "DENY",  "non-string target"),
]

def main() -> None:
    engagement = load_engagement(DEMO_ENGAGEMENT)     # validates on load
    with open_audit_log(engagement) as audit:
        gate = Gate(engagement)
        for target, expected, why in CASES:
            decision = gate.check(target, audit=audit)
            verdict = "ALLOW" if decision.allowed else "DENY"
            ok = "ok " if verdict == expected else "!! "
            print(f"[{ok}] {verdict:5} {target!r:22} {decision.reason}  ({why})")

if __name__ == "__main__":
    main()
```

Running it looks like this (reasons abbreviated):

```
[ok ] ALLOW '203.0.113.5'          allow: IP in in-scope 203.0.113.0/28   (IP inside the in-scope /28)
[ok ] DENY  '203.0.113.9'          deny: IP in out-of-scope 203.0.113.8/29  (deny wins)
[ok ] ALLOW 'app.acme.com'         allow: host in scope                   (host is in scope)
[ok ] DENY  'billing.acme.com'     deny: host matches out-of-scope entry  (explicitly excluded)
[ok ] DENY  'evil.example.net'     deny: host matches no in-scope entry   (fail-closed)
[ok ] DENY  '127.1'                deny: malformed target                 (ambiguous)
[ok ] DENY  None                   deny: unexpected target type           (non-string)
```

> The exact import paths and function signatures above mirror the current module layout
> (`op06d.engagement`, `op06d.gate`, `op06d.audit`). Adjust them if your local API
> differs — the demo's purpose is to show the gate's decisions, not a fixed API.

## Running the tests

```bash
uv run pytest -q
```

The unit suite mocks all subprocesses — **no test starts a real scanner or touches a real
host.** Real-tool behavior is validated separately in the isolated lab.

## Project layout

```
src/op06d/
  engagement.py     engagement-file schema and loader (the authorization boundary)
  gate.py           the single enforcement point (scope · rate · window)
  scope.py          scope decision logic (deny-wins, fail-closed)
  audit.py          append-only, hash-chained per-engagement audit log
  sanitize.py       tool-output sanitization against prompt injection
  orchestrator.py   the plan-act-observe loop
  tools.py          GatedToolbox — tools are reachable only via the gate
  nmap_tool.py      nmap wrapper (argv-only, rate-limited, risk-classified)
  nuclei_tool.py    nuclei wrapper (curated templates, no OOB, no redirects)
examples/
  demo_gate.py      the gate demo above
lab/                isolated Docker lab (Juice Shop + DVWA) for live validation
```

## Project status

**Built and unit-tested:** engagement parser, guardrail gate (scope, rate, window, audit,
sanitize), orchestrator loop, nmap wrapper, nuclei wrapper.

**In progress:** isolated lab stand-up and validation of the wrappers against real tools.

**Before any live client engagement, still required:**

- Lab validation complete (real-tool flags/output confirmed, tag vocabulary audited,
  isolation proven).
- **Resolve-once DNS fix** — close the time-of-check/time-of-use gap between the gate's
  scope check and the tool's own hostname resolution (tracked as RC-23). Until this lands,
  a hostname's DNS could change between check and scan.
- Full adversarial gate testing against a live model with varied injection payloads.

**Deliberately out of the MVP** (later iterations): exploitation tier (Metasploit),
breach-and-attack simulation (CALDERA), cloud posture auditing, authenticated app testing,
and any web UI. OP-06D is config-file + CLI for now.

## License

OP-06D is licensed under the **GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later)** — see [`LICENSE`](LICENSE). In short: you are free to use,
study, modify, and redistribute it, but any modified version you distribute **or
run as a network service** must be made available under the same license. If you
run a modified OP-06D as a service for others, you must offer them its source.

Copyright (c) 2026 Thomas Pavan / Mastodon Security. The copyright holder also
offers **commercial licenses** without the AGPL's source-disclosure obligations —
contact thomas@mastodonsec.com.

Contributions are accepted under the AGPL via the Developer Certificate of Origin;
see [`CONTRIBUTING.md`](CONTRIBUTING.md). Read [`NOTICE`](NOTICE) before running the
tool — it is for authorized testing only.