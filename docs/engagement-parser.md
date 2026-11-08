# Engagement-file parser (RC-6)

Module: [`src/op06d/engagement.py`](../src/op06d/engagement.py) ·
Tests: [`tests/test_engagement.py`](../tests/test_engagement.py) ·
Example: [`examples/engagement.yaml`](../examples/engagement.yaml)

## Purpose

The engagement file is the **safety boundary** of OP-06D. It states who
authorized the work, what may be touched, when, and how hard. Everything
downstream (the guardrail gate, the orchestrator, the report) reads from it.

The parser turns that YAML file into a validated, immutable Python object, or
refuses to. There is no partial load and no "best effort": a bad file stops the
run before any tool is invoked.

## Scope of RC-6

**In scope**

- Pydantic schema for the engagement file (authorization, scope, intensity,
  objective).
- Loading YAML safely and validating it.
- Normalizing scope entries (case, canonical IP/CIDR form) so later matching is
  unambiguous.
- Rejecting unsafe or malformed input (see [Validation rules](#validation-rules)).

**Out of scope (handled elsewhere)**

| Concern | Ticket |
|---|---|
| Deciding whether a target is in scope (`is_in_scope`), including out-of-scope precedence and wildcard matching | RC-9 |
| Checking the current time against the window, rate limiting | RC-10 |
| Audit logging of the loaded engagement | RC-11 |
| Using the engagement to drive the LLM loop | RC-7 |

The parser has no network access and does no I/O beyond reading the one file.

## Architecture

```
engagement.yaml
      |
      v
yaml.safe_load  --(not a mapping / bad YAML)-->  EngagementError
      |
      v
Engagement.model_validate  --(ValidationError)-->  EngagementError (readable, per-field)
      |
      v
Engagement  (frozen pydantic model)
  |- engagement: str
  |- authorization: Authorization   client, signed_scope_ref, authorized_by, window (UTC)
  |- scope: Scope                   in_scope, out_of_scope (normalized)
  |- intensity: Intensity           max_rps, destructive
  `- objective: str
```

Design decisions:

- **Schema-validated on load.** The config is the safety boundary, so it is
  checked structurally, not trusted.
- **Immutable models** (`frozen=True`). Nothing after load, including model
  output, can mutate scope or intensity.
- **Unknown fields are rejected** (`extra="forbid"`). A typo such as
  `out_of_scop` fails loudly instead of silently dropping an exclusion.
- **`yaml.safe_load` only**, so the file cannot construct arbitrary objects.
- **One error type.** Callers catch `EngagementError` and never see raw pydantic
  or YAML exceptions.

## Usage

Install (Python 3.11+):

```bash
pip install -e ".[dev]"
```

Load a file:

```python
from op06d.engagement import load_engagement, EngagementError

try:
    eng = load_engagement("examples/engagement.yaml")
except EngagementError as exc:
    raise SystemExit(str(exc))   # refuse to run

eng.scope.in_scope                 # ['app.acme.com', '203.0.113.0/28']
eng.scope.out_of_scope             # ['*.stripe.com', 'billing.acme.com']
eng.authorization.window           # (datetime UTC start, datetime UTC end)
eng.intensity.max_rps              # 20
```

Parse from a string (useful in tests): `parse_engagement(yaml_text)`.

Example error output:

```
engagement file failed validation:
  - scope.in_scope.0: Value error, CIDR '0.0.0.0/0' is too broad (minimum /8)
  - authorization.window: Value error, window end must be after window start
```

Run the tests:

```bash
python -m pytest
```

## File format

```yaml
engagement: acme-saas-external-2026-11     # identifier
authorization:
  client: "Acme Corp"
  signed_scope_ref: "SOW-2026-114"         # reference to the signed scope document
  authorized_by: "jane.doe@acme.com"
  window: ["2026-11-10T02:00Z", "2026-11-10T06:00Z"]   # [start, end], timezone required
scope:
  in_scope:                                # required, at least one entry
    - app.acme.com
    - 203.0.113.0/28
  out_of_scope:                            # optional
    - "*.stripe.com"
    - billing.acme.com
intensity:
  max_rps: 20                              # 1..10000
  destructive: false                       # default false
objective: "External attack surface recon"
```

Do not put secrets in this file. Use references (e.g. a vault path).

## Validation rules

| Field | Rule |
|---|---|
| Any unknown key | Rejected |
| `engagement`, `objective`, `client`, `signed_scope_ref`, `authorized_by` | Required, non-blank (whitespace is trimmed) |
| `window` | Exactly two datetimes, **timezone required**, end after start; stored in UTC |
| `scope.in_scope` | Required, at least one entry |
| Scope entries | Hostname, `*.host` wildcard, IPv4/IPv6 address, or CIDR. Lowercased; trailing dot removed; IPs and CIDRs canonicalized |
| CIDRs | Must be strict (`203.0.113.1/28` is rejected because host bits are set); IPv4 no broader than /8, IPv6 no broader than /32 |
| Wildcards | Only a leading `*.`, and at least two labels after it (`*.com` and `*` are rejected) |
| URLs, paths, spaces in entries | Rejected |
| Same entry in both `in_scope` and `out_of_scope` | Rejected |
| `max_rps` | Integer, 1 to 10000 |
| `destructive` | Boolean, defaults to `false` |

## Notes for later tickets

- **Precedence is not decided here.** The parser only rejects exact duplicates
  across the two lists. `is_in_scope()` (RC-9) must treat out-of-scope as
  winning, including wildcard and CIDR overlaps (e.g. `x.stripe.com` against
  `*.stripe.com`).
- **Time enforcement is not decided here.** `window` is parsed and normalized to
  UTC; RC-10 compares it with the current time.
- **The gate must take scope only from an `Engagement` object**, never from
  model output or tool output.
- The CIDR and wildcard breadth limits are conservative guardrails against
  typos. Adjust `_MIN_PREFIX_V4`, `_MIN_PREFIX_V6` in the module if a real
  engagement needs more.
