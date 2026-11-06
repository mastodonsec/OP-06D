# Scope allowlist enforcement (RC-9)

Module: [`src/redcell/scope.py`](../src/redcell/scope.py) ·
Audit stub: [`src/redcell/audit.py`](../src/redcell/audit.py) ·
Tests: [`tests/test_scope.py`](../tests/test_scope.py)

## Purpose

Answers one question: **may we touch this target?** The LLM is asked; this code
decides. It reads the validated scope from the RC-6 engagement model
([engagement-parser.md](engagement-parser.md)) and nothing the model or a tool
outputs can change the answer.

Design rules (non-negotiable):

| Rule | Behavior |
|---|---|
| Deny wins | A match against any out-of-scope entry is a deny, even if an in-scope entry also matches |
| Fail closed | No in-scope entries, or a missing/invalid scope, denies everything |
| Default deny | Malformed target, unexpected type, DNS failure, bad resolver answer, audit failure: deny |
| Host and IP | A hostname is checked against host scope and every address it resolves to is checked against IP scope |

## Scope of RC-9

**In scope:** the decision function, hostname resolution step, audit call, tests.

**Not here:**

| Concern | Ticket |
|---|---|
| Making every tool call pass through this function (no bypass path) | RC-7 |
| Time window and rate cap | RC-10 |
| The real audit log (replaces the stub) | RC-11 |
| Sanitizing tool output | RC-12 |

This function protects the tool only if it is the **only door**. A scope check
that some code paths skip is worse than none.

## Architecture

```
target + Scope (RC-6)
        |
        v
evaluate_scope()            pure, never raises, no I/O
   |- scope valid? in-scope non-empty?          else DENY
   |- target parses? (host | IP | CIDR)         else DENY
   |- hostname: out-of-scope name? -> DENY; in-scope name? else DENY
   |       passed -> provisional deny, needs_resolution=True
   v
check_scope()               the only side effects
   |- resolver(host)  (only for hostnames that passed the name checks)
   |- evaluate_scope(target, scope, resolved_ips)   final decision
   |- audit(target, allowed, reason)                fails -> DENY
   v
ScopeDecision(target, allowed, reason, resolved_ips)
```

- `evaluate_scope(target, scope, resolved_ips=None) -> ScopeDecision`: pure and
  exhaustively unit-testable. Any unexpected exception becomes a deny.
- `check_scope(target, scope, *, resolver, audit) -> ScopeDecision`: resolves,
  decides, audits. Use this when you need the reason.
- `is_in_scope(target, scope, *, resolver, audit) -> bool`: convenience wrapper.
- `resolver` and `audit` are injectable, so tests need no network.
- Names that are out of scope are denied **before** any DNS query is made.

## Matching rules

**Targets accepted:** hostname, IP address, or CIDR network. Wildcards, URLs,
ports, paths, whitespace and non-strings are rejected.

| Target | Allowed when |
|---|---|
| IP | Inside an in-scope network and inside no out-of-scope network. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is treated as IPv4 |
| CIDR | Wholly inside one in-scope network and overlapping no out-of-scope network |
| Hostname | Matches an in-scope host entry, matches no out-of-scope host entry, resolves to at least one address, and **no** resolved address is inside an out-of-scope network |

Hostname entry semantics:

- `app.acme.com`: exact match only. It does **not** cover subdomains.
- `*.acme.com`: any subdomain (one or more labels). It does **not** cover
  `acme.com` itself.
- A hostname never becomes in scope merely because it resolves into an in-scope
  CIDR; it needs a matching host entry.
- Resolved addresses must be *not out-of-scope*; they are not required to fall
  inside in-scope CIDRs (otherwise anything behind a CDN or cloud would be
  blocked). If you want the stricter rule, it is a small change in
  `_evaluate`.

Ambiguous targets are denied, for example `127.1`, `2130706433`, `0x7f.0.0.1`,
`010.0.0.1` (resolvers silently expand these), and an IP with a trailing dot.

## Usage

```python
from redcell.engagement import load_engagement
from redcell.scope import check_scope, is_in_scope

eng = load_engagement("examples/engagement.yaml")

is_in_scope("203.0.113.5", eng.scope)        # True
is_in_scope("203.0.113.0/30", eng.scope)     # True  (wholly inside 203.0.113.0/28)
is_in_scope("billing.acme.com", eng.scope)   # False (deny wins)
is_in_scope(None, eng.scope)                 # False (default deny)

d = check_scope("app.acme.com", eng.scope)   # resolves via the OS resolver
print(d.allowed, d.reason, d.resolved_ips)
```

Inject a resolver in tests or offline use:

```python
check_scope("app.acme.com", eng.scope, resolver=lambda host: ["198.51.100.7"])
```

Run the tests:

```bash
uv run --extra dev pytest tests/test_scope.py
```

## Audit sink (RC-11)

The scope code depends only on `AuditSink = Callable[[str, bool, str], None]`
and takes it as the **required** keyword argument `audit=` (there is no
unaudited path). The real implementation is `AuditLog` in
[`src/redcell/audit.py`](../src/redcell/audit.py):

```python
log = AuditLog.for_engagement(eng, "logs/")
check_scope(target, eng.scope, audit=log.sink(tool="nmap", parameters={"ports": "1-1024"}))
```

If the sink raises, the decision becomes a **deny**: an action that cannot be
recorded must not proceed.

## Known limits

- ~~DNS answers can change between the check and the tool's own lookup
  (rebinding, round-robin).~~ **Fixed by RC-23.** `check_scope`/`evaluate_scope`
  here are unchanged (still pure, still take `resolved_ips` as given), but
  the one production caller, `Gate`, no longer calls a fresh resolver per
  check - it resolves each hostname once per engagement and reuses that pin
  for every later check, and `GatedToolbox` scans that pinned address, never
  the hostname. See [`resolve.py`](../src/redcell/resolve.py) and
  [gate-rate-and-window.md](gate-rate-and-window.md#resolve-once-rc-23).
- `system_resolver` ([`resolve.py`](../src/redcell/resolve.py), re-exported
  here for compatibility) uses the OS resolver with no timeout control.
- Redirects, CNAME chains and URLs returned by tools are new targets and must
  go through the gate again.
