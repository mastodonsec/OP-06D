# Gate: rate cap and time window (RC-10)

Modules: [`src/redcell/gate.py`](../src/redcell/gate.py) ·
[`src/redcell/limits.py`](../src/redcell/limits.py) ·
Tests: [`tests/test_gate.py`](../tests/test_gate.py)

## Purpose

RC-9 enforces **where** the tool may act. RC-10 adds **when** (the authorized
window) and **how fast** (`max_rps`). Both limits come from the validated RC-6
engagement file; nothing is hard-coded. The model is asked; the gate decides.

## Scope of RC-10

**In scope:** window check, rate limiter, the `Gate` that combines window,
scope and rate into one decision with one audit entry, tests.

**Not here:**

| Concern | Ticket |
|---|---|
| Making every tool call go through `Gate.check` (no bypass) | RC-7 |
| Passing `max_rps` to the tools themselves (e.g. nmap `--max-rate`) | RC-13, RC-14 |
| Output sanitization | RC-12 |

## Architecture

```
Gate.check(target, audit=sink)
   |
   |- engagement window/rate usable?   no -> DENY (stage "limits")
   |- window: now in [start, end)?     no -> DENY (stage "window")   no DNS, no rate used
   |- scope:  check_scope (RC-9)       no -> DENY (stage "scope")    no rate used
   |- rate:   RateLimiter.try_acquire  no -> DENY (stage "rate")     retry_after set
   v
GateDecision(target, allowed, reason, stage, resolved_ips, retry_after)
   |
   `- exactly one audit(target, allowed, reason) call (RC-11 sink); failure -> DENY (stage "audit")
```

- **Order:** cheapest and most fundamental first, side effects last. Outside the
  window nothing else is evaluated (no DNS). Rate is consumed last, so refused
  actions never spend capacity.
- **One audit entry per check**, written through the existing
  `AuditSink(target, allowed, reason)`; there is no second logging path. The
  gate passes `check_scope` a no-op sink and writes the final decision itself,
  so an action does not produce a scope "allow" followed by a rate "deny".
- The audit event name is `gate_decision` (previously `scope_decision`), since
  the sink now records window and rate decisions too.
- `Gate.check` never raises. Any unexpected error is a deny.

## Resolve-once (RC-23)

**The gap this closes.** The gate used to resolve a hostname to decide scope,
and the tool (nmap/nuclei) re-resolved the same hostname independently when it
ran. If DNS changed in between - attacker-controlled rebinding, a short-TTL
failover, ordinary drift - the tool could scan an address the gate never saw,
let alone approved: a time-of-check/time-of-use bypass of the scope control.

**The fix.** Each `Gate` owns one `DnsPinner` ([`src/redcell/resolve.py`](../src/redcell/resolve.py))
for its whole life - one `Gate` per engagement run, so one pinner per
engagement. The first scope check of a hostname resolves and pins it; every
later check of that same hostname, no matter how much later or how many other
actions ran in between, reuses the identical address(es) without touching DNS
again. `nmap_tool.py`/`nuclei_tool.py` never resolve anything themselves -
`resolve.py` is the only place in Red Cell DNS happens.

`GateDecision.resolved_ips` carries the pinned address(es); `GatedToolbox`
(RC-7/RC-13/RC-14) hands the tool that address to scan, not the hostname -
see [`tools.py`](../src/redcell/tools.py), `__execute`. A multi-address
hostname where *any* address is out of scope denies the whole action (no
"scan the in-scope subset" fallback); a resolution failure denies, fail-closed,
same as any other scope error.

Pass `audit_pin` to record each hostname's first (and only) pin as a
`dns_pinned` audit entry - `AuditLog.record_dns_pin` matches the shape `Gate`
expects, so it is normally wired straight through:

```python
gate = Gate(eng, audit_pin=log.record_dns_pin)
```

If `audit_pin` raises (e.g. the audit log has already failed), that failure
propagates out of the resolution as "resolution failed", so an unrecorded pin
denies the action instead of silently proceeding - the same fail-closed
guarantee the rest of the gate already gives every other audit write.

## Window semantics

The authorized window is the half-open interval **[start, end)**.

| Moment | Result |
|---|---|
| `start - 1µs` | denied |
| exactly `start` | **allowed** |
| `end - 1µs` | allowed |
| exactly `end` | **denied** |

Exclusive end is the conservative side: the instant the booking ends, the tool
is out of bounds.

Times are compared as timezone-aware instants. RC-6 already normalized the file's
window to UTC, and the clock may use any offset. A naive clock value, a clock
that raises, or a non-datetime result denies.

## Rate semantics

A sliding one-second log: at most `max_rps` actions are admitted in **any**
rolling one-second period. An action admitted at `t` stops counting at exactly
`t + 1s`.

- **Blocked, not delayed.** Over-cap actions are denied immediately with a
  `retry_after` (seconds until the oldest slot frees). The orchestrator decides
  whether to wait and retry; the gate never sleeps.
- Blocked actions do not consume capacity.
- The limiter uses a monotonic clock, so wall-clock changes cannot grant extra
  budget. A clock that goes backwards is treated as a deny.
- The cap is engagement-wide: one budget across all tools and targets.
- Thread-safe.

## Fail closed

If the engagement's window or `max_rps` is missing or malformed, **every**
`check` is denied with `deny: engagement window/rate unusable (...)` and the
reason is audited. Malformed means: window not a pair, naive or non-datetime
times, end not after start, `max_rps` not a positive integer (booleans, floats,
strings, `None`, 0 and negatives are rejected), or an object that is not an
`Engagement`. RC-6 already rejects these at load; the gate re-checks so a
bypassed or hand-built model cannot open it.

## Usage

```python
from redcell.audit import AuditLog
from redcell.engagement import load_engagement
from redcell.gate import Gate

eng = load_engagement("examples/engagement.yaml")
log = AuditLog.for_engagement(eng, "logs/")
gate = Gate(eng, audit_pin=log.record_dns_pin)   # one Gate per engagement; holds rate state + DNS pins

d = gate.check("203.0.113.5", audit=log.sink(tool="nmap", parameters={"ports": "1-1024"}))
if d.allowed:
    ...                               # run the tool, then log.record_execution(...)
elif d.stage == "rate":
    wait(d.retry_after)               # then try again
else:
    ...                               # window / scope / limits / audit: do not retry blindly
```

Testing with controllable time (no sleeping):

```python
Gate(eng, now=lambda: some_aware_datetime, monotonic=lambda: some_float,
     resolver=lambda host: ["198.51.100.7"])
```

Run the tests:

```bash
uv run --extra dev pytest tests/test_gate.py
```

## Known limits

- **One action = one request.** The gate counts each approved action once. A
  tool such as nmap sends many packets per action, so tools must also be given
  `max_rps` (RC-13, RC-14). Otherwise the cap limits how often scans start, not
  packets per second. A `cost` parameter could be added if needed.
- Gate state is in memory: restarting the process resets the rate history.
- The window is checked at decision time. A long-running action started just
  before `end` is not interrupted; RC-7 should cancel running actions at the end
  of the window.
- Single process; no cross-process rate sharing.
