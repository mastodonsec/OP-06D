"""Manual smoke test for RC-6 (engagement), RC-9 (scope gate), RC-11 (audit log).

Run from the repo root:  uv run python examples/demo_gate.py
No network needed: DNS is faked.
"""
import tempfile

from op06d.audit import AuditLog, read_log, verify_log
from op06d.engagement import Scope, load_engagement
from op06d.scope import check_scope

eng = load_engagement("examples/engagement.yaml")  # RC-6

# Widen the example scope so the deny-wins cases can be shown.
scope = Scope(
    in_scope=[*eng.scope.in_scope, "*.acme.com"],
    out_of_scope=[*eng.scope.out_of_scope, "203.0.113.8/29"],
)

fake_dns = {"app.acme.com": ["198.51.100.7"], "www.acme.com": ["203.0.113.9"]}
resolver = lambda host: fake_dns[host]

cases = [
    ("203.0.113.5", "ALLOW: inside in-scope CIDR"),
    ("203.0.113.9", "DENY: in-scope CIDR but inside excluded /29 (deny wins)"),
    ("app.acme.com", "ALLOW: in-scope host, resolves to a non-excluded IP"),
    ("billing.acme.com", "DENY: matches *.acme.com but explicitly excluded"),
    ("www.acme.com", "DENY: allowed name, but resolves into the excluded /29"),
    ("evil.example.net", "DENY: not in scope"),
    ("127.1", "DENY: ambiguous IP shorthand"),
    (None, "DENY: wrong type"),
]

with tempfile.TemporaryDirectory() as tmp:
    log = AuditLog.for_engagement(eng, tmp)  # RC-11
    for target, expect in cases:
        d = check_scope(target, scope, resolver=resolver,
                        audit=log.sink(tool="demo", parameters={"note": "manual test"}))
        verdict = "ALLOW" if d.allowed else "DENY"
        ok = "ok " if expect.startswith(verdict) else "BAD"
        print(f"[{ok}] {verdict:5} {target!r:20} {d.reason}")

    entries = read_log(log.path)
    print(f"\nAudit log verified: {verify_log(log.path)} entries -> {log.path.name}")
    print("Last entry as stored:\n ", log.path.read_text(encoding="utf-8").splitlines()[-1])
