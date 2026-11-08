import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from op06d.audit import AuditLog, read_log
from op06d.engagement import (
    Authorization,
    Engagement,
    Intensity,
    load_engagement,
    parse_engagement,
)
from op06d.gate import (
    ALLOWED,
    DENIED_AUDIT,
    DENIED_LIMITS,
    DENIED_RATE,
    DENIED_SCOPE,
    DENIED_WINDOW,
    Gate,
)
from op06d.limits import RateLimiter, evaluate_window

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)  # window 2026-11-10T02:00Z .. 06:00Z, max_rps 20
START = ENG.authorization.window[0]
END = ENG.authorization.window[1]
IN_SCOPE_IP = "203.0.113.5"


class Clock:
    """Controllable wall clock and monotonic clock (no real sleeping)."""

    def __init__(self, wall: datetime = START + timedelta(hours=1), mono: float = 1000.0):
        self.wall = wall
        self.mono = mono

    def now(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, seconds: float):
        self.wall += timedelta(seconds=seconds)
        self.mono += seconds


def make_engagement(max_rps=None, window=None) -> Engagement:
    d = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    if max_rps is not None:
        d["intensity"]["max_rps"] = max_rps
    if window is not None:
        d["authorization"]["window"] = window
    return parse_engagement(yaml.safe_dump(d))


def make_gate(eng=ENG, clock=None, resolver=None):
    clock = clock or Clock()
    resolver = resolver or (lambda host: ["198.51.100.7"])
    return Gate(eng, resolver=resolver, now=clock.now, monotonic=clock.monotonic), clock


class Sink:
    def __init__(self):
        self.calls = []

    def __call__(self, target, allowed, reason):
        self.calls.append((target, allowed, reason))


def check(gate, target=IN_SCOPE_IP, sink=None):
    sink = sink or Sink()
    return gate.check(target, audit=sink), sink


# --- within rate and window -> allowed -------------------------------------

def test_action_within_rate_and_window_is_allowed():
    gate, _ = make_gate()
    d, sink = check(gate)
    assert d.allowed and d.stage == ALLOWED
    assert "within authorized window" in d.reason and "20 rps" in d.reason
    assert len(sink.calls) == 1 and sink.calls[0][1] is True  # exactly one audit call


def test_hostname_allowed_with_resolved_ips():
    gate, _ = make_gate()
    d, _ = check(gate, "app.acme.com")
    assert d.allowed and d.resolved_ips == ("198.51.100.7",)


# --- RC-23: resolve-once (one DnsPinner per Gate, i.e. per engagement) ------

def test_hostname_is_resolved_once_no_matter_how_many_actions_check_it():
    calls = []

    def counting(host):
        calls.append(host)
        return ["198.51.100.7"]

    gate, _ = make_gate(resolver=counting)
    for _ in range(5):
        d, _ = check(gate, "app.acme.com")
        assert d.allowed and d.resolved_ips == ("198.51.100.7",)
    assert calls == ["app.acme.com"]  # one real lookup for five checks


def engagement_with_out_of_scope_net(net: str) -> Engagement:
    d = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    d["scope"]["out_of_scope"].append(net)
    return parse_engagement(yaml.safe_dump(d))


def test_rebinding_after_the_first_check_never_reaches_the_tool():
    # The gate approved 198.51.100.7 on the first check. If DNS for the same
    # hostname were to change afterwards - attacker rebinding, a short-TTL
    # failover, ordinary drift - the pin must mean the gate (and therefore
    # every tool it approves a scan for) keeps using the FIRST address, not
    # whatever a later lookup would return.
    eng = engagement_with_out_of_scope_net("198.51.100.96/28")  # covers .99
    answers = iter([["198.51.100.7"], ["198.51.100.99"]])  # second is out of scope
    gate, _ = make_gate(eng, resolver=lambda h: next(answers))
    first, _ = check(gate, "app.acme.com")
    second, _ = check(gate, "app.acme.com")
    assert first.allowed and first.resolved_ips == ("198.51.100.7",)
    assert second.allowed and second.resolved_ips == ("198.51.100.7",)  # pin held
    # proof the pin (not luck) is why: a gate that resolved to 198.51.100.99
    # from the very first check denies it (it matches an out-of-scope net).
    fresh_gate, _ = make_gate(eng, resolver=lambda h: ["198.51.100.99"])
    assert not check(fresh_gate, "app.acme.com")[0].allowed


def test_dns_pin_is_audited_once_per_hostname(tmp_path):
    log = AuditLog.for_engagement(ENG, tmp_path)
    gate = Gate(ENG, resolver=lambda h: ["198.51.100.7"], audit_pin=log.record_dns_pin,
                now=lambda: START + timedelta(hours=1))
    for _ in range(3):
        gate.check("app.acme.com", audit=log.sink(tool="nmap"))
    pins = [e for e in read_log(log.path) if e.event == "dns_pinned"]
    assert len(pins) == 1  # pinned once, not once per check
    assert pins[0].target == repr("app.acme.com")
    assert pins[0].parameters["resolved_ips"] == ["198.51.100.7"]


def test_dns_pin_audit_failure_denies_the_check(tmp_path):
    def boom(hostname, ips):
        raise OSError("disk full")

    gate = Gate(ENG, resolver=lambda h: ["198.51.100.7"], audit_pin=boom,
                now=lambda: START + timedelta(hours=1))
    d, sink = check(gate, "app.acme.com")
    assert not d.allowed and d.stage == DENIED_SCOPE and "resolution failed" in d.reason


# --- rate cap ---------------------------------------------------------------

def test_burst_above_max_rps_is_blocked():
    gate, _ = make_gate()
    results = [check(gate)[0] for _ in range(25)]
    assert [r.allowed for r in results] == [True] * 20 + [False] * 5
    blocked = results[-1]
    assert blocked.stage == DENIED_RATE and "20 rps" in blocked.reason
    assert blocked.retry_after == pytest.approx(1.0)


def test_capacity_returns_after_one_second():
    gate, clock = make_gate()
    for _ in range(20):
        assert check(gate)[0].allowed
    assert not check(gate)[0].allowed
    clock.advance(0.999)
    assert not check(gate)[0].allowed
    clock.advance(0.001)  # exactly 1.0s after the first batch
    assert check(gate)[0].allowed


def test_cap_holds_over_any_rolling_second():
    gate, clock = make_gate(make_engagement(max_rps=4))
    admitted = []
    for _ in range(40):  # one attempt every 0.1s for 4s
        admitted.append(clock.mono if check(gate)[0].allowed else None)
        clock.advance(0.1)
    times = [t for t in admitted if t is not None]
    for t in times:
        assert sum(1 for u in times if t <= u < t + 1.0) <= 4


def test_retry_after_reports_wait_for_oldest_slot():
    gate, clock = make_gate(make_engagement(max_rps=2))
    check(gate)
    clock.advance(0.25)
    check(gate)
    clock.advance(0.25)
    d, _ = check(gate)
    assert not d.allowed and d.retry_after == pytest.approx(0.5)


def test_limit_comes_from_engagement_not_hardcoded():
    for rps in (1, 3, 50):
        gate, _ = make_gate(make_engagement(max_rps=rps))
        allowed = sum(check(gate)[0].allowed for _ in range(rps + 10))
        assert allowed == rps


def test_refused_actions_do_not_consume_rate_capacity():
    gate, _ = make_gate(make_engagement(max_rps=2))
    for _ in range(100):
        assert check(gate, "198.51.100.99")[0].stage == DENIED_SCOPE  # out of scope
    assert check(gate)[0].allowed and check(gate)[0].allowed


def test_rate_limiter_is_thread_safe():
    clock = Clock()
    limiter = RateLimiter(20, clock.monotonic)
    results = []

    def worker():
        for _ in range(10):
            results.append(limiter.try_acquire()[0])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(results) == 20 and len(results) == 80


def test_rate_limiter_clock_going_backwards_fails_closed():
    clock = Clock()
    limiter = RateLimiter(5, clock.monotonic)
    assert limiter.try_acquire()[0]
    clock.mono -= 10
    assert not limiter.try_acquire()[0]


# --- time window ------------------------------------------------------------

def test_before_and_after_window_denied():
    gate, clock = make_gate()
    clock.wall = START - timedelta(hours=1)
    d, _ = check(gate)
    assert not d.allowed and d.stage == DENIED_WINDOW and "before start" in d.reason
    clock.wall = END + timedelta(hours=1)
    d, _ = check(gate)
    assert not d.allowed and d.stage == DENIED_WINDOW and "at or after end" in d.reason


def test_window_denial_skips_scope_and_dns_and_rate():
    def no_dns(host):
        raise AssertionError("DNS must not run outside the window")

    gate, clock = make_gate(make_engagement(max_rps=1), resolver=no_dns)
    clock.wall = END + timedelta(minutes=1)
    assert check(gate, "app.acme.com")[0].stage == DENIED_WINDOW
    clock.wall = START + timedelta(minutes=1)
    assert check(gate)[0].allowed  # the single rate slot was never used


# --- boundary: window is [start, end) ---------------------------------------

@pytest.mark.parametrize(
    "offset_from, delta, expected",
    [
        ("start", timedelta(0), True),  # exactly start: allowed (inclusive)
        ("start", -timedelta(microseconds=1), False),  # just before start
        ("end", -timedelta(microseconds=1), True),  # just before end
        ("end", timedelta(0), False),  # exactly end: denied (exclusive)
        ("end", timedelta(microseconds=1), False),
    ],
)
def test_window_boundaries(offset_from, delta, expected):
    gate, clock = make_gate()
    clock.wall = (START if offset_from == "start" else END) + delta
    d, _ = check(gate)
    assert d.allowed is expected
    if not expected:
        assert d.stage == DENIED_WINDOW


# --- timezone handling ------------------------------------------------------

def test_window_honors_offsets_in_file_and_clock():
    # 03:00+01:00 == 02:00Z ; RC-6 normalized this to UTC
    eng = make_engagement(window=["2026-11-10T03:00+01:00", "2026-11-10T07:00+01:00"])
    assert eng.authorization.window[0] == START
    gate, clock = make_gate(eng)
    pst = timezone(timedelta(hours=-8))
    clock.wall = datetime(2026, 11, 9, 18, 0, tzinfo=pst)  # == 02:00Z, the start
    assert check(gate)[0].allowed
    clock.wall = datetime(2026, 11, 9, 17, 59, 59, tzinfo=pst)  # 1s before
    assert not check(gate)[0].allowed
    clock.wall = datetime(2026, 11, 10, 2, 0, tzinfo=pst)  # 10:00Z: after the end
    assert not check(gate)[0].allowed


def test_naive_or_broken_clock_denies():
    gate, clock = make_gate()
    clock.wall = datetime(2026, 11, 10, 3, 0)  # naive
    d, _ = check(gate)
    assert not d.allowed and d.stage == DENIED_WINDOW

    def boom():
        raise RuntimeError("clock")

    gate = Gate(ENG, resolver=lambda h: ["198.51.100.7"], now=boom)
    d, _ = check(gate)
    assert not d.allowed and "clock failed" in d.reason


@pytest.mark.parametrize("now", [None, "2026-11-10T03:00Z", 1.0, START.replace(tzinfo=None)])
def test_evaluate_window_rejects_bad_now(now):
    assert not evaluate_window((START, END), now)[0]


# --- malformed window or rate fails closed ----------------------------------

def broken(window=None, max_rps=20, use_window=True):
    auth = Authorization.model_construct(
        client="c", signed_scope_ref="r", authorized_by="a",
        window=window if use_window else None,
    )
    return Engagement.model_construct(
        engagement="x", authorization=auth, scope=ENG.scope,
        intensity=Intensity.model_construct(max_rps=max_rps, destructive=False),
        objective="o",
    )


NAIVE = datetime(2026, 11, 10, 2, 0)


@pytest.mark.parametrize(
    "eng",
    [
        broken(window=None),
        broken(window=(START,)),
        broken(window=(END, START)),  # reversed
        broken(window=(START, START)),  # empty
        broken(window=(NAIVE, NAIVE + timedelta(hours=1))),  # no timezone
        broken(window=("2026-11-10T02:00Z", "2026-11-10T06:00Z")),  # strings
        broken(window=(START, END), max_rps=0),
        broken(window=(START, END), max_rps=-5),
        broken(window=(START, END), max_rps=None),
        broken(window=(START, END), max_rps="20"),
        broken(window=(START, END), max_rps=True),
        broken(window=(START, END), max_rps=1.5),
        None,
        "engagement",
        {},
    ],
)
def test_malformed_config_denies_everything(eng):
    gate, _ = make_gate(eng)
    for target in (IN_SCOPE_IP, "app.acme.com"):
        d, sink = check(gate, target)
        assert not d.allowed and d.stage == DENIED_LIMITS
        assert "unusable" in d.reason
        assert len(sink.calls) == 1 and sink.calls[0][1] is False


# --- scope is still enforced through the gate -------------------------------

def test_scope_denial_through_gate():
    gate, _ = make_gate()
    d, sink = check(gate, "evil.example.net")
    assert not d.allowed and d.stage == DENIED_SCOPE
    d, _ = check(gate, "203.0.113.0/28")
    assert d.allowed  # whole in-scope CIDR
    assert not check(gate, None)[0].allowed


# --- every decision is audited, via the RC-11 log ---------------------------

def test_denials_and_allows_are_recorded_in_the_audit_log(tmp_path):
    clock = Clock()
    log = AuditLog.for_engagement(ENG, tmp_path)
    gate, _ = make_gate(make_engagement(max_rps=1), clock=clock)
    sink = lambda: log.sink(tool="nmap", parameters={"ports": "80"})

    gate.check(IN_SCOPE_IP, audit=sink())  # allow
    gate.check(IN_SCOPE_IP, audit=sink())  # rate block
    gate.check("198.51.100.99", audit=sink())  # scope deny
    clock.wall = END + timedelta(seconds=1)
    gate.check(IN_SCOPE_IP, audit=sink())  # window deny

    entries = [e for e in read_log(log.path) if e.event == "gate_decision"]
    assert [e.allowed for e in entries] == [True, False, False, False]
    assert "within authorized window" in entries[0].reason
    assert "rate cap" in entries[1].reason
    assert "no in-scope network" in entries[2].reason
    assert "outside authorized window" in entries[3].reason
    assert all(e.tool == "nmap" and e.parameters == {"ports": "80"} for e in entries)
    assert all(e.engagement == ENG.engagement for e in entries)


def test_exactly_one_audit_entry_per_check(tmp_path):
    log = AuditLog.for_engagement(ENG, tmp_path)
    gate, _ = make_gate()
    before = len(read_log(log.path))
    gate.check("app.acme.com", audit=log.sink(tool="nuclei"))
    assert len(read_log(log.path)) == before + 1


def test_misconfigured_engagement_denial_is_audited(tmp_path):
    log = AuditLog.for_engagement(ENG, tmp_path)
    gate, _ = make_gate(broken(window=None))
    gate.check(IN_SCOPE_IP, audit=log.sink(tool="nmap"))
    last = read_log(log.path)[-1]
    assert last.allowed is False and "unusable" in last.reason


@pytest.mark.parametrize("scenario", ["allow", "rate", "window"])
def test_audit_failure_denies(scenario):
    def broken_sink(target, allowed, reason):
        raise OSError("disk full")

    gate, clock = make_gate(make_engagement(max_rps=1))
    if scenario == "rate":
        check(gate)
    if scenario == "window":
        clock.wall = END
    d = gate.check(IN_SCOPE_IP, audit=broken_sink)
    assert not d.allowed and d.stage == DENIED_AUDIT


def test_gate_check_never_raises():
    gate, _ = make_gate()
    for target in (None, object(), 5, b"x", [], "\x00"):
        assert not check(gate, target)[0].allowed
