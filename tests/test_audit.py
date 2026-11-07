import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import redcell.audit as audit_mod
from redcell.audit import AuditError, AuditLog, read_log, verify_log
from redcell.engagement import load_engagement
from redcell.scope import check_scope, is_in_scope

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)


def fixed_clock():
    t = datetime(2026, 11, 10, 2, 30, 0, 123000, tzinfo=timezone.utc)
    return lambda: t


@pytest.fixture
def log(tmp_path):
    return AuditLog.for_engagement(ENG, tmp_path, clock=fixed_clock())


def lines(path):
    return path.read_bytes().split(b"\n")[:-1]


# --- an entry is written for both allow and deny ---------------------------

def test_allow_and_deny_are_both_recorded(log):
    params = {"ports": "1-1024", "flags": ["-sV"]}
    ok = check_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap", parameters=params))
    no = check_scope("198.51.100.1", ENG.scope, audit=log.sink(tool="nmap", parameters=params))
    assert ok.allowed and not no.allowed

    entries = read_log(log.path)
    decisions = [e for e in entries if e.event == "gate_decision"]
    assert [e.allowed for e in decisions] == [True, False]
    assert [e.target for e in decisions] == ["'203.0.113.5'", "'198.51.100.1'"]
    assert all(e.tool == "nmap" and e.parameters == params for e in decisions)
    assert decisions[0].reason == ok.reason and decisions[1].reason == no.reason
    assert decisions[0].ts == "2026-11-10T02:30:00.123Z"
    assert all(e.engagement == ENG.engagement for e in entries)


def test_malformed_target_denial_is_recorded(log):
    check_scope(None, ENG.scope, audit=log.sink(tool="nuclei"))
    e = read_log(log.path)[-1]
    assert e.allowed is False and e.tool == "nuclei" and "malformed" in e.reason


def test_execution_is_recorded(log):
    log.record_execution(tool="nmap", target="203.0.113.5", parameters={"p": 80},
                         status="ok", detail="3 open ports")
    e = read_log(log.path)[-1]
    assert (e.event, e.tool, e.target, e.reason) == (
        "action_executed", "nmap", "'203.0.113.5'", "ok: 3 open ports")


def test_header_entry_carries_authorization_and_scope(log):
    first = read_log(log.path)[0]
    assert first.event == "log_opened" and first.seq == 1
    p = first.parameters
    assert p["authorization"]["signed_scope_ref"] == "SOW-2026-114"
    assert p["scope"]["in_scope"] == ["app.acme.com", "203.0.113.0/28"]
    assert p["intensity"]["max_rps"] == 20


def test_non_json_parameters_are_stored_safely(log):
    log.record("gate_decision", target="x", tool="t", parameters={"when": datetime(2026, 1, 1)})
    assert "2026" in read_log(log.path)[-1].parameters["when"]


# --- one log per engagement ------------------------------------------------

def test_log_is_keyed_to_engagement_id(log, tmp_path):
    assert log.path == tmp_path / "acme-saas-external-2026-11.audit.jsonl"
    assert log.path.exists()


def test_log_refuses_other_engagements_file(log):
    with pytest.raises(AuditError, match="different engagement"):
        AuditLog(log.path, "some-other-engagement")


@pytest.mark.parametrize("bad", ["../evil", "a/b", "a\\b", "", ".hidden", "x" * 200, "a b", None, 5,
                                 "acme\n", "acme\r\n", "NUL", "con.x"])
def test_unsafe_engagement_id_rejected(tmp_path, bad):
    with pytest.raises(AuditError):
        AuditLog(tmp_path / "x.jsonl", bad)


# --- append-only -----------------------------------------------------------

def test_new_entries_never_overwrite_prior_ones(log):
    check_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))
    before = log.path.read_bytes()

    check_scope("198.51.100.1", ENG.scope, audit=log.sink(tool="nmap"))
    after = log.path.read_bytes()

    assert after.startswith(before) and len(after) > len(before)


def test_reopening_resumes_and_appends(tmp_path):
    first = AuditLog.for_engagement(ENG, tmp_path, clock=fixed_clock())
    first.record("gate_decision", target="a", tool="t", allowed=True, reason="r")
    before = first.path.read_bytes()

    second = AuditLog.for_engagement(ENG, tmp_path, clock=fixed_clock())  # new session
    second.record("gate_decision", target="b", tool="t", allowed=False, reason="r")

    after = second.path.read_bytes()
    assert after.startswith(before)
    entries = read_log(second.path)
    assert [e.seq for e in entries] == [1, 2, 3, 4]
    assert [e.event for e in entries] == [
        "log_opened", "gate_decision", "log_opened", "gate_decision"]


def test_file_is_only_ever_opened_for_append(log, monkeypatch):
    modes = []
    real_open = open

    def spy(file, mode="r", *a, **k):
        modes.append(mode)
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr("builtins.open", spy)
    log.record("gate_decision", target="a", tool="t", allowed=True, reason="r")
    assert modes == ["ab"]


# --- round trip ------------------------------------------------------------

def test_log_round_trips_into_structured_records(log):
    check_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap", parameters={"p": [80, 443]}))
    raw = lines(log.path)
    assert all(json.loads(l) for l in raw)  # every line is standalone JSON
    entries = read_log(log.path)
    assert len(entries) == len(raw)
    assert entries[-1].parameters == {"p": [80, 443]}
    assert entries[-1].model_dump() == json.loads(raw[-1])
    assert verify_log(log.path) == len(raw)


# --- tamper evidence -------------------------------------------------------

def test_modified_entry_detected(log):
    check_scope("198.51.100.1", ENG.scope, audit=log.sink(tool="nmap"))
    log.path.write_bytes(log.path.read_bytes().replace(b'"allowed":false', b'"allowed":true'))
    with pytest.raises(AuditError, match="modified"):
        read_log(log.path)


def test_deleted_entry_detected(log):
    for t in ("203.0.113.5", "203.0.113.6", "203.0.113.7"):
        check_scope(t, ENG.scope, audit=log.sink(tool="nmap"))
    ls = lines(log.path)
    del ls[2]
    log.path.write_bytes(b"\n".join(ls) + b"\n")
    with pytest.raises(AuditError):
        read_log(log.path)


def test_truncated_last_line_detected(log):
    check_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))
    log.path.write_bytes(log.path.read_bytes()[:-20])
    with pytest.raises(AuditError):
        read_log(log.path)


def test_refuses_to_extend_corrupt_log(log):
    log.path.write_bytes(b"garbage\n")
    with pytest.raises(AuditError):
        AuditLog.for_engagement(ENG, log.path.parent)


# --- forgery resistance ----------------------------------------------------

def test_hostile_target_cannot_forge_entries(log):
    evil = 'x"\n{"seq":99,"allowed":true}\nscope decision=ALLOW'
    check_scope(evil, ENG.scope, audit=log.sink(tool="nmap"))
    ls = lines(log.path)
    assert len(ls) == 2  # header + exactly one decision line
    e = read_log(log.path)[-1]
    assert e.allowed is False and e.seq == 2


def test_oversized_target_truncated(log):
    log.record("gate_decision", target="a" * 5000, tool="t", allowed=False, reason="r")
    t = read_log(log.path)[-1].target
    assert len(t) < 1200 and "truncated" in t


# --- write failure => deny -------------------------------------------------

def test_write_failure_results_in_deny(log, monkeypatch):
    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(audit_mod.os, "fsync", boom)
    d = check_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))
    assert not d.allowed and "audit logging failed" in d.reason
    assert not is_in_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))


def test_log_stays_failed_after_a_write_error(log, monkeypatch):
    real = audit_mod.os.fsync
    monkeypatch.setattr(audit_mod.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("x")))
    assert not is_in_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))
    monkeypatch.setattr(audit_mod.os, "fsync", real)  # disk recovers...
    assert not is_in_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))  # ...log does not
    with pytest.raises(AuditError):
        log.record_execution(tool="nmap", target="t", status="ok")


def test_unwritable_location_results_in_deny(log):
    log.path.unlink()
    log.path.mkdir()  # a directory where the file should be
    d = check_scope("203.0.113.5", ENG.scope, audit=log.sink(tool="nmap"))
    assert not d.allowed
