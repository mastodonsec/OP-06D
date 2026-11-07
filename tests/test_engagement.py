from pathlib import Path

import pytest
import yaml

from redcell.engagement import EngagementError, load_engagement, parse_engagement

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"


def base() -> dict:
    return yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))


def parse(d: dict):
    return parse_engagement(yaml.safe_dump(d))


def test_example_loads():
    e = load_engagement(EXAMPLE)
    assert e.engagement == "acme-saas-external-2026-11"
    assert e.scope.in_scope == ["app.acme.com", "203.0.113.0/28"]
    assert e.scope.out_of_scope == ["*.stripe.com", "billing.acme.com"]
    assert e.authorization.window[0].utcoffset().total_seconds() == 0
    assert e.intensity.destructive is False


def test_models_are_immutable():
    e = load_engagement(EXAMPLE)
    with pytest.raises(Exception):
        e.intensity.max_rps = 9999


def test_missing_file():
    with pytest.raises(EngagementError):
        load_engagement("nope.yaml")


@pytest.mark.parametrize("text", ["", "- a\n- b", "just a string", "a: [unclosed"])
def test_non_mapping_or_bad_yaml(text):
    with pytest.raises(EngagementError):
        parse_engagement(text)


@pytest.mark.parametrize(
    "key", ["engagement", "authorization", "scope", "intensity", "objective"]
)
def test_missing_top_level(key):
    d = base()
    del d[key]
    with pytest.raises(EngagementError, match=key):
        parse(d)


def test_unknown_field_rejected():
    d = base()
    d["scope"]["out_of_scop"] = ["x.com"]
    with pytest.raises(EngagementError, match="out_of_scop"):
        parse(d)


def test_empty_in_scope_rejected():
    d = base()
    d["scope"]["in_scope"] = []
    with pytest.raises(EngagementError):
        parse(d)


def test_out_of_scope_optional():
    d = base()
    del d["scope"]["out_of_scope"]
    assert parse(d).scope.out_of_scope == []


@pytest.mark.parametrize(
    "bad",
    [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "::/0",
        "203.0.113.1/28",
        "*.com",
        "*",
        "not a host",
        "http://app.acme.com",
        "app.acme.com/path",
        "-bad.example.com",
        "",
        "999.1.1.1/24",
    ],
)
def test_bad_scope_entries(bad):
    d = base()
    d["scope"]["in_scope"] = [bad]
    with pytest.raises(EngagementError):
        parse(d)


def test_scope_normalized():
    d = base()
    d["scope"]["in_scope"] = ["App.ACME.com.", "2001:DB8::1", " 10.1.2.0/24 "]
    assert parse(d).scope.in_scope == ["app.acme.com", "2001:db8::1", "10.1.2.0/24"]


def test_overlap_rejected():
    d = base()
    d["scope"]["out_of_scope"] = ["APP.acme.com"]
    with pytest.raises(EngagementError, match="both"):
        parse(d)


def test_window_requires_timezone():
    d = base()
    d["authorization"]["window"] = ["2026-11-10T02:00:00", "2026-11-10T06:00:00"]
    with pytest.raises(EngagementError, match="timezone"):
        parse(d)


def test_window_end_before_start():
    d = base()
    d["authorization"]["window"] = ["2026-11-10T06:00Z", "2026-11-10T02:00Z"]
    with pytest.raises(EngagementError, match="after"):
        parse(d)


def test_window_offsets_normalized_to_utc():
    d = base()
    d["authorization"]["window"] = ["2026-11-10T03:00+01:00", "2026-11-10T07:00+01:00"]
    start, end = parse(d).authorization.window
    assert start.hour == 2 and end.hour == 6


@pytest.mark.parametrize("rps", [0, -1, 10_001, "fast"])
def test_bad_rps(rps):
    d = base()
    d["intensity"]["max_rps"] = rps
    with pytest.raises(EngagementError):
        parse(d)


def test_destructive_defaults_false():
    d = base()
    del d["intensity"]["destructive"]
    assert parse(d).intensity.destructive is False


@pytest.mark.parametrize("field", ["client", "signed_scope_ref", "authorized_by"])
def test_blank_authorization_fields(field):
    d = base()
    d["authorization"][field] = "  "
    with pytest.raises(EngagementError, match=field):
        parse(d)


# --- engagement id (RC-22) -------------------------------------------------
# The id becomes "<id>.audit.jsonl", so the schema is the authoritative check;
# AuditLog re-checks it with the same shared rule as a second line of defense.

BAD_IDS = [
    "../x", "../../etc/passwd", "a/b", "a\b", ".hidden", ".", "..", "-lead", "_lead",
    "a b", "acme\nx", "acme\tx", "x" * 129, "id\x00", "acme∕x", "acme⁄x",
    "acme／x", "аcme", "acme:x", "acme*", "CON", "con", "nul", "Prn", "AUX",
    "COM1", "lpt9", "COM0", "NUL.txt", "con.audit",
]
GOOD_IDS = [
    "a", "x" * 128, "acme-saas-external-2026-11", "A.b_c-1", "rc-lab-2026-11",
    "cli-test-2026-11", "9", "a.", "CONSOLE", "nulx", "com10", "lpt", "x.nul", "acme-con",
]


def _with_id(eid) -> dict:
    d = base()
    d["engagement"] = eid
    return d


@pytest.mark.parametrize("bad", BAD_IDS)
def test_malicious_engagement_id_rejected_at_schema(bad):
    with pytest.raises(EngagementError, match="engagement id must be") as exc:
        parse(_with_id(bad))
    assert "engagement" in str(exc.value)


@pytest.mark.parametrize("good", GOOD_IDS)
def test_valid_engagement_id_accepted(good):
    assert parse(_with_id(good)).engagement == good


def test_engagement_id_outer_whitespace_stripped():
    # Deliberate: NonEmptyStr strips, and the check runs on the stripped value.
    assert parse(_with_id("  acme \n")).engagement == "acme"


@pytest.mark.parametrize("bad", ["", "   "])
def test_blank_engagement_id_rejected(bad):
    with pytest.raises(EngagementError, match="engagement"):
        parse(_with_id(bad))


def test_engagement_id_uses_fullmatch_not_dollar():
    from redcell.engagement import ENGAGEMENT_ID_RE, is_valid_engagement_id

    assert ENGAGEMENT_ID_RE.match("acme\n")  # a raw match() would let this in...
    assert not is_valid_engagement_id("acme\n")  # ...the shared check does not


@pytest.mark.parametrize("eid", BAD_IDS + GOOD_IDS + ["acme\n", "acme\r\n", " acme"])
def test_schema_and_audit_layers_agree(eid, tmp_path):
    """The RC-6 schema and the RC-11 AuditLog must accept exactly the same ids
    (for the value the schema stores, i.e. after outer-whitespace stripping)."""
    from redcell.audit import AuditError, AuditLog

    try:
        stored = parse(_with_id(eid)).engagement
        schema_ok = True
    except EngagementError:
        stored, schema_ok = eid.strip(), False
    try:
        AuditLog(tmp_path / "x.jsonl", stored)
        audit_ok = True
    except AuditError:
        audit_ok = False
    assert schema_ok == audit_ok
