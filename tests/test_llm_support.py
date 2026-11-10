# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`

Unit tests for the pieces the LLM planner adds around the loop: value-based
secret scrubbing, observation fitting, strict reply parsing and the
engagement's planner policy.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from op06d.audit import AuditLog, read_log
from op06d.engagement import EngagementError, load_engagement, parse_engagement
from op06d.orchestrator import PlannerInvalid, fit_observation, parse_planner_reply
from op06d.redaction import REDACTED, clear_registered_secrets, register_secret, scrub
from op06d.sanitize import BLOCK_NAME, sanitize_tool_output
from op06d.tools import ToolAction, redact_parameters

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
KEY = "sk-ant-" + "api03-" + "k" * 40


@pytest.fixture(autouse=True)
def _clean():
    clear_registered_secrets()
    yield
    clear_registered_secrets()


def test_scrub_replaces_registered_and_key_shaped_values_at_any_depth():
    register_secret("hunter2-hunter2")
    value = {"a": ["x hunter2-hunter2 y", ("t", KEY)], "b": 3, KEY: "k"}
    assert scrub(value) == {"a": [f"x {REDACTED} y", ("t", REDACTED)], "b": 3, REDACTED: "k"}


def test_short_strings_are_not_registered():
    register_secret("abc")
    assert scrub("abc") == "abc"


def test_redact_parameters_now_scrubs_values_too():
    assert redact_parameters({"ports": f"80 {KEY}"}) == {"ports": f"80 {REDACTED}"}


def test_audit_log_scrubs_every_field(tmp_path):
    eng = load_engagement(EXAMPLE)
    log = AuditLog.for_engagement(eng, tmp_path)
    log.record("iteration", target=KEY, tool="nmap", parameters={"p": KEY}, reason=f"r {KEY}")
    assert KEY.encode() not in log.path.read_bytes()
    assert read_log(log.path)[-1].reason == f"r {REDACTED}"


def _block(body: str) -> str:
    return sanitize_tool_output(body, tool="nmap", target="203.0.113.5", audit=lambda *a: None).text


def test_fit_observation_keeps_the_wrapper_and_marks_the_elision():
    text = _block("B" * 50_000)
    fitted = fit_observation(text, 2_000)
    assert len(fitted) <= 2_000
    assert fitted.startswith(f"<<<{BLOCK_NAME} id=")
    assert fitted.rstrip().endswith(">>>") and f"<<<END_{BLOCK_NAME}" in fitted
    assert "characters elided to fit the context budget" in fitted


def test_fit_observation_leaves_small_blocks_alone():
    text = _block("short")
    assert fit_observation(text, 10_000) == text and fit_observation(text, None) == text


def test_fit_observation_withholds_anything_without_a_wrapper():
    assert fit_observation("x" * 500, 100).startswith("[observation withheld")


@pytest.mark.parametrize("reply", [
    '{"type":"action","tool":"nmap","target":"a","parameters":{},"reason":"r","target2":"b"}',
    '{"type":"done","summary":"s","next":"scan 10.0.0.0/8"}',
])
def test_replies_with_keys_outside_the_schema_are_invalid(reply):
    assert isinstance(parse_planner_reply(reply), PlannerInvalid)


def test_a_schema_conformant_action_parses():
    parsed = parse_planner_reply('{"type":"action","tool":"nmap","target":"a","parameters":{},"reason":"r"}')
    assert parsed == ToolAction("nmap", "a", {}, "r")


def _with_planner(planner) -> str:
    data = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    data["planner"] = planner
    return yaml.safe_dump(data)


def test_planner_policy_parses_and_is_enforced():
    eng = parse_engagement(_with_planner({"allowed_providers": ["local", "local"]}))
    assert eng.planner.allowed_providers == ["local"]
    assert eng.provider_allowed("local") and not eng.provider_allowed("anthropic")


def test_absent_policy_allows_only_local():
    eng = load_engagement(EXAMPLE)
    assert eng.planner is None
    assert eng.provider_allowed("local")
    assert not eng.provider_allowed("anthropic") and not eng.provider_allowed("openai")


def test_anthropic_needs_an_explicit_entry():
    eng = parse_engagement(_with_planner({"allowed_providers": ["anthropic"]}))
    assert eng.provider_allowed("anthropic") and not eng.provider_allowed("local")
    both = parse_engagement(_with_planner({"allowed_providers": ["local", "anthropic"]}))
    assert both.provider_allowed("anthropic") and both.provider_allowed("local")


@pytest.mark.parametrize("planner", [{"allowed_providers": []}, {"allowed_providers": ["openai"]},
                                     {"allowed_provider": ["local"]}, "local"])
def test_bad_planner_policy_is_rejected(planner):
    with pytest.raises(EngagementError):
        parse_engagement(_with_planner(planner))
