# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`

Unit tests for the production model adapters in ``op06d.llm``: endpoint
policy, constrained-output request shapes, retry/backoff and key handling.
No network: every call goes through an injected transport or fake client.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from op06d.llm import (
    AnthropicLLM,
    LLMConfigError,
    LLMRefused,
    LLMSettings,
    LLMUnavailable,
    LocalLLM,
    RetryPolicy,
    Usage,
    action_grammar,
    action_schema,
    build_llm,
    validate_local_endpoint,
)
from op06d.redaction import REDACTED, clear_registered_secrets, scrub_text

NO_SLEEP = RetryPolicy(attempts=3, base_delay=0.0, sleep=lambda s: None, jitter=lambda: 0.0)
FAKE_KEY = "sk-ant-" + "api03-" + "Z" * 40


@pytest.fixture(autouse=True)
def _clean_secrets():
    clear_registered_secrets()
    yield
    clear_registered_secrets()


# --- endpoint policy -----------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434", "http://localhost:8080/v1", "http://[::1]:11434", "https://127.0.0.2/",
])
def test_loopback_endpoints_are_accepted(url):
    assert validate_local_endpoint(url).startswith(url.split(":")[0])


@pytest.mark.parametrize("url", [
    "http://8.8.8.8:11434",            # public IP
    "https://api.openai.com/v1",       # public DNS name
    "http://ollama.internal:11434",    # any DNS name, even if it would resolve privately
    "http://10.0.0.5:11434",           # private, but not explicitly allowed
    "http://[::ffff:8.8.8.8]:11434",   # IPv4-mapped public
    "http://0.0.0.0:11434",
])
def test_non_loopback_endpoints_are_refused(url):
    with pytest.raises(LLMConfigError):
        validate_local_endpoint(url)


@pytest.mark.parametrize("url", [
    "ftp://127.0.0.1/", "http://user:pw@127.0.0.1:11434", "http://127.0.0.1:11434/?x=1",
    "http://127.0.0.1:99999", "", "127.0.0.1:11434",
])
def test_malformed_endpoints_are_refused(url):
    with pytest.raises(LLMConfigError):
        validate_local_endpoint(url)


def test_an_explicitly_allowed_private_address_is_accepted():
    assert validate_local_endpoint("http://10.0.0.5:11434", ["10.0.0.5"]) == "http://10.0.0.5:11434"
    with pytest.raises(LLMConfigError):
        validate_local_endpoint("http://10.0.0.6:11434", ["10.0.0.5"])


@pytest.mark.parametrize("entry", ["8.8.8.8", "not-an-ip", "10.0.0.0/8"])
def test_the_private_allowlist_itself_only_takes_private_ips(entry):
    with pytest.raises(LLMConfigError):
        validate_local_endpoint("http://127.0.0.1:11434", [entry])


def test_local_llm_refuses_a_public_endpoint_at_construction():
    with pytest.raises(LLMConfigError):
        LocalLLM(endpoint="http://203.0.113.9:11434")


# --- constrained output ----------------------------------------------------------

class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, body, timeout):
        self.calls.append((url, json.loads(body), timeout))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        status, payload = r
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, raw, {}


OLLAMA_OK = (200, {"message": {"role": "assistant", "content": '{"type":"done","summary":"x"}'},
                   "prompt_eval_count": 120, "eval_count": 9})
OPENAI_OK = (200, {"choices": [{"message": {"content": '{"type":"done","summary":"x"}'}}],
                   "usage": {"prompt_tokens": 50, "completion_tokens": 7}})


def test_ollama_request_uses_the_json_schema_format_and_context_size():
    t = Recorder([OLLAMA_OK])
    llm = LocalLLM("m", tool_names=["nmap", "nuclei"], context_tokens=4096, transport=t, retry=NO_SLEEP)
    assert llm.complete("SYS", [{"role": "user", "content": "go"}]) == '{"type":"done","summary":"x"}'
    url, body, timeout = t.calls[0]
    assert url == "http://127.0.0.1:11434/api/chat"
    assert body["format"] == action_schema(["nmap", "nuclei"])
    assert body["options"]["num_ctx"] == 4096 and body["stream"] is False
    assert body["messages"][0] == {"role": "system", "content": "SYS"}
    assert timeout == 300.0
    assert llm.last_usage == Usage(120, 9)


def test_llamacpp_request_carries_a_grammar_restricted_to_the_known_tools():
    t = Recorder([OPENAI_OK])
    llm = LocalLLM("m", endpoint="http://127.0.0.1:8080", runtime="llamacpp",
                   tool_names=["nmap"], transport=t, retry=NO_SLEEP)
    llm.complete("SYS", [{"role": "user", "content": "go"}])
    url, body, _ = t.calls[0]
    assert url == "http://127.0.0.1:8080/v1/chat/completions"
    assert "root ::= action | done" in body["grammar"]
    assert 'tool ::= "\\"nmap\\""' in body["grammar"]
    assert "response_format" not in body
    assert llm.last_usage == Usage(50, 7)


def test_openai_compatible_request_uses_a_strict_json_schema_response_format():
    t = Recorder([OPENAI_OK])
    llm = LocalLLM("m", endpoint="http://127.0.0.1:1234/v1", runtime="openai",
                   tool_names=["nmap"], transport=t, retry=NO_SLEEP)
    llm.complete("SYS", [{"role": "user", "content": "go"}])
    url, body, _ = t.calls[0]
    assert url == "http://127.0.0.1:1234/v1/chat/completions"
    fmt = body["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True
    assert fmt["json_schema"]["schema"] == action_schema(["nmap"])


def test_action_schema_only_admits_the_two_reply_shapes():
    schema = action_schema(["nmap"])
    action, done = schema["anyOf"]
    assert action["properties"]["tool"]["enum"] == ["nmap"]
    assert action["additionalProperties"] is False and done["additionalProperties"] is False


def test_grammar_refuses_a_tool_name_it_cannot_quote():
    with pytest.raises(LLMConfigError):
        action_grammar(['bad"name'])


# --- retries / failures ----------------------------------------------------------

def test_transient_errors_are_retried_with_backoff_then_succeed():
    sleeps = []
    policy = RetryPolicy(attempts=4, base_delay=1.0, max_delay=30.0, sleep=sleeps.append, jitter=lambda: 0.0)
    t = Recorder([(503, b"busy"), ConnectionResetError("reset"), OLLAMA_OK])
    llm = LocalLLM("m", transport=t, retry=policy)
    llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(t.calls) == 3 and sleeps == [1.0, 2.0]


def test_retries_are_bounded_and_end_in_llm_unavailable():
    t = Recorder([(503, b"")] * 3)
    llm = LocalLLM("m", transport=t, retry=NO_SLEEP)
    with pytest.raises(LLMUnavailable):
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(t.calls) == 3


@pytest.mark.parametrize("response", [(404, b"model not found"), (403, b"no"), (200, b"<html>"),
                                      (200, {"unexpected": True})])
def test_non_retryable_failures_are_not_retried(response):
    t = Recorder([response])
    llm = LocalLLM("m", transport=t, retry=NO_SLEEP)
    with pytest.raises(LLMUnavailable):
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(t.calls) == 1


# --- hosted: Anthropic -----------------------------------------------------------

class FakeStatusError(Exception):
    def __init__(self, status, retry_after=None):
        super().__init__(f"status {status}")
        self.status_code = status
        self.response = SimpleNamespace(headers={"retry-after": retry_after} if retry_after else {})


class APIConnectionError(Exception):
    pass


class FakeMessages:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.kwargs = []

    def create(self, **kwargs):
        self.kwargs.append(kwargs)
        r = self.outcomes.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _resp(text, stop="end_turn", usage=(100, 20)):
    return SimpleNamespace(
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        stop_reason=stop, usage=SimpleNamespace(input_tokens=usage[0], output_tokens=usage[1]),
    )


def _client(outcomes):
    msgs = FakeMessages(outcomes)
    return SimpleNamespace(messages=msgs), msgs  # no .beta: the fallback surface is never touched


def test_anthropic_requires_the_key_in_the_environment():
    with pytest.raises(LLMConfigError, match="ANTHROPIC_API_KEY"):
        AnthropicLLM(environ={})


def test_anthropic_call_shape_and_usage_without_refusal_fallbacks():
    client, msgs = _client([_resp('{"type":"done","summary":"s"}')])
    llm = AnthropicLLM("claude-opus-5-5", client=client, environ={}, retry=NO_SLEEP)
    out = llm.complete("SYS", [{"role": "assistant", "content": "x"}, {"role": "user", "content": "y"},
                               {"role": "user", "content": "z"}])
    assert out == '{"type":"done","summary":"s"}'
    kw = msgs.kwargs[0]
    assert kw["model"] == "claude-opus-5-5" and kw["system"] == "SYS"
    assert "fallbacks" not in kw and "betas" not in kw
    assert kw["max_tokens"] == 16_000
    roles = [m["role"] for m in kw["messages"]]
    assert roles[0] == "user" and all(a != b for a, b in zip(roles, roles[1:]))
    assert llm.last_usage == Usage(100, 20)


def test_anthropic_transient_statuses_and_connection_errors_are_retried():
    client, msgs = _client([FakeStatusError(529), APIConnectionError(), _resp("{}")])
    llm = AnthropicLLM(client=client, environ={}, retry=NO_SLEEP)
    assert llm.complete("S", [{"role": "user", "content": "go"}]) == "{}"
    assert len(msgs.kwargs) == 3


def test_anthropic_retry_after_is_honoured():
    sleeps = []
    client, _ = _client([FakeStatusError(429, retry_after="7"), _resp("{}")])
    llm = AnthropicLLM(client=client, environ={},
                       retry=RetryPolicy(attempts=3, sleep=sleeps.append, jitter=lambda: 0.0))
    llm.complete("S", [{"role": "user", "content": "go"}])
    assert sleeps == [7.0]


@pytest.mark.parametrize("exc", [FakeStatusError(401), FakeStatusError(400), ValueError("bug")])
def test_anthropic_non_retryable_errors_fail_immediately(exc):
    client, msgs = _client([exc])
    llm = AnthropicLLM(client=client, environ={}, retry=NO_SLEEP)
    with pytest.raises(LLMUnavailable):
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(msgs.kwargs) == 1


def test_anthropic_refusal_raises_llm_refused_and_is_not_retried():
    client, msgs = _client([_resp("", stop="refusal")])
    llm = AnthropicLLM(client=client, environ={}, retry=NO_SLEEP)
    with pytest.raises(LLMRefused, match="refusal"):
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(msgs.kwargs) == 1 and llm.last_usage == Usage(100, 20)


def test_anthropic_output_cap_bounds_max_tokens():
    client, msgs = _client([_resp("{}"), _resp("{}"), _resp("{}")])
    llm = AnthropicLLM(client=client, environ={}, max_output_tokens=4_000, retry=NO_SLEEP)
    for cap in (1_500, 9_000, None):
        llm.set_output_cap(cap)
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert [k["max_tokens"] for k in msgs.kwargs] == [1_500, 4_000, 4_000]


def test_the_environment_key_is_registered_for_scrubbing():
    client, _ = _client([])
    AnthropicLLM(client=client, environ={"ANTHROPIC_API_KEY": "plain-secret-value-123"})
    assert scrub_text("x plain-secret-value-123 y") == f"x {REDACTED} y"
    assert scrub_text(f"key={FAKE_KEY}") == f"key={REDACTED}"


# --- settings ---------------------------------------------------------------------

def test_anthropic_endpoint_cannot_be_overridden():
    with pytest.raises(LLMConfigError):
        LLMSettings("anthropic", endpoint="https://proxy.example.com").resolved()


def test_settings_defaults_per_provider():
    a = LLMSettings("anthropic").resolved()
    loc = LLMSettings("local").resolved()
    assert (a.model, a.endpoint_class, a.timeout) == ("claude-opus-5-5", "hosted", 120.0)
    assert (loc.endpoint, loc.endpoint_class, loc.timeout) == ("http://127.0.0.1:11434", "local", 300.0)
    assert loc.context_tokens == 8_192


@pytest.mark.parametrize("kw", [dict(context_tokens=100), dict(max_output_tokens=9000, context_tokens=8192),
                                dict(timeout=-1.0), dict(provider="openai")])
def test_settings_validation(kw):
    with pytest.raises(LLMConfigError):
        LLMSettings(**{"provider": "local", **kw}).resolved()


def test_build_llm_local_refuses_public_endpoint():
    with pytest.raises(LLMConfigError):
        build_llm(LLMSettings("local", endpoint="http://1.1.1.1:11434"), tool_names=["nmap"])


# --- Ollama constrained output: schema first, plain JSON when unsupported ---------

def test_ollama_falls_back_to_plain_json_when_the_schema_format_is_rejected():
    t = Recorder([(400, b'{"error":"invalid format"}'), OLLAMA_OK, OLLAMA_OK])
    llm = LocalLLM("m", tool_names=["nmap"], transport=t, retry=NO_SLEEP)
    assert llm.output_mode == "json_schema"
    llm.complete("S", [{"role": "user", "content": "go"}])
    llm.complete("S", [{"role": "user", "content": "go"}])
    formats = [body["format"] for _, body, _ in t.calls]
    assert formats == [action_schema(["nmap"]), "json", "json"]
    assert llm.output_mode == "json"


def test_ollama_bad_request_in_plain_json_mode_is_a_failure():
    t = Recorder([(400, b""), (400, b"")])
    llm = LocalLLM("m", transport=t, retry=NO_SLEEP)
    with pytest.raises(LLMUnavailable):
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(t.calls) == 2


def test_other_runtimes_do_not_drop_their_constraint_on_a_bad_request():
    t = Recorder([(400, b"")])
    llm = LocalLLM("m", endpoint="http://127.0.0.1:8080", runtime="llamacpp", transport=t, retry=NO_SLEEP)
    with pytest.raises(LLMUnavailable):
        llm.complete("S", [{"role": "user", "content": "go"}])
    assert len(t.calls) == 1


def test_local_output_cap_bounds_the_request():
    t = Recorder([OLLAMA_OK, OPENAI_OK])
    a = LocalLLM("m", max_output_tokens=1_024, transport=t, retry=NO_SLEEP)
    b = LocalLLM("m", endpoint="http://127.0.0.1:1234", runtime="openai", max_output_tokens=1_024,
                 transport=t, retry=NO_SLEEP)
    a.set_output_cap(300)
    b.set_output_cap(5_000)
    a.complete("S", [{"role": "user", "content": "go"}])
    b.complete("S", [{"role": "user", "content": "go"}])
    assert t.calls[0][1]["options"]["num_predict"] == 300
    assert t.calls[1][1]["max_tokens"] == 1_024
