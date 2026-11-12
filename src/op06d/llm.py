# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-40: LLM planner: wire a real model into the orchestrator and `op06d run`

Production adapters for the ``op06d.orchestrator.LLM`` protocol:

* ``AnthropicLLM`` - the hosted Claude Messages API (official ``anthropic``
  SDK, optional extra ``llm-anthropic``). The API key is read only from the
  ``ANTHROPIC_API_KEY`` environment variable.
* ``LocalLLM`` - an OpenAI-compatible or Ollama chat endpoint on loopback or
  on an explicitly allowed private address.

Each adapter sets ``last_usage`` after every call. API failures raise
``LLMUnavailable`` after bounded retries; configuration problems raise
``LLMConfigError`` before anything runs.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from op06d.redaction import register_secret, scrub_text

__all__ = [
    "LLMError", "LLMConfigError", "LLMUnavailable", "LLMRefused", "Usage", "RetryPolicy", "LLMSettings",
    "AnthropicLLM", "LocalLLM", "action_schema", "action_grammar", "validate_local_endpoint",
    "build_llm", "PROVIDERS", "LOCAL_RUNTIMES", "ANTHROPIC_API_KEY_ENV",
    "validate_anthropic_key", "MIN_ANTHROPIC_KEY_CHARS",
]

PROVIDERS = ("anthropic", "local")
LOCAL_RUNTIMES = ("ollama", "llamacpp", "openai")
ANTHROPIC_API_KEY_ENV = "ANTHROPIC_API_KEY"
ANTHROPIC_ENDPOINT = "https://api.anthropic.com"

DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
DEFAULT_LOCAL_MODEL = "llama3.1:8b-instruct-q5_K_M"
DEFAULT_LOCAL_ENDPOINT = "http://127.0.0.1:11434"

ANTHROPIC_PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}

TRANSIENT_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})
MAX_RETRY_AFTER_SECONDS = 60.0


MIN_ANTHROPIC_KEY_CHARS = 40
ANTHROPIC_KEY_PREFIX = "sk-ant-"
_ERROR_TYPE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")


class LLMError(Exception):
    """Base class for model-adapter failures.

    ``http_status`` and ``error_type`` say why a call failed (for example 401
    and ``authentication_error``) when the adapter knows; neither ever holds
    response text or key material.
    """

    http_status: int | None = None
    error_type: str | None = None

    def with_cause(self, http_status: object = None, error_type: object = None) -> "LLMError":
        if isinstance(http_status, int) and not isinstance(http_status, bool) and 100 <= http_status <= 599:
            self.http_status = http_status
        if isinstance(error_type, str) and _ERROR_TYPE_RE.fullmatch(error_type):
            self.error_type = error_type
        return self


class LLMConfigError(LLMError):
    """The adapter cannot be constructed as configured; nothing has run."""


class LLMUnavailable(LLMError):
    """The model could not produce a reply (non-retryable error or retries exhausted)."""


class LLMRefused(LLMError):
    """The model declined the request."""


class _BadRequest(LLMUnavailable):
    pass


def _capped(configured: int, cap: int | None) -> int:
    return configured if cap is None else max(1, min(configured, cap))


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 4
    base_delay: float = 1.0
    max_delay: float = 30.0
    sleep: Callable[[float], None] = time.sleep
    jitter: Callable[[], float] = random.random

    def delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None and retry_after >= 0:
            return min(retry_after, MAX_RETRY_AFTER_SECONDS)
        return min(self.base_delay * (2 ** attempt) + self.jitter(), self.max_delay)


class _Transient(Exception):
    def __init__(self, label: str, retry_after: float | None = None, *,
                 http_status: int | None = None, error_type: str | None = None) -> None:
        super().__init__(label)
        self.label = label
        self.retry_after = retry_after
        self.http_status = http_status
        self.error_type = error_type


def _with_retries(call: Callable[[], Any], policy: RetryPolicy, what: str) -> Any:
    last: _Transient | None = None
    for attempt in range(max(1, policy.attempts)):
        try:
            return call()
        except _Transient as exc:
            last = exc
            if attempt + 1 >= policy.attempts:
                break
            policy.sleep(policy.delay(attempt, exc.retry_after))
    label = last.label if last is not None else "unknown error"
    raise LLMUnavailable(
        scrub_text(f"{what}: gave up after {policy.attempts} attempts ({label})")
    ).with_cause(getattr(last, "http_status", None), getattr(last, "error_type", None))


def _api_error_type(exc: Exception) -> str | None:
    """The API's own error type (``authentication_error``, ...) from an SDK
    exception's parsed body. Only a short identifier is accepted, so no
    message text can come through."""
    body = getattr(exc, "body", None)
    if not isinstance(body, Mapping):
        return None
    inner = body.get("error")
    value = inner.get("type") if isinstance(inner, Mapping) else body.get("type")
    return value if isinstance(value, str) and _ERROR_TYPE_RE.fullmatch(value) else None


def validate_anthropic_key(key: object) -> str:
    """Return ``key`` if it is plausibly an Anthropic API key, else raise
    ``LLMConfigError``. The message gives the length, never the value."""
    if not isinstance(key, str) or not key:
        raise LLMConfigError(
            f"{ANTHROPIC_API_KEY_ENV} is not set; the API key is read only from the environment"
        )
    problem = None
    if any(c.isspace() for c in key):
        problem = "contains whitespace"
    elif not key.startswith(ANTHROPIC_KEY_PREFIX):
        problem = f"does not start with {ANTHROPIC_KEY_PREFIX!r}"
    elif len(key) < MIN_ANTHROPIC_KEY_CHARS:
        problem = f"is too short (a real key has at least {MIN_ANTHROPIC_KEY_CHARS} characters)"
    if problem:
        raise LLMConfigError(
            f"{ANTHROPIC_API_KEY_ENV} does not look like an Anthropic API key: it {problem}; "
            f"the value in the environment is {len(key)} character(s) long. Set it again "
            "(a masked prompt can take a paste as a single character)"
        )
    return key


def _retry_after(headers: object) -> float | None:
    try:
        value = headers.get("retry-after") if headers is not None else None  # type: ignore[union-attr]
        return float(value) if value is not None else None
    except (TypeError, ValueError, AttributeError):
        return None


# --- the action schema -------------------------------------------------------

ToolParameters = Mapping[str, Mapping[str, Mapping[str, Any]]]
"""Per tool name, per parameter name, a JSON-schema fragment for the value
(``GatedToolbox.describe()``'s ``parameter_schema``)."""


def _action_branch(tool: dict[str, Any], parameters: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["action"]},
            "tool": tool,
            "target": {"type": "string"},
            "parameters": parameters,
            "reason": {"type": "string"},
        },
        "required": ["type", "tool", "target", "parameters", "reason"],
        "additionalProperties": False,
    }


def action_schema(tool_names: Sequence[str], tool_parameters: ToolParameters | None = None) -> dict[str, Any]:
    """JSON schema for one planner reply (action or done).

    One action branch per tool: ``tool`` is pinned to that name and
    ``parameters`` is an object of that tool's parameter fragments, none of
    them required and no others allowed. A tool with no entry in
    ``tool_parameters`` takes any object."""
    names = sorted({str(n) for n in tool_names})
    known = tool_parameters or {}
    branches = []
    for name in names:
        parameters: dict[str, Any] = {"type": "object"}
        if name in known:
            parameters.update(
                properties={str(k): dict(v) for k, v in sorted(known[name].items())},
                additionalProperties=False,
            )
        branches.append(_action_branch({"type": "string", "enum": [name]}, parameters))
    if not names:
        branches.append(_action_branch({"type": "string"}, {"type": "object"}))
    return {
        "anyOf": [
            *branches,
            {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["done"]},
                    "summary": {"type": "string"},
                },
                "required": ["type", "summary"],
                "additionalProperties": False,
            },
        ]
    }


_GBNF_COMMON = r'''
value ::= object | array | string | number | "true" | "false" | "null"
object ::= "{" ws ( string ws ":" ws value ( ws "," ws string ws ":" ws value )* )? ws "}"
array ::= "[" ws ( value ( ws "," ws value )* )? ws "]"
string ::= "\"" ( [^"\\\x7F\x00-\x1F] | "\\" ( ["\\/bfnrt] | "u" [0-9a-fA-F] [0-9a-fA-F] [0-9a-fA-F] [0-9a-fA-F] ) )* "\""
number ::= "-"? ( "0" | [1-9] [0-9]* ) ( "." [0-9]+ )? ( [eE] [-+]? [0-9]+ )?
integer ::= "-"? ( "0" | [1-9] [0-9]* )
ws ::= ( " " | "\n" | "\t" )*
'''


def _gbnf_quoted(text: object, what: str) -> str:
    """The GBNF literal that matches ``text`` as a JSON string."""
    if not isinstance(text, str) or not text or any(c in text for c in '"\\') or not text.isprintable():
        raise LLMConfigError(f"{what} {text!r} cannot be expressed in the grammar")
    return f'"\\"{text}\\""'


def _gbnf_value(fragment: Mapping[str, Any], what: str) -> str:
    """A GBNF expression for the values a parameter fragment admits. Enums of
    strings, the scalar types and arrays (with ``minItems`` of 0 or 1) are
    expressed; numeric ranges, ``maxItems`` and anything else are not, and
    fall back to the type or to any JSON value."""
    enum = fragment.get("enum")
    if isinstance(enum, (list, tuple)) and enum:
        return "( " + " | ".join(_gbnf_quoted(v, f"{what} value") for v in enum) + " )"
    kind = fragment.get("type")
    if kind == "array":
        items = fragment.get("items") if isinstance(fragment.get("items"), Mapping) else {}
        item = _gbnf_value(items, what)
        some = f'{item} ( ws "," ws {item} )*'
        if not fragment.get("minItems"):
            some = f"( {some} )?"
        return f'"[" ws {some} ws "]"'
    return {"string": "string", "integer": "integer", "number": "number",
            "boolean": '( "true" | "false" )', "object": "object"}.get(kind, "value")


def _gbnf_parameters(index: int, parameters: Mapping[str, Mapping[str, Any]], tool: str) -> list[str]:
    """Rules for one tool's ``parameters`` object: its keys only, each at most
    once and each optional, in name order."""
    keys = sorted(str(k) for k in parameters)
    if not keys:
        return [f'params-{index} ::= "{{" ws "}}"']
    rules = []
    for i, key in enumerate(keys):
        what = f"{tool} parameter"
        rules.append(f'p{index}-kv{i} ::= {_gbnf_quoted(key, what)} ws ":" ws '
                     f'{_gbnf_value(parameters[key], f"{what} {key}")}')
        if i + 1 < len(keys):  # what may follow key i: any later keys, still in order
            later = f"p{index}-rest{i + 1}" if i + 2 < len(keys) else ""
            rules.append(f'p{index}-rest{i} ::= ( ws "," ws p{index}-kv{i + 1} )? {later}'.rstrip())
    starts = " | ".join(f"p{index}-kv{i}" + (f" p{index}-rest{i}" if i + 1 < len(keys) else "")
                        for i in range(len(keys)))
    return [f'params-{index} ::= "{{" ws ( ( {starts} ) ws )? "}}"', *rules]


def action_grammar(tool_names: Sequence[str], tool_parameters: ToolParameters | None = None) -> str:
    """GBNF grammar (llama.cpp) for ``action_schema``: the same tool names, and
    per tool the same parameter keys and value shapes.

    It is narrower than the schema in one way and wider in two. Parameter
    keys must come in name order (JSON objects are unordered; the fixed order
    is what keeps each key optional and unrepeated in a grammar). Numeric
    ranges and ``maxItems`` are not expressed. ``validate_parameters`` decides
    either way."""
    names = sorted({str(n) for n in tool_names})
    known = tool_parameters or {}
    done = ('done ::= "{" ws "\\"type\\"" ws ":" ws "\\"done\\"" ws "," ws '
            '"\\"summary\\"" ws ":" ws string ws "}"')

    def action(rule: str, tool: str, parameters: str) -> str:
        return (f'{rule} ::= "{{" ws "\\"type\\"" ws ":" ws "\\"action\\"" ws "," ws '
                f'"\\"tool\\"" ws ":" ws {tool} ws "," ws "\\"target\\"" ws ":" ws string ws "," ws '
                f'"\\"parameters\\"" ws ":" ws {parameters} ws "," ws "\\"reason\\"" ws ":" ws string ws "}}"')

    quoted = [_gbnf_quoted(n, "tool name") for n in names]
    if not names:
        rules = ["root ::= action | done", action("action", "string", "object"), done]
        return "\n".join(rules) + _GBNF_COMMON
    rules = ["root ::= action | done",
             "action ::= " + " | ".join(f"action-{i}" for i in range(len(names))), done]
    for i, name in enumerate(names):
        if name in known:
            rules.append(action(f"action-{i}", quoted[i], f"params-{i}"))
            rules += _gbnf_parameters(i, known[name], name)
        else:
            rules.append(action(f"action-{i}", quoted[i], "object"))
    return "\n".join(rules) + _GBNF_COMMON


# --- message shaping ---------------------------------------------------------

def _alternating(messages: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for m in messages:
        role = m.get("role") if m.get("role") in ("user", "assistant") else "user"
        content = str(m.get("content", ""))
        if out and out[-1]["role"] == role:
            out[-1]["content"] += "\n\n" + content
        else:
            out.append({"role": role, "content": content})
    if not out or out[0]["role"] != "user":
        out.insert(0, {"role": "user", "content": "Begin."})
    return out


# --- hosted: Anthropic ---------------------------------------------------------

class AnthropicLLM:
    provider = "anthropic"
    endpoint_class = "hosted"

    def __init__(
        self,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        *,
        client: Any = None,
        environ: Mapping[str, str] | None = None,
        max_output_tokens: int = 16_000,
        timeout: float = 120.0,
        retry: RetryPolicy | None = None,
    ) -> None:
        if not isinstance(model, str) or not model.strip():
            raise LLMConfigError("a model name is required")
        env = os.environ if environ is None else environ
        key = env.get(ANTHROPIC_API_KEY_ENV) or ""
        if key:
            register_secret(key)
        if client is None:
            validate_anthropic_key(key)
            try:
                import anthropic
            except ImportError:
                raise LLMConfigError(
                    "the anthropic SDK is not installed (pip install 'op06d[llm-anthropic]')"
                ) from None
            client = anthropic.Anthropic(api_key=key, max_retries=0, timeout=timeout)
        self._client = client
        self.model = model
        self._max_output = max_output_tokens
        self._retry = retry or RetryPolicy()
        self._output_cap: int | None = None
        self.last_usage: Usage | None = None

    def set_output_cap(self, cap: int | None) -> None:
        """Bound the next requests' ``max_tokens`` to ``min(configured, cap)``."""
        self._output_cap = cap

    def _classify(self, exc: Exception) -> Exception:
        status = getattr(exc, "status_code", None)
        name = type(exc).__name__
        if isinstance(status, int):
            api_type = _api_error_type(exc)
            label = f"{name} (HTTP {status}{', ' + api_type if api_type else ''})"
            if status in TRANSIENT_STATUSES:
                return _Transient(label, _retry_after(getattr(getattr(exc, "response", None), "headers", None)),
                                  http_status=status, error_type=api_type)
            return LLMUnavailable(f"model API error: {label}").with_cause(status, api_type)
        mro = {c.__name__ for c in type(exc).__mro__}
        if mro & {"APIConnectionError", "APITimeoutError"} or isinstance(exc, (OSError, TimeoutError)):
            return _Transient(name, error_type=name)
        return LLMUnavailable(f"model API error: {name}").with_cause(None, name)

    def _call(self, system: str, messages: list[dict[str, str]]) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model, "max_tokens": _capped(self._max_output, self._output_cap),
            "system": system, "messages": messages,
        }
        try:
            return self._client.messages.create(**kwargs)
        except Exception as exc:
            raise self._classify(exc) from None

    def complete(self, system: str, messages: Sequence[Mapping[str, str]]) -> str:
        self.last_usage = None
        resp = _with_retries(
            lambda: self._call(system, _alternating(messages)), self._retry, "anthropic",
        )
        usage = getattr(resp, "usage", None)
        self.last_usage = Usage(
            int(getattr(usage, "input_tokens", 0) or 0), int(getattr(usage, "output_tokens", 0) or 0),
        )
        if getattr(resp, "stop_reason", None) == "refusal":
            raise LLMRefused("model declined the request (stop_reason=refusal)")
        return "".join(
            getattr(b, "text", "") for b in getattr(resp, "content", []) or []
            if getattr(b, "type", None) == "text"
        )


# --- local: OpenAI-compatible / Ollama ------------------------------------------

Transport = Callable[[str, bytes, float], tuple[int, bytes, Mapping[str, str]]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _local_transport(url: str, body: bytes, timeout: float) -> tuple[int, bytes, Mapping[str, str]]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b"", dict(exc.headers or {})


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def validate_local_endpoint(endpoint: str, allowed_private: Sequence[str] = ()) -> str:
    """Return the normalized base URL, or raise ``LLMConfigError``. Accepted:
    ``localhost``, a loopback IP literal, or a private IP literal listed in
    ``allowed_private``."""
    if not isinstance(endpoint, str) or not endpoint:
        raise LLMConfigError("an endpoint URL is required")
    allowed: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for entry in allowed_private:
        ip = _parse_ip(str(entry))
        if ip is None or not ip.is_private or ip.is_global or ip.is_unspecified or ip.is_multicast:
            raise LLMConfigError(f"allowed private address {entry!r} is not a private IP address")
        allowed.add(ip)
    try:
        parts = urlsplit(endpoint)
        port = parts.port
    except ValueError as exc:
        raise LLMConfigError(f"invalid endpoint URL: {exc}") from None
    if parts.scheme not in ("http", "https"):
        raise LLMConfigError("endpoint must be an http:// or https:// URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise LLMConfigError("endpoint must not carry credentials, a query or a fragment")
    host = (parts.hostname or "").lower()
    if host != "localhost":
        ip = _parse_ip(host)
        if ip is None:
            raise LLMConfigError(
                f"endpoint host {host!r} must be localhost or an IP literal (no DNS names)"
            )
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped  # type: ignore[union-attr]
        if not ip.is_loopback and ip not in allowed:
            raise LLMConfigError(
                f"endpoint {host} is not loopback and is not an explicitly allowed private address; "
                "refusing to send engagement data to it"
            )
    path = parts.path.rstrip("/")
    for suffix in ("/v1", "/api"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
    del port
    return f"{parts.scheme}://{parts.netloc}{path}"


class LocalLLM:
    provider = "local"
    endpoint_class = "local"

    def __init__(
        self,
        model: str = DEFAULT_LOCAL_MODEL,
        *,
        endpoint: str = DEFAULT_LOCAL_ENDPOINT,
        runtime: str = "ollama",
        tool_names: Sequence[str] = (),
        tool_parameters: ToolParameters | None = None,
        context_tokens: int = 8_192,
        max_output_tokens: int = 1_024,
        timeout: float = 300.0,
        allowed_private: Sequence[str] = (),
        retry: RetryPolicy | None = None,
        transport: Transport | None = None,
    ) -> None:
        if not isinstance(model, str) or not model.strip():
            raise LLMConfigError("a model name is required")
        if runtime not in LOCAL_RUNTIMES:
            raise LLMConfigError(f"runtime must be one of {LOCAL_RUNTIMES}")
        self.base_url = validate_local_endpoint(endpoint, allowed_private)
        self.model = model
        self.runtime = runtime
        self.context_tokens = context_tokens
        self._max_output = max_output_tokens
        self._timeout = timeout
        self._retry = retry or RetryPolicy()
        self._transport = transport or _local_transport
        self._tool_names = tuple(tool_names)
        self.set_tool_parameters(tool_parameters)
        self._output_cap: int | None = None
        self.output_mode = {"ollama": "json_schema", "llamacpp": "grammar", "openai": "json_schema"}[runtime]
        self.last_usage: Usage | None = None

    def set_output_cap(self, cap: int | None) -> None:
        """Bound the next requests' output tokens to ``min(configured, cap)``."""
        self._output_cap = cap

    def set_tool_parameters(self, tool_parameters: ToolParameters | None) -> None:
        """Constrain each tool's ``parameters`` object to that tool's parameter
        schema, in the action schema and in the grammar."""
        self._schema = action_schema(self._tool_names, tool_parameters)
        self._grammar = (action_grammar(self._tool_names, tool_parameters)
                         if self.runtime == "llamacpp" else None)

    def _request(self, system: str, messages: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
        chat = [{"role": "system", "content": system}, *messages]
        max_output = _capped(self._max_output, self._output_cap)
        if self.runtime == "ollama":
            return f"{self.base_url}/api/chat", {
                "model": self.model, "messages": chat, "stream": False,
                "format": self._schema if self.output_mode == "json_schema" else "json",
                "options": {"num_ctx": self.context_tokens, "num_predict": max_output,
                            "temperature": 0},
            }
        body: dict[str, Any] = {
            "model": self.model, "messages": chat, "max_tokens": max_output,
            "temperature": 0, "stream": False,
        }
        if self.runtime == "llamacpp":
            body["grammar"] = self._grammar
        else:
            # Not "strict": that mode wants every property listed in "required", and a
            # tool's parameters are all optional.
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "op06d_planner_reply", "schema": self._schema, "strict": False},
            }
        return f"{self.base_url}/v1/chat/completions", body

    def _post(self, url: str, payload: bytes) -> dict[str, Any]:
        try:
            status, raw, headers = self._transport(url, payload, self._timeout)
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            raise _Transient(type(exc).__name__, error_type=type(exc).__name__) from None
        if status in TRANSIENT_STATUSES:
            raise _Transient(f"HTTP {status}", _retry_after({k.lower(): v for k, v in headers.items()}),
                             http_status=status)
        if status == 404:
            raise LLMUnavailable(
                f"local endpoint returned 404 (is model {self.model!r} available on the server?)"
            ).with_cause(status)
        if status == 400:
            raise _BadRequest("local endpoint returned HTTP 400").with_cause(status)
        if not 200 <= status < 300:
            raise LLMUnavailable(f"local endpoint returned HTTP {status}").with_cause(status)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise LLMUnavailable("local endpoint returned a response that is not JSON") from None
        if not isinstance(data, dict):
            raise LLMUnavailable("local endpoint returned an unexpected response shape")
        return data

    def complete(self, system: str, messages: Sequence[Mapping[str, str]]) -> str:
        self.last_usage = None
        chat = _alternating(messages)

        def send() -> dict[str, Any]:
            url, body = self._request(system, chat)
            payload = json.dumps(body).encode("utf-8")
            return _with_retries(lambda: self._post(url, payload), self._retry, "local model")

        try:
            data = send()
        except _BadRequest:
            if self.runtime != "ollama" or self.output_mode != "json_schema":
                raise
            self.output_mode = "json"
            data = send()
        try:
            if self.runtime == "ollama":
                text = data["message"]["content"]
                usage = Usage(int(data.get("prompt_eval_count") or 0), int(data.get("eval_count") or 0))
            else:
                text = data["choices"][0]["message"]["content"]
                u = data.get("usage") or {}
                usage = Usage(int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0))
        except (KeyError, IndexError, TypeError, ValueError):
            raise LLMUnavailable("local endpoint returned an unexpected response shape") from None
        self.last_usage = usage
        if not isinstance(text, str):
            raise LLMUnavailable("local endpoint returned non-text content")
        return text


# --- settings + factory --------------------------------------------------------

@dataclass(frozen=True)
class LLMSettings:
    provider: str
    model: str | None = None
    endpoint: str | None = None
    runtime: str = "ollama"
    context_tokens: int | None = None
    max_output_tokens: int | None = None
    timeout: float | None = None
    allowed_private: tuple[str, ...] = field(default_factory=tuple)

    def resolved(self) -> "LLMSettings":
        if self.provider not in PROVIDERS:
            raise LLMConfigError(f"provider must be one of {PROVIDERS}")
        if self.provider == "anthropic":
            if self.endpoint not in (None, ANTHROPIC_ENDPOINT):
                raise LLMConfigError(
                    f"the anthropic provider only talks to {ANTHROPIC_ENDPOINT}; --llm-endpoint is "
                    "for the local provider"
                )
            defaults = dict(model=DEFAULT_ANTHROPIC_MODEL, endpoint=ANTHROPIC_ENDPOINT,
                            context_tokens=200_000, max_output_tokens=16_000, timeout=120.0)
        else:
            defaults = dict(model=DEFAULT_LOCAL_MODEL, endpoint=DEFAULT_LOCAL_ENDPOINT,
                            context_tokens=8_192, max_output_tokens=1_024, timeout=300.0)
        values = {k: getattr(self, k) if getattr(self, k) is not None else v for k, v in defaults.items()}
        for name in ("context_tokens", "max_output_tokens"):
            v = values[name]
            if isinstance(v, bool) or not isinstance(v, int) or v < 256:
                raise LLMConfigError(f"{name} must be an integer >= 256")
        if values["max_output_tokens"] >= values["context_tokens"]:
            raise LLMConfigError("max_output_tokens must be smaller than context_tokens")
        if not values["timeout"] or values["timeout"] <= 0:
            raise LLMConfigError("timeout must be positive")
        return LLMSettings(
            provider=self.provider, runtime=self.runtime, allowed_private=tuple(self.allowed_private),
            **values,
        )

    @property
    def endpoint_class(self) -> str:
        return "hosted" if self.provider == "anthropic" else "local"


def build_llm(settings: LLMSettings, *, tool_names: Sequence[str],
              tool_parameters: ToolParameters | None = None) -> AnthropicLLM | LocalLLM:
    s = settings.resolved()
    if s.provider == "anthropic":
        return AnthropicLLM(s.model, max_output_tokens=s.max_output_tokens, timeout=s.timeout)
    return LocalLLM(
        s.model, endpoint=s.endpoint, runtime=s.runtime, tool_names=tool_names,
        tool_parameters=tool_parameters,
        context_tokens=s.context_tokens, max_output_tokens=s.max_output_tokens,
        timeout=s.timeout, allowed_private=s.allowed_private,
    )
