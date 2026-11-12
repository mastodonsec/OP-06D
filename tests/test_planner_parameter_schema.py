# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-50: Planner never learns parameter types: nuclei severity/tags sent as strings, always refused

Each tool's ``parameter_schema()`` and its three uses: the planner prompt, the
action JSON schema and the GBNF grammar. No JSON-schema validator and no GBNF
engine is a dependency, so this file has a small checker for the schema
keywords the action schema uses, and a small matcher for the GBNF the grammar
uses.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path

import pytest

from op06d.audit import AuditLog
from op06d.engagement import load_engagement
from op06d.gate import Gate
from op06d.llm import LLMConfigError, LocalLLM, action_grammar, action_schema
from op06d.nmap_tool import ALL_CATEGORIES, PROFILES, NmapTool
from op06d.nuclei_tool import ALL_TAGS, SEVERITIES, NucleiTool
from op06d.orchestrator import build_system_prompt, describe_parameter
from op06d.tools import GatedToolbox, Risk, parameter_schema_of

ENG = load_engagement(Path(__file__).resolve().parent.parent / "examples" / "engagement.yaml")
CURATED_ID = "tech-detect"


def nmap() -> NmapTool:
    return NmapTool(5)


def nuclei(curated: bool = False) -> NucleiTool:
    return NucleiTool(5, template_dir="/opt/nuclei-templates",
                      curated_ids={CURATED_ID: Risk.ACTIVE_RECON} if curated else None)


def schemas(curated: bool = False) -> dict:
    return {t.name: parameter_schema_of(t) for t in (nmap(), nuclei(curated))}


# --- a checker for the JSON-schema keywords in use -------------------------------------------

_KEYWORDS = {"anyOf", "type", "enum", "properties", "required", "additionalProperties", "items",
             "minItems", "maxItems", "minimum", "maximum"}
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
}


def conforms(schema: dict, value: object) -> bool:
    assert set(schema) <= _KEYWORDS, set(schema) - _KEYWORDS  # nothing this checker would skip
    if "anyOf" in schema and not any(conforms(s, value) for s in schema["anyOf"]):
        return False
    if "type" in schema and not _TYPES[schema["type"]](value):
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if isinstance(value, dict):
        props = schema.get("properties", {})
        if any(k not in value for k in schema.get("required", [])):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(props):
            return False
        if not all(conforms(props[k], v) for k, v in value.items() if k in props):
            return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            return False
        if "items" in schema and not all(conforms(schema["items"], v) for v in value):
            return False
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            return False
    return True


def reply(tool: str, **parameters) -> dict:
    return {"type": "action", "tool": tool, "target": "203.0.113.5", "parameters": parameters, "reason": "recon"}


# --- a matcher for the GBNF in use -----------------------------------------------------------

_TOKEN = re.compile(r'\s*(?:(?P<lit>"(?:[^"\\]|\\.)*")|(?P<cls>\[(?:[^\]\\]|\\.)*\])|(?P<op>::=|[()|?*+])'
                    r'|(?P<name>[A-Za-z][A-Za-z0-9-]*))')
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def _unescape(body: str) -> list[str]:
    out, i = [], 0
    while i < len(body):
        if body[i] != "\\":
            out.append(body[i])
            i += 1
        elif body[i + 1] == "x":
            out.append(chr(int(body[i + 2:i + 4], 16)))
            i += 4
        else:
            out.append(_ESCAPES.get(body[i + 1], body[i + 1]))
            i += 2
    return out


def _char_class(body: str):
    negate = body.startswith("^")
    chars = _unescape(body[1:] if negate else body)
    ranges, i = [], 0
    while i < len(chars):
        if i + 2 < len(chars) and chars[i + 1] == "-":
            ranges.append((chars[i], chars[i + 2]))
            i += 3
        else:
            ranges.append((chars[i], chars[i]))
            i += 1
    return ("cls", negate, ranges)


def parse_gbnf(grammar: str) -> dict:
    rules = {}
    for line in filter(None, (ln.strip() for ln in grammar.splitlines())):
        tokens, pos = [], 0
        while pos < len(line):
            m = _TOKEN.match(line, pos)
            assert m, f"not GBNF at {line[pos:pos + 30]!r} in {line!r}"
            tokens.append((m.lastgroup, m.group(m.lastgroup)))
            pos = m.end()
        assert tokens[0][0] == "name" and tokens[1] == ("op", "::="), line
        assert tokens[0][1] not in rules, f"rule {tokens[0][1]} defined twice"
        stream = tokens[2:]

        def alternation():
            options = [sequence()]
            while stream and stream[0] == ("op", "|"):
                stream.pop(0)
                options.append(sequence())
            return ("alt", options)

        def sequence():
            items = []
            while stream and stream[0] not in (("op", "|"), ("op", ")")):
                kind, text = stream.pop(0)
                if kind == "lit":
                    node = ("lit", "".join(_unescape(text[1:-1])))
                elif kind == "cls":
                    node = _char_class(text[1:-1])
                elif kind == "name":
                    node = ("ref", text)
                else:
                    assert text == "(", f"unexpected {text!r} in {line!r}"
                    node = alternation()
                    assert stream.pop(0) == ("op", ")"), line
                while stream and stream[0][0] == "op" and stream[0][1] in "?*+":
                    node = ("rep", node, stream.pop(0)[1])
                items.append(node)
            return ("seq", items)

        rules[tokens[0][1]] = alternation()
        assert not stream, f"trailing tokens in {line!r}"
    for name, node in rules.items():
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur[0] == "ref":
                assert cur[1] in rules, f"{name} refers to undefined rule {cur[1]}"
            elif cur[0] in ("alt", "seq"):
                stack += cur[1]
            elif cur[0] == "rep":
                stack.append(cur[1])
    return rules


def _ends(rules, node, text, pos):
    kind = node[0]
    if kind == "lit":
        if text.startswith(node[1], pos):
            yield pos + len(node[1])
    elif kind == "cls":
        if pos < len(text) and any(lo <= text[pos] <= hi for lo, hi in node[2]) != node[1]:
            yield pos + 1
    elif kind == "ref":
        yield from _ends(rules, rules[node[1]], text, pos)
    elif kind == "alt":
        for option in node[1]:
            yield from _ends(rules, option, text, pos)
    elif kind == "seq":
        def chain(i, at):
            if i == len(node[1]):
                yield at
            else:
                for nxt in _ends(rules, node[1][i], text, at):
                    yield from chain(i + 1, nxt)
        yield from chain(0, pos)
    else:
        _, inner, op = node
        if op in "?*":
            yield pos
        seen, frontier = set(), {pos}
        while frontier:
            step = {e for at in frontier for e in _ends(rules, inner, text, at) if e > at} - seen
            yield from step
            seen |= step
            frontier = step if op != "?" else set()


def accepts(grammar: str, value: object) -> bool:
    text = value if isinstance(value, str) else json.dumps(value)
    rules = parse_gbnf(grammar)
    return any(end == len(text) for end in _ends(rules, rules["root"], text, 0))


# --- the tools' schemas ----------------------------------------------------------------------

def test_nmap_schema_is_built_from_the_constants_validation_uses():
    schema = nmap().parameter_schema()
    assert set(schema) == NmapTool.allowed_parameters
    assert schema["profile"] == {"type": "string", "enum": list(PROFILES)}
    assert schema["ports"] == {"type": "string"}
    assert schema["scripts"]["type"] == "array" and schema["scripts"]["minItems"] == 1
    assert schema["scripts"]["items"] == {"type": "string", "enum": sorted(ALL_CATEGORIES)}


def test_nuclei_schema_is_built_from_the_constants_validation_uses():
    schema = nuclei().parameter_schema()
    assert schema["severity"]["type"] == "array" and schema["severity"]["minItems"] == 1
    assert schema["severity"]["items"] == {"type": "string", "enum": list(SEVERITIES)}
    assert schema["tags"]["type"] == "array" and schema["tags"]["minItems"] == 1
    assert schema["tags"]["items"] == {"type": "string", "enum": sorted(ALL_TAGS)}
    assert schema["port"] == {"type": "integer", "minimum": 1, "maximum": 65535}
    assert schema["scheme"] == {"type": "string", "enum": list(NucleiTool.SCHEMES)}


def test_nuclei_offers_template_ids_only_when_a_curated_list_is_configured():
    assert set(nuclei().parameter_schema()) == NucleiTool.allowed_parameters - {"template_ids"}
    with_list = nuclei(curated=True).parameter_schema()
    assert set(with_list) == NucleiTool.allowed_parameters
    assert with_list["template_ids"] == {"type": "array", "items": {"type": "string"}, "minItems": 1}
    assert nuclei().validate_parameters({"template_ids": [CURATED_ID]}) is not None  # as validation requires


# (tool, parameter, values the schema admits, values of the wrong type or outside the vocabulary)
AGREEMENT = [
    (nmap, "profile", list(PROFILES), [5, ["default"], "nope", None]),
    (nmap, "ports", ["22,80,8000-8100", "443"], [80, ["80"], None]),
    (nmap, "scripts", [[c] for c in sorted(ALL_CATEGORIES)] + [sorted(ALL_CATEGORIES)],
     ["safe", "safe,default", [], ["nope"], [1], None]),
    (nuclei, "severity", [[s] for s in SEVERITIES] + [list(SEVERITIES)],
     ["low", "low,medium", [], ["urgent"], [1], None, list(SEVERITIES) + ["low"]]),
    (nuclei, "tags", [[t] for t in sorted(ALL_TAGS)] + [sorted(ALL_TAGS)[:20]],
     ["detect", "tech,detect", [], ["nope"], [1], None]),
    (nuclei, "port", [1, 80, 65535], ["80", 0, 65536, 8.5, True, [80], None]),
    (nuclei, "scheme", list(NucleiTool.SCHEMES), ["ftp", ["http"], 1, None]),
    (lambda: nuclei(curated=True), "template_ids", [[CURATED_ID]], [CURATED_ID, [], [1], None]),
]


@pytest.mark.parametrize("make, name, good, bad", AGREEMENT, ids=[row[1] for row in AGREEMENT])
def test_parameter_schema_agrees_with_validate_parameters(make, name, good, bad):
    tool = make()
    fragment = parameter_schema_of(tool)[name]
    for value in good:
        assert conforms(fragment, value), (name, value)
        assert tool.validate_parameters({name: value}) is None, (name, value)
    for value in bad:
        assert not conforms(fragment, value), (name, value)
        assert tool.validate_parameters({name: value}) is not None, (name, value)


def test_a_tool_without_the_hook_offers_its_allowed_parameters_unconstrained():
    class Plain:
        name, description, risk, destructive = "plain", "x", Risk.ACTIVE_RECON, False
        allowed_parameters = frozenset({"b", "a"})

    class Loose(Plain):
        def parameter_schema(self):
            return {"a": {"type": "string"}, "not_allowed": {"type": "string"}}
    assert parameter_schema_of(Plain()) == {"a": {}, "b": {}}
    assert parameter_schema_of(Loose()) == {"a": {"type": "string"}}  # never wider than allowed_parameters


# --- the toolbox description and the prompt ----------------------------------------------------

def _describe(tmp_path, *tools):
    wall = ENG.authorization.window[0] + timedelta(hours=1)
    gate = Gate(ENG, resolver=lambda h: ["198.51.100.7"], now=lambda: wall)
    return GatedToolbox(ENG, gate, AuditLog.for_engagement(ENG, tmp_path), list(tools)).describe()


def test_describe_carries_each_tools_parameter_schema(tmp_path):
    described = {t["name"]: t for t in _describe(tmp_path, nmap(), nuclei())}
    assert described["nmap"]["parameter_schema"] == parameter_schema_of(nmap())
    assert described["nmap"]["parameters"] == ["ports", "profile", "scripts"]
    assert described["nuclei"]["parameters"] == ["port", "scheme", "severity", "tags"]  # no curated list
    json.dumps(described)  # data only, nothing callable


def test_the_prompt_shows_type_and_allowed_values_for_each_parameter(tmp_path):
    prompt = build_system_prompt(ENG, _describe(tmp_path, nmap(), nuclei(curated=True)), 5)
    assert "severity (array of: info, low, medium, high, critical)" in prompt
    assert "tags (array of: " + ", ".join(sorted(ALL_TAGS)) + ")" in prompt
    assert "scripts (array of: " + ", ".join(sorted(ALL_CATEGORIES)) + ")" in prompt
    assert "profile (one of: " + ", ".join(PROFILES) + ")" in prompt
    assert "port (integer 1-65535)" in prompt and "scheme (one of: http, https)" in prompt
    assert "ports (string)" in prompt and "template_ids (array of strings)" in prompt
    assert 'an array is a JSON array even for one value (["low"], not "low" and not "low,medium")' in prompt
    without = build_system_prompt(ENG, _describe(tmp_path / "b", nuclei()), 5)
    assert "template_ids" not in without


def test_a_parameter_without_a_schema_is_listed_by_name():
    assert describe_parameter("mode", {}) == "mode"
    assert describe_parameter("n", {"type": "integer"}) == "n (integer)"
    prompt = build_system_prompt(ENG, [{"name": "t", "risk": "ACTIVE_RECON", "description": "d.",
                                        "parameters": ["a", "b"]}], 5)
    assert "Parameters: a; b." in prompt  # a description from before parameter_schema existed


# --- the action schema -------------------------------------------------------------------------

DONE_BRANCH = {
    "type": "object",
    "properties": {"type": {"type": "string", "enum": ["done"]}, "summary": {"type": "string"}},
    "required": ["type", "summary"],
    "additionalProperties": False,
}


def test_every_tool_has_its_own_branch_and_the_done_branch_is_unchanged():
    tools = schemas()
    schema = action_schema(list(tools), tools)
    *branches, done = schema["anyOf"]
    assert done == DONE_BRANCH
    assert [b["properties"]["tool"] for b in branches] == [
        {"type": "string", "enum": ["nmap"]}, {"type": "string", "enum": ["nuclei"]}]
    for branch, name in zip(branches, ("nmap", "nuclei")):
        parameters = branch["properties"]["parameters"]
        assert parameters["type"] == "object" and parameters["additionalProperties"] is False
        assert parameters["properties"] == tools[name] and "required" not in parameters
        assert branch["required"] == ["type", "tool", "target", "parameters", "reason"]
        assert branch["additionalProperties"] is False
    assert conforms(schema, {"type": "done", "summary": "x"})
    assert not conforms(schema, {"type": "done", "summary": "x", "tool": "nmap"})


def test_the_nmap_branch_takes_scripts_from_the_categories_and_profile_from_the_profiles():
    tools = schemas()
    nmap_branch = action_schema(list(tools), tools)["anyOf"][0]["properties"]["parameters"]["properties"]
    assert nmap_branch["scripts"]["type"] == "array"
    assert nmap_branch["scripts"]["items"]["enum"] == sorted(ALL_CATEGORIES)
    assert nmap_branch["profile"]["enum"] == list(PROFILES)


def test_the_nuclei_branch_refuses_strings_where_lists_are_required():
    tools = schemas()
    schema = action_schema(list(tools), tools)
    assert conforms(schema, reply("nuclei"))  # every parameter is optional
    assert conforms(schema, reply("nuclei", severity=["low"], tags=["detect"], port=8080, scheme="https"))
    assert conforms(schema, reply("nuclei", severity=list(SEVERITIES)))
    assert not conforms(schema, reply("nuclei", severity="low"))       # what the model used to send
    assert not conforms(schema, reply("nuclei", severity="low,medium"))
    assert not conforms(schema, reply("nuclei", severity=["urgent"]))
    assert not conforms(schema, reply("nuclei", severity=[]))
    assert conforms(schema, reply("nuclei", tags=["tech", "detect"]))
    assert not conforms(schema, reply("nuclei", tags="detect"))
    assert not conforms(schema, reply("nuclei", tags=["not-a-tag"]))
    assert not conforms(schema, reply("nuclei", port="8080"))
    assert not conforms(schema, reply("nuclei", port=70000))


def test_a_branch_takes_only_its_own_tools_parameters():
    tools = schemas()
    schema = action_schema(list(tools), tools)
    assert conforms(schema, reply("nmap", profile="service", ports="22,80", scripts=["safe"]))
    assert not conforms(schema, reply("nmap", severity=["low"]))      # a nuclei parameter
    assert not conforms(schema, reply("nuclei", profile="service"))   # an nmap parameter
    assert not conforms(schema, reply("nuclei", url="http://198.51.100.7/"))
    assert not conforms(schema, reply("nuclei", template_ids=["x"]))  # not offered without a curated list
    assert not conforms(schema, reply("masscan"))
    assert not conforms(schema, reply("nmap", scripts="safe"))
    assert not conforms(schema, reply("nmap", profile="stealth"))


def test_a_tool_without_a_schema_keeps_a_free_parameters_object():
    schema = action_schema(["nmap", "other"], {"nmap": parameter_schema_of(nmap())})
    other = schema["anyOf"][1]
    assert other["properties"]["tool"]["enum"] == ["other"]
    assert other["properties"]["parameters"] == {"type": "object"}
    assert action_schema([])["anyOf"][0]["properties"]["tool"] == {"type": "string"}


# --- the grammar -------------------------------------------------------------------------------

def test_the_grammar_covers_every_tool_name_and_parameter_key():
    tools = schemas(curated=True)
    grammar = action_grammar(list(tools), tools)
    parse_gbnf(grammar)  # well formed, every rule it names is defined
    for name, parameters in tools.items():
        assert f'"\\"{name}\\""' in grammar
        for key in parameters:
            assert f'"\\"{key}\\"" ws ":" ws' in grammar, key
            assert accepts(grammar, reply(name)), name
    for value in [*SEVERITIES, *ALL_TAGS, *ALL_CATEGORIES, *PROFILES, *NucleiTool.SCHEMES]:
        assert f'"\\"{value}\\""' in grammar, value


def test_the_grammar_admits_what_the_schema_admits_and_refuses_string_lists():
    tools = schemas()
    grammar, schema = action_grammar(list(tools), tools), action_schema(list(tools), tools)
    good = [
        {"type": "done", "summary": "x"},
        reply("nuclei", severity=["low"]),
        reply("nuclei", port=8080, scheme="https", severity=["low", "medium"], tags=["tech", "detect"]),
        reply("nmap", ports="22,80", profile="service", scripts=["safe", "default"]),
        reply("nmap", scripts=["version"]),
    ]
    bad = [
        reply("nuclei", severity="low"),
        reply("nuclei", severity=["urgent"]),
        reply("nuclei", severity=[]),
        reply("nuclei", tags="detect"),
        reply("nuclei", port="8080"),
        reply("nuclei", profile="service"),
        reply("nuclei", template_ids=["x"]),
        reply("nmap", scripts="safe"),
        reply("nmap", profile="stealth"),
        reply("nmap", severity=["low"]),
        reply("masscan"),
        {"type": "done", "summary": "x", "tool": "nmap"},
    ]
    for value in good:
        assert conforms(schema, value) and accepts(grammar, value), value
        assert accepts(grammar, json.dumps(value, indent=1)), value  # whitespace is free
    for value in bad:
        assert not conforms(schema, value) and not accepts(grammar, value), value


def test_the_grammar_wants_parameter_keys_in_name_order_and_only_once():
    tools = schemas()
    grammar = action_grammar(list(tools), tools)
    head = '{"type": "action", "tool": "nuclei", "target": "203.0.113.5", "parameters": '
    tail = ', "reason": "recon"}'
    assert accepts(grammar, head + '{"severity": ["low"], "tags": ["tech"]}' + tail)
    assert not accepts(grammar, head + '{"tags": ["tech"], "severity": ["low"]}' + tail)
    assert not accepts(grammar, head + '{"severity": ["low"], "severity": ["high"]}' + tail)
    assert not accepts(grammar, head + '{"severity": ["low"],}' + tail)


def test_the_grammar_without_parameter_schemas_keeps_a_free_object():
    grammar = action_grammar(["nmap"])
    assert accepts(grammar, reply("nmap", anything={"goes": [1, "two", None]}))
    assert not accepts(grammar, reply("nuclei"))
    assert accepts(action_grammar([]), reply("whatever", x=1))
    empty = action_grammar(["t"], {"t": {}})
    assert accepts(empty, reply("t")) and not accepts(empty, reply("t", x=1))


@pytest.mark.parametrize("tools", [
    {"t": {'bad"key': {"type": "string"}}},
    {"t": {"k": {"type": "string", "enum": ["fine", "back\\slash"]}}},
    {"t": {"k": {"type": "array", "items": {"type": "string", "enum": ["new\nline"]}}}},
])
def test_the_grammar_refuses_a_key_or_value_it_cannot_quote(tools):
    with pytest.raises(LLMConfigError, match="cannot be expressed in the grammar"):
        action_grammar(["t"], tools)
    action_schema(["t"], tools)  # the schema has no quoting to get wrong


# --- the adapter -------------------------------------------------------------------------------

def test_the_adapter_builds_schema_and_grammar_from_the_tool_parameters():
    tools = schemas()
    ollama = LocalLLM("m", tool_names=list(tools), tool_parameters=tools)
    assert ollama._schema == action_schema(list(tools), tools) and ollama._grammar is None
    llamacpp = LocalLLM("m", endpoint="http://127.0.0.1:8080", runtime="llamacpp", tool_names=list(tools))
    assert llamacpp._grammar == action_grammar(list(tools))
    llamacpp.set_tool_parameters(tools)
    assert llamacpp._grammar == action_grammar(list(tools), tools)
    assert llamacpp._schema == action_schema(list(tools), tools)
