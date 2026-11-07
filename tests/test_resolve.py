"""Unit tests for the RC-23 resolve-once pin (``redcell.resolve.DnsPinner``)."""

import ast
from pathlib import Path

import pytest

from redcell.resolve import DnsPinner

ROOT = Path(__file__).parent.parent
SRC = ROOT / "src" / "redcell"


class CountingResolver:
    """Returns ``answers.pop(0)`` for a NEW host, repeats the last answer for a
    host it has already seen (as a real resolver would), and records every
    call so tests can assert it was invoked exactly once per host."""

    def __init__(self, **per_host):
        self.per_host = {h: list(v) for h, v in per_host.items()}
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        answers = self.per_host[host]
        return answers.pop(0) if len(answers) > 1 else answers[0]


def test_second_resolve_for_the_same_host_does_not_call_the_resolver_again():
    r = CountingResolver(**{"app.acme.com": [["198.51.100.7"]]})
    pinner = DnsPinner(r)
    assert pinner.resolve("app.acme.com") == ("198.51.100.7",)
    assert pinner.resolve("app.acme.com") == ("198.51.100.7",)
    assert pinner.resolve("app.acme.com") == ("198.51.100.7",)
    assert r.calls == ["app.acme.com"]  # exactly one real lookup


def test_rebinding_after_the_pin_is_ignored():
    # The resolver would answer differently on a second call (DNS rebinding);
    # the pin must mean the second answer is never even requested, let alone used.
    r = CountingResolver(**{"app.acme.com": [["198.51.100.7"], ["10.0.0.99"]]})
    pinner = DnsPinner(r)
    first = pinner.resolve("app.acme.com")
    second = pinner.resolve("app.acme.com")
    assert first == second == ("198.51.100.7",)
    assert r.calls == ["app.acme.com"]  # the "10.0.0.99" answer was never fetched


def test_different_hosts_are_pinned_independently():
    r = CountingResolver(**{"a.example": [["1.2.3.4"]], "b.example": [["5.6.7.8"]]})
    pinner = DnsPinner(r)
    assert pinner.resolve("a.example") == ("1.2.3.4",)
    assert pinner.resolve("b.example") == ("5.6.7.8",)
    assert pinner.resolve("a.example") == ("1.2.3.4",)
    assert sorted(r.calls) == ["a.example", "b.example"]


def test_hostname_is_normalized_before_caching():
    r = CountingResolver(**{"APP.ACME.COM.": [["198.51.100.7"]]})
    pinner = DnsPinner(r)
    assert pinner.resolve("APP.ACME.COM.") == ("198.51.100.7",)
    # the resolver itself is called with the caller's original casing...
    assert r.calls == ["APP.ACME.COM."]
    # ...but the cache key is normalized, so a different-cased repeat is a hit
    assert pinner.resolve("app.acme.com") == ("198.51.100.7",)
    assert r.calls == ["APP.ACME.COM."]  # still just the one lookup


def test_on_pin_is_called_exactly_once_per_host_with_the_resolved_addresses():
    seen = []
    pinner = DnsPinner(lambda h: ["198.51.100.7"], on_pin=lambda host, ips: seen.append((host, ips)))
    pinner.resolve("app.acme.com")
    pinner.resolve("app.acme.com")
    pinner.resolve("app.acme.com")
    assert seen == [("app.acme.com", ("198.51.100.7",))]


def test_on_pin_failure_propagates_from_resolve():
    def boom(host, ips):
        raise OSError("disk full")

    pinner = DnsPinner(lambda h: ["198.51.100.7"], on_pin=boom)
    with pytest.raises(OSError, match="disk full"):
        pinner.resolve("app.acme.com")


def test_resolver_failure_propagates_and_is_not_cached():
    calls = []

    def flaky(host):
        calls.append(host)
        if len(calls) == 1:
            raise OSError("NXDOMAIN")
        return ["198.51.100.7"]

    pinner = DnsPinner(flaky)
    with pytest.raises(OSError):
        pinner.resolve("app.acme.com")
    # a failed lookup must not be pinned as "no addresses" - the next attempt
    # tries DNS again rather than being stuck denying forever on a blip
    assert pinner.resolve("app.acme.com") == ("198.51.100.7",)
    assert len(calls) == 2


def test_pinned_snapshot_reflects_resolved_hosts_only():
    pinner = DnsPinner(lambda h: ["198.51.100.7"])
    assert pinner.pinned() == {}
    pinner.resolve("app.acme.com")
    assert pinner.pinned() == {"app.acme.com": ("198.51.100.7",)}


# --- structure: resolve.py is the only place DNS happens --------------------

def test_nothing_outside_resolve_py_imports_socket():
    """``resolve.py`` is the only module allowed to perform DNS. If another
    module starts importing ``socket``, it can do its own, unaudited,
    un-pinned resolution - exactly the RC-23 gap this module exists to close."""
    offenders = []
    for path in SRC.glob("*.py"):
        if path.name == "resolve.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name == "socket" for a in node.names):
                offenders.append(path.name)
            if isinstance(node, ast.ImportFrom) and node.module == "socket":
                offenders.append(path.name)
    assert offenders == []


def test_only_gate_and_scope_import_redcell_resolve():
    importers = set()
    for path in SRC.glob("*.py"):
        if path.name == "resolve.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            if any(n == "redcell.resolve" for n in names):
                importers.add(path.name)
    # cli.py (RC-29) is the run wiring that constructs the Gate: it imports
    # Resolver/system_resolver only to plumb a resolver through to Gate(...)
    # (and to accept a test's fake resolver as an injection point) - it does
    # no DNS lookup of its own.
    assert importers == {"gate.py", "scope.py", "cli.py"}
