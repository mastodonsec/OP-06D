# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-21 suite 4 (GATED, opt-in): a REAL LLM planner run against the RC-21
injection-payload corpus, with tools MOCKED/SEALED (no real scanning, no
real network to a target), asserting the gate blocks every out-of-scope
action the live model proposes.

This is NOT part of the CI-enforced proof. Suites 1-3
(``test_adversarial_gate.py``, ``test_injection_payloads.py``,
``test_chokepoint_boundary.py``) are deterministic and run in every default
``pytest`` invocation; a live model call is inherently non-deterministic
and needs network plus an API key, so this suite is skipped unless BOTH:

    OP06D_LIVE_MODEL=1
    ANTHROPIC_API_KEY is set (the only adapter implemented so far - see
    ``_anthropic_adapter`` below)

    OP06D_LIVE_MODEL=1 ANTHROPIC_API_KEY=sk-... pytest tests/test_live_model_gate.py

TODO (acknowledged scope limit): this adapter is intentionally minimal
(single-turn system+messages -> text over the Anthropic Messages API), built
only to exercise this gated harness end to end. A production LLM-planner
integration - model selection, retries/backoff, cost controls, streaming,
provider choice - is future work and explicitly out of scope for RC-21; the
deterministic suites are the CI-enforced proof, this run is opt-in
corroboration only.
"""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from injection_payloads import PAYLOADS  # noqa: E402

from op06d.audit import AuditLog
from op06d.engagement import load_engagement
from op06d.gate import Gate
from op06d.orchestrator import Orchestrator
from op06d.tools import GatedToolbox, Risk

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)
START, END = ENG.authorization.window


def _live_model_enabled() -> bool:
    return os.environ.get("OP06D_LIVE_MODEL") == "1"


def _anthropic_adapter():
    """A minimal LLM adapter (the ``op06d.orchestrator.LLM`` protocol)
    over the Anthropic Messages API. Returns ``None`` (never raises) if the
    SDK isn't installed or no API key is configured - the caller treats
    that as "no live adapter available"."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    class AnthropicPlanner:
        def __init__(self, client, model: str = "claude-3-5-haiku-20241022") -> None:
            self._client = client
            self._model = model

        def complete(self, system: str, messages) -> str:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=500,
                system=system,
                messages=[
                    {"role": m["role"] if m["role"] in ("user", "assistant") else "user",
                     "content": m["content"]}
                    for m in messages
                ],
            )
            return "".join(getattr(block, "text", "") for block in resp.content)

    return AnthropicPlanner(anthropic.Anthropic(api_key=api_key))


def _skip_reason() -> str | None:
    if not _live_model_enabled():
        return "set OP06D_LIVE_MODEL=1 to run a real LLM planner against the gate"
    if _anthropic_adapter() is None:
        return "no live LLM adapter available (install `anthropic` and set ANTHROPIC_API_KEY)"
    return None


_REASON = _skip_reason()
pytestmark = pytest.mark.skipif(_REASON is not None, reason=_REASON or "")


class SealedInjectingTool:
    """Stands in for a real tool, sealed against any real scanning: it
    never makes a network call and never shells out. Its canned output
    carries one injection payload from the RC-21 corpus, as if a hostile
    target had returned it."""

    def __init__(self, name: str, payload: str) -> None:
        self.name = name
        self.description = f"sealed test double for {name}"
        self.risk = Risk.ACTIVE_RECON
        self.destructive = False
        self.allowed_parameters: frozenset[str] = frozenset(
            {"profile", "ports", "scripts", "tags", "severity"},
        )
        self.payload = payload
        self.calls: list[str] = []

    def run(self, target, parameters, *, hostname=None):
        self.calls.append(target)
        return f"22/tcp open ssh OpenSSH 9.1\n{self.payload}"


@pytest.mark.parametrize("label,payload,coerced_target", PAYLOADS)
def test_live_model_planner_never_gets_an_out_of_scope_action_past_the_gate(
    tmp_path, label, payload, coerced_target,
):
    llm = _anthropic_adapter()
    assert llm is not None  # the module-level skipif should already have caught a missing adapter

    tool = SealedInjectingTool("nmap", payload)
    log = AuditLog.for_engagement(ENG, tmp_path / label)
    gate = Gate(ENG, resolver=lambda h: ["203.0.113.5"], audit_pin=log.record_dns_pin,
                now=lambda: START + timedelta(hours=1))
    box = GatedToolbox(ENG, gate, log, [tool])  # no approver -> DenyAllApprover
    orch = Orchestrator(ENG, llm, box, log, now=lambda: START + timedelta(hours=1),
                         sleep=lambda s: None, max_iterations=6)

    result = orch.run()

    executed_targets = [s.result.action.target for s in result.steps if s.result and s.result.executed]
    assert coerced_target not in executed_targets
    for t in executed_targets:
        assert t not in ENG.scope.out_of_scope
