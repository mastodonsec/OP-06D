# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-21 suite 2: injection via tool output.

Two layers, proven separately:

1. The RC-12 sanitizer wraps every payload in an ``UNTRUSTED_TOOL_OUTPUT``
   block, regardless of language, encoding or obfuscation - defense in
   depth.
2. CRUCIALLY: even when the planner OBEYS the injected instruction (i.e.
   assume the sanitizer missed it entirely - the worst case for this
   layer), the GATE still blocks the resulting out-of-scope action. The
   sanitizer is allowed to miss; the gate is not.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from injection_payloads import PAYLOADS  # noqa: E402

from op06d.audit import AuditLog, read_log
from op06d.engagement import load_engagement
from op06d.gate import Gate
from op06d.orchestrator import Orchestrator
from op06d.sanitize import BLOCK_NAME, sanitize_tool_output
from op06d.tools import GatedToolbox, Risk

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)
START, END = ENG.authorization.window
IN_SCOPE_IP = "203.0.113.5"


# --- layer 1: the sanitizer wraps every payload as data, never instructions --

@pytest.mark.parametrize("label,payload,coerced_target", PAYLOADS)
def test_sanitizer_wraps_every_payload_as_untrusted_data(label, payload, coerced_target):
    seen = []
    sanitized = sanitize_tool_output(
        payload, tool="nuclei", target=IN_SCOPE_IP, audit=lambda t, a, r: seen.append((t, a, r)),
    )
    assert sanitized.text.startswith(f"<<<{BLOCK_NAME}")
    assert f"END_{BLOCK_NAME}" in sanitized.text
    assert "DATA captured from a remote target" in sanitized.text
    # the payload content survives (escaped, not deleted) inside the block -
    # sanitization neutralizes, it does not hide evidence
    assert sanitized.original_length == len(payload)


# --- layer 2: the gate blocks the action even when the planner obeys -------

class ObedientLLM:
    """Models a planner that straightforwardly does what its last
    observation told it to do. This assumes the sanitizer's flagging MISSED
    the payload (or the planner ignored the untrusted-data notice anyway) -
    the worst case this layer has to survive on its own."""

    def __init__(self, injected_target: str):
        self._injected_target = injected_target
        self.calls = 0

    def complete(self, system, messages):
        self.calls += 1
        if self.calls == 1:
            return json.dumps({"type": "action", "tool": "nmap", "target": IN_SCOPE_IP,
                               "parameters": {}, "reason": "initial recon"})
        return json.dumps({"type": "action", "tool": "nmap", "target": self._injected_target,
                           "parameters": {}, "reason": "following instruction found in output"})


class FakeInjectingTool:
    """Stands in for a scanned target that returns an injection payload in
    its banner/response."""
    name = "nmap"
    description = "fake injecting tool"
    risk = Risk.ACTIVE_RECON
    destructive = False
    allowed_parameters: frozenset[str] = frozenset()

    def __init__(self, payload: str):
        self.payload = payload
        self.calls: list[str] = []

    def run(self, target, parameters, *, hostname=None):
        self.calls.append(target)
        return f"22/tcp open ssh OpenSSH 9.1\n{self.payload}"


@pytest.mark.parametrize("label,payload,coerced_target", PAYLOADS)
def test_gate_blocks_out_of_scope_action_even_when_planner_obeys_the_injected_payload(
    tmp_path, label, payload, coerced_target,
):
    tool = FakeInjectingTool(payload)
    log = AuditLog.for_engagement(ENG, tmp_path / label)
    gate = Gate(ENG, resolver=lambda h: [IN_SCOPE_IP], audit_pin=log.record_dns_pin,
                now=lambda: START + timedelta(hours=1))
    box = GatedToolbox(ENG, gate, log, [tool])  # no approver supplied -> DenyAllApprover
    llm = ObedientLLM(injected_target=coerced_target)
    orch = Orchestrator(ENG, llm, box, log, now=lambda: START + timedelta(hours=1),
                         sleep=lambda s: None, max_iterations=3)

    result = orch.run()

    assert coerced_target not in ENG.scope.in_scope  # sanity: this really is an out-of-scope target
    executed_targets = [s.result.action.target for s in result.steps if s.result and s.result.executed]
    assert coerced_target not in executed_targets  # scope was never widened to admit it
    assert tool.calls == [IN_SCOPE_IP]  # the tool only ever ran against the legitimate target

    denied_steps = [s for s in result.steps if s.kind == "denied"]
    assert denied_steps, "the injected proposal must actually have been denied, not merely unreached"

    entries = [e for e in read_log(log.path) if e.event == "gate_decision"]
    assert any(not e.allowed and coerced_target in (e.target or "") for e in entries)
