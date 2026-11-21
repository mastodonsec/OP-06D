# SPDX-License-Identifier: AGPL-3.0-or-later
"""End to end on the real tools: a scripted planner (no LLM, no network)
drives the real orchestrator, gate, tools, sanitizer and audit log.

The planner proposes two allowed scans, one out-of-scope target (the gate
must deny it), one intrusive selection (declined: no approver), then
finishes.

Runs inside the scanner:

    python3 /lab/steps/end_to_end.py [--audit-dir /captures/e2e-audit]
        [--engagement /captures/engagement.now.yaml] [--json]

Prints the termination, each step, the audit log and what the planner saw
after the first scan. ``--json`` prints the facts lab/validation_harness.py
judges.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from typing import Any

OUT_OF_SCOPE = "1.1.1.1"
WRAPPED = re.compile(r"^<<<UNTRUSTED_TOOL_OUTPUT id=(\w+) .*?^<<<END_UNTRUSTED_TOOL_OUTPUT id=\1>>>\s*$", re.S | re.M)


def act(tool: str, target: str, **params: Any) -> str:
    return json.dumps({"type": "action", "tool": tool, "target": target, "parameters": params, "reason": "lab e2e"})


def scripted_replies() -> list[str]:
    return [
        act("nmap", "172.31.77.11", profile="service", ports="80"),
        act("nuclei", "dvwa.lab"),
        act("nmap", OUT_OF_SCOPE),                          # out of scope: the gate must deny
        act("nuclei", "dvwa.lab", tags=["default-login"]),  # INTRUSIVE: no approver -> declined
        json.dumps({"type": "done", "summary": "lab e2e finished"}),
    ]


class ScriptedLLM:
    def __init__(self, replies: list[str]) -> None:
        self.replies, self.seen = list(replies), []

    def complete(self, system, messages):
        self.seen.append(messages[-1]["content"])
        return self.replies.pop(0)


def plain(v: Any) -> Any:
    try:
        return ast.literal_eval(v) if isinstance(v, str) else v
    except (ValueError, SyntaxError):
        return v


def planner_view_facts(seen: list[str]) -> dict:
    """What the planner saw after the first scan: the orchestrator prefixes one
    "Result of step N ... untrusted data." line, then the sanitizer's block;
    the tool output must sit inside it, and no raw nmap XML may reach it."""
    view = seen[1] if len(seen) > 1 else None
    return {
        "planner_view_wrapped": view is not None and bool(WRAPPED.search(view)),
        "planner_view_has_raw_xml": view is not None and ("<?xml" in view or "<nmaprun" in view),
        "planner_view_head": view[:1200] if view is not None else "",
    }


def facts(result, entries, audit_verified, audit_path, seen: list[str]) -> dict:
    steps = []
    for s in result.steps:
        d = s.result.decision if s.result else None
        steps.append({"iteration": s.iteration, "kind": s.kind,
                      "stage": d.stage if d else None, "reason": (d.reason[:120] if d else None)})
    return {
        "termination": result.termination.value,
        "iterations": result.iterations,
        "steps": steps,
        "audit_verified": audit_verified,
        "audit_path": str(audit_path),
        "dns_pinned": [plain(e.target) for e in entries if e.event == "dns_pinned"],
        "denied_out_of_scope": any(e.event == "gate_decision" and e.allowed is False
                                   and plain(e.target) == OUT_OF_SCOPE for e in entries),
        "executed_out_of_scope": any(e.event == "action_executed" and plain(e.target) == OUT_OF_SCOPE
                                     for e in entries),
        **planner_view_facts(seen),
    }


def format_report(f: dict, entries) -> str:
    lines = [f"termination: {f['termination']} iterations: {f['iterations']}"]
    for s in f["steps"]:
        decision = f"{s['stage']}: {s['reason'][:90]}" if s["stage"] else ""
        lines.append(f"  step {s['iteration']}: {s['kind']:14} {decision}".rstrip())
    lines.append(f"audit entries verified: {f['audit_verified']}")
    for e in entries:
        lines.append(f"  #{e.seq:<3} {e.event:16} tool={e.tool or '-':12} target={e.target or '-':18} "
                     f"allowed={e.allowed}  {(e.reason or '')[:70]}")
    lines += ["", "What the planner saw after the first scan (sanitized, wrapped):", "", f["planner_view_head"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scripted-planner end-to-end run in the lab.")
    parser.add_argument("--audit-dir", default="/captures/e2e-audit", help="where the audit log goes")
    parser.add_argument("--engagement", default="/captures/engagement.now.yaml", help="the generated engagement")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)

    from op06d.audit import AuditLog, read_log, verify_log
    from op06d.engagement import load_engagement
    from op06d.gate import Gate
    from op06d.orchestrator import Orchestrator
    from op06d.tools import GatedToolbox, default_tools

    eng = load_engagement(args.engagement)
    log = AuditLog.for_engagement(eng, args.audit_dir)
    box = GatedToolbox(eng, Gate(eng, audit_pin=log.record_dns_pin), log,
                       default_tools(eng, nuclei_template_dir="/opt/nuclei-templates", nuclei_templates_pin="v10.5.1"))
    llm = ScriptedLLM(scripted_replies())
    result = Orchestrator(eng, llm, box, log, max_iterations=10).run()
    entries = read_log(log.path)
    f = facts(result, entries, verify_log(log.path), log.path, llm.seen)
    print(json.dumps(f) if args.json else format_report(f, entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
