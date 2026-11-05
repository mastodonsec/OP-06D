"""The gated tool layer: the only way from the loop to a tool (RC-7, RC-8).

``GatedToolbox`` owns the tools. It exposes exactly one way to run one:
``execute(action)``, which always goes

    validate -> Gate.check -> (approval, if risky) -> run -> sanitize -> record

There is no accessor that returns a tool, and the tools live in a name-mangled
private attribute, so code holding a toolbox (the orchestrator loop) cannot
invoke a tool without passing the gate. Python cannot make this absolute, so
the property is also asserted by tests (a denied action's tool is never run).

Sanitization happens here too: ``execute`` returns the raw output (for
evidence, RC-15/16) alongside the sanitized, wrapped version, and the loop only
ever puts the sanitized version in the planning context.

Risk and approval (RC-8 hook)
-----------------------------
Every tool declares a ``Risk``. An action whose tool risk is at or above the
toolbox's ``approval_threshold`` pauses for operator approval *after* the gate
allows it (so the operator is never asked about something the gate would
refuse). Declined, timed-out, errored or unrecordable approvals all mean the
action does not run. The default threshold is ``Risk.INTRUSIVE``; see
docs/orchestrator.md for why nothing in the recon MVP crosses it.

Tool wrappers (RC-13/14) must: use argv, never a shell; declare only
``allowed_parameters`` that cannot carry a second target (the gate checks
``target`` only); and apply their own request-rate flag from ``max_rps``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Iterable, Mapping, Protocol

from redcell.audit import (
    EVENT_APPROVAL,
    EVENT_INJECTION_FLAG,
    AuditError,
    AuditLog,
)
from redcell.engagement import Engagement
from redcell.gate import ALLOWED, DENIED_AUDIT, DENIED_RATE, Gate, GateDecision
from redcell.sanitize import SanitizedOutput, sanitize_tool_output

STAGE_TOOL = "tool"  # denied before the gate: unknown tool, bad parameters, destructive
STAGE_APPROVAL = "approval"

MAX_PARAMETERS_CHARS = 4_000
MAX_TARGET_CHARS = 253


class Risk(IntEnum):
    PASSIVE_RECON = 0  # reads public data, never touches the target
    ACTIVE_RECON = 1  # probes the target in ways a normal client could (nmap, nuclei default templates)
    INTRUSIVE = 2  # may degrade a service or send attack-shaped traffic (fuzzing, intrusive templates)
    EXPLOIT = 3  # attempts to gain access or change state


class Tool(Protocol):
    name: str
    description: str
    risk: Risk
    destructive: bool
    allowed_parameters: frozenset[str]

    def run(self, target: str, parameters: Mapping[str, Any]) -> object: ...


class ApprovalHook(Protocol):
    """RC-8 implements this (CLI prompt). It must enforce its own timeout and
    return False on timeout; any exception is treated as a decline."""

    def approve(self, request: "ApprovalRequest") -> bool: ...


class DenyAllApprover:
    """Default: nothing is approved unless a real hook is supplied."""

    def approve(self, request: "ApprovalRequest") -> bool:
        return False


@dataclass(frozen=True)
class ToolAction:
    tool: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class ApprovalRequest:
    iteration: int
    tool: str
    target: str
    parameters: dict[str, Any]
    risk: Risk
    reason: str


class Outcome(str, Enum):
    EXECUTED = "executed"
    TOOL_ERROR = "tool_error"  # the tool ran and raised
    DENIED = "denied"
    RATE_LIMITED = "rate_limited"
    DECLINED = "declined"


@dataclass(frozen=True)
class ExecutionResult:
    action: ToolAction
    outcome: Outcome
    decision: GateDecision
    executed: bool
    raw_output: object = None  # evidence only: never goes into the planning context
    sanitized: SanitizedOutput | None = None  # the only form the planner may see
    status: str = ""
    recorded: bool = True  # False if the execution record could not be written


def _decision(target: object, reason: str, stage: str) -> GateDecision:
    label = target if isinstance(target, str) else f"<{type(target).__name__}>"
    return GateDecision(label, False, reason, stage)


def _json_safe(value: object, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, (list, tuple)):
        return all(_json_safe(v, depth + 1) for v in value)
    return False


class GatedToolbox:
    def __init__(
        self,
        engagement: Engagement,
        gate: Gate,
        log: AuditLog,
        tools: Iterable[Tool],
        *,
        approver: ApprovalHook | None = None,
        approval_threshold: Risk = Risk.INTRUSIVE,
    ) -> None:
        self.__tools: dict[str, Tool] = {}
        for t in tools:
            if t.name in self.__tools:
                raise ValueError(f"duplicate tool name {t.name!r}")
            self.__tools[t.name] = t
        self.__gate = gate
        self.__log = log
        self.__destructive_ok = bool(engagement.intensity.destructive)
        self.__approver: ApprovalHook = approver or DenyAllApprover()
        self.__threshold = approval_threshold

    # -- read-only description for the system prompt (no callables) ----------
    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "risk": Risk(t.risk).name,
                "parameters": sorted(t.allowed_parameters),
            }
            for t in self.__tools.values()
        ]

    # -- the only door --------------------------------------------------------
    def execute(self, action: ToolAction, *, iteration: int) -> ExecutionResult:
        """Gate, (approve), run, sanitize, record. Never raises."""
        try:
            return self.__execute(action, iteration)
        except Exception as exc:  # fail closed: nothing ran unless we got past the gate
            return ExecutionResult(
                action, Outcome.DENIED,
                _decision(action.target if isinstance(action, ToolAction) else None,
                          f"deny: toolbox error ({type(exc).__name__})", STAGE_TOOL),
                executed=False,
            )

    def __sink(self, action: ToolAction, iteration: int, event: str | None = None):
        kwargs = {} if event is None else {"event": event}
        return self.__log.sink(
            tool=action.tool,
            parameters={"iteration": iteration, "params": action.parameters},
            **kwargs,
        )

    def __execute(self, action: ToolAction, iteration: int) -> ExecutionResult:
        sink = self.__sink(action, iteration)

        problem = self.__validate(action)
        if problem:
            return self.__refuse(action, sink, f"deny: {problem}")
        tool = self.__tools[action.tool]
        if tool.destructive and not self.__destructive_ok:
            return self.__refuse(
                action, sink,
                "deny: tool is destructive and the engagement does not permit destructive actions",
            )

        decision = self.__gate.check(action.target, audit=sink)  # <- the gate
        if not decision.allowed:
            outcome = Outcome.RATE_LIMITED if decision.stage == DENIED_RATE else Outcome.DENIED
            return ExecutionResult(action, outcome, decision, executed=False)
        assert decision.stage == ALLOWED

        if tool.risk >= self.__threshold and not self.__approved(action, tool, iteration):
            return ExecutionResult(
                action, Outcome.DECLINED,
                GateDecision(decision.target, False, "deny: operator approval not granted",
                             STAGE_APPROVAL, decision.resolved_ips),
                executed=False,
            )

        outcome, raw, status = Outcome.EXECUTED, None, "ok"
        try:
            raw = tool.run(action.target, dict(action.parameters))
        except Exception as exc:
            outcome, raw, status = Outcome.TOOL_ERROR, f"tool error: {type(exc).__name__}: {exc}", "error"

        sanitized = sanitize_tool_output(
            raw, tool=action.tool, target=action.target,
            audit=self.__sink(action, iteration, EVENT_INJECTION_FLAG),
        )
        recorded = True
        try:
            self.__log.record_execution(
                tool=action.tool, target=action.target,
                parameters={"iteration": iteration, "params": action.parameters},
                status=status,
                detail=f"{sanitized.original_length} chars sha256={sanitized.sha256}"
                       + (" flagged" if sanitized.flagged else ""),
            )
        except AuditError:
            recorded = False
        return ExecutionResult(action, outcome, decision, True, raw, sanitized, status, recorded)

    def __refuse(self, action: ToolAction, sink, reason: str) -> ExecutionResult:
        stage = STAGE_TOOL
        try:
            sink(action.target if isinstance(action.target, str) else repr(action.target), False, reason)
        except Exception:
            stage, reason = DENIED_AUDIT, "deny: audit logging failed"
        return ExecutionResult(
            action, Outcome.DENIED, _decision(action.target, reason, stage), executed=False
        )

    def __validate(self, action: ToolAction) -> str | None:
        if not isinstance(action, ToolAction):
            return "action is not a ToolAction"
        if not isinstance(action.tool, str) or action.tool not in self.__tools:
            return "unknown tool"
        t = action.target
        if (not isinstance(t, str) or not t or len(t) > MAX_TARGET_CHARS
                or t != t.strip() or not t.isprintable()):
            return "malformed target"
        params = action.parameters
        if not isinstance(params, dict) or not all(isinstance(k, str) for k in params):
            return "parameters must be an object with string keys"
        extra = set(params) - set(self.__tools[action.tool].allowed_parameters)
        if extra:
            return f"parameters not allowed for {action.tool}: {sorted(extra)}"
        if not all(_json_safe(v) for v in params.values()):
            return "parameter values must be strings, numbers, booleans or lists of those"
        if len(json.dumps(params, default=repr)) > MAX_PARAMETERS_CHARS:
            return "parameters too large"
        return None

    def __approved(self, action: ToolAction, tool: Tool, iteration: int) -> bool:
        request = ApprovalRequest(
            iteration, action.tool, action.target, dict(action.parameters),
            Risk(tool.risk), action.reason,
        )
        try:
            granted = self.__approver.approve(request) is True
        except Exception:
            granted = False
        reason = (
            f"operator {'approved' if granted else 'declined'} {Risk(tool.risk).name} action"
        )
        try:  # an approval that cannot be recorded does not count
            self.__log.record(
                EVENT_APPROVAL, target=action.target, tool=action.tool,
                parameters={"iteration": iteration, "params": action.parameters},
                allowed=granted, reason=reason,
            )
        except AuditError:
            return False
        return granted
