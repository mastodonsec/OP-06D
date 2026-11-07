"""The gated tool layer: the only way from the loop to a tool (RC-7, RC-8, RC-13).

``GatedToolbox`` owns the tools. It exposes exactly one way to run one:
``execute(action)``, which always goes

    validate -> Gate.check -> (approval, if risky) -> run -> sanitize -> record

There is no accessor that returns a tool, and the tools live in a name-mangled
private attribute, so code holding a toolbox (the orchestrator loop) cannot
invoke a tool without passing the gate. Python cannot make this absolute, so
the property is also asserted by tests (a denied action's tool is never run).
Concrete tools (e.g. ``redcell.nmap_tool``) are constructed only by
``default_tools`` below; nothing else imports them.

Sanitization happens here too: ``execute`` returns the raw output (for
evidence, RC-15/16) alongside the sanitized, wrapped version of the tool's
findings, and the loop only ever puts the sanitized version in the planning
context.

Per-invocation risk, destructiveness and redaction
--------------------------------------------------
A tool may refine its declared ``risk``/``destructive`` for one concrete
invocation by implementing ``risk_for(parameters)`` / ``destructive_for(
parameters)`` (nmap: an intrusive NSE category raises the risk). The toolbox
uses the invocation's value for the approval threshold and the destructive
check, and fails closed (EXPLOIT / destructive) if those hooks raise.

Parameters are redacted before they reach ANY audit record or approval
request: keys the tool lists in ``sensitive_parameters`` and any key that looks
like a secret (password, token, key, ...) are replaced by ``[REDACTED]``. This
includes actions the toolbox refuses, so a secret in a rejected action cannot
leak into the client-facing log either.

Approval (RC-8 hook)
--------------------
An action whose invocation risk is at or above ``approval_threshold`` pauses for
operator approval *after* the gate allows it. Declined, timed-out, errored or
unrecordable approvals all mean the action does not run. Default threshold:
``Risk.INTRUSIVE``; see docs/orchestrator.md.

Tool wrappers must: use argv, never a shell; declare only ``allowed_parameters``
that cannot carry a second target (the gate checks ``target`` only); validate
parameter values in ``validate_parameters``; and bound the traffic the tool
itself sends using the engagement's ``max_rps``.

RC-23 (resolve-once): ``__execute`` never hands a tool the hostname it was
given. If ``action.target`` was a hostname, the gate already resolved and
pinned it (``redcell.resolve.DnsPinner``) to decide scope, and
``GateDecision.resolved_ips`` carries that pinned address; ``__execute`` scans
*that* address, passing the original hostname separately only as the
``hostname=`` keyword (for vhost/SNI correctness - nuclei). A tool must never
perform its own DNS lookup; this is what closes the TOCTOU between "the gate
approved this address" and "the tool touched that address".
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
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
from redcell.sanitize import SanitizedOutput, sanitize_tool_output, sha256_of

STAGE_TOOL = "tool"  # denied before the gate: unknown tool, bad parameters, destructive
STAGE_APPROVAL = "approval"

MAX_PARAMETERS_CHARS = 4_000
MAX_TARGET_CHARS = 253

REDACTED = "[REDACTED]"
# Over-redaction is the safe direction: a harmless key lost from the log is
# better than a credential in client-facing evidence.
_SECRET_KEY_RE = re.compile(
    r"pass|secret|token|key|cred|auth|cookie|session|bearer|signature|otp", re.I
)


class Risk(IntEnum):
    PASSIVE_RECON = 0  # reads public data, never touches the target
    ACTIVE_RECON = 1  # probes the target in ways a normal client could (nmap, nuclei default templates)
    INTRUSIVE = 2  # may degrade a service or send attack-shaped traffic (fuzzing, intrusive templates)
    EXPLOIT = 3  # attempts to gain access or change state


class Tool(Protocol):
    """What a tool must provide. Optional hooks (looked up by name):

    ``sensitive_parameters: frozenset[str]``
    ``validate_parameters(parameters) -> str | None`` (a problem, or None)
    ``risk_for(parameters) -> Risk``
    ``destructive_for(parameters) -> bool``
    """

    name: str
    description: str
    risk: Risk  # baseline; risk_for may raise it for a specific invocation
    destructive: bool
    allowed_parameters: frozenset[str]

    def run(self, target: str, parameters: Mapping[str, Any], *, hostname: str | None = None) -> object: ...
    # ``target``: the address to actually scan - the IP the gate resolved and
    # approved (RC-23), or the original target unchanged if it was already an
    # IP/CIDR. ``hostname``: the original hostname when ``target`` is its
    # pinned IP, else None. A tool must never resolve ``target`` itself; it
    # may use ``hostname`` only for vhost/SNI correctness (nuclei), never as
    # something to connect to or re-resolve.


@dataclass(frozen=True)
class ToolOutput:
    """A structured tool result.

    ``findings`` is parsed, structured data: it is what is sanitized and shown
    to the planner (and later normalized by RC-15). ``raw`` is the tool's
    unmodified output, kept only as evidence. ``status`` is "ok" or an error
    code; a non-ok status is a tool error the loop handles, not an exception.
    """

    findings: object
    raw: object = None
    status: str = "ok"


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
    parameters: dict[str, Any]  # redacted
    risk: Risk  # this invocation's risk
    reason: str


class Outcome(str, Enum):
    EXECUTED = "executed"
    TOOL_ERROR = "tool_error"  # the tool ran and failed or raised
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
    findings: object = None  # structured, unsanitized: for RC-15 normalization only
    risk: Risk | None = None  # the invocation's risk


def redact_parameters(
    parameters: object, sensitive: Iterable[str] = ()
) -> dict[str, Any]:
    """A copy of ``parameters`` that is safe to write to the audit log."""
    if not isinstance(parameters, dict):
        return {"_invalid_parameters": True}
    sens = {str(s).lower() for s in sensitive}
    out: dict[str, Any] = {}
    for k, v in parameters.items():
        key = k if isinstance(k, str) else repr(k)
        out[key] = REDACTED if (key.lower() in sens or _SECRET_KEY_RE.search(key)) else v
    return out


# --- helpers shared by concrete tools (nmap, nuclei) --------------------------

_TARGET_CHARS_RE = re.compile(r"[A-Za-z0-9:][A-Za-z0-9.:/_-]*")


def clip(value: object, limit: int = 2_000) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def tool_error(code: str, message: str, raw: object = None) -> ToolOutput:
    """A structured, non-raising tool failure the loop can read."""
    return ToolOutput(
        {"status": "error", "error": {"code": code, "message": clip(message, 500)}},
        raw=raw,
        status=code,
    )


def argv_target_problem(target: object) -> str | None:
    """Defense in depth for tools that put the target in an argv list. The gate
    has already approved it; this still refuses anything that could be read as
    an option, a URL, a second host or an octet range (``203.0.113.1-20``)."""
    if not isinstance(target, str) or not target or len(target) > 253:
        return "target must be a non-empty string"
    if not _TARGET_CHARS_RE.fullmatch(target):
        return "target contains characters that are not allowed"
    try:
        ipaddress.ip_network(target, strict=True)
        return None
    except ValueError:
        pass
    last = target.rsplit(".", 1)[-1]
    if "/" in target or not re.search(r"[A-Za-z]", last):
        return "target must be a hostname, an IP address or a CIDR network"
    return None


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_subprocess(
    argv: list[str], timeout: float, *, env: Mapping[str, str] | None = None,
) -> ProcessResult:
    """The only place a process is started: argv list, no shell, no stdin.

    ``env=None`` (the default) means inherit the current process environment
    unchanged - this is exactly nmap's call path (RC-13), untouched. A caller
    that needs a controlled environment (RC-35: nuclei's ambient
    ``~/.config/nuclei``) passes an explicit mapping instead."""
    proc = subprocess.run(
        argv,
        capture_output=True,
        timeout=timeout,
        shell=False,
        stdin=subprocess.DEVNULL,
        check=False,
        env=env,
    )
    return ProcessResult(proc.returncode, proc.stdout or b"", proc.stderr or b"")


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

    def redact(self, action: ToolAction) -> dict[str, Any]:
        """The action's parameters as safe to log (used by the loop's records)."""
        tool = self.__tools.get(action.tool) if isinstance(action.tool, str) else None
        sensitive = getattr(tool, "sensitive_parameters", ()) if tool else ()
        return redact_parameters(action.parameters, sensitive)

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
            parameters={"iteration": iteration, "params": self.redact(action)},
            **kwargs,
        )

    def __invocation_risk(self, tool: Tool, params: dict[str, Any]) -> Risk:
        hook = getattr(tool, "risk_for", None)
        if hook is None:
            return Risk(tool.risk)
        try:
            return max(Risk(tool.risk), Risk(hook(dict(params))))
        except Exception:
            return Risk.EXPLOIT  # cannot classify -> treat as the most dangerous

    def __invocation_destructive(self, tool: Tool, params: dict[str, Any]) -> bool:
        if tool.destructive:
            return True
        hook = getattr(tool, "destructive_for", None)
        if hook is None:
            return False
        try:
            return bool(hook(dict(params)))
        except Exception:
            return True

    def __execute(self, action: ToolAction, iteration: int) -> ExecutionResult:
        sink = self.__sink(action, iteration)

        problem = self.__validate(action)
        if problem:
            return self.__refuse(action, sink, f"deny: {problem}")
        tool = self.__tools[action.tool]
        risk = self.__invocation_risk(tool, action.parameters)
        if (self.__invocation_destructive(tool, action.parameters)
                and not self.__destructive_ok):
            return self.__refuse(
                action, sink,
                "deny: action is destructive and the engagement does not permit destructive actions",
            )

        decision = self.__gate.check(action.target, audit=sink)  # <- the gate
        if not decision.allowed:
            outcome = Outcome.RATE_LIMITED if decision.stage == DENIED_RATE else Outcome.DENIED
            return ExecutionResult(action, outcome, decision, executed=False, risk=risk)
        assert decision.stage == ALLOWED

        if risk >= self.__threshold and not self.__approved(action, risk, iteration):
            return ExecutionResult(
                action, Outcome.DECLINED,
                GateDecision(decision.target, False, "deny: operator approval not granted",
                             STAGE_APPROVAL, decision.resolved_ips),
                executed=False, risk=risk,
            )

        # RC-23 resolve-once: scan exactly the IP the gate approved, never the
        # hostname. ``resolved_ips`` is populated only when ``action.target``
        # was a hostname (scope.py never sets it for an IP/CIDR target), so
        # this also leaves IP/CIDR actions byte-for-byte unchanged.
        scan_target = decision.resolved_ips[0] if decision.resolved_ips else action.target
        hostname = action.target if decision.resolved_ips else None

        outcome, status = Outcome.EXECUTED, "ok"
        raw: object
        findings: object
        try:
            produced = tool.run(scan_target, dict(action.parameters), hostname=hostname)
        except Exception as exc:
            produced = ToolOutput(
                {"status": "error", "error": {"code": "tool_exception",
                                              "message": f"{type(exc).__name__}: {exc}"}},
                raw=f"tool error: {type(exc).__name__}: {exc}", status="error",
            )
        if isinstance(produced, ToolOutput):
            raw, findings, status = produced.raw, produced.findings, produced.status
            if status != "ok":
                outcome = Outcome.TOOL_ERROR
        else:
            raw = findings = produced

        sanitized = sanitize_tool_output(
            findings, tool=action.tool, target=action.target,
            audit=self.__sink(action, iteration, EVENT_INJECTION_FLAG),
        )
        recorded = True
        try:
            self.__log.record_execution(
                tool=action.tool, target=action.target,
                parameters={"iteration": iteration, "params": self.redact(action)},
                status=status,
                detail=f"risk={risk.name} output={sanitized.original_length} chars "
                       f"sha256={sanitized.sha256} raw_sha256={sha256_of(raw)}"
                       + (f" scanned_ip={scan_target}" if hostname else "")
                       + (" flagged" if sanitized.flagged else ""),
            )
        except AuditError:
            recorded = False
        return ExecutionResult(action, outcome, decision, True, raw, sanitized, status,
                               recorded, findings, risk)

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
        tool = self.__tools[action.tool]
        extra = set(params) - set(tool.allowed_parameters)
        if extra:
            return f"parameters not allowed for {action.tool}: {sorted(extra)}"
        if not all(_json_safe(v) for v in params.values()):
            return "parameter values must be strings, numbers, booleans or lists of those"
        if len(json.dumps(params, default=repr)) > MAX_PARAMETERS_CHARS:
            return "parameters too large"
        check = getattr(tool, "validate_parameters", None)
        if check is not None:
            try:
                why = check(dict(params))
            except Exception:
                why = "parameter validation failed"
            if why:
                return f"invalid parameters for {action.tool}: {why}"
        return None

    def __approved(self, action: ToolAction, risk: Risk, iteration: int) -> bool:
        safe = self.redact(action)
        request = ApprovalRequest(
            iteration, action.tool, action.target, safe, Risk(risk), action.reason,
        )
        try:
            granted = self.__approver.approve(request) is True
        except Exception:
            granted = False
        reason = f"operator {'approved' if granted else 'declined'} {Risk(risk).name} action"
        try:  # an approval that cannot be recorded does not count
            self.__log.record(
                EVENT_APPROVAL, target=action.target, tool=action.tool,
                parameters={"iteration": iteration, "params": safe},
                allowed=granted, reason=reason,
            )
        except AuditError:
            return False
        return granted


def default_tools(
    engagement: Engagement,
    *,
    nuclei_template_dir: str | None = None,
    nuclei_templates_pin: str = "",
    nuclei_curated_ids: Mapping[str, Risk] | None = None,
) -> list[Tool]:
    """The tools Red Cell ships with, configured from the engagement (rate
    limits come from ``intensity.max_rps``, the out-of-band server from
    ``interactsh_server``). This is the only place concrete tool modules are
    imported and constructed. nuclei is registered only when a pinned template
    directory is supplied."""
    from redcell.nmap_tool import NmapTool

    tools: list[Tool] = [NmapTool.from_engagement(engagement)]
    if nuclei_template_dir:
        from redcell.nuclei_tool import NucleiTool

        tools.append(
            NucleiTool.from_engagement(
                engagement,
                template_dir=nuclei_template_dir,
                templates_pin=nuclei_templates_pin,
                curated_ids=nuclei_curated_ids,
            )
        )
    return tools
