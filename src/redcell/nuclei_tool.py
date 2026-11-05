"""nuclei tool wrapper (RC-14).

A ``Tool`` for ``GatedToolbox``. Construct it only through
``redcell.tools.default_tools`` (nothing else imports this module). By the time
``run`` is called the action has passed validate -> Gate.check -> approval.

Carried over from RC-13 (each tested): argv with ``shell=False``; a parameter
allow-list whose members cannot carry a host or URL; the rate limit derived from
``intensity.max_rps`` and always passed; risk derived from the template
selection; secrets redacted before they reach the audit log; errors returned as
structured results, never raised.

RC-14 follow-up: the gate approves a bare host/IP/CIDR, so by default nuclei is
pointed at the bare target and probes 80/443, which cannot reach a service on a
non-default port (e.g. Juice Shop on 3000 in the lab, RC-19). Two optional
parameters fix this without opening a host-smuggling path: ``port`` (a strict
int, 1-65535) and ``scheme`` (the fixed enum ``http``/``https``). Neither can
hold a host string, so the request's host is always exactly the gate-approved
target - ``_target_url`` builds ``scheme://target[:port]`` from the approved
target, never from anything the planner supplies.

The three nuclei-specific controls:

1. No arbitrary templates. The planner chooses templates only by curated
   *severity*, *tag* (a fixed vocabulary) or, if the operator configured a
   curated manifest, *template id*. No parameter can hold a path or a URL, and
   the only ``-t`` is the operator's pinned template directory. A custom
   template could request any URL or carry out-of-band payloads, routing around
   the gate's target check; workflows (``-w``), template URLs and custom headers
   or variables are therefore unreachable.
2. Out-of-band detection is OFF by default (``-no-interactsh``): by default
   nuclei sends callback data about the client's systems to a public interactsh
   server. A self-hosted server may be set in the engagement
   (``interactsh_server``); public servers are refused in the engagement schema
   and again here.
3. Redirects are never followed (``-disable-redirects``). As a second layer,
   any result whose host is not the approved target is removed from the findings
   and reported as ``off_target_activity``.

Reproducibility (RC-20): templates come from the pinned ``template_dir`` and are
never updated by the tool (``-disable-update-check``); an optional
``templates_pin`` label is recorded in every result.

Flag names follow nuclei v3; verify them against the pinned nuclei version in the
lab (RC-19).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from redcell.engagement import PUBLIC_INTERACTSH_DOMAINS, Engagement
from redcell.tools import (
    ProcessResult,
    Risk,
    ToolOutput,
    argv_target_problem,
    clip as _clip,
    run_subprocess,
    tool_error as _error,
)

# --- curated vocabulary -----------------------------------------------------

SEVERITIES = ("info", "low", "medium", "high", "critical")

ACTIVE_TAGS = frozenset(
    {"tech", "detect", "panel", "exposure", "misconfig", "config", "ssl", "dns", "waf", "favicon"}
)
INTRUSIVE_TAGS = frozenset(
    {"cve", "kev", "vuln", "default-login", "bruteforce", "fuzz", "fuzzing", "xss", "sqli", "lfi",
     "rfi", "ssrf", "rce", "ssti", "redirect", "takeover", "auth-bypass", "intrusive", "oast"}
)
EXPLOIT_TAGS = frozenset({"dos", "exploit"})
ALL_TAGS = ACTIVE_TAGS | INTRUSIVE_TAGS | EXPLOIT_TAGS
TAG_RISK: dict[str, Risk] = {
    **{t: Risk.ACTIVE_RECON for t in ACTIVE_TAGS},
    **{t: Risk.INTRUSIVE for t in INTRUSIVE_TAGS},
    **{t: Risk.EXPLOIT for t in EXPLOIT_TAGS},
}
# When the planner selects nothing, only these low-impact detection tags run.
DEFAULT_TAGS = ("tech", "detect", "panel", "exposure", "misconfig", "config")

MAX_RAW_BYTES = 5_000_000
MAX_FINDINGS = 5_000
_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,100}")


def _csv(items: Any) -> str:
    return ",".join(items)


def _tags_of(info: Mapping[str, Any]) -> list[str]:
    tags = info.get("tags")
    if isinstance(tags, str):
        tags = tags.split(",")
    return [_clip(t, 50) for t in tags][:30] if isinstance(tags, list) else []


# --- parsing ----------------------------------------------------------------

def parse_nuclei_jsonl(text: str) -> tuple[list[dict[str, Any]], int]:
    """Parse ``-jsonl`` output: one JSON object per line. Returns (findings,
    number of unparseable non-empty lines)."""
    findings: list[dict[str, Any]] = []
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(d, dict) or "template-id" not in d:
            bad += 1
            continue
        if len(findings) >= MAX_FINDINGS:
            break
        info = d.get("info") if isinstance(d.get("info"), dict) else {}
        cls = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        refs = info.get("reference")
        extracted = d.get("extracted-results")
        findings.append({
            "template_id": _clip(d.get("template-id"), 200),
            "name": _clip(info.get("name"), 300),
            "severity": _clip(info.get("severity"), 20),
            "tags": _tags_of(info),
            "description": _clip(info.get("description"), 1_000),
            "type": _clip(d.get("type"), 30),
            "host": _clip(d.get("host"), 300),
            "matched_at": _clip(d.get("matched-at"), 500),
            "ip": _clip(d.get("ip"), 60),
            "matcher_name": _clip(d.get("matcher-name"), 200),
            "extracted": [_clip(x, 300) for x in extracted][:20] if isinstance(extracted, list) else [],
            "references": [_clip(r, 300) for r in refs][:10] if isinstance(refs, list) else [],
            "cve": _clip(cls.get("cve-id") if not isinstance(cls.get("cve-id"), list)
                         else ",".join(map(str, cls["cve-id"])), 200),
            "cvss_score": cls.get("cvss-score") if isinstance(cls.get("cvss-score"), (int, float)) else None,
            "timestamp": _clip(d.get("timestamp"), 50),
        })
    return findings, bad


def _hostname_of(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "//" + value
    try:
        return (urlsplit(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def on_target(finding: Mapping[str, Any], target: str) -> bool:
    """True if the finding's host is the approved target (or inside the approved
    network). Anything else means nuclei contacted a host the gate never saw."""
    target = target.lower().rstrip(".")
    try:
        network = ipaddress.ip_network(target, strict=True)
    except ValueError:
        network = None
    for field in ("host", "matched_at"):
        h = _hostname_of(str(finding.get(field, "")))
        if not h:
            return False
        if network is not None and "/" in target:
            try:
                if ipaddress.ip_address(h) not in network:
                    return False
            except ValueError:
                return False  # a name where an address in the network was expected
        else:
            try:
                same = ipaddress.ip_address(h) == ipaddress.ip_address(target)
            except ValueError:
                same = h == target
            if not same:
                return False
    return True


# --- the tool ---------------------------------------------------------------

class NucleiTool:
    name = "nuclei"
    description = (
        "Templated web and service checks via nuclei, using a curated, pinned template set. "
        "Select with 'severity' (info, low, medium, high, critical) and 'tags' ("
        + ", ".join(sorted(ACTIVE_TAGS)) + " are low impact; intrusive tags need operator approval). "
        "Optional 'port' (1-65535) and 'scheme' (http, https) target a non-default port or force "
        "a scheme; both apply only to the gate-approved target, never a second host. "
        "Default: low-impact detection tags only. Redirects are not followed."
    )
    risk = Risk.ACTIVE_RECON  # baseline; risk_for refines it per invocation
    destructive = False
    allowed_parameters = frozenset({"severity", "tags", "template_ids", "port", "scheme"})
    sensitive_parameters: frozenset[str] = frozenset()
    SCHEMES = ("http", "https")

    def __init__(
        self,
        max_rps: int,
        *,
        template_dir: str,
        templates_pin: str = "",
        curated_ids: Mapping[str, Risk] | None = None,
        interactsh_server: str | None = None,
        nuclei_path: str = "nuclei",
        config_path: str | None = None,
        run_timeout_s: float = 900.0,
        request_timeout_s: int = 10,
        runner: Callable[[list[str], float], ProcessResult] = run_subprocess,
        which: Callable[[str], str | None] = shutil.which,
        isdir: Callable[[str], bool] = os.path.isdir,
    ) -> None:
        if isinstance(max_rps, bool) or not isinstance(max_rps, int) or max_rps < 1:
            raise ValueError(f"max_rps must be a positive integer, got {max_rps!r}")
        if not template_dir or not isinstance(template_dir, str):
            raise ValueError("template_dir (the pinned, curated template set) is required")
        if interactsh_server is not None:
            host = str(interactsh_server).strip().lower().rstrip(".")
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
            if (is_ip or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host) or "." not in host
                    or any(host == d or host.endswith("." + d) for d in PUBLIC_INTERACTSH_DOMAINS)):
                raise ValueError("interactsh_server must be a self-hosted hostname, never a public server")
            interactsh_server = host
        self.max_rps = max_rps
        self._template_dir = template_dir
        self._pin = templates_pin
        self._curated = {k: Risk(v) for k, v in (curated_ids or {}).items()}
        self._interactsh = interactsh_server
        self._nuclei_path = nuclei_path
        self._config = config_path
        self._run_timeout = float(run_timeout_s)
        self._request_timeout = int(request_timeout_s)
        self._runner, self._which, self._isdir = runner, which, isdir

    @classmethod
    def from_engagement(cls, engagement: Engagement, *, template_dir: str, **kwargs: Any) -> "NucleiTool":
        """Rate limit from ``intensity.max_rps``; out-of-band server from the
        engagement (None means out-of-band stays off)."""
        return cls(
            engagement.intensity.max_rps,
            template_dir=template_dir,
            interactsh_server=engagement.interactsh_server,
            **kwargs,
        )

    # -- availability guards --------------------------------------------------
    def check_available(self) -> str:
        path = self._which(self._nuclei_path)
        if not path:
            raise FileNotFoundError(
                f"nuclei was not found ({self._nuclei_path!r} is not on PATH). Install nuclei "
                "(https://github.com/projectdiscovery/nuclei) or configure its path; refusing to run."
            )
        if not self._isdir(self._template_dir):
            raise NotADirectoryError(
                f"the pinned template directory {self._template_dir!r} does not exist. Install the "
                "curated template set there; the tool never downloads or updates templates."
            )
        return path

    # -- hooks used by the toolbox --------------------------------------------
    def validate_parameters(self, parameters: Mapping[str, Any]) -> str | None:
        if "severity" in parameters:
            sev = parameters["severity"]
            if (not isinstance(sev, list) or not sev or len(sev) > len(SEVERITIES)
                    or not all(isinstance(s, str) and s in SEVERITIES for s in sev)):
                return f"severity must be a non-empty list from {list(SEVERITIES)}"
        if "tags" in parameters:
            tags = parameters["tags"]
            if (not isinstance(tags, list) or not tags or len(tags) > 20
                    or not all(isinstance(t, str) and t in ALL_TAGS for t in tags)):
                return f"tags must be a non-empty list from the curated set {sorted(ALL_TAGS)}"
        if "template_ids" in parameters:
            ids = parameters["template_ids"]
            if not self._curated:
                return "no curated template-id list is configured; select by severity and tags"
            if (not isinstance(ids, list) or not ids or len(ids) > 50
                    or not all(isinstance(i, str) and _ID_RE.fullmatch(i) and i in self._curated
                               for i in ids)):
                return "template_ids must be a non-empty list of curated template ids"
        if "port" in parameters:
            port = parameters["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
                return "port must be an integer between 1 and 65535"
        if "scheme" in parameters:
            if parameters["scheme"] not in self.SCHEMES:
                return f"scheme must be one of {list(self.SCHEMES)}"
        return None

    def _effective_tags(self, parameters: Mapping[str, Any]) -> list[str]:
        if "tags" in parameters:
            return sorted(set(parameters["tags"]))
        if "template_ids" in parameters:
            return []
        return list(DEFAULT_TAGS)

    def risk_for(self, parameters: Mapping[str, Any]) -> Risk:
        risk = Risk.ACTIVE_RECON
        for t in self._effective_tags(parameters):
            risk = max(risk, TAG_RISK[t])
        for i in parameters.get("template_ids", []) or []:
            risk = max(risk, self._curated[i])
        return risk

    def destructive_for(self, parameters: Mapping[str, Any]) -> bool:
        tags = set(self._effective_tags(parameters))
        return bool(tags & EXPLOIT_TAGS) or any(
            self._curated[i] >= Risk.EXPLOIT for i in parameters.get("template_ids", []) or []
        )

    # -- argv -----------------------------------------------------------------
    @staticmethod
    def target_problem(target: object) -> str | None:
        return argv_target_problem(target)

    @staticmethod
    def _target_url(target: str, parameters: Mapping[str, Any]) -> str:
        """The approved ``target`` only, with an explicit scheme/port when the
        planner asked for one. ``port``/``scheme`` are validated (int 1-65535;
        enum) before this runs, so neither can carry a host of its own -
        the URL's host is always exactly the gate-approved ``target``."""
        port = parameters.get("port")
        scheme = parameters.get("scheme")
        if port is None and scheme is None:
            return target  # unchanged: nuclei is given the bare target, as before
        host = f"[{target}]" if ":" in target and not target.startswith("[") else target
        url = f"{scheme or 'https'}://{host}"
        return f"{url}:{port}" if port is not None else url

    def build_argv(self, nuclei: str, target: str, parameters: Mapping[str, Any]) -> list[str]:
        concurrency = max(1, min(self.max_rps, 10))
        argv = [nuclei]
        if self._config:
            argv += ["-config", self._config]
        argv += [
            "-u", self._target_url(target, parameters),
            "-t", self._template_dir,  # the operator's pinned set: the only -t
            "-jsonl", "-silent", "-no-color",
            "-disable-update-check",
            "-rate-limit", str(self.max_rps),
            "-c", str(concurrency),
            "-bs", "1",
            "-timeout", str(self._request_timeout),
            "-retries", "1",
            "-disable-redirects",
        ]
        argv += ["-interactsh-server", self._interactsh] if self._interactsh else ["-no-interactsh"]
        argv += ["-severity", _csv(parameters.get("severity") or SEVERITIES)]
        tags = self._effective_tags(parameters)
        if tags:
            argv += ["-tags", _csv(tags)]
            # never let a low-impact selection pull in a template that also carries
            # a dangerous tag the planner did not ask for
            blocked = sorted((INTRUSIVE_TAGS | EXPLOIT_TAGS) - set(tags))
            argv += ["-exclude-tags", _csv(blocked)]
        if parameters.get("template_ids"):
            argv += ["-id", _csv(sorted(set(parameters["template_ids"])))]
        return argv

    # -- run ------------------------------------------------------------------
    def run(self, target: str, parameters: Mapping[str, Any]) -> ToolOutput:
        try:
            return self._run(target, parameters)
        except Exception as exc:  # a wrapper bug must not kill the loop
            return _error("wrapper_error", f"{type(exc).__name__}: {exc}")

    def _run(self, target: str, parameters: Mapping[str, Any]) -> ToolOutput:
        problem = self.validate_parameters(parameters) or self.target_problem(target)
        if problem:
            return _error("invalid_input", problem)
        try:
            nuclei = self.check_available()
        except FileNotFoundError as exc:
            return _error("nuclei_not_found", str(exc))
        except NotADirectoryError as exc:
            return _error("templates_not_found", str(exc))
        argv = self.build_argv(nuclei, target, parameters)

        try:
            proc = self._runner(argv, self._run_timeout)
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout if isinstance(exc.stdout, bytes) else b""
            return _error("timeout", f"nuclei did not finish within {self._run_timeout:.0f}s",
                          raw=partial.decode("utf-8", errors="replace"))
        except FileNotFoundError:
            return _error("nuclei_not_found", f"could not execute {nuclei!r}; refusing to run")
        except OSError as exc:
            return _error("exec_failed", f"could not start nuclei: {exc}")

        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if len(proc.stdout) > MAX_RAW_BYTES:
            return _error("output_too_large", f"nuclei output exceeded {MAX_RAW_BYTES} bytes",
                          raw=stdout[:MAX_RAW_BYTES])
        if proc.returncode != 0:
            return _error("nuclei_failed", f"nuclei exited with {proc.returncode}: {_clip(stderr, 300)}",
                          raw=stdout)
        findings, bad = parse_nuclei_jsonl(stdout)
        if bad and not findings:
            return _error("malformed_output", f"{bad} output line(s) were not nuclei JSON results",
                          raw=stdout)

        kept = [f for f in findings if on_target(f, target)]
        off = sorted({f["matched_at"] or f["host"] for f in findings if not on_target(f, target)})
        result: dict[str, Any] = {
            "scanner": "nuclei",
            "templates_pin": self._pin,
            "selection": {
                "severity": list(parameters.get("severity") or SEVERITIES),
                "tags": self._effective_tags(parameters),
                "template_ids": list(parameters.get("template_ids") or []),
            },
            "out_of_band": "self-hosted" if self._interactsh else "off",
            "findings": kept,
            "summary": {"findings": len(kept), "off_target": len(findings) - len(kept),
                        "unparsed_lines": bad},
        }
        if off:
            result["status"] = "error"
            result["error"] = {
                "code": "off_target_activity",
                "message": "nuclei produced results for hosts other than the approved target; "
                           "those results were removed. Redirects are meant to be disabled, so "
                           "this needs review.",
            }
            result["off_target_hosts"] = [_clip(h, 300) for h in off[:20]]
            return ToolOutput(result, raw=stdout, status="off_target_activity")
        return ToolOutput(result, raw=stdout, status="ok")
