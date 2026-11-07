"""nmap tool wrapper (RC-13).

A ``Tool`` for ``GatedToolbox``. Construct it only through
``redcell.tools.default_tools`` (nothing else imports this module): the
toolbox runs it strictly behind validate -> Gate.check -> approval -> sanitize
-> record, so by the time ``run`` is called the target has been gate-approved.

Security properties, each covered by tests:

* argv, never a shell. nmap is started with an argument list
  (``shell=False``); the target and every parameter value are single argv
  elements, validated against strict patterns first. ``--`` precedes the
  target so it can never be read as an option.
* Parameter allow-list. ``profile``, ``ports``, ``scripts``: none can carry a
  host. ``scripts`` accepts NSE *categories* only (never script names, files,
  expressions or ``--script-args``, which could add targets such as
  ``newtargets``).
* Rate propagation. ``--max-rate`` is always passed, taken from the
  engagement's ``intensity.max_rps``, so the packets nmap emits are bounded,
  not just how often scans start.
* Risk from the profile. ``risk_for`` classifies the actual invocation:
  safe/default/discovery/version scripts and plain port/service scans are
  ACTIVE_RECON; vuln/intrusive/brute/auth/external/fuzzer/malware/broadcast
  scripts or the aggressive (-A) profile are INTRUSIVE; dos/exploit are
  EXPLOIT (and destructive). INTRUSIVE+ trips the RC-8 approval threshold.
* Structured output. nmap's XML (``-oX -``) is parsed with the standard
  library after rejecting DTD entities and oversized documents; the raw XML is
  returned separately as evidence.
* Errors do not raise. Timeout, missing nmap, unresolvable or unreachable
  host, malformed or oversized output come back as a ``ToolOutput`` with a
  non-ok status and a structured error the loop can read.

RC-23 (resolve-once): the toolbox always hands this wrapper the gate-approved
IP as ``target`` - never a hostname - and ``-n`` is always passed, disabling
nmap's own forward *and* reverse DNS. This closes what used to be a real gap:
nmap resolved a hostname target itself, independently of the gate, so a DNS
change between the gate's check and nmap's own lookup could make it scan an
address the gate never saw. ``hostname``, when given, is recorded in the
result for the report; it is never resolved or used to build the command.

RC-25 (privilege-degradation surfacing): running unprivileged, the
``aggressive`` profile (``-A``, which implies ``-O`` OS detection) does not
fail - nmap degrades gracefully, falling back from a SYN to a connect scan
and simply omitting OS detection, still exiting 0 with valid XML. Confirmed
live in the lab against the pinned nmap 7.93: stderr was completely empty in
both the privileged and unprivileged case, so the only reliable signal is
structural, not textual: ``-O`` was requested (profile ``aggressive``) but no
``os`` element was parsed for any up host, together with the ``<scaninfo>``
type having fallen back from ``syn`` to ``connect``. A real privilege warning
on stderr, if a different nmap version ever prints one, is treated as an
equally valid, independent trigger. Either way this sets ``degraded: true`` +
``degraded_capabilities`` on the result - status stays ``ok``, since a
reduced-fidelity scan is not itself a tool failure - and ``normalize_nmap``
(RC-15) turns it into a ``NormalizationIssue`` so it reaches the evidence
store and the client report's Limitations section without any report-layer
change. ``summary.scan_types`` records every ``<scaninfo>`` type nmap
actually used (``syn``, ``connect``, ...), the structural sibling of RC-26's
``templates_loaded`` for nuclei. Stderr warnings are now captured whenever
present, not only on a non-zero exit - the exact gap that let a degraded-but-
successful run report ``status=ok`` with no signal at all.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Callable, Mapping

from redcell.engagement import Engagement
from redcell.tools import (
    ProcessResult,
    Risk,
    ToolOutput,
    argv_target_problem,
    clip as _clip,
    run_subprocess,
    tool_error as _error,
)

# --- vocabulary -------------------------------------------------------------

SAFE_CATEGORIES = frozenset({"safe", "default", "discovery", "version"})
INTRUSIVE_CATEGORIES = frozenset(
    {"auth", "brute", "broadcast", "external", "fuzzer", "intrusive", "malware", "vuln"}
)
EXPLOIT_CATEGORIES = frozenset({"dos", "exploit"})
ALL_CATEGORIES = SAFE_CATEGORIES | INTRUSIVE_CATEGORIES | EXPLOIT_CATEGORIES

# profile -> (nmap flags, risk of the profile itself)
PROFILES: dict[str, tuple[tuple[str, ...], Risk]] = {
    "ping": (("-sn",), Risk.ACTIVE_RECON),
    "quick": (("-F",), Risk.ACTIVE_RECON),
    "default": ((), Risk.ACTIVE_RECON),
    "service": (("-sV",), Risk.ACTIVE_RECON),
    "full": (("-p-", "-sV"), Risk.ACTIVE_RECON),
    "aggressive": (("-A",), Risk.INTRUSIVE),
}
PROFILES_ALLOWING_PORTS = frozenset({"default", "service"})
DEFAULT_PROFILE = "default"

MAX_RAW_BYTES = 5_000_000
MAX_HOSTS = 2_048
MAX_PORTS_PER_HOST = 70_000
MAX_SCRIPTS_PER_PORT = 50
MAX_FIELD_CHARS = 2_000

_PORT_PART = r"[0-9]{1,5}(?:-[0-9]{1,5})?"
_PORTS_RE = re.compile(rf"{_PORT_PART}(?:,{_PORT_PART})*")

# RC-25: nmap did not print anything to stderr for an unprivileged -A fallback
# against the pinned lab version (empty stderr, confirmed live) - this is a
# defensive secondary signal only, for a different nmap version/build that
# does. The structural check (requested OS detection, scaninfo fell back to
# "connect", no <os> element anywhere) is the one actually observed to fire.
_PRIVILEGE_WARNING_RE = re.compile(
    r"requires?\s+root\s+privileges|running?\s+as\s+root|need(?:s)?\s+to\s+(?:be|run\s+as)\s+root",
    re.I,
)


# --- parsing ----------------------------------------------------------------

class NmapParseError(Exception):
    pass


def _int(value: object, default: int = 0) -> int:
    try:
        return int(str(value))
    except ValueError:
        return default


def _float(value: object) -> float | None:
    try:
        return float(str(value))
    except ValueError:
        return None


def parse_nmap_xml(text: str) -> dict[str, Any]:
    """Parse nmap ``-oX`` output into plain structured data. Raises
    ``NmapParseError`` on anything malformed, hostile or oversized."""
    if not isinstance(text, str) or not text.strip():
        raise NmapParseError("empty output")
    if len(text) > MAX_RAW_BYTES:
        raise NmapParseError("output too large")
    upper = text.upper()
    if "<!ENTITY" in upper or re.search(r"<!DOCTYPE[^>]*\[", upper):
        raise NmapParseError("DTD entity declarations are not allowed")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise NmapParseError(f"not valid XML: {exc}") from None
    if root.tag != "nmaprun":
        raise NmapParseError("not an nmap XML document")

    hosts: list[dict[str, Any]] = []
    for h in root.findall("host")[:MAX_HOSTS]:
        status = h.find("status")
        addrs = [
            {"address": _clip(a.get("addr"), 100), "type": _clip(a.get("addrtype"), 20)}
            for a in h.findall("address")
        ]
        names = [
            _clip(n.get("name"), 253) for n in h.findall("hostnames/hostname") if n.get("name")
        ]
        ports: list[dict[str, Any]] = []
        for p in h.findall("ports/port")[:MAX_PORTS_PER_HOST]:
            state = p.find("state")
            svc = p.find("service")
            entry: dict[str, Any] = {
                "port": _int(p.get("portid")),
                "protocol": _clip(p.get("protocol"), 10),
                "state": _clip(state.get("state") if state is not None else "unknown", 30),
                "reason": _clip(state.get("reason") if state is not None else "", 50),
            }
            if svc is not None:
                entry["service"] = {
                    "name": _clip(svc.get("name"), 100),
                    "product": _clip(svc.get("product"), 200),
                    "version": _clip(svc.get("version"), 200),
                    "extrainfo": _clip(svc.get("extrainfo"), 200),
                    "tunnel": _clip(svc.get("tunnel"), 20),
                    "cpe": [_clip(c.text, 200) for c in svc.findall("cpe")][:10],
                }
            scripts = [
                {"id": _clip(s.get("id"), 100), "output": _clip(s.get("output"))}
                for s in p.findall("script")[:MAX_SCRIPTS_PER_PORT]
            ]
            if scripts:
                entry["scripts"] = scripts
            ports.append(entry)
        host: dict[str, Any] = {
            "status": _clip(status.get("state") if status is not None else "unknown", 20),
            "addresses": addrs,
            "hostnames": names[:20],
            "ports": ports,
        }
        os_matches = [
            {"name": _clip(m.get("name"), 200), "accuracy": _int(m.get("accuracy"))}
            for m in h.findall("os/osmatch")[:5]
        ]
        if os_matches:
            host["os"] = os_matches
        host_scripts = [
            {"id": _clip(s.get("id"), 100), "output": _clip(s.get("output"))}
            for s in h.findall("hostscript/script")[:MAX_SCRIPTS_PER_PORT]
        ]
        if host_scripts:
            host["host_scripts"] = host_scripts
        hosts.append(host)

    up = down = total = 0
    elapsed = None
    stats = root.find("runstats")
    if stats is not None:
        counts = stats.find("hosts")
        if counts is not None:
            up, down, total = (_int(counts.get(k)) for k in ("up", "down", "total"))
        fin = stats.find("finished")
        if fin is not None:
            elapsed = _float(fin.get("elapsed"))
    # RC-25: which scan technique(s) nmap actually used (e.g. a connect-scan
    # fallback when unprivileged) - a scan with no port-scan phase at all
    # (the "ping" profile) legitimately has no <scaninfo> element.
    scan_types = sorted({
        _clip(si.get("type"), 20) for si in root.findall("scaninfo") if si.get("type")
    })
    return {
        "scanner": "nmap",
        "version": _clip(root.get("version"), 30),
        "hosts": hosts,
        "summary": {"hosts_up": up, "hosts_down": down, "hosts_total": total,
                    "elapsed_seconds": elapsed, "scan_types": scan_types},
    }


# --- subprocess -------------------------------------------------------------

# --- the tool ---------------------------------------------------------------

class NmapTool:
    name = "nmap"
    description = (
        "Port, service and (with safe NSE categories) basic host reconnaissance via nmap. "
        "Profiles: " + ", ".join(PROFILES) + ". 'ports' (e.g. \"22,80,8000-8100\") works with "
        "profiles default and service. 'scripts' takes NSE categories only. "
        "'aggressive' includes OS detection, which needs root/raw-socket privileges; running "
        "unprivileged, it silently falls back to a connect scan with OS detection skipped - "
        "the result reports this as degraded, it does not fail."
    )
    risk = Risk.ACTIVE_RECON  # baseline; risk_for refines it per invocation
    destructive = False
    allowed_parameters = frozenset({"profile", "ports", "scripts"})
    sensitive_parameters: frozenset[str] = frozenset()

    def __init__(
        self,
        max_rps: int,
        *,
        nmap_path: str = "nmap",
        host_timeout_s: int = 300,
        run_timeout_s: float = 900.0,
        runner: Callable[[list[str], float], ProcessResult] = run_subprocess,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        if isinstance(max_rps, bool) or not isinstance(max_rps, int) or max_rps < 1:
            raise ValueError(f"max_rps must be a positive integer, got {max_rps!r}")
        self.max_rps = max_rps
        self._nmap_path = nmap_path
        self._host_timeout = int(host_timeout_s)
        self._run_timeout = float(run_timeout_s)
        self._runner = runner
        self._which = which

    @classmethod
    def from_engagement(cls, engagement: Engagement, **kwargs: Any) -> "NmapTool":
        """Derive nmap's own rate limit from the engagement's ``max_rps``."""
        return cls(engagement.intensity.max_rps, **kwargs)

    # -- availability guard ---------------------------------------------------
    def check_available(self) -> str | None:
        """Return the absolute path of nmap, or raise a clear error."""
        path = self._which(self._nmap_path)
        if not path:
            raise FileNotFoundError(
                f"nmap was not found ({self._nmap_path!r} is not on PATH). Install nmap "
                "(https://nmap.org/download) or configure its path; refusing to run."
            )
        return path

    # -- hooks used by the toolbox --------------------------------------------
    def validate_parameters(self, parameters: Mapping[str, Any]) -> str | None:
        profile = parameters.get("profile", DEFAULT_PROFILE)
        if not isinstance(profile, str) or profile not in PROFILES:
            return f"profile must be one of {sorted(PROFILES)}"
        if "ports" in parameters:
            ports = parameters["ports"]
            if profile not in PROFILES_ALLOWING_PORTS:
                return f"'ports' cannot be combined with profile {profile!r}"
            if not isinstance(ports, str) or len(ports) > 200 or not _PORTS_RE.fullmatch(ports):
                return "ports must look like 22,80,8000-8100"
            for part in ports.split(","):
                lo, _, hi = part.partition("-")
                nums = [int(lo)] + ([int(hi)] if hi else [])
                if any(n < 1 or n > 65535 for n in nums) or (hi and nums[0] > nums[1]):
                    return "ports out of range (1-65535) or reversed"
        if "scripts" in parameters:
            scripts = parameters["scripts"]
            if (not isinstance(scripts, list) or not scripts or len(scripts) > len(ALL_CATEGORIES)
                    or not all(isinstance(s, str) and s in ALL_CATEGORIES for s in scripts)):
                return f"scripts must be a non-empty list of NSE categories from {sorted(ALL_CATEGORIES)}"
        return None

    def _categories(self, parameters: Mapping[str, Any]) -> set[str]:
        return set(parameters.get("scripts", []) or [])

    @staticmethod
    def _requests_os_detection(parameters: Mapping[str, Any]) -> bool:
        # Only "aggressive" (-A) implies -O today; kept as its own check so a
        # future profile/parameter that also requests OS detection has one
        # place to extend, matching degraded_capabilities' own extensibility.
        return parameters.get("profile", DEFAULT_PROFILE) == "aggressive"

    def risk_for(self, parameters: Mapping[str, Any]) -> Risk:
        risk = PROFILES[parameters.get("profile", DEFAULT_PROFILE)][1]
        cats = self._categories(parameters)
        if cats & EXPLOIT_CATEGORIES:
            risk = max(risk, Risk.EXPLOIT)
        if cats & INTRUSIVE_CATEGORIES:
            risk = max(risk, Risk.INTRUSIVE)
        return risk

    def destructive_for(self, parameters: Mapping[str, Any]) -> bool:
        return bool(self._categories(parameters) & EXPLOIT_CATEGORIES)

    # -- argv -----------------------------------------------------------------
    @staticmethod
    def target_problem(target: object) -> str | None:
        """Defense in depth: the gate already approved the target, but the wrapper
        still refuses anything that could be read as an option, a second host,
        or an nmap octet range."""
        return argv_target_problem(target)

    def build_argv(self, nmap: str, target: str, parameters: Mapping[str, Any]) -> list[str]:
        profile = parameters.get("profile", DEFAULT_PROFILE)
        argv = [
            nmap,
            "-oX", "-",
            "--no-stylesheet",
            "-n",  # RC-23: never resolve - target is always the gate-approved IP
            "--max-rate", str(self.max_rps),
            "--host-timeout", f"{self._host_timeout}s",
            *PROFILES[profile][0],
        ]
        if "ports" in parameters:
            argv += ["-p", parameters["ports"]]
        cats = self._categories(parameters)
        if cats:
            argv.append("--script=" + ",".join(sorted(cats)))
        argv += ["--", target]
        return argv

    # -- run ------------------------------------------------------------------
    def run(self, target: str, parameters: Mapping[str, Any], *, hostname: str | None = None) -> ToolOutput:
        try:
            return self._run(target, parameters, hostname)
        except Exception as exc:  # a wrapper bug must not kill the loop
            return _error("wrapper_error", f"{type(exc).__name__}: {exc}")

    def _run(self, target: str, parameters: Mapping[str, Any], hostname: str | None = None) -> ToolOutput:
        problem = self.validate_parameters(parameters) or self.target_problem(target)
        if problem:
            return _error("invalid_input", problem)
        try:
            nmap = self.check_available()
        except FileNotFoundError as exc:
            return _error("nmap_not_found", str(exc))
        argv = self.build_argv(nmap, target, parameters)

        try:
            proc = self._runner(argv, self._run_timeout)
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout if isinstance(exc.stdout, bytes) else b""
            return _error("timeout", f"nmap did not finish within {self._run_timeout:.0f}s",
                          raw=partial.decode("utf-8", errors="replace"))
        except FileNotFoundError:
            return _error("nmap_not_found", f"could not execute {nmap!r}; refusing to run")
        except OSError as exc:
            return _error("exec_failed", f"could not start nmap: {exc}")

        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if len(proc.stdout) > MAX_RAW_BYTES:
            return _error("output_too_large", f"nmap output exceeded {MAX_RAW_BYTES} bytes",
                          raw=stdout[:MAX_RAW_BYTES])
        if "failed to resolve" in stderr.lower():
            return _error("resolution_failed", f"nmap could not resolve the target: {_clip(stderr, 300)}",
                          raw=stdout)
        if proc.returncode != 0 and not stdout.strip():
            return _error("nmap_failed", f"nmap exited with {proc.returncode}: {_clip(stderr, 300)}")
        try:
            findings = parse_nmap_xml(stdout)
        except NmapParseError as exc:
            return _error("malformed_output", f"could not parse nmap output: {exc}", raw=stdout)

        # RC-25: capture stderr warnings whenever present, not only on a
        # non-zero exit - a degraded-but-successful run (exit 0) used to
        # report status=ok with no signal at all.
        warnings: list[str] = []
        stripped_stderr = stderr.strip()
        if stripped_stderr:
            warnings.append(_clip(stripped_stderr, 500))
        if proc.returncode != 0:
            warnings.append(f"nmap exited with {proc.returncode}")
        if warnings:
            findings["warnings"] = warnings

        if hostname:
            findings["target_hostname"] = hostname  # RC-23: which name this pinned IP was

        # RC-25: privilege-degradation surfacing. The only case today that
        # requests OS detection is the aggressive profile; if it was asked
        # for but no up host carries an "os" result, that is either a
        # connect-scan fallback (confirmed: nmap prints nothing to stderr for
        # this on the pinned lab version) or, on some other build, an actual
        # stderr privilege warning - either is sufficient on its own.
        up_hosts = [h for h in findings["hosts"] if h["status"] == "up"]
        if self._requests_os_detection(parameters) and up_hosts and not any("os" in h for h in up_hosts):
            scan_types = findings["summary"].get("scan_types", [])
            fell_back_to_connect = "connect" in scan_types and "syn" not in scan_types
            stderr_signals_privilege = bool(_PRIVILEGE_WARNING_RE.search(stderr))
            if fell_back_to_connect or stderr_signals_privilege:
                reasons = []
                if fell_back_to_connect:
                    reasons.append("the scan fell back from a SYN to a connect scan (scaninfo type=connect)")
                if stderr_signals_privilege:
                    reasons.append("nmap reported a root-privilege warning")
                findings["degraded"] = True
                findings["degraded_capabilities"] = ["os_detection"]
                findings["degraded_reason"] = (
                    "OS detection (requested via the 'aggressive' profile) was not performed: "
                    + "; ".join(reasons) + " - likely running without root/raw-socket privileges."
                )

        if not up_hosts:
            findings["status"] = "error"
            findings["error"] = {"code": "host_unreachable",
                                 "message": "no host responded (down, filtered or unreachable)"}
            return ToolOutput(findings, raw=stdout, status="host_unreachable")
        return ToolOutput(findings, raw=stdout, status="ok")
