# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs

Host-side launcher for the opt-in model-relay overlays. Run from the
repository root with the project venv (it imports op06d from src/):

    uv run python lab/model_relay.py build  <local|anthropic>
    uv run python lab/model_relay.py up     <local|anthropic> [--engagement lab/<file>.yaml]
    uv run python lab/model_relay.py check  <local|anthropic>
    uv run python lab/model_relay.py run    <local|anthropic> [--engagement ...] [--model ...]
    uv run python lab/model_relay.py down
    uv run python lab/model_relay.py status

Rules it enforces before any docker call:

* exactly one overlay (one upstream) per stack: ``up``/``run`` refuse while a
  relay for the other mode is running;
* engagement policy: the engagement must allow the provider
  (``planner.allowed_providers``; without a planner block only ``local``).
  ``anthropic`` has no default engagement - it must be named explicitly;
* the engagement file must live under lab/ (the scanner sees it at /lab).

``up`` returns only once every lab target answers HTTP from the scanner, and
fails if one never does, so ``check`` can follow it directly.

The API key is never written anywhere: ``run anthropic`` passes
``ANTHROPIC_API_KEY`` to the one ``docker compose exec`` by name, and docker
reads its value from this process's environment.

The docker runner is injectable, so tests/test_lab_model_relay.py exercises
the policy and command construction without docker;
tests/integration/test_lab_rc47.py drives the real thing (``-m lab``).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Sequence

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
sys.path.insert(0, str(ROOT / "src"))

from op06d.audit import verify_log  # noqa: E402
from op06d.engagement import Engagement, EngagementError, load_engagement  # noqa: E402
from op06d.evidence import EvidenceStore  # noqa: E402
from op06d.llm import DEFAULT_LOCAL_MODEL  # noqa: E402

MODES = ("local", "anthropic")
PROJECT = "rc-lab"
COMPOSE_BASE = LAB / "docker-compose.yml"
OVERLAYS = {mode: LAB / f"model-relay.{mode}.yml" for mode in MODES}
DEFAULT_ENGAGEMENT = {"local": LAB / "engagement.yaml", "anthropic": None}

NET_LAB = f"{PROJECT}_labnet"
NET_RELAY = f"{PROJECT}_relaynet"
NET_EGRESS = f"{PROJECT}_relay_egress"
RELAY_IP = "172.31.78.2"
RELAY_PORT = {"local": 11434, "anthropic": 443}
RELAY_ALLOWED_CAPS = frozenset({"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"})
EXPECTED_EXTRA_HOSTS = {"local": [], "anthropic": [f"api.anthropic.com:{RELAY_IP}"]}
TARGET_SERVICES = ("juice-shop", "dvwa")
TARGET_READY = {"juice-shop": "http://juice-shop.lab:3000/", "dvwa": "http://dvwa.lab/"}
READY_TIMEOUT = 180.0
READY_INTERVAL = 3.0

CAPTURE_SUBDIR = "_rc47_ephemeral"
HOST_OLLAMA = "http://127.0.0.1:11434"
KEY_ENV = "ANTHROPIC_API_KEY"
KEY_SHAPE = re.compile(rb"sk-ant-[A-Za-z0-9_\-]{8,}")

ACCEPTANCE_LIMITS = {"max_iterations": 12, "max_actions": 6, "max_wall_clock": 1800, "max_tokens": 300_000}
BAD_TERMINATIONS = frozenset({
    "model_failure", "model_refused", "audit_failure", "gate_unusable", "window_expired",
    "window_not_open", "operator_stop",
})

Runner = Callable[[Sequence[str], float], subprocess.CompletedProcess]


class RelayError(RuntimeError):
    """The launcher refuses, or a step failed."""


class PolicyRefused(RelayError):
    """The engagement does not allow the requested provider."""


class NotReady(RelayError):
    """The stack started but a lab target never answered."""


def default_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)


# --- policy -----------------------------------------------------------------------

def _mode(mode: str) -> str:
    if mode not in MODES:
        raise RelayError(f"mode must be one of {MODES}, got {mode!r}")
    return mode


def resolve_engagement(mode: str, engagement: str | os.PathLike | None) -> pathlib.Path:
    _mode(mode)
    if engagement is None:
        default = DEFAULT_ENGAGEMENT[mode]
        if default is None:
            raise PolicyRefused(
                "the anthropic relay needs an engagement that explicitly allows it: pass "
                "--engagement lab/engagement-llm-hosted.yaml (or another lab/ engagement whose "
                "planner.allowed_providers lists anthropic)"
            )
        return default
    path = pathlib.Path(engagement)
    path = (path if path.is_absolute() else ROOT / path).resolve()
    if LAB.resolve() not in path.parents:
        raise RelayError(f"the engagement must be a file under lab/ (the scanner sees it at /lab): {path}")
    return path


def check_policy(mode: str, engagement: str | os.PathLike | None) -> tuple[pathlib.Path, Engagement]:
    path = resolve_engagement(mode, engagement)
    try:
        eng = load_engagement(path)
    except EngagementError as exc:
        raise RelayError(f"cannot load {path}: {exc}") from None
    if not eng.provider_allowed(mode):
        allowed = list(eng.planner.allowed_providers) if eng.planner else ["local (default: no planner block)"]
        raise PolicyRefused(
            f"{path.relative_to(ROOT)} does not allow the {mode!r} provider "
            f"(planner.allowed_providers: {allowed}); refusing to start the {mode} relay"
        )
    return path, eng


def container_path(host_path: pathlib.Path) -> str:
    return "/lab/" + host_path.resolve().relative_to(LAB.resolve()).as_posix()


# --- docker compose -----------------------------------------------------------------

def compose_argv(mode: str, *args: str) -> list[str]:
    return ["docker", "compose", "-f", str(COMPOSE_BASE), "-f", str(OVERLAYS[_mode(mode)]), *args]


def _ok(cp: subprocess.CompletedProcess, what: str) -> subprocess.CompletedProcess:
    if cp.returncode != 0:
        raise RelayError(f"{what} failed (exit {cp.returncode}):\n{cp.stdout}\n{cp.stderr}")
    return cp


def _container_id(mode: str, service: str, run: Runner) -> str | None:
    cp = run(compose_argv(mode, "ps", "-q", service), 60)
    cid = cp.stdout.strip() if cp.returncode == 0 else ""
    return cid or None


def _inspect(ref: str, run: Runner, kind: str = "container") -> dict | None:
    cp = run(["docker", kind, "inspect", ref], 60)
    if cp.returncode != 0:
        return None
    data = json.loads(cp.stdout or "[]")
    return data[0] if data else None


def running_relay_mode(run: Runner) -> str | None:
    cid = _container_id("local", "model-relay", run)
    if not cid:
        return None
    info = _inspect(cid, run) or {}
    if not info.get("State", {}).get("Running"):
        return None
    cmd = info.get("Config", {}).get("Cmd") or []
    return cmd[0] if cmd else "unknown"


def build(mode: str, run: Runner = default_runner) -> None:
    _ok(run(["docker", "compose", "-f", str(COMPOSE_BASE), "build", "scanner"], 1800), "base scanner build")
    _ok(run(compose_argv(mode, "build", "scanner", "model-relay"), 1800), "overlay build")


def up(mode: str, engagement: str | None = None, run: Runner = default_runner) -> pathlib.Path:
    path, _ = check_policy(mode, engagement)
    other = running_relay_mode(run)
    if other is not None and other != mode:
        raise RelayError(
            f"a {other!r} relay is already running; one upstream per stack. Run "
            "`uv run python lab/model_relay.py down` first"
        )
    _ok(run(compose_argv(mode, "up", "-d", "--remove-orphans"), 1800), "docker compose up")
    wait_for_targets(mode, run)
    return path


def _probe_target(mode: str, url: str, run: Runner) -> str | None:
    """One HTTP probe from the scanner. Returns None when the target answered."""
    argv = compose_argv(mode, "exec", "-T", "scanner", "curl", "-sS", "--noproxy", "*",
                        "--max-time", "5", "-o", "/dev/null", url)
    try:
        cp = run(argv, 30)
    except subprocess.TimeoutExpired:
        return "the probe timed out"
    if cp.returncode == 0:
        return None
    return (cp.stderr or cp.stdout or "").strip()[:300] or f"curl exit {cp.returncode}"


def wait_for_targets(mode: str, run: Runner = default_runner, *, timeout: float = READY_TIMEOUT,
                     interval: float = READY_INTERVAL, clock: Callable[[], float] = time.monotonic,
                     sleep: Callable[[float], None] = time.sleep) -> None:
    """Block until every lab target answers HTTP from the scanner.

    ``docker compose up -d`` returns when the containers have started, not when
    the services inside them listen (Juice Shop takes about a minute), and a
    ``check`` run in that gap is INCONCLUSIVE. The probes are the same requests
    as the controls in lab/check_relay_isolation.sh, over labnet.
    """
    pending = dict(TARGET_READY)
    last: dict[str, str] = {}
    deadline = clock() + timeout
    while True:
        for svc, url in list(pending.items()):
            error = _probe_target(mode, url, run)
            if error is None:
                del pending[svc]
                continue
            last[svc] = error
            cid = _container_id(mode, svc, run)
            state = (_inspect(cid, run) or {}).get("State", {}) if cid else {}
            if not state.get("Running"):
                raise NotReady(
                    f"lab target {svc} is not running (status: {state.get('Status', 'no container')}, "
                    f"exit code: {state.get('ExitCode', 'n/a')}); it will not become ready.\n{_not_ready_hint(mode, svc)}"
                )
        if not pending:
            return
        if clock() >= deadline:
            detail = "\n".join(f"  {svc} ({pending[svc]}): {last[svc]}" for svc in pending)
            raise NotReady(
                f"lab target(s) not ready after {timeout:.0f}s:\n{detail}\n{_not_ready_hint(mode, *pending)}"
            )
        sleep(interval)


def _not_ready_hint(mode: str, *services: str) -> str:
    logs = " ".join(["docker", "compose", "-f", "lab/docker-compose.yml", "-f", f"lab/model-relay.{mode}.yml",
                     "logs", "--tail", "50", *services])
    return (f"The stack was left up for inspection: `{logs}`. Do not run `check` or `run` against it; "
            "tear it down with `uv run python lab/model_relay.py down`.")


def down(run: Runner = default_runner) -> subprocess.CompletedProcess:
    return run(compose_argv("local", "down", "--remove-orphans"), 300)


# --- isolation check ------------------------------------------------------------------

@dataclass
class CheckReport:
    lines: list[str] = field(default_factory=list)
    failed: bool = False
    inconclusive: bool = False

    def ok(self, msg: str) -> None:
        self.lines.append(f"PASS  {msg}")

    def fail(self, msg: str) -> None:
        self.lines.append(f"FAIL  {msg}")
        self.failed = True

    def unsure(self, msg: str) -> None:
        self.lines.append(f"INCONCLUSIVE  {msg}")
        self.inconclusive = True

    def expect(self, cond: bool, good: str, bad: str) -> None:
        self.ok(good) if cond else self.fail(bad)

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 2 if self.inconclusive else 0


def _members(net: dict) -> set[str]:
    return {c.get("Name", "") for c in (net.get("Containers") or {}).values()}


def host_checks(mode: str, run: Runner, report: CheckReport) -> str | None:
    """Docker-side structure. Returns the relay's relay_egress address."""
    _mode(mode)
    nets = {name: _inspect(name, run, "network") for name in (NET_LAB, NET_RELAY, NET_EGRESS)}
    for name, info in nets.items():
        if info is None:
            report.unsure(f"network {name} not found (is the {mode} overlay up?)")
    if report.inconclusive:
        return None
    report.expect(nets[NET_LAB].get("Internal") is True, f"{NET_LAB} is internal", f"{NET_LAB} is NOT internal")
    report.expect(nets[NET_RELAY].get("Internal") is True, f"{NET_RELAY} is internal", f"{NET_RELAY} is NOT internal")
    report.expect(nets[NET_EGRESS].get("Internal") is False, f"{NET_EGRESS} has an outbound route (relay only)",
                  f"{NET_EGRESS} is internal: the relay cannot reach its upstream")

    ids: dict[str, str] = {}
    for svc in (*TARGET_SERVICES, "scanner", "model-relay"):
        cid = _container_id(mode, svc, run)
        if not cid:
            report.unsure(f"service {svc} is not running")
        else:
            ids[svc] = cid
    if report.inconclusive:
        return None
    info = {svc: _inspect(cid, run) or {} for svc, cid in ids.items()}
    names = {svc: i.get("Name", "").lstrip("/") for svc, i in info.items()}

    expected_members = {
        NET_LAB: {names["juice-shop"], names["dvwa"], names["scanner"]},
        NET_RELAY: {names["scanner"], names["model-relay"]},
        NET_EGRESS: {names["model-relay"]},
    }
    for net, want in expected_members.items():
        have = _members(nets[net])
        report.expect(have == want, f"{net} members are exactly {sorted(want)}",
                      f"{net} members are {sorted(have)}, expected exactly {sorted(want)}")

    expected_nets = {
        "juice-shop": {NET_LAB}, "dvwa": {NET_LAB},
        "scanner": {NET_LAB, NET_RELAY}, "model-relay": {NET_RELAY, NET_EGRESS},
    }
    for svc, want in expected_nets.items():
        i = info[svc]
        have = set((i.get("NetworkSettings", {}).get("Networks") or {}))
        report.expect(have == want, f"{svc} is attached to exactly {sorted(want)}",
                      f"{svc} is attached to {sorted(have)}, expected exactly {sorted(want)}")
        ports = i.get("NetworkSettings", {}).get("Ports") or {}
        published = [p for p, b in ports.items() if b]
        report.expect(not published, f"{svc} publishes no ports", f"{svc} publishes ports: {published}")
        hc = i.get("HostConfig", {})
        report.expect(hc.get("NetworkMode") != "host" and not hc.get("Privileged"),
                      f"{svc} is not privileged and not on host networking",
                      f"{svc} uses unsafe settings: NetworkMode={hc.get('NetworkMode')} Privileged={hc.get('Privileged')}")

    relay = info["model-relay"]
    caps = {c if c.startswith("CAP_") else f"CAP_{c}" for c in (relay.get("HostConfig", {}).get("CapAdd") or [])}
    report.expect(caps <= RELAY_ALLOWED_CAPS, "relay adds only the entrypoint's capabilities",
                  f"relay adds unexpected capabilities: {sorted(caps - RELAY_ALLOWED_CAPS)}")
    cmd = relay.get("Config", {}).get("Cmd") or []
    report.expect(cmd == [mode], f"relay upstream mode is {mode!r} (one upstream)",
                  f"relay command is {cmd}, expected [{mode!r}]")

    scanner = info["scanner"]
    extra = sorted(scanner.get("HostConfig", {}).get("ExtraHosts") or [])
    report.expect(extra == EXPECTED_EXTRA_HOSTS[mode], f"scanner extra hosts are {EXPECTED_EXTRA_HOSTS[mode]}",
                  f"scanner extra hosts are {extra}, expected {EXPECTED_EXTRA_HOSTS[mode]}")
    env = scanner.get("Config", {}).get("Env") or []
    leaked = [e.split("=", 1)[0] for e in env if e.startswith(f"{KEY_ENV}=") or KEY_SHAPE.search(e.encode())]
    report.expect(not leaked, "no API key in the scanner's container configuration",
                  f"API key material in the scanner's container environment: {leaked}")

    egress = (relay.get("NetworkSettings", {}).get("Networks") or {}).get(NET_EGRESS, {}).get("IPAddress")
    if not egress:
        report.unsure("could not read the relay's relay_egress address")
    return egress or None


def _exec_check(report: CheckReport, label: str, cp: subprocess.CompletedProcess) -> None:
    report.lines.append(f"--- {label} (exit {cp.returncode})")
    report.lines += [f"    {line}" for line in (cp.stdout or "").splitlines() if line.strip()]
    if cp.returncode == 0:
        report.ok(label)
    elif cp.returncode == 2:
        report.unsure(f"{label}: {(cp.stderr or '').strip()[:300]}")
    else:
        report.fail(f"{label}: {(cp.stderr or '').strip()[:300]}")


def check(mode: str, run: Runner = default_runner) -> CheckReport:
    report = CheckReport()
    egress = host_checks(mode, run, report)
    if report.failed or report.inconclusive or egress is None:
        return report
    _exec_check(report, "scanner-side isolation (lab/check_relay_isolation.sh)",
                run(compose_argv(mode, "exec", "-T", "scanner", "bash", "/lab/check_relay_isolation.sh",
                                 mode, egress), 600))
    _exec_check(report, "relay-side egress (check_relay_egress.sh, as the relay user)",
                run(compose_argv(mode, "exec", "-T", "-u", "relay", "model-relay", "sh",
                                 "/usr/local/bin/check_relay_egress.sh", mode), 300))
    for port in sorted({RELAY_PORT[mode], 11434, 443}):
        cp = run(compose_argv(mode, "exec", "-T", "dvwa", "timeout", "6", "bash", "-c",
                              f"exec 3<>/dev/tcp/{RELAY_IP}/{port}"), 60)
        report.expect(cp.returncode != 0, f"target dvwa cannot reach the relay network ({RELAY_IP}:{port})",
                      f"target dvwa REACHED {RELAY_IP}:{port} on the relay network")
    return report


# --- acceptance run ------------------------------------------------------------------

@dataclass
class RunOutcome:
    mode: str
    returncode: int
    stdout: str
    stderr: str
    out_dir: pathlib.Path
    report_html: pathlib.Path | None
    problems: list[str]


def ollama_has_model(model: str, base: str = HOST_OLLAMA, timeout: float = 5.0) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=timeout) as resp:
            names = {m.get("name") for m in json.load(resp).get("models", [])}
    except (OSError, urllib.error.URLError, ValueError):
        raise RelayError(f"host Ollama is not answering on {base}; start it first") from None
    return model in names or f"{model}:latest" in names


def op06d_run_argv(mode: str, engagement_in_scanner: str, out_in_scanner: str, *, model: str | None,
                   limits: dict[str, int]) -> list[str]:
    argv = [
        "python3", "-m", "op06d.cli", "run",
        "--engagement", engagement_in_scanner, "--out", out_in_scanner,
        "--template-dir", "/opt/nuclei-templates", "--templates-pin", "v10.5.1",
        "--nmap-version", "7.93", "--nuclei-version", "3.11.1",
        "--non-interactive", "--planner", "llm", "--llm-provider", mode,
        "--max-iterations", str(limits["max_iterations"]), "--max-actions", str(limits["max_actions"]),
        "--max-wall-clock", str(limits["max_wall_clock"]), "--max-tokens", str(limits["max_tokens"]),
    ]
    if mode == "local":
        argv += ["--llm-endpoint", f"http://{RELAY_IP}:11434", "--llm-allow-private", RELAY_IP]
    if model:
        argv += ["--model", model]
    return argv


def run_acceptance(mode: str, engagement: str | None = None, *, model: str | None = None,
                   limits: dict[str, int] | None = None, run: Runner = default_runner,
                   environ: dict[str, str] | None = None) -> RunOutcome:
    env = os.environ if environ is None else environ
    path, _ = check_policy(mode, engagement)
    if mode == "anthropic" and not env.get(KEY_ENV):
        raise RelayError(f"{KEY_ENV} is not set in this shell; it is passed to the scanner by name only")
    if mode == "local":
        wanted = model or DEFAULT_LOCAL_MODEL
        if not ollama_has_model(wanted):
            raise RelayError(f"host Ollama does not have {wanted!r}: run `ollama pull {wanted}`")
    if running_relay_mode(run) != mode:
        raise RelayError(f"the {mode} relay is not running: `uv run python lab/model_relay.py up {mode} ...`")

    limits = {**ACCEPTANCE_LIMITS, **(limits or {})}
    base = f"/captures/{CAPTURE_SUBDIR}/{mode}"
    _ok(run(compose_argv(mode, "exec", "-T", "scanner", "sh", "-c",
                         f"rm -rf {base} && mkdir -p {base}"), 60), "preparing the capture directory")
    gen = f"{base}/engagement.yaml"
    _ok(run(compose_argv(mode, "exec", "-T", "scanner", "python3", "/lab/make_lab_engagement.py", gen,
                         "--template", container_path(path)), 120), "generating the run engagement")

    exec_args = ["exec", "-T"] + (["-e", KEY_ENV] if mode == "anthropic" else []) + ["scanner"]
    cp = run(compose_argv(mode, *exec_args,
                          *op06d_run_argv(mode, gen, f"{base}/run", model=model, limits=limits)),
             float(limits["max_wall_clock"]) + 600)
    out_dir = LAB / "captures" / CAPTURE_SUBDIR / mode
    m = re.search(r"report \(html\):\s*(\S+)", cp.stdout or "")
    report = (LAB / "captures" / pathlib.PurePosixPath(m.group(1)).relative_to("/captures")) if m else None
    problems = [] if cp.returncode == 0 else [f"op06d run exited {cp.returncode}: {(cp.stderr or '').strip()[:500]}"]
    problems += verify_run(mode, out_dir / "run", report, secret=env.get(KEY_ENV))
    return RunOutcome(mode, cp.returncode, cp.stdout or "", cp.stderr or "", out_dir, report, problems)


def verify_run(mode: str, run_dir: pathlib.Path, report: pathlib.Path | None, *,
               secret: str | None = None) -> list[str]:
    """What a finished acceptance run must show. Returns the problems found."""
    problems: list[str] = []
    if report is None or not report.is_file():
        return problems + [f"no HTML report was produced under {run_dir}"]
    html = report.read_text(encoding="utf-8")
    if "<h2>Planner</h2>" not in html:
        problems.append("the report has no Planner section")
    db = run_dir / "evidence.db"
    if not db.is_file():
        return problems + ["no evidence store"]
    store = EvidenceStore(db)
    runs = store.list_runs()
    if not runs:
        return problems + ["the evidence store has no run"]
    recon = store.reconstruct_run(runs[-1].run_id)
    planner = recon.planner or {}
    want_class = "local" if mode == "local" else "hosted"
    if planner.get("provider") != mode or planner.get("endpoint_class") != want_class:
        problems.append(f"planner record is {planner.get('provider')}/{planner.get('endpoint_class')}, "
                        f"expected {mode}/{want_class}")
    termination = planner.get("termination")
    if termination in BAD_TERMINATIONS or not termination:
        problems.append(f"the run ended with termination {termination!r}")
    executed = [a for a in recon.actions if a.executed]
    if not executed:
        problems.append("no action was executed through the gate")
    in_scope = set(recon.run.scope.get("in_scope") or [])
    stray = sorted({a.target for a in executed if a.target not in in_scope})
    if stray:
        problems.append(f"executed actions on targets outside the engagement scope: {stray}")
    if recon.run.audit_log_path:
        audit = run_dir / "audit" / pathlib.PurePosixPath(recon.run.audit_log_path).name
        try:
            verify_log(audit)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"audit log does not verify: {exc}")
    for p in sorted(run_dir.parent.rglob("*")):
        if not p.is_file():
            continue
        data = p.read_bytes()
        if (secret and secret.encode() in data) or KEY_SHAPE.search(data):
            problems.append(f"API key material found in {p.relative_to(LAB)}")
    return problems


# --- CLI --------------------------------------------------------------------------------

def _print_check(report: CheckReport) -> int:
    for line in report.lines:
        print(line)
    verdict = {0: "PASS - isolation confirmed with the relay up",
               1: "FAIL - NOT ISOLATED. Tear down: uv run python lab/model_relay.py down",
               2: "INCONCLUSIVE - not a pass; fix and rerun"}[report.exit_code]
    print(f"RESULT: {verdict}")
    return report.exit_code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="model_relay.py", description="RC-47 opt-in model relay for lab LLM runs")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("build", "up", "check", "run"):
        sp = sub.add_parser(name)
        sp.add_argument("mode", choices=MODES)
        if name in ("up", "run"):
            sp.add_argument("--engagement", default=None, help="lab/ engagement template (anthropic: required)")
        if name == "run":
            sp.add_argument("--model", default=None)
            for k, v in ACCEPTANCE_LIMITS.items():
                sp.add_argument(f"--{k.replace('_', '-')}", type=int, default=v)
    sub.add_parser("down")
    sub.add_parser("status")
    args = p.parse_args(argv)
    try:
        if args.cmd == "build":
            build(args.mode)
            print(f"built the overlay images ({args.mode})")
        elif args.cmd == "up":
            path = up(args.mode, args.engagement)
            print(f"{args.mode} relay up and lab targets ready (engagement {path.relative_to(ROOT)} allows it). "
                  f"Next: uv run python lab/model_relay.py check {args.mode}")
        elif args.cmd == "check":
            return _print_check(check(args.mode))
        elif args.cmd == "run":
            report = check(args.mode)
            if report.exit_code != 0:
                print("isolation check did not PASS; refusing to run:")
                return _print_check(report) or 1
            limits = {k: getattr(args, k) for k in ACCEPTANCE_LIMITS}
            outcome = run_acceptance(args.mode, args.engagement, model=args.model, limits=limits)
            print(outcome.stdout)
            if outcome.problems:
                print("ACCEPTANCE: FAIL")
                for prob in outcome.problems:
                    print(f"  - {prob}")
                return 1
            print(f"ACCEPTANCE: PASS - report {outcome.report_html}")
        elif args.cmd == "down":
            cp = down()
            print(cp.stdout + cp.stderr)
            return cp.returncode
        elif args.cmd == "status":
            mode = running_relay_mode(default_runner)
            print(f"relay: {mode or 'not running'}")
    except NotReady as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 1
    except RelayError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
