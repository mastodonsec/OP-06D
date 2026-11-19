# SPDX-License-Identifier: AGPL-3.0-or-later
"""OP-06D lab isolation gate, host side. Run BEFORE any scan, from the repository
root, on Windows, Linux or macOS:

    uv run python lab/check_isolation.py [--with-internet-control] [--compose lab/docker-compose.yml] [--project rc-lab]

Two groups of checks; the result is PASS only if ALL pass:

  A. Host-side (how Docker is configured):
       - the lab network is 'internal'
       - every lab container is attached to that one network only
       - no lab container publishes a port, uses host networking or is privileged
  B. Inside the scanner container: lab/check_isolation.sh, which tries to reach
     the internet, the Docker host and neighbouring networks. EVERY attempt is
     EXPECTED TO FAIL.

--with-internet-control also runs a throwaway container on Docker's DEFAULT
bridge network and shows that it CAN reach the internet (one HTTPS request to
example.com, not from the lab). That proves the method can detect
connectivity, so the lab's "blocked" results mean something.

The expected services are read from the compose file
(``docker compose config --services``), never from a list kept here.

Exit codes: 0 = PASS, 1 = FAIL (not isolated: stop), 2 = INCONCLUSIVE,
            3 = NOT RUN (Docker is unreachable, the compose file cannot be read
                or the lab stack is not up, so nothing was checked; this says
                nothing about isolation).

Standard library only. Docker is called with argument lists, never through a
shell. lab/validation_harness.py imports ``run_checks`` from here.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Sequence

DEFAULT_COMPOSE = "lab/docker-compose.yml"
DEFAULT_PROJECT = "rc-lab"
CONTROL_IMAGE = "op06d-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1"
CONTROL_URL = "https://example.com"
SCANNER_SERVICE = "scanner"
IN_SCANNER_SCRIPT = "/lab/check_isolation.sh"
INHIBIT_IPV4 = "com.docker.network.bridge.inhibit_ipv4"

EXIT_PASS, EXIT_FAIL, EXIT_INCONCLUSIVE, EXIT_NOT_RUN = 0, 1, 2, 3

Runner = Callable[[Sequence[str], float], subprocess.CompletedProcess]


def default_runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess:
    """Run docker without a shell. A missing binary or a timeout comes back as a
    failed process (exit -1), so every caller judges by return code."""
    argv = list(argv)
    exe = shutil.which(argv[0])
    if exe is None:
        return subprocess.CompletedProcess(argv, -1, "", f"{argv[0]}: not found on PATH")
    try:
        return subprocess.run([exe, *argv[1:]], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, -1, "", f"timed out after {timeout:.0f}s")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, -1, "", str(exc))


@dataclass
class Report:
    emit: Callable[[str], None] | None = None
    lines: list[str] = field(default_factory=list)
    failed: bool = False
    inconclusive: bool = False
    not_run: bool = False
    network_internal: str = ""
    scanner_exit: int | None = None
    exit_code: int = EXIT_NOT_RUN

    def say(self, line: str = "") -> None:
        self.lines.append(line)
        if self.emit is not None:
            self.emit(line)

    def ok(self, msg: str) -> None:
        self.say(f"PASS  {msg}")

    def fail(self, msg: str) -> None:
        self.say(f"FAIL  {msg}")
        self.failed = True

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _compose(compose: str, project: str, *args: str) -> list[str]:
    return ["docker", "compose", "-p", project, "-f", compose, *args]


def _out_lines(cp: subprocess.CompletedProcess) -> list[str]:
    return [ln.strip() for ln in (cp.stdout or "").splitlines() if ln.strip()]


def _not_run(report: Report, msg: str, hint: str) -> Report:
    report.say(f"RESULT: NOT RUN - {msg}")
    report.say("Nothing was checked. This is neither a PASS nor an isolation FAIL.")
    report.say(hint)
    report.not_run = True
    report.exit_code = EXIT_NOT_RUN
    return report


def _finish(report: Report, compose: str) -> Report:
    report.say("")
    if report.failed:
        report.say("RESULT: FAIL - THE LAB IS NOT PROVEN ISOLATED. DO NOT SCAN.")
        report.say(f"Tear down:  docker compose -f {compose} down")
        report.exit_code = EXIT_FAIL
    elif report.inconclusive:
        report.say("RESULT: INCONCLUSIVE - not a pass. Fix the cause and run the check again.")
        report.exit_code = EXIT_INCONCLUSIVE
    else:
        report.say("RESULT: PASS - lab isolation confirmed (host-side and from inside). You may proceed.")
        report.exit_code = EXIT_PASS
    return report


def expected_services(compose: str, project: str, run: Runner) -> tuple[list[str] | None, str]:
    """The services the compose file declares, in its order, or (None, reason)."""
    cp = run(_compose(compose, project, "config", "--services"), 60)
    services = _out_lines(cp)
    if cp.returncode != 0:
        return None, f"docker compose config --services failed (exit {cp.returncode}): {(cp.stderr or '').strip()[:300]}"
    if not services:
        return None, "docker compose config --services listed no services"
    return services, ""


def running_services(project: str, run: Runner) -> dict[str, str]:
    """service -> container name, for this project's running containers."""
    cp = run(["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
              "--filter", "status=running",
              "--format", '{{.Label "com.docker.compose.service"}} {{.Names}}'], 60)
    found: dict[str, str] = {}
    if cp.returncode != 0:
        return found
    for line in _out_lines(cp):
        svc, _, name = line.partition(" ")
        found[svc] = name.strip()
    return found


def host_checks(report: Report, network: str, expected: list[str], running: dict[str, str], run: Runner) -> None:
    report.say("=== A. Host-side checks ===================================================")

    # A1. the network is internal
    cp = run(["docker", "network", "inspect", network, "--format", "{{.Internal}}"], 60)
    internal = (cp.stdout or "").strip() if cp.returncode == 0 else ""
    report.network_internal = internal
    if internal == "true":
        report.ok(f"network {network} is internal (no gateway, no NAT)")
    else:
        report.fail(f"network {network} is not internal (got '{internal}'). Is 'internal: true' set?")

    # A1b. the bridge holds no address (otherwise the gateway address is the Docker host's)
    cp = run(["docker", "network", "inspect", network, "--format", "{{json .Options}}"], 60)
    try:
        options = json.loads(cp.stdout or "null") if cp.returncode == 0 else None
        inhibit = options.get(INHIBIT_IPV4) if isinstance(options, dict) else None
    except ValueError:
        inhibit = None
    if inhibit == "true":
        report.ok(f"network {network} sets {INHIBIT_IPV4}=true (the bridge holds no gateway address)")
    else:
        report.fail(f"network {network} does not set {INHIBIT_IPV4}=true (got {inhibit!r}): the bridge "
                    "would hold the gateway address, an address of the Docker host")

    # A2. which containers are on it, and what else they are attached to
    cp = run(["docker", "network", "inspect", network, "--format",
              "{{range $id, $c := .Containers}}{{$c.Name}} {{end}}"], 60)
    members = (cp.stdout or "").split() if cp.returncode == 0 else []
    if len(members) != len(expected):
        report.fail(f"expected {len(expected)} containers on {network} ({', '.join(expected)}), "
                    f"found {len(members)}: {', '.join(members)}")
    else:
        report.ok(f"{len(expected)} containers on {network}: {', '.join(members)}")

    # Every container on the network, and every lab service's container even if it is not on it.
    containers = list(members)
    containers += [name for svc in expected if (name := running.get(svc)) and name not in containers]
    for c in containers:
        cp = run(["docker", "inspect", c, "--format", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"], 60)
        nets = (cp.stdout or "").strip() if cp.returncode == 0 else f"<inspect failed, exit {cp.returncode}>"
        if nets == network:
            report.ok(f"{c} is attached only to {network}")
        else:
            report.fail(f"{c} is attached to: {nets} (must be only {network})")

        cp = run(["docker", "inspect", c, "--format", "{{json .NetworkSettings.Ports}}"], 60)
        raw = (cp.stdout or "").strip()
        try:
            ports = json.loads(raw) if cp.returncode == 0 else None
            published = [p for p, bindings in (ports or {}).items() if bindings]
            readable = cp.returncode == 0 and isinstance(ports, (dict, type(None)))
        except (ValueError, AttributeError):
            published, readable = [], False
        if not readable:
            report.fail(f"{c}: could not read its port bindings ({raw[:200] or cp.stderr.strip()[:200]})")
        elif published:
            report.fail(f"{c} publishes ports to the host: {raw}")
        else:
            report.ok(f"{c} publishes no ports to the host")

        cp = run(["docker", "inspect", c, "--format",
                  "{{.HostConfig.NetworkMode}} privileged={{.HostConfig.Privileged}}"], 60)
        mode = (cp.stdout or "").strip()
        if cp.returncode != 0 or " privileged=" not in mode:
            report.fail(f"{c}: could not read its network mode / privilege ({mode or cp.stderr.strip()[:200]})")
        elif mode.startswith("host ") or mode.endswith("privileged=true"):
            report.fail(f"{c} uses unsafe settings: {mode}")
        else:
            report.ok(f"{c} network mode / privilege OK ({mode})")


def internet_control(report: Report, run: Runner) -> bool:
    """True when a default-bridge container reached the internet."""
    report.say("")
    report.say("--- Control: a throwaway container on the DEFAULT bridge (expected to REACH the internet) ---")
    cp = run(["docker", "run", "--rm", "--network", "bridge", CONTROL_IMAGE,
              "curl", "-sS", "--max-time", "10", "-o", "/dev/null", "-w", "HTTP %{http_code}\n", CONTROL_URL], 180)
    for line in _out_lines(cp):
        report.say(f"  {line}")
    if cp.returncode == 0:
        report.ok("control: default-bridge container reached the internet (so the lab's failures are meaningful)")
        return True
    report.say("INCONCLUSIVE  control could not reach the internet from the default bridge; the host may be "
               "offline. 'Blocked' results are then not proof.")
    report.inconclusive = True
    return False


def scanner_check(report: Report, compose: str, project: str, run: Runner) -> None:
    report.say("")
    report.say("=== B. Inside the scanner (every outbound attempt is EXPECTED TO FAIL) ====")
    report.say(f"(running {IN_SCANNER_SCRIPT}; about a minute, its output follows when it finishes)")
    cp = run(_compose(compose, project, "exec", "-T", SCANNER_SERVICE, "bash", IN_SCANNER_SCRIPT), 600)
    for line in (cp.stdout or "").splitlines():
        report.say(line)
    report.scanner_exit = cp.returncode
    if cp.returncode == 2:
        report.say("INCONCLUSIVE inside the scanner. Not a pass.")
        report.inconclusive = True
    elif cp.returncode != 0:
        detail = (cp.stderr or "").strip()[:300]
        report.fail(f"scanner-side check failed (exit {cp.returncode}){': ' + detail if detail else ''}")


def run_checks(compose: str = DEFAULT_COMPOSE, project: str = DEFAULT_PROJECT, *,
               with_internet_control: bool = False, run: Runner = default_runner,
               emit: Callable[[str], None] | None = None) -> Report:
    """The whole gate. ``report.exit_code`` is 0 PASS, 1 FAIL, 2 INCONCLUSIVE, 3 NOT RUN.
    A FAIL anywhere outranks an INCONCLUSIVE."""
    report = Report(emit=emit)
    network = f"{project}_labnet"
    up_hint = f"Bring it up, then run this again:  docker compose -f {compose} up -d"

    # Preconditions: without a daemon and a running stack every check below would
    # fail for the wrong reason and read as "not isolated".
    cp = run(["docker", "version", "--format", "{{.Server.Version}}"], 60)
    if cp.returncode != 0:
        return _not_run(report, "cannot reach the Docker daemon.",
                        f"Start Docker (Docker Desktop, or the docker service on Linux), then bring the lab up:  "
                        f"docker compose -f {compose} up -d")
    expected, why = expected_services(compose, project, run)
    if expected is None:
        return _not_run(report, f"cannot read the expected services from {compose} ({why}).",
                        "Run this from the repository root, or pass --compose <path to lab/docker-compose.yml>.")
    cp = run(["docker", "network", "inspect", network], 60)
    network_exists = cp.returncode == 0
    running = running_services(project, run)
    missing = [s for s in expected if s not in running]
    if not network_exists or missing:
        what = []
        if not network_exists:
            what.append(f"network {network} does not exist")
        if missing:
            what.append(f"not running: {', '.join(missing)}")
        return _not_run(report, f"the {project} stack is not up ({'; '.join(what)}).", up_hint)

    host_checks(report, network, expected, running, run)
    if with_internet_control and not internet_control(report, run):
        if not report.failed:
            return _finish(report, compose)
    scanner_check(report, compose, project, run)
    return _finish(report, compose)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="OP-06D lab isolation gate (host side, then inside the scanner).")
    p.add_argument("--compose", default=DEFAULT_COMPOSE, help=f"compose file (default {DEFAULT_COMPOSE})")
    p.add_argument("--project", default=DEFAULT_PROJECT, help=f"compose project name (default {DEFAULT_PROJECT})")
    p.add_argument("--with-internet-control", action="store_true",
                   help="also show that a default-bridge container CAN reach the internet")
    args = p.parse_args(argv)
    report = run_checks(args.compose, args.project, with_internet_control=args.with_internet_control,
                        emit=lambda line: print(line, flush=True))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
