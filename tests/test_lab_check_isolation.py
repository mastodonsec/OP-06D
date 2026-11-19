# SPDX-License-Identifier: AGPL-3.0-or-later
"""lab/check_isolation.py, the host-side isolation gate, with docker mocked at
the subprocess boundary (``subprocess.run`` and ``shutil.which`` inside the
module): PASS, each FAIL kind, INCONCLUSIVE and NOT RUN. The expected services
always come from the mocked ``docker compose config --services``.
"""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import check_isolation as ci  # noqa: E402

NET = "rc-lab_labnet"
SERVICES = ["juice-shop", "dvwa", "redirect", "scanner"]


def _healthy() -> dict:
    containers = {
        f"rc-lab-{s}-1": {"service": s, "networks": [NET], "ports": {"80/tcp": None},
                          "mode": NET, "privileged": False}
        for s in SERVICES
    }
    return {
        "daemon": True,
        "config_rc": 0,
        "services": list(SERVICES),
        "network": {"exists": True, "internal": "true", "members": list(containers),
                    "options": {"com.docker.network.bridge.inhibit_ipv4": "true",
                                "com.docker.network.enable_ipv4": "true"}},
        "containers": containers,
        "control_rc": 0,
        "scanner_rc": 0,
    }


class FakeDocker:
    """Answers docker argv lists the way the real CLI does, from a state dict."""

    def __init__(self, state: dict):
        self.state = state
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        assert kwargs.get("shell") in (None, False)  # never through a shell
        assert argv[0] == "/fake/bin/docker"
        args = argv[1:]
        self.calls.append(args)
        s = self.state

        def cp(code, out="", err=""):
            return subprocess.CompletedProcess(argv, code, out, err)

        if args[0] == "version":
            return cp(0, "29.0.0\n") if s["daemon"] else cp(1, "", "Cannot connect to the Docker daemon")
        if not s["daemon"]:
            return cp(1, "", "Cannot connect to the Docker daemon")
        if args[0] == "compose":
            if "config" in args:
                return cp(s["config_rc"], "".join(f"{x}\n" for x in s["services"]) if s["config_rc"] == 0 else "",
                          "" if s["config_rc"] == 0 else "no such file")
            if "exec" in args:
                return cp(s["scanner_rc"], f"scanner says RESULT {s['scanner_rc']}\n")
        if args[:2] == ["network", "inspect"]:
            n = s["network"]
            if not n["exists"]:
                return cp(1, "", "network not found")
            fmt = args[args.index("--format") + 1] if "--format" in args else None
            if fmt is None:
                return cp(0, "[{}]")
            if fmt == "{{.Internal}}":
                return cp(0, n["internal"] + "\n")
            if fmt == "{{json .Options}}":
                return cp(0, json.dumps(n["options"]) + "\n")
            return cp(0, "".join(f"{m} " for m in n["members"]) + "\n")
        if args[0] == "ps":
            running = [f"{c['service']} {name}" for name, c in s["containers"].items() if c.get("running", True)]
            return cp(0, "\n".join(running) + "\n")
        if args[0] == "inspect":
            c = s["containers"].get(args[1])
            if c is None:
                return cp(1, "", "No such object")
            fmt = args[args.index("--format") + 1]
            if "Networks" in fmt:
                return cp(0, "".join(f"{n} " for n in c["networks"]) + "\n")
            if "Ports" in fmt:
                return cp(0, json.dumps(c["ports"]) + "\n")
            return cp(0, f"{c['mode']} privileged={str(c['privileged']).lower()}\n")
        if args[0] == "run":
            return cp(s["control_rc"], "HTTP 200\n" if s["control_rc"] == 0 else "")
        raise AssertionError(f"unexpected docker call: {args}")


def _check(monkeypatch, state: dict, **kw) -> tuple[ci.Report, FakeDocker]:
    fake = FakeDocker(state)
    monkeypatch.setattr(ci.shutil, "which", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(ci.subprocess, "run", fake)
    return ci.run_checks("lab/docker-compose.yml", "rc-lab", **kw), fake


def _mutated(mutate) -> dict:
    state = copy.deepcopy(_healthy())
    mutate(state)
    return state


def _fails(report: ci.Report) -> list[str]:
    return [ln for ln in report.lines if ln.startswith("FAIL  ")]


# --- PASS --------------------------------------------------------------------------------

def test_a_healthy_isolated_lab_passes(monkeypatch):
    report, fake = _check(monkeypatch, _healthy(), with_internet_control=True)
    assert report.exit_code == ci.EXIT_PASS, report.text
    assert _fails(report) == []
    assert report.lines[-1].startswith("RESULT: PASS - lab isolation confirmed")
    assert "PASS  4 containers on rc-lab_labnet" in report.text
    assert report.network_internal == "true" and report.scanner_exit == 0
    assert ["compose", "-p", "rc-lab", "-f", "lab/docker-compose.yml", "config", "--services"] in fake.calls
    assert ["compose", "-p", "rc-lab", "-f", "lab/docker-compose.yml", "exec", "-T", "scanner", "bash",
            "/lab/check_isolation.sh"] in fake.calls
    assert any(c[:6] == ["run", "--rm", "--network", "bridge", "--platform", "linux/amd64"] for c in fake.calls)


def test_without_the_control_no_container_is_started(monkeypatch):
    report, fake = _check(monkeypatch, _healthy())
    assert report.exit_code == ci.EXIT_PASS
    assert not any(c[0] == "run" for c in fake.calls)


def test_the_expected_services_come_from_the_compose_file(monkeypatch):
    def add_service(s):
        s["services"].append("extra")
        s["containers"]["rc-lab-extra-1"] = {"service": "extra", "networks": [NET], "ports": {},
                                             "mode": NET, "privileged": False}
        s["network"]["members"].append("rc-lab-extra-1")
    report, _ = _check(monkeypatch, _mutated(add_service))
    assert report.exit_code == ci.EXIT_PASS, report.text
    assert "PASS  5 containers on rc-lab_labnet" in report.text


# --- FAIL --------------------------------------------------------------------------------

@pytest.mark.parametrize("name,mutate,expect", [
    ("not internal", lambda s: s["network"].update(internal="false"),
     "network rc-lab_labnet is not internal (got 'false')"),
    ("extra container", lambda s: s["network"]["members"].append("intruder"),
     "expected 4 containers on rc-lab_labnet"),
    ("extra network", lambda s: s["containers"]["rc-lab-dvwa-1"]["networks"].append("bridge"),
     "rc-lab-dvwa-1 is attached to: rc-lab_labnet bridge (must be only rc-lab_labnet)"),
    ("published port", lambda s: s["containers"]["rc-lab-juice-shop-1"].update(
        ports={"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3000"}]}),
     "rc-lab-juice-shop-1 publishes ports to the host"),
    ("host mode", lambda s: s["containers"]["rc-lab-scanner-1"].update(mode="host"),
     "rc-lab-scanner-1 uses unsafe settings: host privileged=false"),
    ("privileged", lambda s: s["containers"]["rc-lab-redirect-1"].update(privileged=True),
     "rc-lab-redirect-1 uses unsafe settings: rc-lab_labnet privileged=true"),
    ("in-scanner FAIL", lambda s: s.update(scanner_rc=1), "scanner-side check failed (exit 1)"),
])
def test_each_fail_kind_fails(monkeypatch, name, mutate, expect):
    report, _ = _check(monkeypatch, _mutated(mutate))
    assert report.exit_code == ci.EXIT_FAIL, name
    assert any(expect in ln for ln in _fails(report)), report.text
    assert "RESULT: FAIL - THE LAB IS NOT PROVEN ISOLATED. DO NOT SCAN." in report.lines


def test_a_lab_service_that_left_the_network_is_checked_and_fails(monkeypatch):
    def leave(s):
        s["containers"]["rc-lab-dvwa-1"]["networks"] = ["bridge"]
        s["network"]["members"].remove("rc-lab-dvwa-1")
    report, _ = _check(monkeypatch, _mutated(leave))
    assert report.exit_code == ci.EXIT_FAIL
    assert any("rc-lab-dvwa-1 is attached to: bridge" in ln for ln in _fails(report))


def test_unreadable_port_bindings_fail_closed(monkeypatch):
    report, _ = _check(monkeypatch, _mutated(lambda s: s["containers"]["rc-lab-dvwa-1"].update(ports="not-json")))
    assert report.exit_code == ci.EXIT_FAIL


def test_a_fail_outranks_an_inconclusive(monkeypatch):
    state = _mutated(lambda s: (s["network"].update(internal="false"), s.update(control_rc=1, scanner_rc=2)))
    report, _ = _check(monkeypatch, state, with_internet_control=True)
    assert report.exit_code == ci.EXIT_FAIL


# --- INCONCLUSIVE --------------------------------------------------------------------------

def test_an_unreachable_internet_control_is_inconclusive_and_skips_the_scanner(monkeypatch):
    report, fake = _check(monkeypatch, _mutated(lambda s: s.update(control_rc=1)), with_internet_control=True)
    assert report.exit_code == ci.EXIT_INCONCLUSIVE
    assert any(ln.startswith("INCONCLUSIVE  control could not reach the internet") for ln in report.lines)
    assert not any("exec" in c for c in fake.calls)
    assert "RESULT: PASS" not in report.text


def test_an_inconclusive_scanner_check_is_inconclusive(monkeypatch):
    report, _ = _check(monkeypatch, _mutated(lambda s: s.update(scanner_rc=2)))
    assert report.exit_code == ci.EXIT_INCONCLUSIVE
    assert "INCONCLUSIVE inside the scanner. Not a pass." in report.lines
    assert report.lines[-1].startswith("RESULT: INCONCLUSIVE")


# --- NOT RUN -------------------------------------------------------------------------------

def _assert_not_run(report: ci.Report) -> str:
    assert report.exit_code == ci.EXIT_NOT_RUN
    text = report.text
    assert "RESULT: NOT RUN" in text and "neither a PASS nor an isolation FAIL" in text
    assert _fails(report) == [] and "RESULT: PASS" not in text and "RESULT: FAIL" not in text
    return text


def test_no_daemon_is_not_run(monkeypatch):
    report, fake = _check(monkeypatch, _mutated(lambda s: s.update(daemon=False)))
    assert "cannot reach the Docker daemon" in _assert_not_run(report)
    assert fake.calls == [["version", "--format", "{{.Server.Version}}"]]


def test_docker_missing_from_path_is_not_run(monkeypatch):
    monkeypatch.setattr(ci.shutil, "which", lambda name: None)
    monkeypatch.setattr(ci.subprocess, "run", lambda *a, **k: pytest.fail("ran without a docker binary"))
    report = ci.run_checks()
    assert "cannot reach the Docker daemon" in _assert_not_run(report)


def test_a_stack_that_is_down_is_not_run(monkeypatch):
    def down(s):
        s["network"]["exists"] = False
        for c in s["containers"].values():
            c["running"] = False
    report, fake = _check(monkeypatch, _mutated(down))
    text = _assert_not_run(report)
    assert "network rc-lab_labnet does not exist" in text
    assert "not running: juice-shop, dvwa, redirect, scanner" in text
    assert not any("exec" in c for c in fake.calls)


def test_a_failing_compose_config_is_not_run_never_pass(monkeypatch):
    report, fake = _check(monkeypatch, _mutated(lambda s: s.update(config_rc=1)))
    assert "cannot read the expected services" in _assert_not_run(report)
    assert not any(c[:2] == ["network", "inspect"] for c in fake.calls)


def test_an_empty_service_list_is_not_run(monkeypatch):
    report, _ = _check(monkeypatch, _mutated(lambda s: s.update(services=[])))
    assert "listed no services" in _assert_not_run(report)


def test_a_missing_service_is_not_run(monkeypatch):
    report, _ = _check(monkeypatch, _mutated(lambda s: s["containers"]["rc-lab-redirect-1"].update(running=False)))
    text = _assert_not_run(report)
    assert "not running: redirect" in text and "does not exist" not in text


# --- runner and CLI ------------------------------------------------------------------------

def test_the_default_runner_turns_a_timeout_into_a_failed_process(monkeypatch):
    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
    monkeypatch.setattr(ci.shutil, "which", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(ci.subprocess, "run", boom)
    cp = ci.default_runner(["docker", "version"], 5)
    assert cp.returncode == -1 and "timed out" in cp.stderr


@pytest.mark.parametrize("state_fn,code", [
    (_healthy, 0),
    (lambda: _mutated(lambda s: s.update(scanner_rc=1)), 1),
    (lambda: _mutated(lambda s: s.update(scanner_rc=2)), 2),
    (lambda: _mutated(lambda s: s.update(daemon=False)), 3),
])
def test_main_returns_the_gate_exit_code_and_prints_the_report(monkeypatch, capsys, state_fn, code):
    fake = FakeDocker(state_fn())
    monkeypatch.setattr(ci.shutil, "which", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(ci.subprocess, "run", fake)
    assert ci.main([]) == code
    assert "RESULT: " in capsys.readouterr().out


def test_main_passes_compose_project_and_control_through(monkeypatch):
    fake = FakeDocker(_healthy())
    monkeypatch.setattr(ci.shutil, "which", lambda name: f"/fake/bin/{name}")
    monkeypatch.setattr(ci.subprocess, "run", fake)
    assert ci.main(["--compose", "x/c.yml", "--project", "rc-lab", "--with-internet-control"]) == 0
    assert ["compose", "-p", "rc-lab", "-f", "x/c.yml", "config", "--services"] in fake.calls
    assert any(c[0] == "run" for c in fake.calls)


# --- the bridge holds no gateway address -----------------------------------------------------

def test_the_inhibit_ipv4_option_present_passes(monkeypatch):
    report, fake = _check(monkeypatch, _healthy())
    assert report.exit_code == ci.EXIT_PASS
    assert ("PASS  network rc-lab_labnet sets com.docker.network.bridge.inhibit_ipv4=true "
            "(the bridge holds no gateway address)") in report.lines
    assert ["network", "inspect", "rc-lab_labnet", "--format", "{{json .Options}}"] in fake.calls


@pytest.mark.parametrize("options,shown", [
    ({"com.docker.network.enable_ipv4": "true"}, "None"),
    ({"com.docker.network.bridge.inhibit_ipv4": "false"}, "'false'"),
    ({"com.docker.network.bridge.inhibit_ipv4": "True"}, "'True'"),
    (None, "None"),
])
def test_the_inhibit_ipv4_option_missing_or_not_true_fails(monkeypatch, options, shown):
    report, _ = _check(monkeypatch, _mutated(lambda s: s["network"].update(options=options)))
    assert report.exit_code == ci.EXIT_FAIL
    assert any(f"does not set com.docker.network.bridge.inhibit_ipv4=true (got {shown})" in ln
               for ln in _fails(report)), report.text
