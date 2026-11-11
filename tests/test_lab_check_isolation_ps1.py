# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs

lab/check_isolation.ps1 must tell "the lab stack is not up" apart from "the
lab is not isolated": the first is NOT RUN (exit 3), never an isolation FAIL.

The script is run with a stub ``docker`` first on PATH, so no real Docker is
needed; the tests skip where PowerShell is not installed.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "lab" / "check_isolation.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")

pytestmark = pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")

# The stub answers by first argument. STUB_MODE picks the scenario.
STUB_SH = """#!/bin/sh
echo "$@" >> "$STUB_LOG"
case "$STUB_MODE:$1" in
  no-daemon:*) exit 1 ;;
  *:version) echo 27.0.0; exit 0 ;;
  no-stack:network) exit 1 ;;
  partial:network) exit 0 ;;
  no-stack:ps) exit 0 ;;
  partial:ps) echo scanner; echo dvwa; exit 0 ;;
esac
exit 1
"""
STUB_CMD = """@echo off
echo %*>> "%STUB_LOG%"
if "%STUB_MODE%"=="no-daemon" exit /b 1
if "%1"=="version" (echo 27.0.0& exit /b 0)
if "%STUB_MODE%:%1"=="no-stack:network" exit /b 1
if "%STUB_MODE%:%1"=="partial:network" exit /b 0
if "%STUB_MODE%:%1"=="no-stack:ps" exit /b 0
if "%STUB_MODE%:%1"=="partial:ps" (echo scanner& echo dvwa& exit /b 0)
exit /b 1
"""


def _run(tmp_path: pathlib.Path, mode: str) -> tuple[subprocess.CompletedProcess, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker.cmd").write_text(STUB_CMD, encoding="ascii", newline="\r\n")
    sh = bin_dir / "docker"
    sh.write_text(STUB_SH, encoding="ascii", newline="\n")
    sh.chmod(sh.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "docker-calls.log"
    log.write_text("", encoding="ascii")
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "STUB_MODE": mode, "STUB_LOG": str(log)}
    cp = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, env=env, cwd=ROOT,
    )
    return cp, log.read_text(encoding="utf-8", errors="replace")


def _assert_not_run(cp: subprocess.CompletedProcess) -> str:
    out = cp.stdout + cp.stderr
    assert cp.returncode == 3, out
    assert "RESULT: NOT RUN" in out and "neither a PASS nor an isolation FAIL" in out
    assert "FAIL  " not in out and "RESULT: FAIL" not in out and "RESULT: PASS" not in out
    return out


def test_a_stack_that_is_not_up_is_not_run_rather_than_an_isolation_fail(tmp_path):
    cp, calls = _run(tmp_path, "no-stack")
    out = _assert_not_run(cp)
    assert "the rc-lab stack is not up" in out and "network rc-lab_labnet does not exist" in out
    assert "not running: juice-shop, dvwa, scanner" in out and "up -d" in out
    assert "exec" not in calls  # the scanner-side check never started


def test_a_partly_started_stack_names_the_service_that_is_missing(tmp_path):
    cp, _ = _run(tmp_path, "partial")
    out = _assert_not_run(cp)
    assert "not running: juice-shop" in out and "does not exist" not in out


def test_an_unreachable_docker_daemon_is_not_run(tmp_path):
    cp, calls = _run(tmp_path, "no-daemon")
    out = _assert_not_run(cp)
    assert "cannot reach the Docker daemon" in out
    assert "network" not in calls
