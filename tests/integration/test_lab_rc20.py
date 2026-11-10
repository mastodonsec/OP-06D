# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-20: gated lab integration + repeatability harness.

Automates, as a single gated test, the lab validation RUNBOOK.md Steps 4/8
otherwise walk through by hand: stand up the lab, PROVE isolation, run the
real scans through the gated toolbox (`lab/scan_driver.py`, shared with the
runbook so the two cannot drift), and assert the results against the frozen
baseline in tests/integration/baseline.json - including the RC-23
resolve-once markers. This does not replace the exploratory one-off steps
(10/11/12), only the hand-run functional + repeatability check (Step 8/9).

NOT part of the default suite: excluded via the `lab` marker
(see pyproject.toml's `addopts = "-m 'not lab'"`) and skipped unless
OP06D_LAB=1 is set, or docker/compose is unavailable.

    OP06D_LAB=1 uv run pytest -m lab tests/integration/test_lab_rc20.py
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.lab

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = ROOT / "lab" / "docker-compose.yml"

# RC-24: the baseline assertions live in lab/lab_asserts.py, shared with the
# one-command validation harness (lab/validation_harness.py) so they can't drift.
sys.path.insert(0, str(ROOT / "lab"))
import lab_asserts  # noqa: E402
from scan_driver import isolation_failure_reason  # noqa: E402

BASELINE = lab_asserts.load_baseline()
EPHEMERAL_SUBDIR = "_rc20_ephemeral"  # under the scanner's /captures mount; wiped before every run


def _require_lab_enabled() -> None:
    if os.environ.get("OP06D_LAB") != "1":
        pytest.skip("set OP06D_LAB=1 to run the gated lab integration test (RC-20)")


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is not available")
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "config"],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker compose could not be invoked")
    if r.returncode != 0:
        pytest.skip(f"docker compose is not available or the compose file is invalid: {r.stderr!r}")


def _compose(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _exec(*args: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return _compose("exec", "-T", "scanner", *args, timeout=timeout)


@pytest.fixture(scope="module")
def lab_stack():
    """Stand up the lab, require the isolation gate to PASS, and ALWAYS tear
    down - even if isolation fails or a later assertion raises (non-negotiable
    #3: never leave containers running)."""
    _require_lab_enabled()
    _require_docker()
    up = _compose("up", "-d", timeout=180)
    try:
        if up.returncode != 0:
            pytest.fail(f"docker compose up failed:\n{up.stdout}\n{up.stderr}")
        _wait_for_targets()
        _assert_isolation_or_abort()
        yield
    finally:
        _compose("down", timeout=120)


def _wait_for_targets(attempts: int = 30, delay: float = 2.0) -> None:
    for _ in range(attempts):
        j = _exec("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://juice-shop.lab:3000/", timeout=15)
        d = _exec("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://dvwa.lab/", timeout=15)
        if j.stdout.strip()[:1] in ("2", "3") and d.stdout.strip()[:1] in ("2", "3"):
            return
        time.sleep(delay)
    pytest.fail("lab targets never came up (juice-shop/dvwa did not answer HTTP in time)")


def _assert_isolation_or_abort() -> None:
    """HARD precondition (non-negotiable #2): ABORT before any scan unless
    isolation PASSES. Uses the same pure decision (`isolation_failure_reason`)
    the fast unit test in tests/test_lab_isolation_guard.py exercises without
    docker."""
    inspect = subprocess.run(
        ["docker", "network", "inspect", "rc-lab_labnet", "--format", "{{.Internal}}"],
        capture_output=True, text=True, timeout=30,
    )
    internal = inspect.stdout.strip() if inspect.returncode == 0 else "<inspect failed>"
    iso = _exec("bash", "/lab/check_isolation.sh", timeout=120)

    reason = isolation_failure_reason(internal, iso.returncode)
    if reason is not None:
        pytest.fail(f"ABORT: isolation precondition failed, refusing to scan: {reason}\n{iso.stdout}\n{iso.stderr}")


def _fresh_capture_dir(name: str) -> str:
    """A fresh, ephemeral capture dir under the scanner's writable /captures
    mount, wiped before use so the audit log starts empty (non-negotiable #4 -
    a piled log breaks the dns_pinned count assertion). Never lab/captures/
    itself and never the frozen *.findings.json fixtures there."""
    path = f"/captures/{EPHEMERAL_SUBDIR}/{name}"
    r = _exec("sh", "-c", f"rm -rf {path} && mkdir -p {path}", timeout=30)
    assert r.returncode == 0, f"could not prepare ephemeral capture dir {path}: {r.stderr}"
    return path


def _run_scan_set(name: str) -> dict:
    out_dir = _fresh_capture_dir(name)
    summary_path = f"{out_dir}/summary.json"
    r = _exec("python3", "/lab/scan_driver.py", out_dir, "--json", summary_path, timeout=300)
    assert r.returncode == 0, f"scan_driver.py failed:\n{r.stdout}\n{r.stderr}"
    read = _exec("cat", summary_path, timeout=30)
    assert read.returncode == 0, f"could not read scan summary: {read.stderr}"
    return json.loads(read.stdout)


def test_scan_set_matches_the_frozen_baseline(lab_stack):
    summary = _run_scan_set("run1")
    lab_asserts.assert_scan_summary(summary, BASELINE)


def test_scan_set_is_repeatable(lab_stack):
    first = _run_scan_set("repeat1")
    second = _run_scan_set("repeat2")
    assert lab_asserts.fingerprint(first) == lab_asserts.fingerprint(second)
