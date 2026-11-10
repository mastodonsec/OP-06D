# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-25: gated lab check that privilege-degradation surfacing matches the
real nmap binary in both privilege modes (RUNBOOK Step 12).

NOT part of the default suite: excluded via the `lab` marker and skipped
unless OP06D_LAB=1 is set, or docker/compose is unavailable - same gating
as tests/integration/test_lab_rc20.py.

    OP06D_LAB=1 uv run pytest -m lab tests/integration/test_lab_rc25.py
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

sys.path.insert(0, str(ROOT / "lab"))
import lab_stack as stack  # noqa: E402

_PROBE = """
import json
from op06d.nmap_tool import NmapTool
t = NmapTool(50)
r = t.run("172.31.77.11", {"profile": "aggressive"})
print(json.dumps({
    "status": r.status,
    "degraded": r.findings.get("degraded"),
    "degraded_capabilities": r.findings.get("degraded_capabilities"),
    "scan_types": r.findings.get("summary", {}).get("scan_types"),
    "has_os": any("os" in h for h in r.findings.get("hosts", [])),
}))
"""


def _require_lab_enabled() -> None:
    if os.environ.get("OP06D_LAB") != "1":
        pytest.skip("set OP06D_LAB=1 to run the gated lab check (RC-25)")


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


def _exec(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return _compose("exec", "-T", *args, timeout=timeout)


@pytest.fixture(scope="module")
def lab_stack():
    _require_lab_enabled()
    _require_docker()
    with stack.lab_stack(_compose):
        _wait_for_targets()
        iso = _exec("scanner", "bash", "/lab/check_isolation.sh", timeout=120)
        if iso.returncode != 0:
            pytest.fail(f"ABORT: isolation did not PASS, refusing to scan:\n{iso.stdout}\n{iso.stderr}")
        yield


def _wait_for_targets(attempts: int = 30, delay: float = 2.0) -> None:
    for _ in range(attempts):
        j = _exec("scanner", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                   "http://juice-shop.lab:3000/", timeout=15)
        d = _exec("scanner", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                   "http://dvwa.lab/", timeout=15)
        if j.stdout.strip()[:1] in ("2", "3") and d.stdout.strip()[:1] in ("2", "3"):
            return
        time.sleep(delay)
    pytest.fail("lab targets never came up in time")


def _probe(user: str | None) -> dict:
    args = ["scanner"]
    if user:
        args = ["-u", user, "scanner"]
    r = _exec(*args, "python3", "-c", _PROBE, timeout=120)
    assert r.returncode == 0, f"probe failed:\n{r.stdout}\n{r.stderr}"
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_unprivileged_real_nmap_aggressive_scan_is_surfaced_as_degraded(lab_stack):
    result = _probe(user="scanner")
    assert result["status"] == "ok"
    assert result["degraded"] is True
    assert result["degraded_capabilities"] == ["os_detection"]
    assert result["scan_types"] == ["connect"]
    assert result["has_os"] is False


def test_privileged_real_nmap_aggressive_scan_is_not_degraded(lab_stack):
    result = _probe(user=None)  # root, the scanner container's default user
    assert result["status"] == "ok"
    assert result["degraded"] is None
    assert result["scan_types"] == ["syn"]
    assert result["has_os"] is True
