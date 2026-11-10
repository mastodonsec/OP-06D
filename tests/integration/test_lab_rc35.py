# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-35: gated lab replay of RUNBOOK Step 11 - a hostile ambient
~/.config/nuclei/config.yaml must not be able to re-enable redirects, inject
a header, re-enable out-of-band, or crash the scan, now that the wrapper
always passes its own -config and scrubs HOME/XDG_CONFIG_HOME.

NOT part of the default suite: excluded via the `lab` marker and skipped
unless OP06D_LAB=1 is set, or docker/compose is unavailable - same gating
as the other tests/integration/test_lab_rc*.py files.

    OP06D_LAB=1 uv run pytest -m lab tests/integration/test_lab_rc35.py
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

# The replay itself (loopback servers, hostile config, the run) is
# lab/ambient_config_probe.py and the judgement is lab_asserts.py's
# ambient_config_failures; lab/validation_harness.py uses both too.
sys.path.insert(0, str(ROOT / "lab"))
import lab_asserts  # noqa: E402
import lab_stack as stack  # noqa: E402


def _require_lab_enabled() -> None:
    if os.environ.get("OP06D_LAB") != "1":
        pytest.skip("set OP06D_LAB=1 to run the gated lab check (RC-35)")


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


def test_hostile_ambient_config_cannot_override_the_wrapper_against_real_nuclei(lab_stack):
    r = _exec("scanner", "python3", "/lab/ambient_config_probe.py", timeout=420)
    assert r.returncode == 0, f"probe failed:\n{r.stdout}\n{r.stderr}"
    result = json.loads(r.stdout.strip().splitlines()[-1])

    assert result["hostile_config_removed"] is True  # the hostile config must not linger
    # probe hit, status ok (no [FTL] redirect-conflict crash), no redirect
    # followed, no hostile header, no OAST contact, out_of_band == "off"
    lab_asserts.assert_ambient_config_neutralized(result["wrapper"])
