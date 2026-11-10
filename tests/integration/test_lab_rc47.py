# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs

Gated lab acceptance: `op06d run --planner llm` end to end against the sealed
lab targets, with the model reached only through the opt-in model relay.

NOT part of the default suite (`lab` marker) and skipped unless OP06D_LAB=1.
One upstream per run, chosen by OP06D_LLM_PROVIDER:

    OP06D_LAB=1 OP06D_LLM_PROVIDER=local     uv run pytest -m lab tests/integration/test_lab_rc47.py
    OP06D_LAB=1 OP06D_LLM_PROVIDER=anthropic uv run pytest -m lab tests/integration/test_lab_rc47.py

local needs host Ollama with the model (OP06D_LLM_MODEL, default the RC-40
local default); anthropic needs ANTHROPIC_API_KEY in the environment, passed
to the scanner by name only. The stack is brought up with
lab/docker-compose.yml + the one overlay (down first, down again at the end),
the relay isolation check must PASS before anything runs, and the run's
report, evidence, audit log and key absence are checked by
lab/model_relay.verify_run.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.lab

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import lab_stack as stack  # noqa: E402
import model_relay as relay  # noqa: E402

MODE = os.environ.get("OP06D_LLM_PROVIDER", "")
MODEL = os.environ.get("OP06D_LLM_MODEL") or None
ENGAGEMENT = {"local": "lab/engagement.yaml", "anthropic": "lab/engagement-llm-hosted.yaml"}


def _require_prerequisites() -> None:
    if os.environ.get("OP06D_LAB") != "1":
        pytest.skip("set OP06D_LAB=1 to run the gated lab acceptance (RC-47)")
    if MODE not in relay.MODES:
        pytest.skip("set OP06D_LLM_PROVIDER=local or OP06D_LLM_PROVIDER=anthropic (one upstream per run)")
    if shutil.which("docker") is None:
        pytest.skip("docker is not available")
    if MODE == "anthropic" and not os.environ.get(relay.KEY_ENV):
        pytest.skip(f"{relay.KEY_ENV} is not set")
    if MODE == "local":
        model = MODEL or relay.DEFAULT_LOCAL_MODEL
        try:
            present = relay.ollama_has_model(model)
        except relay.RelayError as exc:
            pytest.skip(str(exc))
        if not present:
            pytest.skip(f"host Ollama does not have {model!r}: ollama pull {model}")


def _compose(*args: str, timeout: float) -> subprocess.CompletedProcess:
    extra = ("--remove-orphans",) if args and args[0] == "down" else ()
    return relay.default_runner(relay.compose_argv(MODE, *args, *extra), timeout)


def _wait_for_targets(attempts: int = 30, delay: float = 2.0) -> None:
    for _ in range(attempts):
        codes = [
            _compose("exec", "-T", "scanner", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", url,
                     timeout=20).stdout.strip()[:1]
            for url in ("http://juice-shop.lab:3000/", "http://dvwa.lab/")
        ]
        if all(c in ("2", "3") for c in codes):
            return
        time.sleep(delay)
    pytest.fail("lab targets never came up")


@pytest.fixture(scope="module")
def relay_stack():
    _require_prerequisites()
    relay.check_policy(MODE, ENGAGEMENT[MODE])  # refuse before any docker call
    _ok = relay.default_runner(["docker", "compose", "-f", str(relay.COMPOSE_BASE), "build", "scanner"], 1800)
    assert _ok.returncode == 0, f"base scanner build failed:\n{_ok.stdout}\n{_ok.stderr}"
    with stack.lab_stack(_compose):
        _wait_for_targets()
        report = relay.check(MODE)
        if report.exit_code != 0:
            pytest.fail("ABORT: relay isolation did not PASS, refusing to run:\n" + "\n".join(report.lines))
        yield report


def test_relay_isolation_passes(relay_stack):
    assert relay_stack.exit_code == 0
    assert any("scanner-side isolation" in line and line.startswith("PASS") for line in relay_stack.lines)
    assert any("relay-side egress" in line and line.startswith("PASS") for line in relay_stack.lines)


def test_llm_planner_run_end_to_end_through_the_relay(relay_stack):
    outcome = relay.run_acceptance(MODE, ENGAGEMENT[MODE], model=MODEL)
    assert outcome.returncode == 0, f"op06d run failed:\n{outcome.stdout}\n{outcome.stderr}"
    assert outcome.problems == [], "\n".join(outcome.problems) + f"\n{outcome.stdout}"
    assert outcome.report_html is not None and outcome.report_html.is_file()
