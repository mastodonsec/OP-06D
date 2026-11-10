# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-28: RC-20 follow-up: make the lab harness teardown idempotent (down-before-up)

Lab stack lifecycle shared by the gated integration-test fixtures
(tests/integration/test_lab_rc*.py) and lab/validation_harness.py, plus the
call that generates a run-specific engagement file inside the scanner.

``lab_stack`` runs ``docker compose down`` first (clearing a stack left
running by a killed earlier run), then ``up -d`` inside the ``try``, and
``down`` again in the ``finally`` - so a failure or timeout during ``up``
still tears the stack down. ``keep=True`` skips only that final ``down``.

Host-side, stdlib only. The compose runner is passed in, so the ordering is
testable without docker (tests/test_lab_stack.py).
"""

from __future__ import annotations

import contextlib
import subprocess
from typing import Callable, Iterator

ComposeRunner = Callable[..., subprocess.CompletedProcess]
Recorder = Callable[[subprocess.CompletedProcess], None]

DOWN_TIMEOUT = 300.0
UP_TIMEOUT = 900.0
ENGAGEMENT_TEMPLATE = "/lab/engagement.yaml"
GENERATOR = "/lab/make_lab_engagement.py"


class LabStackError(RuntimeError):
    """``docker compose up`` did not succeed."""


@contextlib.contextmanager
def lab_stack(
    compose: ComposeRunner,
    *,
    keep: bool = False,
    record: Recorder | None = None,
    up_timeout: float = UP_TIMEOUT,
    down_timeout: float = DOWN_TIMEOUT,
) -> Iterator[subprocess.CompletedProcess]:
    """Bring the lab up for the ``with`` body; yields the ``up`` result.

    ``compose(*args, timeout=...)`` runs ``docker compose -f <file> *args``.
    Raises ``LabStackError`` if ``up`` exits non-zero (after tearing down).
    ``record`` receives every compose result, for evidence capture."""

    def run(*args: str, timeout: float) -> subprocess.CompletedProcess:
        cp = compose(*args, timeout=timeout)
        if record is not None:
            record(cp)
        return cp

    run("down", timeout=down_timeout)
    try:
        up = run("up", "-d", timeout=up_timeout)
        if up.returncode != 0:
            raise LabStackError(f"docker compose up failed (exit {up.returncode}):\n{up.stdout}\n{up.stderr}")
        yield up
    finally:
        if not keep:
            run("down", timeout=down_timeout)


def generate_engagement(
    scanner_exec: Callable[..., subprocess.CompletedProcess],
    out_path: str,
    *,
    hours: float | None = None,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess:
    """Run the engagement generator inside the scanner, writing ``out_path``
    (a path under the scanner's writable ``/captures`` mount).

    ``scanner_exec(*argv, timeout=...)`` runs ``argv`` in the scanner. The
    caller checks ``returncode``; the generator itself validates the file
    with ``load_engagement`` and exits non-zero if it does not load."""
    argv = ["python3", GENERATOR, out_path, "--template", ENGAGEMENT_TEMPLATE]
    if hours is not None:
        argv += ["--hours", str(hours)]
    return scanner_exec(*argv, timeout=timeout)
