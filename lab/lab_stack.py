# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-28: RC-20 follow-up: make the lab harness teardown idempotent (down-before-up)

Lab stack lifecycle shared by the gated integration-test fixtures
(tests/integration/test_lab_rc*.py) and lab/validation_harness.py, plus the
call that generates a run-specific engagement file inside the scanner.

``lab_stack`` runs ``docker compose down`` first (clearing a stack left
running by a killed earlier run), then ``up -d``, and ``down`` again when the
``with`` block ends - including when ``up`` fails or times out, or the body
raises. ``keep=True`` skips only that final ``down``.

Errors are kept apart so callers can report them differently:

* the initial ``down`` timing out raises ``subprocess.TimeoutExpired``, and
  ``up`` failing raises ``LabStackError`` (or ``TimeoutExpired``) - the stack
  never came up;
* the final ``down`` failing or timing out after a normal exit from the body
  raises ``TeardownError`` - the body's work completed, but the lab may still
  be running;
* if the body itself raised, the final ``down`` is best-effort and never
  replaces the body's exception.

Every compose call is passed to ``record``, including one that timed out
(recorded with returncode -1 and a ``TIMEOUT`` stderr).

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


class TeardownError(RuntimeError):
    """The final ``docker compose down`` failed or timed out; the lab may
    still be running."""


TEARDOWN_HINT = "docker compose -f lab/docker-compose.yml down"


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
    See the module docstring for which error is raised when."""

    def run(*args: str, timeout: float) -> subprocess.CompletedProcess:
        try:
            cp = compose(*args, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if record is not None:
                out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                record(subprocess.CompletedProcess(
                    exc.cmd if exc.cmd else ["docker", "compose", *args], -1, out,
                    f"TIMEOUT: docker compose {' '.join(args)} did not finish within {timeout:.0f}s"))
            raise
        if record is not None:
            record(cp)
        return cp

    def final_down() -> None:
        try:
            cp = run("down", timeout=down_timeout)
        except subprocess.TimeoutExpired as exc:
            raise TeardownError(f"docker compose down timed out after {down_timeout:.0f}s") from exc
        if cp.returncode != 0:
            raise TeardownError(f"docker compose down failed (exit {cp.returncode}):\n{cp.stdout}\n{cp.stderr}")

    run("down", timeout=down_timeout)
    try:
        up = run("up", "-d", timeout=up_timeout)
        if up.returncode != 0:
            raise LabStackError(f"docker compose up failed (exit {up.returncode}):\n{up.stdout}\n{up.stderr}")
        yield up
    except BaseException:
        if not keep:
            # Best effort: a teardown problem must not replace the original error.
            with contextlib.suppress(Exception):
                final_down()
        raise
    if not keep:
        final_down()


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
