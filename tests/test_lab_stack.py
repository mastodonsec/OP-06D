# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-28: RC-20 follow-up: make the lab harness teardown idempotent (down-before-up)

Docker-free tests of lab/lab_stack.py with a mocked compose runner: down
runs before up, down still runs when up fails, times out or the body
raises, keep=True skips only the final down, and a failing final down is
reported as TeardownError without masking an error from the body."""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import lab_stack as stack  # noqa: E402


class FakeCompose:
    """Records calls. ``fail`` maps a call index (0 = initial down, 1 = up,
    2 = final down) to an exception to raise or a non-zero returncode."""

    def __init__(self, up_returncode: int = 0, up_raises: BaseException | None = None,
                 fail: dict[int, BaseException | int] | None = None):
        self.calls: list[tuple[str, ...]] = []
        self.fail = dict(fail or {})
        if up_raises is not None:
            self.fail[1] = up_raises
        elif up_returncode:
            self.fail[1] = up_returncode

    def __call__(self, *args: str, timeout: float) -> subprocess.CompletedProcess:
        i = len(self.calls)
        self.calls.append(args)
        outcome = self.fail.get(i, 0)
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(["docker", "compose", *args], outcome, "", "boom" if outcome else "")

    @property
    def verbs(self) -> list[str]:
        return [c[0] for c in self.calls]


def _timeout(*args: str) -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(["docker", "compose", *args], 300)


def test_down_before_up_and_down_after():
    c = FakeCompose()
    with stack.lab_stack(c) as up:
        assert c.verbs == ["down", "up"]
        assert up.returncode == 0
    assert c.verbs == ["down", "up", "down"]
    assert c.calls[1] == ("up", "-d")


def test_down_still_runs_when_up_raises():
    c = FakeCompose(up_raises=subprocess.TimeoutExpired(["docker", "compose", "up"], 900))
    with pytest.raises(subprocess.TimeoutExpired):
        with stack.lab_stack(c):
            pytest.fail("the body must not run when up raises")
    assert c.verbs == ["down", "up", "down"]


def test_down_still_runs_when_up_exits_nonzero():
    c = FakeCompose(up_returncode=1)
    with pytest.raises(stack.LabStackError):
        with stack.lab_stack(c):
            pytest.fail("the body must not run when up fails")
    assert c.verbs == ["down", "up", "down"]


def test_down_runs_when_the_body_raises():
    c = FakeCompose()
    with pytest.raises(RuntimeError):
        with stack.lab_stack(c):
            raise RuntimeError("isolation failed")
    assert c.verbs == ["down", "up", "down"]


def test_keep_skips_only_the_final_down():
    c = FakeCompose()
    with stack.lab_stack(c, keep=True):
        pass
    assert c.verbs == ["down", "up"]


def test_keep_still_tears_down_first_and_on_up_failure_does_not_retear():
    c = FakeCompose(up_returncode=1)
    with pytest.raises(stack.LabStackError):
        with stack.lab_stack(c, keep=True):
            pass
    assert c.verbs == ["down", "up"]


def test_recorder_sees_every_compose_call():
    c, seen = FakeCompose(), []
    with stack.lab_stack(c, record=seen.append):
        pass
    assert [cp.args[2] for cp in seen] == ["down", "up", "down"]


def test_generate_engagement_runs_the_generator_in_the_scanner():
    calls = []

    def scanner_exec(*argv, timeout):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "wrote", "")

    stack.generate_engagement(scanner_exec, "/captures/x/engagement.yaml", hours=2)
    assert calls == [("python3", "/lab/make_lab_engagement.py", "/captures/x/engagement.yaml",
                      "--template", "/lab/engagement.yaml", "--hours", "2")]


def test_initial_down_timeout_propagates_and_up_never_runs():
    c = FakeCompose(fail={0: _timeout("down")})
    with pytest.raises(subprocess.TimeoutExpired):
        with stack.lab_stack(c):
            pytest.fail("the body must not run")
    assert c.verbs == ["down"]


@pytest.mark.parametrize("outcome", [_timeout("down"), 1], ids=["timeout", "nonzero-exit"])
def test_final_down_failure_after_a_clean_body_raises_teardown_error(outcome):
    c, body_ran = FakeCompose(fail={2: outcome}), []
    with pytest.raises(stack.TeardownError):
        with stack.lab_stack(c):
            body_ran.append(True)
    assert body_ran == [True]
    assert c.verbs == ["down", "up", "down"]


def test_final_down_failure_never_masks_an_error_from_the_body():
    c = FakeCompose(fail={2: _timeout("down")})
    with pytest.raises(RuntimeError, match="isolation failed"):
        with stack.lab_stack(c):
            raise RuntimeError("isolation failed")
    assert c.verbs == ["down", "up", "down"]


def test_final_down_failure_never_masks_an_up_failure():
    c = FakeCompose(fail={1: 1, 2: _timeout("down")})
    with pytest.raises(stack.LabStackError):
        with stack.lab_stack(c):
            pass


def test_a_timed_out_call_is_still_recorded():
    c, seen = FakeCompose(fail={2: _timeout("down")}), []
    with pytest.raises(stack.TeardownError):
        with stack.lab_stack(c, record=seen.append):
            pass
    assert [cp.returncode for cp in seen] == [0, 0, -1]
    assert "TIMEOUT" in seen[-1].stderr
