# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for RC-8 (op06d.approval.ConsoleApprover): default-deny behavior,
explicit yes/no, EOF, and the cross-platform timeout path."""

from __future__ import annotations

import time

from op06d.approval import ConsoleApprover
from op06d.tools import ApprovalRequest, Risk


def _request(**overrides) -> ApprovalRequest:
    base = dict(
        iteration=1, tool="nmap", target="172.31.77.11",
        parameters={"profile": "aggressive"}, risk=Risk.INTRUSIVE, reason="test request",
    )
    base.update(overrides)
    return ApprovalRequest(**base)


def test_explicit_yes_approves():
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "y", print_fn=lambda s: None)
    assert approver.approve(_request()) is True


def test_explicit_yes_full_word_approves():
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "YES", print_fn=lambda s: None)
    assert approver.approve(_request()) is True


def test_explicit_no_denies():
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "n", print_fn=lambda s: None)
    assert approver.approve(_request()) is False


def test_empty_line_denies():
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "", print_fn=lambda s: None)
    assert approver.approve(_request()) is False


def test_garbage_input_denies():
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "sure whatever", print_fn=lambda s: None)
    assert approver.approve(_request()) is False


def test_eof_denies():
    def raise_eof():
        raise EOFError

    approver = ConsoleApprover(timeout=5, input_fn=raise_eof, print_fn=lambda s: None)
    assert approver.approve(_request()) is False


def test_timeout_denies():
    def blocking_input():
        time.sleep(5)  # much longer than the approver's timeout below
        return "y"

    approver = ConsoleApprover(timeout=0.05, input_fn=blocking_input, print_fn=lambda s: None)
    started = time.monotonic()
    result = approver.approve(_request())
    elapsed = time.monotonic() - started

    assert result is False
    assert elapsed < 1.0  # it did not wait for the blocking input to return


def test_any_exception_while_prompting_denies():
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "y", print_fn=lambda s: 1 / 0)
    assert approver.approve(_request()) is False


def test_prompt_shows_redacted_parameters_not_a_raw_secret():
    seen: list[str] = []
    request = _request(parameters={"api_token": "[REDACTED]"})
    approver = ConsoleApprover(timeout=5, input_fn=lambda: "n", print_fn=seen.append)
    approver.approve(request)
    rendered = "\n".join(seen)
    assert "[REDACTED]" in rendered
    assert "api_token" in rendered
