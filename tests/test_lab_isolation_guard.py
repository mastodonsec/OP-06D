# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fast, docker-free proof of RC-20's isolation precondition: a failed
isolation check must abort before any scan. This is the pure decision
function (`lab/scan_driver.isolation_failure_reason`) that
tests/integration/test_lab_rc20.py's real docker-backed fixture also calls;
testing it here means the "isolation-fail aborts" guarantee has a check that
runs in the default suite, with no lab and no Docker required."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

from scan_driver import isolation_failure_reason  # noqa: E402


def test_network_not_internal_aborts():
    assert isolation_failure_reason("false", 0) is not None


def test_isolation_script_nonzero_exit_aborts():
    assert isolation_failure_reason("true", 1) is not None


def test_isolation_script_inconclusive_exit_aborts():
    assert isolation_failure_reason("true", 2) is not None


def test_both_checks_passing_does_not_abort():
    assert isolation_failure_reason("true", 0) is None
