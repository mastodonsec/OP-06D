# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-28: RC-20 follow-up: make the lab harness teardown idempotent (down-before-up)

lab/scan_driver.py requires --engagement: omitting it is an argparse error
before anything runs or is written."""

from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lab"))

import scan_driver  # noqa: E402


def test_missing_engagement_is_an_argparse_error_before_anything_runs(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(scan_driver, "run", lambda *a, **k: pytest.fail("run() must not be reached"))
    out = tmp_path / "captures"
    with pytest.raises(SystemExit) as exc:
        scan_driver.main([str(out)])
    assert exc.value.code == 2
    assert "--engagement" in capsys.readouterr().err
    assert not out.exists()


def test_engagement_is_passed_through_to_run(monkeypatch, tmp_path):
    seen = {}

    def fake_run(out_dir, **kw):
        seen.update(kw)
        return {"runs": [], "audit_entries": 0, "dns_pinned": {}}

    monkeypatch.setattr(scan_driver, "run", fake_run)
    assert scan_driver.main([str(tmp_path), "--engagement", "/captures/x/engagement.yaml"]) == 0
    assert seen["engagement_path"] == "/captures/x/engagement.yaml"


def test_run_has_no_default_engagement():
    import inspect
    param = inspect.signature(scan_driver.run).parameters["engagement_path"]
    assert param.default is inspect.Parameter.empty
