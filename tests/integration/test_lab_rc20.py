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

import ast
import json
import os
import pathlib
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.lab

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = ROOT / "lab" / "docker-compose.yml"
BASELINE = json.loads((pathlib.Path(__file__).parent / "baseline.json").read_text(encoding="utf-8"))
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


def _unrepr(value: object) -> object:
    """Audit targets are stored as ``repr(value)`` (op06d.audit._safe_repr);
    undo that so assertions compare plain strings."""
    if isinstance(value, str):
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value
    return value


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
    import sys

    sys.path.insert(0, str(ROOT / "lab"))
    from scan_driver import isolation_failure_reason  # noqa: PLC0415

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


def _open_ports(nmap_findings: dict) -> set:
    return {p["port"] for h in nmap_findings["hosts"] for p in h["ports"] if p["state"] == "open"}


def _service_string(nmap_findings: dict, port: int) -> str | None:
    for h in nmap_findings["hosts"]:
        for p in h["ports"]:
            if p["port"] == port and p.get("service"):
                svc = p["service"]
                text = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                return text or None
    return None


def _template_ids(nuclei_findings: dict) -> set:
    return {f["template_id"] for f in nuclei_findings["findings"]}


def _assert_runs_against_baseline(summary: dict) -> None:
    runs_by_name = {row["name"]: row for row in summary["runs"]}
    for name, expected in BASELINE["runs"].items():
        row = runs_by_name.get(name)
        assert row is not None, f"expected run {name!r} is missing from the summary"
        assert row["executed"], f"{name}: expected outcome=executed, got {row['outcome']} ({row['reason']})"
        findings = row["findings"]

        if expected["tool"] == "nmap":
            ports = _open_ports(findings)
            assert ports == set(expected["open_ports"]), f"{name}: open ports {ports} != {expected['open_ports']}"
            for port_str, expected_svc in expected.get("service_strings", {}).items():
                svc = _service_string(findings, int(port_str))
                assert svc == expected_svc, f"{name}: port {port_str} service {svc!r} != {expected_svc!r}"
        else:
            ids = _template_ids(findings)
            assert ids == set(expected["template_ids"]), f"{name}: template ids {ids} != {expected['template_ids']}"
            assert findings["out_of_band"] == "off", f"{name}: out_of_band must be 'off'"
            assert findings["summary"]["off_target"] == 0, f"{name}: off_target must be 0"
            # RC-26: the templates-loaded instrumentation must actually report a
            # real count against the live pinned template set - a regression here
            # would silently bring back the "loaded nothing vs matched nothing"
            # blind spot the whole ticket exists to close.
            loaded = findings["summary"].get("templates_loaded")
            assert loaded is not None and loaded > 0, (
                f"{name}: templates_loaded is {loaded!r} - coverage instrumentation regressed"
            )
            assert "coverage_warning" not in findings, f"{name}: unexpected coverage_warning: {findings.get('coverage_warning')}"
            if expected.get("hostname_target"):
                assert findings.get("target_hostname") == expected["hostname_target"], (
                    f"{name}: target_hostname missing/wrong for a hostname target"
                )


def _assert_action_executed_carries_scanned_ip(summary: dict) -> None:
    for name, expected in BASELINE["runs"].items():
        hostname = expected.get("hostname_target")
        if not hostname:
            continue
        matches = [e for e in summary["action_executed"] if _unrepr(e["target"]) == hostname]
        assert matches, f"{name}: no action_executed entry recorded for hostname target {hostname!r}"
        assert any("scanned_ip=" in (m["reason"] or "") for m in matches), (
            f"{name}: action_executed for {hostname!r} does not carry scanned_ip"
        )


def _fingerprint(summary: dict) -> dict:
    out = {}
    for row in summary["runs"]:
        findings = row["findings"]
        if row["tool"] == "nmap":
            out[row["name"]] = {"ports": sorted(_open_ports(findings))}
        else:
            out[row["name"]] = {"template_ids": sorted(_template_ids(findings))}
    return out


def test_scan_set_matches_the_frozen_baseline(lab_stack):
    summary = _run_scan_set("run1")
    assert summary["audit_entries"] > 0
    _assert_runs_against_baseline(summary)

    pinned = {_unrepr(h): v for h, v in summary["dns_pinned"].items()}
    assert pinned == BASELINE["dns_pinned"], f"dns_pinned {pinned} != {BASELINE['dns_pinned']}"
    _assert_action_executed_carries_scanned_ip(summary)


def test_scan_set_is_repeatable(lab_stack):
    first = _run_scan_set("repeat1")
    second = _run_scan_set("repeat2")
    assert _fingerprint(first) == _fingerprint(second)
