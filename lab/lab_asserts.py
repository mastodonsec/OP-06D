# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-24: the ONE copy of the lab-result assertions, shared by the gated
pytest integration tests (tests/integration/test_lab_rc20.py,
tests/integration/test_lab_rc35.py) and the one-command validation harness
(lab/validation_harness.py), so a pass in one means the same thing as a pass
in the other.

Host-side, stdlib-only, pure: every function takes already-parsed JSON
(a ``lab/scan_driver.py`` summary, or a ``lab/ambient_config_probe.py``
result row) and either returns quietly or raises ``LabAssertionError``.
``LabAssertionError`` subclasses ``AssertionError`` so pytest reports it like
a plain ``assert``, but the checks are explicit ``raise`` statements, so they
still hold under ``python -O`` (which strips ``assert``).

Not an op06d package module on purpose: a lab fixture, like scan_driver.py.
"""

from __future__ import annotations

import ast
import json
import pathlib
from typing import Any

BASELINE_PATH = pathlib.Path(__file__).resolve().parent.parent / "tests" / "integration" / "baseline.json"


class LabAssertionError(AssertionError):
    """A lab result did not match what the frozen baseline / fix requires."""


def _check(condition: object, message: str) -> None:
    if not condition:
        raise LabAssertionError(message)


def load_baseline(path: pathlib.Path = BASELINE_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def unrepr(value: object) -> object:
    """Audit targets are stored as ``repr(value)`` (op06d.audit._safe_repr);
    undo that so assertions compare plain strings."""
    if isinstance(value, str):
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value
    return value


# -- RC-20: scan set vs the frozen baseline ----------------------------------

def open_ports(nmap_findings: dict) -> set:
    return {p["port"] for h in nmap_findings["hosts"] for p in h["ports"] if p["state"] == "open"}


def service_string(nmap_findings: dict, port: int) -> str | None:
    for h in nmap_findings["hosts"]:
        for p in h["ports"]:
            if p["port"] == port and p.get("service"):
                svc = p["service"]
                text = f"{svc.get('product', '')} {svc.get('version', '')}".strip()
                return text or None
    return None


def template_ids(nuclei_findings: dict) -> set:
    return {f["template_id"] for f in nuclei_findings["findings"]}


def assert_runs_against_baseline(summary: dict, baseline: dict) -> None:
    runs_by_name = {row["name"]: row for row in summary["runs"]}
    for name, expected in baseline["runs"].items():
        row = runs_by_name.get(name)
        _check(row is not None, f"expected run {name!r} is missing from the summary")
        _check(row["executed"], f"{name}: expected outcome=executed, got {row['outcome']} ({row['reason']})")
        findings = row["findings"]

        if expected["tool"] == "nmap":
            ports = open_ports(findings)
            _check(ports == set(expected["open_ports"]), f"{name}: open ports {ports} != {expected['open_ports']}")
            for port_str, expected_svc in expected.get("service_strings", {}).items():
                svc = service_string(findings, int(port_str))
                _check(svc == expected_svc, f"{name}: port {port_str} service {svc!r} != {expected_svc!r}")
        else:
            ids = template_ids(findings)
            _check(ids == set(expected["template_ids"]), f"{name}: template ids {ids} != {expected['template_ids']}")
            _check(findings["out_of_band"] == "off", f"{name}: out_of_band must be 'off'")
            _check(findings["summary"]["off_target"] == 0, f"{name}: off_target must be 0")
            # RC-26: the templates-loaded instrumentation must actually report a
            # real count against the live pinned template set - a regression here
            # would silently bring back the "loaded nothing vs matched nothing"
            # blind spot the whole ticket exists to close.
            loaded = findings["summary"].get("templates_loaded")
            _check(loaded is not None and loaded > 0,
                   f"{name}: templates_loaded is {loaded!r} - coverage instrumentation regressed")
            _check("coverage_warning" not in findings,
                   f"{name}: unexpected coverage_warning: {findings.get('coverage_warning')}")
            if expected.get("hostname_target"):
                _check(findings.get("target_hostname") == expected["hostname_target"],
                       f"{name}: target_hostname missing/wrong for a hostname target")


def assert_dns_pinned(summary: dict, baseline: dict) -> None:
    """RC-23: exactly one pin per scanned hostname, to the expected IPs."""
    pinned = {unrepr(h): v for h, v in summary["dns_pinned"].items()}
    _check(pinned == baseline["dns_pinned"], f"dns_pinned {pinned} != {baseline['dns_pinned']}")


def assert_action_executed_carries_scanned_ip(summary: dict, baseline: dict) -> None:
    for name, expected in baseline["runs"].items():
        hostname = expected.get("hostname_target")
        if not hostname:
            continue
        matches = [e for e in summary["action_executed"] if unrepr(e["target"]) == hostname]
        _check(matches, f"{name}: no action_executed entry recorded for hostname target {hostname!r}")
        _check(any("scanned_ip=" in (m["reason"] or "") for m in matches),
               f"{name}: action_executed for {hostname!r} does not carry scanned_ip")


def assert_scan_summary(summary: dict, baseline: dict) -> None:
    """Everything RC-20's baseline test asserts about one scan-set run."""
    _check(summary["audit_entries"] > 0, "the audit log has no verified entries")
    assert_runs_against_baseline(summary, baseline)
    assert_dns_pinned(summary, baseline)
    assert_action_executed_carries_scanned_ip(summary, baseline)


def fingerprint(summary: dict) -> dict:
    """The repeatability fingerprint: open ports per nmap row, matched
    template ids per nuclei row."""
    out = {}
    for row in summary["runs"]:
        findings = row["findings"]
        if row["tool"] == "nmap":
            out[row["name"]] = {"ports": sorted(open_ports(findings))}
        else:
            out[row["name"]] = {"template_ids": sorted(template_ids(findings))}
    return out


# -- RC-35: hostile ambient nuclei config ------------------------------------

def ambient_config_failures(wrapper_row: dict[str, Any]) -> list[str]:
    """What is wrong with the wrapper-as-built run of the RC-35 replay
    (``lab/ambient_config_probe.py``'s ``wrapper`` row); empty means the fix
    holds. Returned as a list (not raised) so the harness can print every
    problem at once; ``assert_ambient_config_neutralized`` raises on it."""
    problems = []
    if wrapper_row.get("probe_hit") is not True:
        problems.append("the probe target was never hit - the experiment did not run")
    if wrapper_row.get("status") != "ok":
        problems.append(f"wrapper status {wrapper_row.get('status')!r} != 'ok' (crash / [FTL] redirect conflict?)")
    if wrapper_row.get("redirect_followed") is not False:
        problems.append("a redirect was followed despite -disable-redirects")
    if wrapper_row.get("hostile_header_sent") is not False:
        problems.append("the ambient config's hostile header was sent")
    if wrapper_row.get("oast_contacted") is not False:
        problems.append("the ambient config's OAST server was contacted")
    if wrapper_row.get("out_of_band") != "off":
        problems.append(f"out_of_band {wrapper_row.get('out_of_band')!r} != 'off'")
    return problems


def assert_ambient_config_neutralized(wrapper_row: dict[str, Any]) -> None:
    problems = ambient_config_failures(wrapper_row)
    _check(not problems, "hostile ambient config affected the wrapper: " + "; ".join(problems))
