# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-20: the one gated scan-run driver, shared by RUNBOOK.md Step 8 and the
automated lab integration test (tests/integration/test_lab_rc20.py), so the
two cannot drift apart.

Runs only *inside* the scanner container (it imports ``op06d``, which is on
``PYTHONPATH`` there). Not an op06d package module on purpose: it is a lab
fixture, read-only-mounted at ``/lab``, not something the product ships.

Usage (inside the scanner):

    python3 /lab/scan_driver.py <captures-dir> [--json <summary-path>]

Writes the raw + ``*.findings.json`` captures under ``<captures-dir>`` exactly
as RUNBOOK Step 8 describes, and (with ``--json``) a machine-readable summary:
per-run outcome/status/findings, the audit log's verified entry count, every
``dns_pinned`` entry, and every ``action_executed`` entry - what a host-side
test reads back to assert against the frozen baseline.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# RUNS: (capture name, tool, target, parameters, raw-output file extension).
# nuclei targets are hostnames (dvwa.lab / juice-shop.lab) on purpose - that is
# what exercises the RC-23 resolve-once pin end to end; nmap targets are the
# literal IPs, as the gate always hands it.
RUNS: list[tuple[str, str, str, dict, str]] = [
    ("nmap_juice-shop_service", "nmap", "172.31.77.10", {"profile": "service", "ports": "3000"}, "xml"),
    ("nmap_dvwa_service", "nmap", "172.31.77.11", {"profile": "service", "ports": "80"}, "xml"),
    ("nmap_dvwa_default", "nmap", "172.31.77.11", {}, "xml"),
    ("nmap_dvwa_safe_scripts", "nmap", "172.31.77.11",
     {"profile": "service", "ports": "80", "scripts": ["safe", "default", "discovery", "version"]}, "xml"),
    ("nuclei_dvwa_default", "nuclei", "dvwa.lab", {}, "jsonl"),
    ("nuclei_dvwa_exposure", "nuclei", "dvwa.lab",
     {"tags": ["exposure", "misconfig", "config", "panel", "tech"]}, "jsonl"),
    ("nuclei_juice-shop_3000", "nuclei", "juice-shop.lab", {"port": 3000, "scheme": "http"}, "jsonl"),
]


def isolation_failure_reason(network_internal: str, isolation_exit_code: int) -> str | None:
    """Pure decision for the isolation precondition (RC-20 non-negotiable #2):
    a reason to ABORT, or ``None`` to proceed. Kept separate from the
    subprocess calls that gather ``network_internal``/``isolation_exit_code``
    so the "isolation-fail aborts before scanning" guarantee has a fast,
    deterministic, docker-free test (see tests/test_lab_isolation_guard.py)."""
    if network_internal != "true":
        return f"the lab network is not internal (docker network inspect reported {network_internal!r})"
    if isolation_exit_code != 0:
        return f"lab/check_isolation.sh did not PASS (exit {isolation_exit_code})"
    return None


def run(
    out_dir: pathlib.Path,
    *,
    engagement_path: str = "/lab/engagement.yaml",
    template_dir: str = "/opt/nuclei-templates",
    templates_pin: str = "v10.5.1",
    audit_subdir: str = "audit",
) -> dict:
    """Run every row in RUNS through the real ``GatedToolbox`` and write
    captures to ``out_dir`` (which must already be empty - callers are
    responsible for that, so the audit log starts empty too). Returns a
    machine-readable summary."""
    from op06d.audit import AuditLog, read_log, verify_log
    from op06d.engagement import load_engagement
    from op06d.gate import Gate
    from op06d.tools import GatedToolbox, ToolAction, default_tools

    out_dir.mkdir(parents=True, exist_ok=True)
    eng = load_engagement(engagement_path)
    log = AuditLog.for_engagement(eng, out_dir / audit_subdir)
    tools = default_tools(eng, nuclei_template_dir=template_dir, nuclei_templates_pin=templates_pin)
    box = GatedToolbox(eng, Gate(eng, audit_pin=log.record_dns_pin), log, tools)

    runs_summary = []
    for i, (name, tool, target, params, ext) in enumerate(RUNS, 1):
        # RC-24: progress only. Callers parse the --json summary file, never stdout.
        print(f"starting row {i}/{len(RUNS)}: {name}", flush=True)
        r = box.execute(ToolAction(tool, target, params), iteration=i)
        row: dict = {
            "name": name,
            "tool": tool,
            "target": target,
            "outcome": r.outcome.value,
            "status": r.status or None,
            "stage": r.decision.stage,
            "risk": r.risk.name if r.risk is not None else None,
            "executed": r.executed,
            "reason": r.decision.reason,
        }
        if r.executed:
            raw = r.raw_output if isinstance(r.raw_output, str) else json.dumps(r.raw_output, indent=2, default=repr)
            (out_dir / f"{name}.{ext}").write_text(raw, encoding="utf-8")
            (out_dir / f"{name}.findings.json").write_text(
                json.dumps(r.findings, indent=2, default=repr), encoding="utf-8"
            )
            row["findings"] = r.findings
        runs_summary.append(row)

    entries = read_log(log.path)
    dns_pinned = {e.target: e.parameters.get("resolved_ips") for e in entries if e.event == "dns_pinned"}
    action_executed = [
        {"target": e.target, "tool": e.tool, "reason": e.reason}
        for e in entries if e.event == "action_executed"
    ]
    return {
        "runs": runs_summary,
        "audit_entries": verify_log(log.path),
        "audit_path": str(log.path),
        "dns_pinned": dns_pinned,
        "action_executed": action_executed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir")
    parser.add_argument("--json", dest="json_path", default=None)
    parser.add_argument("--engagement", default="/lab/engagement.yaml")
    parser.add_argument("--template-dir", default="/opt/nuclei-templates")
    parser.add_argument("--templates-pin", default="v10.5.1")
    args = parser.parse_args(argv)

    summary = run(
        pathlib.Path(args.out_dir),
        engagement_path=args.engagement,
        template_dir=args.template_dir,
        templates_pin=args.templates_pin,
    )
    for row in summary["runs"]:
        print(f"{row['name']:28} outcome={row['outcome']:12} status={row['status'] or '-':18} "
              f"stage={row['stage']} risk={row['risk']}", flush=True)
        if not row["executed"]:
            print("    not run:", row["reason"], flush=True)
    print("audit entries verified:", summary["audit_entries"], flush=True)
    for host, ips in summary["dns_pinned"].items():
        print(f"    dns_pinned: {host} -> {ips}", flush=True)
    if args.json_path:
        pathlib.Path(args.json_path).write_text(json.dumps(summary, indent=2, default=repr), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
