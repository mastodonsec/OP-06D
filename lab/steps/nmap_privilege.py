# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run every nmap profile against the lab's DVWA target and report how the
wrapper handles the current user's privileges.

Runs inside the scanner, once as root and once as the unprivileged
``scanner`` user:

    python3 /lab/steps/nmap_privilege.py [--json]

Prints ``uid: <n>`` and one line per profile (status, scan types, degraded
capabilities, error text). ``--json`` prints
``{"uid": n, "profiles": [...], "rows": [...]}`` for lab/validation_harness.py.
A profile that raises is reported with its traceback, not hidden.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

TARGET = "172.31.77.11"


def row_for(profile: str, result) -> dict:
    f = result.findings if isinstance(result.findings, dict) else {}
    return {"profile": profile, "status": result.status,
            "scan_types": f.get("summary", {}).get("scan_types", []),
            "degraded": bool(f.get("degraded")),
            "degraded_capabilities": f.get("degraded_capabilities"),
            "error": (f.get("error") or {}).get("message", "")}


def probe(tool, profiles) -> list[dict]:
    rows = []
    for prof in profiles:
        try:
            rows.append(row_for(prof, tool.run(TARGET, {"profile": prof})))
        except Exception:
            rows.append({"profile": prof, "status": None, "traceback": traceback.format_exc()})
    return rows


def format_row(r: dict) -> str:
    if r.get("traceback"):
        return f"{r['profile']:11} TRACEBACK\n{r['traceback'].rstrip()}"
    scan_types = ",".join(r["scan_types"]) or "-"
    degraded = r["degraded_capabilities"] if r["degraded"] else "-"
    return f"{r['profile']:11} status={r['status']:18} scan-types={scan_types:10} degraded={degraded} {r['error'][:150]}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="nmap profiles as the current user.")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)

    from op06d.nmap_tool import PROFILES, NmapTool

    rows = probe(NmapTool(50), PROFILES)
    if args.json:
        print(json.dumps({"uid": os.getuid(), "profiles": list(PROFILES), "rows": rows}))
    else:
        print(f"uid: {os.getuid()}")
        for r in rows:
            print(format_row(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
