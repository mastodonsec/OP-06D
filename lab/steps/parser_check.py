# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the nmap and nuclei parsers over real captures.

Runs inside the scanner:

    python3 /lab/steps/parser_check.py [<captures dir>] [--json]

The directory defaults to ``/captures``; every ``nmap_*.xml`` and
``nuclei_*.jsonl`` in it is parsed. Prints one line per file: ``OK``,
``WARN`` (a nuclei file with unparsed lines) or ``FAIL`` (the parser raised).
``--json`` prints the rows for lab/validation_harness.py.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Callable

DEFAULT_DIR = "/captures"


def check_dir(d: pathlib.Path, parse_nmap: Callable | None = None, parse_nuclei: Callable | None = None) -> list[dict]:
    if parse_nmap is None or parse_nuclei is None:
        from op06d.nmap_tool import parse_nmap_xml
        from op06d.nuclei_tool import parse_nuclei_jsonl
        parse_nmap = parse_nmap or parse_nmap_xml
        parse_nuclei = parse_nuclei or parse_nuclei_jsonl
    rows = []
    for p in sorted(d.glob("nmap_*.xml")):
        try:
            f = parse_nmap(p.read_text(encoding="utf-8"))
            rows.append({"file": p.name, "ok": True, "unparsed": 0, "hosts": len(f["hosts"]),
                         "ports": [x["port"] for h in f["hosts"] for x in h["ports"]]})
        except Exception as e:
            rows.append({"file": p.name, "ok": False, "unparsed": 0, "error": f"{type(e).__name__}: {e}"})
    for p in sorted(d.glob("nuclei_*.jsonl")):
        try:
            findings, bad = parse_nuclei(p.read_text(encoding="utf-8"))
            rows.append({"file": p.name, "ok": True, "unparsed": bad, "findings": len(findings)})
        except Exception as e:
            rows.append({"file": p.name, "ok": False, "unparsed": 0, "error": f"{type(e).__name__}: {e}"})
    return rows


def format_row(r: dict) -> str:
    if not r["ok"]:
        return f"FAIL {r['file']} {r['error']}"
    if "hosts" in r:
        return f"OK   {r['file']} hosts: {r['hosts']} ports: {r['ports']}"
    word = "OK  " if r["unparsed"] == 0 else "WARN"
    return f"{word} {r['file']} findings: {r['findings']} unparsed lines: {r['unparsed']}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse real nmap and nuclei captures.")
    parser.add_argument("dir", nargs="?", default=DEFAULT_DIR, help=f"captures directory (default {DEFAULT_DIR})")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)
    rows = check_dir(pathlib.Path(args.dir))
    print(json.dumps(rows) if args.json else "\n".join(format_row(r) for r in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
