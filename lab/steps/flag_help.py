# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-check the wrappers' flags against ``nmap --help`` and ``nuclei -h``.
Informational: ``--`` and a few flags do not appear in either tool's help.

Runs inside the scanner:

    python3 /lab/steps/flag_help.py [--json]

Prints ``<tool> listed <flag>`` or ``<tool> NOT LISTED <flag>`` per flag;
``--json`` prints ``{"nmap": {flag: listed}, "nuclei": {flag: listed}}``.
An nmap flag counts as listed if it appears anywhere in the help text; a
nuclei flag only if it appears after a space (so ``-c`` does not match inside
``-no-color``).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

NMAP_FLAGS = ("-oX", "--no-stylesheet", "--max-rate", "--host-timeout", "-sn", "-F", "-sV", "-p-", "-A", "-p",
              "--script")
NUCLEI_FLAGS = ("-config", "-u", "-t", "-jsonl", "-silent", "-no-color", "-disable-update-check", "-rate-limit",
                "-c", "-bs", "-timeout", "-retries", "-disable-redirects", "-no-interactsh", "-interactsh-server",
                "-severity", "-tags", "-exclude-tags", "-id")


def listed(help_text: str, tool: str, flag: str) -> bool:
    return (" " + flag) in help_text if tool == "nuclei" else flag in help_text


def check(nmap_help: str, nuclei_help: str) -> dict[str, dict[str, bool]]:
    return {"nmap": {f: listed(nmap_help, "nmap", f) for f in NMAP_FLAGS},
            "nuclei": {f: listed(nuclei_help, "nuclei", f) for f in NUCLEI_FLAGS}}


def format_check(result: dict[str, dict[str, bool]]) -> str:
    lines = []
    for tool, width in (("nmap", 11), ("nuclei", 10)):
        for flag, ok in result[tool].items():
            word = "listed" if ok else "NOT LISTED"
            lines.append(f"{tool} {word:<{width}} {flag}")
    return "\n".join(lines)


def _help(argv: list[str]) -> str:
    p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=60, stdin=subprocess.DEVNULL)
    return p.stdout + p.stderr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-check the wrappers' flags against the tools' help.")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    result = check(_help(["nmap", "--help"]), _help(["nuclei", "-h"]))
    print(json.dumps(result) if args.json else format_check(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
