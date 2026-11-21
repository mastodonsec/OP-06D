# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every command line the nmap and nuclei wrappers build. Nothing is executed:
the wrappers' runner is replaced by one that records the argv.

Runs inside the scanner:

    python3 /lab/steps/wrapper_argv.py [--json]

Prints one argv per line (eight nmap, two nuclei); ``--json`` prints the list
of argvs for lab/validation_harness.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

TARGET_IP = "172.31.77.11"
TARGET_HOST = "dvwa.lab"
TEMPLATE_DIR = "/opt/nuclei-templates"


def build_argvs(nmap_kwargs: dict[str, Any] | None = None,
                nuclei_kwargs: dict[str, Any] | None = None) -> list[list[str]]:
    """The argvs the wrappers build for the lab's fixed set of calls. The
    kwargs (``which``, ``isdir``, ``privilege``) are passed to each tool."""
    from op06d.nmap_tool import PROFILES, NmapTool
    from op06d.nuclei_tool import NucleiTool
    from op06d.tools import ProcessResult

    seen: list[list[str]] = []

    def cap(argv, timeout, **kw):  # nuclei's runner is also passed env=
        seen.append(list(argv))
        return ProcessResult(0, b"", b"")

    nm = NmapTool(50, runner=cap, **(nmap_kwargs or {}))
    for prof in PROFILES:
        nm.run(TARGET_IP, {"profile": prof})
    nm.run(TARGET_IP, {"profile": "service", "ports": "80,443"})
    nm.run(TARGET_IP, {"scripts": ["safe", "default", "discovery", "version", "vuln"]})
    nu = NucleiTool(50, template_dir=TEMPLATE_DIR, runner=cap, **(nuclei_kwargs or {}))
    nu.run(TARGET_HOST, {})
    nu.run(TARGET_HOST, {"tags": ["tech", "cve"], "severity": ["info", "high"]})
    return seen


def format_argvs(argvs: list[list[str]]) -> str:
    return "\n".join(" ".join(argv) for argv in argvs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the argvs the wrappers build.")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)
    argvs = build_argvs()
    print(json.dumps(argvs) if args.json else format_argvs(argvs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
