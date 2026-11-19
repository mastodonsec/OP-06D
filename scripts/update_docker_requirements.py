#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regenerate the image's hash-pinned requirement files. Standard library + uv.

    uv run python scripts/update_docker_requirements.py                 # rewrite
    uv run python scripts/update_docker_requirements.py --check         # CI
    uv run python scripts/update_docker_requirements.py --setuptools 85.0.0

The files under docker/ are generated, never edited by hand:

  * docker/requirements.txt and docker/requirements-lab.txt from uv.lock
    (``uv export --frozen``), so they change only when uv.lock does;
  * docker/build-requirements.txt from its own setuptools pin
    (``uv pip compile --generate-hashes``). Build backends are not locked in
    uv.lock, so that pin is bumped here with --setuptools.

Each file is its fixed comment header followed by uv's output (without uv's own
header). --check rewrites nothing; it exits 1 and names every file that differs
from what uv.lock and the setuptools pin produce. Line endings are ignored when
comparing (a Windows checkout has CRLF); files are written with LF.
Exit 0 when up to date (or after rewriting), 1 when stale, 2 when uv fails.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
EXPORT = ["uv", "export", "--frozen", "--no-dev", "--no-emit-project",
          "--extra", "llm-anthropic", "--extra", "report-pdf"]
COMPILE = ["uv", "pip", "compile", "-", "--generate-hashes", "--python-version", "3.11"]
SETUPTOOLS_PIN = re.compile(r"^setuptools==([0-9][0-9A-Za-z.]*) \\$", re.M)
FIX = "uv run python scripts/update_docker_requirements.py"


@dataclass(frozen=True)
class Target:
    path: str
    header: str
    command: list[str]
    stdin: str | None = None


def _export_header(what: str, extra: str, out: str, tail: str = "") -> str:
    return (f"# {what}\n"
            "# Generated from uv.lock, never edited by hand. Regenerate with:\n"
            f"#   uv export --frozen --no-dev --no-emit-project --extra llm-anthropic --extra report-pdf{extra} -o {out}\n"
            "# tests/test_container_image.py checks every pin against uv.lock.\n" + tail)


def targets(setuptools: str) -> list[Target]:
    return [
        Target("docker/requirements.txt",
               _export_header("Runtime dependencies of the OP-06D image (op06d + llm-anthropic + report-pdf).",
                              "", "docker/requirements.txt"),
               EXPORT + ["--no-header"]),
        Target("docker/requirements-lab.txt",
               _export_header("Lab scanner extras: the image's dependencies plus pytest (op06d's dev extra).",
                              " --extra dev", "docker/requirements-lab.txt"),
               EXPORT + ["--extra", "dev", "--no-header"]),
        Target("docker/build-requirements.txt",
               "# Build-only: setuptools to build the OP-06D wheel (pyproject build-system), hash-pinned.\n"
               "# Not part of uv.lock (build backends are not locked there). Regenerate with:\n"
               f"#   echo setuptools=={setuptools} | uv pip compile - --generate-hashes --python-version 3.11 --no-header\n",
               COMPILE + ["--no-header"], stdin=f"setuptools=={setuptools}\n"),
    ]


def current_setuptools(root: Path) -> str:
    text = (root / "docker" / "build-requirements.txt").read_text(encoding="utf-8")
    match = SETUPTOOLS_PIN.search(text)
    if not match:
        raise SystemExit("docker/build-requirements.txt: no 'setuptools==<version> \\' line found")
    return match.group(1)


def run_uv(target: Target, root: Path) -> str:
    """uv's output for one target (the body below the header)."""
    proc = subprocess.run(target.command, cwd=root, input=target.stdin, capture_output=True,
                          text=True, encoding="utf-8")
    if proc.returncode != 0:
        sys.stderr.write(f"{' '.join(target.command)} failed:\n{proc.stderr}")
        raise SystemExit(2)
    return proc.stdout


def _normalize(text: str) -> str:
    return text.replace("\r\n", "\n")


def update(root: Path, *, check: bool, setuptools: str | None = None,
           generate: Callable[[Target, Path], str] | None = None) -> list[str]:
    """Regenerate (or, with check, only compare) every file; return the stale ones."""
    generate = generate or run_uv
    stale = []
    for target in targets(setuptools or current_setuptools(root)):
        wanted = target.header + _normalize(generate(target, root))
        path = root / target.path
        have = _normalize(path.read_text(encoding="utf-8")) if path.exists() else None
        if have == wanted:
            continue
        stale.append(target.path)
        if not check:
            path.write_text(wanted, encoding="utf-8", newline="\n")
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="rewrite nothing; exit 1 if any file differs from what uv produces")
    parser.add_argument("--setuptools", metavar="VERSION",
                        help="pin this setuptools version in docker/build-requirements.txt")
    args = parser.parse_args(argv)
    stale = update(ROOT, check=args.check, setuptools=args.setuptools)
    if args.check:
        for path in stale:
            print(f"{path}: out of date with uv.lock / the setuptools pin")
        if stale:
            print(f"Regenerate with: {FIX}")
            return 1
        print("docker requirement files: up to date")
        return 0
    for path in stale:
        print(f"rewrote {path}")
    if not stale:
        print("docker requirement files: already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
