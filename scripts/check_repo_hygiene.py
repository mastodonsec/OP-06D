#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repository hygiene guard. Standard library only.

    uv run python scripts/check_repo_hygiene.py

Scans the text files git tracks (binaries, uv.lock, LICENSE and everything
under lab/captures/ are skipped) and fails, listing file:line, on:

  * an issue-tracker ticket key (the project's key followed by a number);
  * the project's previous name;
  * the product-stage abbreviation for a first release, as a word;
  * in Markdown only: roadmap or status wording (planned work, roadmaps,
    backlogs, later iterations, temporary states, future tiers, active
    development, the project board);
  * in Markdown only, outside fenced code blocks (``` and ~~~):
      - a call-out note: a blockquote line;
      - history wording: an upper-case resolution marker, a dated test
        note, a parenthesised ISO date, before/after phrasing (what a
        thing did in the past, what it does not do any more, what changed
        since a fix), a pointer to later work, references to a first or a
        future run, a live-confirmation note, strikethrough, and change
        notes about something staying the same (in parentheses, or "is" /
        "are" followed by that word; the bare word is fine);
  * a reference to the internal handoff notes file, anywhere but .gitignore;
  * a tracked file or directory name that carries a ticket number.

The patterns are assembled from fragments, so this file does not match them
itself and is scanned like any other. There is no allowlist: if a pattern
catches a legitimate use, report it instead of weakening the guard.
Exit 0 when clean, 1 when anything is found, 2 when git is unavailable.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

KEY = "R" + "C"
TICKET = re.compile(r"\b" + KEY + r"-[0-9]+")
OLD_NAME = re.compile("(?i)" + "re" + r"d[ -]?" + "ce" + "ll")
STAGE_WORD = re.compile(r"(?i)\b" + "M" + "VP" + r"\b")
ROADMAP = re.compile("(?i)" + "|".join(rf"\b{w}\b" for w in (
    "plan" + "ned", "road" + "map", "back" + "log", "later " + "iterations?", "for " + "now",
    "future " + "tier", "active " + "development", "project " + "board",
)))
NOTES_FILE = re.compile(r"\b" + "CON" + r"TEXT\.md\b")
CALLOUT = re.compile(r"^ {0,3}" + ">")
SAME = "un" + "changed"
HISTORY = re.compile("(?i)" + "|".join((
    r"(?-i:\b" + "RESOL" + r"VED\b)",                 # upper case only: "resolved IPs" is fine
    r"\b" + "test" + r"ed\s+[0-9]{4}\b",
    r"\([0-9]{4}-[0-9]{2}-[0-9]{2}\)",
    r"\b" + "used" + r" to\b",
    r"\b" + "no" + r" longer\b",
    r"\b" + "since" + r" the [\w-]+ fix\b",
    r"\b" + "follow" + r"-up\b",
    r"\b" + "first" + r" (?:real )?run\b",
    r"\b" + "future" + r" run\b",
    r"\b" + "confirmed" + r" live\b",
    "~" + "~",
    r"\([^()]*\b" + SAME + r"\)",
    r"\b(?:is|are) " + SAME + r"\b",
)))
FENCE_OPEN = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
NUMBERED_NAME = re.compile(r"(?i)(?:^|[^a-z0-9])" + KEY.lower() + r"[-_]?[0-9]+")

SKIP_FILES = {"uv.lock", "LICENSE"}
SKIP_PREFIXES = ("lab/captures/",)
NOTES_ALLOWED_IN = {".gitignore"}


@dataclass(frozen=True)
class Problem:
    path: str
    line: int  # 0 for a problem with the path itself
    what: str

    def __str__(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{where}: {self.what}"


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def skipped(path: str) -> bool:
    return path in SKIP_FILES or path.startswith(SKIP_PREFIXES)


def read_text(path: Path) -> str | None:
    """The file's text, or None for a binary or unreadable file."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def check_path(path: str) -> list[Problem]:
    return [Problem(path, 0, "file or directory name carries a ticket number")] if NUMBERED_NAME.search(path) else []


def prose_lines(text: str) -> list[bool]:
    """Per line of a Markdown text: True when it is outside a fenced code block.
    Fence lines themselves count as inside. A closing fence uses the opening
    fence's character, at least as many times, and nothing else; a backtick
    "fence" whose info string holds a backtick is inline code, not a fence."""
    flags, fence = [], None
    for line in text.splitlines():
        if fence is None:
            m = FENCE_OPEN.match(line)
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                fence = m.group(1)
                flags.append(False)
            else:
                flags.append(True)
        else:
            flags.append(False)
            if re.fullmatch(r"\s*" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*", line):
                fence = None
    return flags


def check_text(path: str, text: str) -> list[Problem]:
    problems = []
    is_md = path.lower().endswith(".md")
    prose = prose_lines(text) if is_md else []
    for n, line in enumerate(text.splitlines(), 1):
        checks = [(TICKET, "ticket key"), (OLD_NAME, "previous project name"), (STAGE_WORD, "product-stage wording")]
        if is_md:
            checks.append((ROADMAP, "roadmap or status wording"))
            if prose[n - 1]:
                checks += [(CALLOUT, "call-out note"), (HISTORY, "history wording")]
        if path not in NOTES_ALLOWED_IN:
            checks.append((NOTES_FILE, "reference to the internal notes file"))
        for pattern, what in checks:
            m = pattern.search(line)
            if m:
                problems.append(Problem(path, n, f"{what}: {m.group(0)!r}"))
    return problems


def scan(root: Path, paths: Iterable[str]) -> list[Problem]:
    problems: list[Problem] = []
    for path in paths:
        if skipped(path):
            continue
        problems += check_path(path)
        text = read_text(root / path)
        if text is not None:
            problems += check_text(path, text)
    return problems


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        paths = tracked_files(root)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"error: cannot list tracked files: {exc}", file=sys.stderr)
        return 2
    problems = scan(root, paths)
    for p in problems:
        print(p)
    print(f"repo hygiene: {len(paths)} tracked files, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
