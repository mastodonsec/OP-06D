# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit the nuclei default selection read from the pinned template set.

Offline and read-only. The default selection is every template with a tag in
``DEFAULT_TAGS`` and none of the tags the wrapper passes to ``-exclude-tags``
(``INTRUSIVE_TAGS | EXPLOIT_TAGS`` minus the default tags). For those
templates it counts the ones that send a non-GET request, the ones that
declare a write method, and any write-method one the bundled ``-eid`` list
does not cover.

Runs inside the scanner:

    python3 -u /lab/steps/tag_audit.py [--root /opt/nuclei-templates] [--json]

Progress goes to stderr every 1,000 files. Prints a summary; ``--json``
prints the full audit for lab/validation_harness.py.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys
from typing import Iterable

DEFAULT_ROOT = "/opt/nuclei-templates"
READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def tags_of(info: dict) -> set[str]:
    t = info.get("tags", [])
    if isinstance(t, str):
        t = t.split(",")
    return {str(x).strip().lower() for x in t if str(x).strip()}


def selection_tags() -> tuple[set[str], set[str]]:
    """(default tags, tags the wrapper excludes)."""
    from op06d.nuclei_tool import DEFAULT_TAGS, EXPLOIT_TAGS, INTRUSIVE_TAGS

    default = set(DEFAULT_TAGS)
    return default, (INTRUSIVE_TAGS | EXPLOIT_TAGS) - default


def in_default_selection(tags: set[str], default: set[str], blocked: set[str]) -> bool:
    return bool(tags & default) and not (tags & blocked)


def load_template(p: pathlib.Path) -> tuple[dict, str] | None:
    """The parsed template and its text, or None if it is not a template."""
    import yaml

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        d = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(d, dict) or not isinstance(d.get("info"), dict):
        return None
    return d, text


def request_methods(d: dict) -> set[str]:
    methods = set()
    for key in ("http", "requests"):
        for blk in d.get(key) or []:
            if not isinstance(blk, dict):
                continue
            if isinstance(blk.get("method"), str):
                methods.add(blk["method"].strip().upper())
            for raw in blk.get("raw") or []:
                s = str(raw).lstrip()
                m = re.match(r"([A-Z]+)\s", s.splitlines()[0]) if s else None
                if m:
                    methods.add(m.group(1))
    return methods


def audit(files: Iterable[pathlib.Path], root: pathlib.Path, eid: set[str], default: set[str], blocked: set[str],
          declares_write_method, progress=None) -> dict:
    files = list(files)
    n = len(files)
    survivors, non_get, write, unexcluded = 0, [], [], []
    other: collections.Counter = collections.Counter()
    for i, p in enumerate(files, 1):
        if progress and i % 1000 == 0:
            progress(f"[{i}/{n}] scanning templates...")
        loaded = load_template(p)
        if loaded is None:
            continue
        d, text = loaded
        if not in_default_selection(tags_of(d["info"]), default, blocked):
            continue
        survivors += 1
        tid, rel = str(d.get("id")), str(p.relative_to(root))
        ng = sorted(request_methods(d) - READ_METHODS)
        if ng:
            non_get.append({"id": tid, "path": rel, "methods": ng})
        if declares_write_method(d):
            write.append(tid)
            if tid not in eid:
                unexcluded.append(tid)
        for proto in ("code", "headless", "javascript"):
            if proto in d:
                other["protocol:" + proto] += 1
        if "interactsh" in text:
            other["uses-interactsh"] += 1
    if progress:
        progress(f"scanned {n} templates")
    return {"templates_scanned": n, "default_survivors": survivors, "non_get": non_get,
            "non_get_methods": dict(collections.Counter(m for r in non_get for m in r["methods"])),
            "write_method": write, "write_method_unexcluded": unexcluded, "other": dict(other)}


def format_audit(a: dict) -> str:
    methods = ", ".join(f"{m} {c}" for m, c in sorted(a["non_get_methods"].items())) or "-"
    other = ", ".join(f"{k} {v}" for k, v in sorted(a["other"].items())) or "-"
    lines = [
        f"templates scanned:                  {a['templates_scanned']}",
        f"in the default selection:           {a['default_survivors']}",
        f"  send a non-GET request:           {len(a['non_get'])} ({methods})",
        f"  declare a write method:           {len(a['write_method'])}",
        f"  write method not covered by -eid: {len(a['write_method_unexcluded'])}",
        f"  other:                            {other}",
    ]
    if a["non_get"]:
        lines.append("non-GET templates in the default selection:")
        lines += [f"  {r['id']} {','.join(r['methods'])} {r['path']}" for r in a["non_get"]]
    if a["write_method_unexcluded"]:
        lines.append("NOT COVERED by -eid: " + ", ".join(a["write_method_unexcluded"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit the nuclei default selection.")
    parser.add_argument("--root", default=DEFAULT_ROOT, help=f"template directory (default {DEFAULT_ROOT})")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)

    from op06d.nuclei_method_audit import template_declares_write_method
    from op06d.nuclei_tool import DEFAULT_WRITE_METHOD_EXCLUSIONS_PATH, load_write_method_exclusions

    root = pathlib.Path(args.root)
    default, blocked = selection_tags()
    result = audit(sorted(root.rglob("*.yaml")), root, set(load_write_method_exclusions(DEFAULT_WRITE_METHOD_EXCLUSIONS_PATH)),
                   default, blocked, template_declares_write_method,
                   progress=lambda msg: print(msg, file=sys.stderr, flush=True))
    print(json.dumps(result) if args.json else format_audit(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
