# SPDX-License-Identifier: AGPL-3.0-or-later
"""List the templates the nuclei default selection really selects: every
template with a default tag and none of the tags the wrapper's
``-exclude-tags`` drops, read from the same YAML as tag_audit.py.

Runs inside the scanner:

    python3 -u /lab/steps/default_selection.py [<out>] [--root /opt/nuclei-templates] [--json]

``<out>`` defaults to ``/captures/default-selection-templates.txt`` (one
relative path per line). Prints ``wrote <out> (<n> templates)``; ``--json``
prints ``{"path": ..., "templates": n}``.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from tag_audit import DEFAULT_ROOT, in_default_selection, load_template, selection_tags, tags_of  # noqa: E402

DEFAULT_OUT = "/captures/default-selection-templates.txt"


def default_selection(files, root: pathlib.Path, default: set[str], blocked: set[str]) -> list[str]:
    out = []
    for p in files:
        loaded = load_template(p)
        if loaded is not None and in_default_selection(tags_of(loaded[0]["info"]), default, blocked):
            out.append(str(p.relative_to(root)))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the nuclei default selection to a file.")
    parser.add_argument("out", nargs="?", default=DEFAULT_OUT, help=f"output file (default {DEFAULT_OUT})")
    parser.add_argument("--root", default=DEFAULT_ROOT, help=f"template directory (default {DEFAULT_ROOT})")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root)
    default, blocked = selection_tags()
    selected = default_selection(sorted(root.rglob("*.yaml")), root, default, blocked)
    pathlib.Path(args.out).write_text("\n".join(selected) + "\n", encoding="utf-8")
    print(json.dumps({"path": args.out, "templates": len(selected)}) if args.json
          else f"wrote {args.out} ({len(selected)} templates)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
