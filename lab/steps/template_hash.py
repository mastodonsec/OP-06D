# SPDX-License-Identifier: AGPL-3.0-or-later
"""A stable SHA-256 of the pinned nuclei template set.

Runs inside the scanner:

    python3 /lab/steps/template_hash.py [--root /opt/nuclei-templates] [--json]

The hash is sha256 over the sorted (relative path, NUL, sha256(content)) of
every file in the tree, so it does not depend on filesystem order. Prints
``<sha256>  <root> (<n> files)``; ``--json`` prints ``{"sha256": ..., "files": n}``
for lab/validation_harness.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

DEFAULT_ROOT = "/opt/nuclei-templates"


def tree_hash(root: pathlib.Path) -> tuple[str, int]:
    files = sorted((p.relative_to(root).as_posix(), p) for p in root.rglob("*") if p.is_file())
    h = hashlib.sha256()
    for rel, p in files:
        h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest(), len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hash the pinned nuclei template set.")
    parser.add_argument("--root", default=DEFAULT_ROOT, help=f"template directory (default {DEFAULT_ROOT})")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)
    digest, count = tree_hash(pathlib.Path(args.root))
    print(json.dumps({"sha256": digest, "files": count}) if args.json else f"{digest}  {args.root} ({count} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
