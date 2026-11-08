#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-36: regenerate the bundled write-method exclusion list.

Run this whenever the pinned nuclei template set changes (a re-pin of
``lab/scanner/Dockerfile``'s ``TEMPLATES_VERSION``) - it's the "regenerated
and verified when the set is re-pinned" half of the RC-36 backstop; the
CI-enforced audit test and the lab-gated test are the "verified" half.

Usage (inside the scanner, where the pinned template set actually lives):

    python3 scripts/generate_nuclei_write_method_exclusions.py \
        /opt/nuclei-templates v10.5.1 \
        --out src/op06d/nuclei_write_method_exclusions.json

Prints a short diff summary against the previous bundled file (ids added /
removed) so a re-pin's effect on the exclusion list is visible in review,
not just silently overwritten.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from op06d.nuclei_method_audit import scan_template_dir_for_write_methods  # noqa: E402

DEFAULT_OUT = ROOT / "src" / "op06d" / "nuclei_write_method_exclusions.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template_dir", help="the pinned template directory to scan")
    parser.add_argument("templates_pin", help="a label for this template set, e.g. v10.5.1")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="where to write the exclusion list")
    args = parser.parse_args(argv)

    out_path = Path(args.out)
    previous_ids: set[str] = set()
    if out_path.exists():
        try:
            previous_ids = set(json.loads(out_path.read_text(encoding="utf-8")).get(
                "write_method_template_ids", [],
            ))
        except (ValueError, OSError):
            pass

    new_ids = scan_template_dir_for_write_methods(args.template_dir)

    out_path.write_text(
        json.dumps(
            {
                "templates_pin": args.templates_pin,
                "generated_by": "scripts/generate_nuclei_write_method_exclusions.py",
                "generated_from": f"{args.template_dir} (pin {args.templates_pin})",
                "write_method_template_ids": new_ids,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    added = sorted(set(new_ids) - previous_ids)
    removed = sorted(previous_ids - set(new_ids))
    print(f"wrote {out_path} ({len(new_ids)} write-method template ids, pin {args.templates_pin})")
    if added:
        print(f"  added   ({len(added)}): {added}")
    if removed:
        print(f"  removed ({len(removed)}): {removed}")
    if not added and not removed and previous_ids:
        print("  no change from the previous bundled list")
    return 0


if __name__ == "__main__":
    sys.exit(main())
