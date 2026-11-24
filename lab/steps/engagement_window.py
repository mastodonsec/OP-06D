# SPDX-License-Identifier: AGPL-3.0-or-later
"""Is "now" inside a generated engagement's authorization window?

Runs inside the scanner (op06d is installed there):

    python3 /lab/steps/engagement_window.py /captures/engagement.now.yaml [--json]

Prints the window and the current UTC time, and whether now falls inside the
window. ``--json`` prints ``{"start": ..., "end": ..., "now": ...}`` (ISO 8601)
for lab/validation_harness.py, which judges it. Exits 0 once the engagement
loads; a file that does not load is an error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys


def window_facts(start: dt.datetime, end: dt.datetime, now: dt.datetime) -> dict:
    return {"start": start.isoformat(), "end": end.isoformat(), "now": now.isoformat()}


def format_window(start: dt.datetime, end: dt.datetime, now: dt.datetime) -> str:
    where = "inside" if start <= now < end else "OUTSIDE"
    return (f"window {start.isoformat()} .. {end.isoformat()}\n"
            f"now    {now.isoformat()} ({where} the window)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Is now inside the engagement's window?")
    parser.add_argument("engagement", help="the generated engagement file, e.g. /captures/engagement.now.yaml")
    parser.add_argument("--json", action="store_true", help="print JSON for the validation harness")
    args = parser.parse_args(argv)

    from op06d.engagement import load_engagement

    start, end = load_engagement(args.engagement).authorization.window
    now = dt.datetime.now(dt.timezone.utc)
    print(json.dumps(window_facts(start, end, now)) if args.json else format_window(start, end, now))
    return 0


if __name__ == "__main__":
    sys.exit(main())
