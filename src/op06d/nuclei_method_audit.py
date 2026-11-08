# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-36: detect nuclei templates that declare an HTTP *write* method
(``PUT``/``DELETE``/``PATCH``/``PURGE``), in either shape nuclei templates use
to express a request method:

* an ``http``/``requests`` block's ``method:`` field, or
* a raw HTTP request (``raw:``) whose request line starts with one of those
  verbs (e.g. ``PUT /resource HTTP/1.1``).

This is shared by three callers that must never disagree with each other:
``NucleiTool`` (which always excludes these ids, regardless of tags - see
``nuclei_tool.py``'s RC-36 note), the bundled exclusion-list generator
(``scripts/generate_nuclei_write_method_exclusions.py``), and the CI-enforced
audit test (``tests/test_nuclei_tool.py``) that fails if a write-method
template is ever selectable in the default pass.

Query-style ``POST`` (GraphQL introspection, JSON-RPC reads, API
fingerprinting - ``POST`` because the protocol needs it, not to modify state)
and plain ``GET`` are never flagged; only the four write verbs are.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

WRITE_METHODS = frozenset({"PUT", "DELETE", "PATCH", "PURGE"})

_RAW_WRITE_METHOD_RE = re.compile(
    r"^\s*(" + "|".join(WRITE_METHODS) + r")\s+\S",
)


def template_declares_write_method(doc: Any) -> bool:
    """True if a parsed nuclei template (a YAML document already loaded into
    a dict) declares a write HTTP method, in either detection shape. Never
    raises: a malformed document simply is not flagged (the caller decides
    what "malformed" itself means for its own purposes)."""
    if not isinstance(doc, dict):
        return False
    for key in ("http", "requests"):
        blocks = doc.get(key)
        if not isinstance(blocks, list):
            continue
        for blk in blocks:
            if not isinstance(blk, dict):
                continue
            method = blk.get("method")
            if isinstance(method, str) and method.strip().upper() in WRITE_METHODS:
                return True
            raws = blk.get("raw")
            if isinstance(raws, list):
                for raw in raws:
                    text = str(raw)
                    if not text.strip():
                        continue
                    first_line = text.lstrip().splitlines()[0]
                    if _RAW_WRITE_METHOD_RE.match(first_line):
                        return True
    return False


def scan_template_dir_for_write_methods(template_dir: str | Path) -> list[str]:
    """Scan every ``*.yaml`` file under ``template_dir`` (recursively);
    return the sorted, de-duplicated list of template ids that declare a
    write HTTP method. Unreadable or malformed files are skipped, never
    raised - an audit must survive one bad file in a 14,000-template set."""
    ids: set[str] = set()
    for path in Path(template_dir).rglob("*.yaml"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            doc = yaml.safe_load(text)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        tid = doc.get("id")
        if not isinstance(tid, str) or not tid:
            continue
        if template_declares_write_method(doc):
            ids.add(tid)
    return sorted(ids)


def find_unexcluded_write_method_templates(
    template_dir: str | Path, excluded_ids: Any,
) -> list[str]:
    """Write-method template ids present in ``template_dir`` that are NOT
    covered by ``excluded_ids``: templates that would still be selectable
    despite declaring a write method. Empty means the backstop fully covers
    the template set as it stands; non-empty is the real "a re-pin
    introduced one and nothing is excluding it" drift signal this ticket
    exists to catch in CI, not just confirm safe-today-by-accident."""
    actual = set(scan_template_dir_for_write_methods(template_dir))
    return sorted(actual - set(excluded_ids))
