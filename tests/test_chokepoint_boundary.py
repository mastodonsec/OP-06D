# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-21 suite 3: the chokepoint architectural test.

Statically asserts (AST scan of ``src/redcell/*.py``) that NOTHING except
``tools.py`` imports the concrete ``Tool`` implementations
(``redcell.nmap_tool`` / ``redcell.nuclei_tool``, including ``NmapTool`` /
``NucleiTool`` by name). ``default_tools()`` in ``tools.py`` is the only
sanctioned constructor for either.

This matters because ``GatedToolbox.execute`` (validate -> ``Gate.check``
-> approval -> run -> sanitize -> record) is the ONLY place a tool is
supposed to run from. A module that imports a concrete tool class directly
could construct and call it without ever going through the gate - a silent
guardrail bypass that no amount of adversarial testing of ``GatedToolbox``
itself (suite 1) would ever catch, because the bypass wouldn't use
``GatedToolbox`` at all. This test is the one that would catch it.

(Equivalent single-module checks already exist in ``test_nmap_tool.py`` and
``test_nuclei_tool.py``; this is the unified version plus a direct proof
that the detector isn't vacuous - see
``test_the_detector_actually_catches_a_violation`` below.)
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "redcell"
CONCRETE_TOOL_MODULES = ("nmap_tool", "nuclei_tool")
SANCTIONED_IMPORTER = "tools.py"


def _importers_of_concrete_tools(src_dir: Path) -> dict[str, set[str]]:
    """For each concrete tool module, the set of ``.py`` filenames (direct
    children of ``src_dir``) that import it, in any form: ``import
    redcell.nmap_tool``, ``from redcell import nmap_tool``, ``from
    redcell.nmap_tool import NmapTool``, or a relative ``from . import
    nmap_tool``."""
    importers: dict[str, set[str]] = {m: set() for m in CONCRETE_TOOL_MODULES}
    for path in sorted(src_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            candidates: list[str] = []
            if isinstance(node, ast.Import):
                candidates = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                candidates = [module, *(f"{module}.{a.name}" for a in node.names)]
                if node.level:  # relative import: from . import nmap_tool
                    candidates += [a.name for a in node.names]
            for candidate in candidates:
                for concrete in CONCRETE_TOOL_MODULES:
                    if candidate in (concrete, f"redcell.{concrete}") or candidate.endswith(f".{concrete}"):
                        importers[concrete].add(path.name)
    return importers


def test_only_tools_py_imports_the_concrete_tool_modules():
    """The chokepoint guarantee itself. If this ever fails because a new
    module imports ``nmap_tool``/``nuclei_tool`` directly, that is a real
    gate bypass and must be fixed, not the test weakened."""
    importers = _importers_of_concrete_tools(SRC)
    for module, who in importers.items():
        assert who == {SANCTIONED_IMPORTER}, (
            f"{module} is imported directly by {sorted(who - {SANCTIONED_IMPORTER})} - "
            f"only {SANCTIONED_IMPORTER} may construct a concrete tool"
        )


def test_the_detector_actually_catches_a_violation():
    """Prove the check above is not vacuous: feed the same detector a
    synthetic source tree that DOES import a concrete tool directly from
    outside ``tools.py``, in several different import forms, and confirm
    every one is flagged."""
    with tempfile.TemporaryDirectory() as d:
        src_dir = Path(d)
        (src_dir / "tools.py").write_text(
            "from redcell.nmap_tool import NmapTool\nfrom redcell.nuclei_tool import NucleiTool\n",
            encoding="utf-8",
        )
        (src_dir / "sneaky_from_import.py").write_text(
            "from redcell.nmap_tool import NmapTool\n\ndef run_it():\n    return NmapTool(10)\n",
            encoding="utf-8",
        )
        (src_dir / "sneaky_plain_import.py").write_text(
            "import redcell.nuclei_tool\n", encoding="utf-8",
        )

        importers = _importers_of_concrete_tools(src_dir)

        assert importers["nmap_tool"] == {"tools.py", "sneaky_from_import.py"}
        assert importers["nuclei_tool"] == {"tools.py", "sneaky_plain_import.py"}

        # and the real acceptance assertion (the same one the production
        # test above makes) would correctly fail on this synthetic tree -
        # i.e. the guard actually catches the violation, not just detects
        # importers in the abstract.
        violations = {m: who for m, who in importers.items() if who != {SANCTIONED_IMPORTER}}
        assert violations == {
            "nmap_tool": {"tools.py", "sneaky_from_import.py"},
            "nuclei_tool": {"tools.py", "sneaky_plain_import.py"},
        }


def test_a_clean_tree_with_only_tools_py_importing_passes():
    """The companion sanity check: a tree where only tools.py imports the
    concrete modules must NOT be flagged (the detector isn't trigger-happy)."""
    with tempfile.TemporaryDirectory() as d:
        src_dir = Path(d)
        (src_dir / "tools.py").write_text(
            "from redcell.nmap_tool import NmapTool\nfrom redcell.nuclei_tool import NucleiTool\n",
            encoding="utf-8",
        )
        (src_dir / "report.py").write_text("from redcell.evidence import ReconstructedRun\n", encoding="utf-8")
        importers = _importers_of_concrete_tools(src_dir)
        for module, who in importers.items():
            assert who == {SANCTIONED_IMPORTER}
