# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-40 — LLM planner: wire a real model into the orchestrator and `op06d run`

Static checks that the LLM planner adds no path to the tools: the adapter and
redaction modules import nothing that can start a process or reach a tool,
and the orchestrator touches the toolbox only through ``execute`` (plus the
read-only ``describe``/``redact``). The RC-21 chokepoint test
(test_chokepoint_boundary.py) is unchanged and still covers every module.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "op06d"
FORBIDDEN_IMPORTS = {"subprocess", "op06d.tools", "op06d.nmap_tool", "op06d.nuclei_tool", "pty", "shlex"}
TOOLBOX_METHODS = {"execute", "describe", "redact"}


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names |= {f"{module}.{a.name}" for a in node.names}
    return names


def test_model_adapters_cannot_reach_a_tool_or_a_process():
    for name in ("llm.py", "redaction.py"):
        found = _imports(SRC / name)
        assert not (found & FORBIDDEN_IMPORTS), (name, sorted(found & FORBIDDEN_IMPORTS))
        source = (SRC / name).read_text(encoding="utf-8")
        for call in ("os.system", "os.popen", "os.exec", "os.spawn"):
            assert call not in source, (name, call)


def test_orchestrator_uses_the_toolbox_only_through_execute():
    tree = ast.parse((SRC / "orchestrator.py").read_text(encoding="utf-8"))
    used = {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute)
        and node.value.attr == "_toolbox"
    }
    assert used <= TOOLBOX_METHODS, used
    assert "execute" in used
    assert not (_imports(SRC / "orchestrator.py") & {"subprocess", "op06d.nmap_tool", "op06d.nuclei_tool"})


def test_new_modules_are_flat_so_the_chokepoint_scan_covers_them():
    assert (SRC / "llm.py").exists() and (SRC / "redaction.py").exists()
    assert not [p for p in SRC.iterdir() if p.is_dir() and (p / "__init__.py").exists()]
