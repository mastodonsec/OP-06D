# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-48: Gate chokepoint test: prove GatedToolbox.execute() is the only path to the tools

Static (AST) checks over every module in ``src/op06d/``:

1. process creation - only the tool-wrapper layer may start a process;
   aliased imports, attribute access, dynamic imports and third-party
   process launchers are all detected;
2. wrapper calls - inside ``tools.py`` a tool is invoked only from
   ``GatedToolbox.__execute``, reachable only from ``execute`` (call graph);
3. toolbox surface - ``GatedToolbox`` exposes ``execute`` plus an explicit
   read-only allowlist, and code outside ``tools.py`` uses nothing else;
4. the LLM-module checks formerly in ``test_llm_boundary.py``.

Every allowlist is a module-level constant below. The fixtures in
``tests/fixtures/chokepoint/`` break one rule each; they are parsed, never
imported. The RC-21 import check stays in ``test_chokepoint_boundary.py``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

SRC = Path(__file__).parent.parent / "src" / "op06d"
FIXTURES = Path(__file__).parent / "fixtures" / "chokepoint"

# --- allowlists ----------------------------------------------------------------

# The tool-wrapper layer: the toolbox module and the wrappers it constructs.
WRAPPER_LAYER = frozenset({"tools.py", "nmap_tool.py", "nuclei_tool.py"})
CONCRETE_WRAPPER_MODULES = ("nmap_tool", "nuclei_tool")
CONCRETE_WRAPPER_CLASSES = frozenset({"NmapTool", "NucleiTool"})

# file -> {enclosing scope ("*" = anywhere in the file): subprocess attributes}
SUBPROCESS_USE_ALLOWLIST: dict[str, dict[str, frozenset[str]]] = {
    # the one function that starts a process (argv list, no shell)
    "tools.py": {"run_subprocess": frozenset({"run", "DEVNULL"})},
    # the wrappers only catch the runner's timeout exception
    "nmap_tool.py": {"*": frozenset({"TimeoutExpired"})},
    "nuclei_tool.py": {"*": frozenset({"TimeoutExpired"})},
}

# (file, scope, detail). Empty: src/op06d has no dynamic import today.
DYNAMIC_IMPORT_ALLOWLIST: frozenset[tuple[str, str, str]] = frozenset()

# (file, scope, top-level module) -> "use" | "probe"
THIRD_PARTY_LAUNCHER_ALLOWLIST: dict[tuple[str, str, str], str] = {
    # RC-18 alternative PDF backend: headless Chromium renders the report HTML.
    ("report_render.py", "_pdf_via_playwright", "playwright"): "use",
    # availability probe for that backend: an unused import inside
    # try/except ImportError, enforced structurally by the check.
    ("report_render.py", "render_pdf", "playwright"): "probe",
}

# GatedToolbox methods that may read the tool registry without being
# execute-only helpers: none of them may contain a tool invocation.
TOOL_REGISTRY_READERS = frozenset({
    "__init__",  # stores the tools
    "describe",  # name/description/risk/parameters for the system prompt
    "redact",    # sensitive-parameter names for audit redaction
})

# The public surface of GatedToolbox. A new public name fails
# test_gatedtoolbox_public_surface_is_exactly_the_allowlist until it is added here.
TOOLBOX_EXECUTE = "execute"
TOOLBOX_READ_ONLY = frozenset({
    "describe",  # read-only: builds the planner's tool list
    "redact",    # read-only: parameters as safe to log
})
TOOLBOX_SURFACE = frozenset({TOOLBOX_EXECUTE}) | TOOLBOX_READ_ONLY
TOOLBOX_DUNDERS = frozenset({"__init__"})

# Modules outside tools.py that may call default_tools() to hand the result
# straight to GatedToolbox.
DEFAULT_TOOLS_CALLERS = frozenset({
    "cli.py",  # run_engagement wires the default tools into the toolbox
})
# What such a module may read from a raw tool object, and where it may pass one.
RAW_TOOL_ATTRIBUTES = frozenset({
    "name",  # cli.py lists tool names for the planner's action schema
})
RAW_TOOL_SINKS = frozenset({"GatedToolbox"})
RAW_TOOL_PASSTHROUGH = frozenset({"list", "tuple"})

# --- rule tables -----------------------------------------------------------------

FORBIDDEN_PROCESS_MODULES = frozenset({
    "subprocess", "pty", "multiprocessing", "_posixsubprocess", "_winapi", "posix", "nt",
    "popen2", "commands", "pipes",
})
OS_FORBIDDEN_EXACT = frozenset({
    "system", "popen", "startfile", "fork", "forkpty", "posix_spawn", "posix_spawnp",
})
OS_FORBIDDEN_PREFIXES = ("exec", "spawn")
ASYNCIO_FORBIDDEN = frozenset({"create_subprocess_exec", "create_subprocess_shell", "subprocess"})
ANY_RECEIVER_FORBIDDEN = frozenset({
    "create_subprocess_exec", "create_subprocess_shell", "subprocess_exec", "subprocess_shell",
    "ProcessPoolExecutor",
})
DYNAMIC_IMPORT_MODULES = frozenset({"importlib", "runpy", "pkgutil", "zipimport", "imp", "builtins"})
DYNAMIC_BUILTINS = frozenset({"__import__", "eval", "exec", "compile", "__builtins__"})
THIRD_PARTY_LAUNCHERS = frozenset({
    "playwright", "pyppeteer", "selenium", "undetected_chromedriver", "splinter", "pexpect",
    "ptyprocess", "winpty", "sh", "plumbum", "docker", "podman", "invoke", "fabric", "delegator",
    "sarge", "psutil", "ansible_runner", "envoy",
})
REFLECTION_CALLS = frozenset({"getattr", "setattr", "delattr", "vars"})

PROCESS = "process"
DYNAMIC = "dynamic-import"
LAUNCHER = "third-party-launcher"
WRAPPER_REF = "wrapper-reference"
WRAPPER_CALL = "wrapper-call"
SURFACE = "toolbox-surface"
TOOLBOX_USE = "toolbox-use"
RAW_TOOL = "raw-tool-use"


@dataclass(frozen=True)
class Violation:
    file: str
    line: int
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: [{self.rule}] {self.detail}"


# --- AST helpers -------------------------------------------------------------------

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def parse(path: Path) -> ast.Module:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    _annotate(tree, None, "", None)
    return tree


def _annotate(node: ast.AST, parent: ast.AST | None, scope: str, func: ast.AST | None) -> None:
    node._parent = parent  # type: ignore[attr-defined]
    node._scope = scope  # type: ignore[attr-defined]
    node._func = func  # type: ignore[attr-defined]
    child_scope, child_func = scope, func
    if isinstance(node, _DEFS):
        child_scope = f"{scope}.{node.name}" if scope else node.name
        if isinstance(node, _FUNCS):
            child_func = node
    for child in ast.iter_child_nodes(node):
        _annotate(child, node, child_scope, child_func)


def _line(node: ast.AST) -> int:
    return getattr(node, "lineno", 0)


def _is_load(node: ast.AST) -> bool:
    return isinstance(getattr(node, "ctx", None), ast.Load)


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _os_forbidden(attr: str) -> bool:
    return attr in OS_FORBIDDEN_EXACT or attr.startswith(OS_FORBIDDEN_PREFIXES)


def src_modules() -> dict[str, ast.Module]:
    return {p.relative_to(SRC).as_posix(): parse(p) for p in sorted(SRC.rglob("*.py"))}


# --- 1. process creation --------------------------------------------------------

def _probe_ok(node: ast.AST, bound: str) -> bool:
    parent = node._parent  # type: ignore[attr-defined]
    if not isinstance(parent, ast.Try) or node not in parent.body:
        return False
    catches_import_error = any(
        isinstance(h.type, ast.Name) and h.type.id in ("ImportError", "ModuleNotFoundError")
        for h in parent.handlers
    )
    func = node._func  # type: ignore[attr-defined]
    used = func is not None and any(
        isinstance(n, ast.Name) and n.id == bound and _is_load(n) for n in ast.walk(func)
    )
    return catches_import_error and not used


def check_process(tree: ast.Module, filename: str) -> list[Violation]:
    out: list[Violation] = []
    os_alias: set[str] = set()
    sp_alias: set[str] = set()
    asyncio_alias: set[str] = set()

    def add(node: ast.AST, rule: str, detail: str) -> None:
        out.append(Violation(filename, _line(node), rule, detail))

    def dynamic(node: ast.AST, detail: str) -> None:
        if (filename, node._scope, detail) not in DYNAMIC_IMPORT_ALLOWLIST:  # type: ignore[attr-defined]
            add(node, DYNAMIC, f"dynamic import/evaluation: {detail}")

    def launcher(node: ast.AST, root: str, bound: str) -> None:
        kind = THIRD_PARTY_LAUNCHER_ALLOWLIST.get((filename, node._scope, root))  # type: ignore[attr-defined]
        if kind == "use" or (kind == "probe" and _probe_ok(node, bound)):
            return
        add(node, LAUNCHER, f"third-party process launcher {root!r}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                bound = a.asname or root
                if root == "os":
                    os_alias.add(bound)
                elif root == "subprocess":
                    if filename in SUBPROCESS_USE_ALLOWLIST:
                        sp_alias.add(bound)
                    else:
                        add(node, PROCESS, f"imports subprocess (as {bound!r})")
                elif root == "asyncio":
                    asyncio_alias.add(bound)
                    if a.name.startswith("asyncio.subprocess"):
                        add(node, PROCESS, "imports asyncio.subprocess")
                elif root in FORBIDDEN_PROCESS_MODULES:
                    add(node, PROCESS, f"imports {a.name}")
                elif root in DYNAMIC_IMPORT_MODULES:
                    dynamic(node, a.name)
                elif root in THIRD_PARTY_LAUNCHERS:
                    launcher(node, root, bound)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            module = node.module or ""
            root = module.split(".")[0]
            names = [a.name for a in node.names]
            if module == "os":
                for name in names:
                    if name == "*" or _os_forbidden(name):
                        add(node, PROCESS, f"from os import {name}")
            elif root == "subprocess" or root in FORBIDDEN_PROCESS_MODULES:
                add(node, PROCESS, f"from {module} import {', '.join(names)}")
            elif root == "asyncio":
                if module.startswith("asyncio.subprocess"):
                    add(node, PROCESS, f"from {module} import {', '.join(names)}")
                for name in names:
                    if name in ASYNCIO_FORBIDDEN or name == "*":
                        add(node, PROCESS, f"from {module} import {name}")
            elif root == "concurrent":
                for name in names:
                    if name in ANY_RECEIVER_FORBIDDEN or name == "*":
                        add(node, PROCESS, f"from {module} import {name}")
            elif root in DYNAMIC_IMPORT_MODULES:
                dynamic(node, f"{module}.{','.join(names)}")
            elif root in THIRD_PARTY_LAUNCHERS:
                launcher(node, root, node.names[0].asname or node.names[0].name)

    module_aliases = os_alias | sp_alias | asyncio_alias
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            base = node.value.id if isinstance(node.value, ast.Name) else None
            if base in os_alias and _os_forbidden(node.attr):
                add(node, PROCESS, f"os.{node.attr}")
            elif base in sp_alias:
                scopes = SUBPROCESS_USE_ALLOWLIST.get(filename, {})
                allowed = scopes.get("*", frozenset()) | scopes.get(node._scope, frozenset())  # type: ignore[attr-defined]
                if node.attr not in allowed:
                    add(node, PROCESS, f"subprocess.{node.attr} in {node._scope or '<module>'}")  # type: ignore[attr-defined]
            elif base in asyncio_alias and node.attr in ASYNCIO_FORBIDDEN:
                add(node, PROCESS, f"asyncio.{node.attr}")
            elif node.attr in ANY_RECEIVER_FORBIDDEN:
                add(node, PROCESS, f".{node.attr}")
            if base == "sys" and node.attr == "modules":
                dynamic(node, "sys.modules")
        elif isinstance(node, ast.Name) and _is_load(node):
            if node.id in DYNAMIC_BUILTINS:
                dynamic(node, node.id)
            elif node.id in module_aliases:
                parent = node._parent  # type: ignore[attr-defined]
                if not (isinstance(parent, ast.Attribute) and parent.value is node):
                    add(node, PROCESS, f"module object {node.id!r} used as a value")
    return out


# --- wrapper references (who may name a wrapper, the runner, default_tools) ---------

def check_wrapper_references(tree: ast.Module, filename: str) -> list[Violation]:
    out: list[Violation] = []

    def add(node: ast.AST, detail: str) -> None:
        out.append(Violation(filename, _line(node), WRAPPER_REF, detail))

    own_module = filename[:-3] in CONCRETE_WRAPPER_MODULES
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Name):
            names = [node.id]
        elif isinstance(node, ast.Attribute):
            names = [node.attr]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name.split(".")[-1] for a in node.names]
        for name in names:
            if name == "run_subprocess" and filename not in WRAPPER_LAYER:
                add(node, "run_subprocess referenced outside the wrapper layer")
            elif name in CONCRETE_WRAPPER_CLASSES and not own_module:
                if filename != "tools.py" or node._scope != "default_tools":  # type: ignore[attr-defined]
                    add(node, f"{name} referenced outside tools.py::default_tools")
            elif name == "default_tools" and filename != "tools.py" and filename not in DEFAULT_TOOLS_CALLERS:
                add(node, "default_tools referenced by a module that is not an allowed caller")
    return out


# --- 2. wrapper calls inside tools.py (call graph) ------------------------------------

def _toolbox_class(tree: ast.Module) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "GatedToolbox":
            return node
    raise AssertionError("GatedToolbox class not found")


def _is_tool_invocation(node: ast.AST, sp_alias: set[str]) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "run":
        return not (isinstance(node.value, ast.Name) and node.value.id in sp_alias)
    if isinstance(node, ast.Call) and _call_name(node) in REFLECTION_CALLS:
        return any(isinstance(a, ast.Constant) and a.value == "run" for a in node.args)
    return False


def check_tools_module(tree: ast.Module, filename: str = "tools.py") -> list[Violation]:
    out: list[Violation] = []

    def add(node: ast.AST, rule: str, detail: str) -> None:
        out.append(Violation(filename, _line(node), rule, detail))

    sp_alias = {
        (a.asname or a.name) for n in ast.walk(tree) if isinstance(n, ast.Import)
        for a in n.names if a.name == "subprocess"
    }
    cls = _toolbox_class(tree)
    methods = {n.name: n for n in cls.body if isinstance(n, _FUNCS)}

    for name in methods:
        if name.startswith("__") and name.endswith("__") and name not in TOOLBOX_DUNDERS:
            add(methods[name], SURFACE, f"GatedToolbox defines special method {name}")

    invoke_scope = "GatedToolbox.__execute"
    for node in ast.walk(tree):
        if _is_tool_invocation(node, sp_alias) and node._scope != invoke_scope:  # type: ignore[attr-defined]
            add(node, WRAPPER_CALL,
                f"tool invocation in {node._scope or '<module>'}, outside {invoke_scope}")  # type: ignore[attr-defined]

    edges: dict[str, set[str]] = {name: set() for name in methods}
    touches_registry: set[str] = set()
    for name, fn in methods.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
                if node.attr in methods:
                    edges[name].add(node.attr)
                if node.attr == "__tools":
                    touches_registry.add(name)

    def entry_points(target: str) -> set[str]:
        found: set[str] = set()
        for start in methods:
            if start.startswith("_") and not (start.startswith("__") and start.endswith("__")):
                continue
            seen, stack = set(), [start]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                stack.extend(edges[cur])
            if target in seen and start != "__init__":
                found.add(start)
        return found

    if "__execute" not in methods or TOOLBOX_EXECUTE not in methods:
        add(cls, WRAPPER_CALL, "GatedToolbox must define execute and __execute")
        return out
    guarded = (touches_registry - TOOL_REGISTRY_READERS) | {"__execute"}
    for name in sorted(guarded):
        entries = entry_points(name)
        if entries != {TOOLBOX_EXECUTE}:
            add(methods[name], WRAPPER_CALL,
                f"GatedToolbox.{name} reaches the tools and is reachable from {sorted(entries)}, "
                f"not only from {TOOLBOX_EXECUTE}")
    return out


# --- 3. toolbox surface ------------------------------------------------------------------

def toolbox_public_surface(tree: ast.Module) -> set[str]:
    cls = _toolbox_class(tree)
    names: set[str] = set()
    for node in cls.body:
        if isinstance(node, _DEFS):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    for node in ast.walk(cls):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
                and isinstance(node.value, ast.Name) and node.value.id == "self"):
            names.add(node.attr)
    return {n for n in names if not n.startswith("_")}


def _mangled_access(tree: ast.Module, filename: str) -> list[Violation]:
    out = []
    for node in ast.walk(tree):
        text = None
        if isinstance(node, ast.Attribute):
            text = node.attr
        elif isinstance(node, ast.Name):
            text = node.id
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        if text and text.startswith("_GatedToolbox__"):
            out.append(Violation(filename, _line(node), TOOLBOX_USE, f"name-mangled access {text!r}"))
    return out


def _assigned_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for t in target.elts for n in _assigned_names(t)]
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    return []


class _Taint:
    """Names (and ``self.<attr>``) in one module that hold a tracked object."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.self_attrs: set[str] = set()

    def is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.names
        if isinstance(node, ast.Attribute):
            return (isinstance(node.value, ast.Name) and node.value.id == "self"
                    and node.attr in self.self_attrs)
        if isinstance(node, (ast.Subscript, ast.Starred)):
            return self.is_tainted(node.value)
        return False

    def carries(self, node: ast.AST, is_source) -> bool:
        """True if evaluating ``node`` yields a tracked object itself."""
        if is_source(node, False) or self.is_tainted(node):
            return True
        if isinstance(node, ast.IfExp):
            return self.carries(node.body, is_source) or self.carries(node.orelse, is_source)
        if isinstance(node, ast.BoolOp):
            return any(self.carries(v, is_source) for v in node.values)
        if isinstance(node, ast.NamedExpr):
            return self.carries(node.value, is_source)
        if isinstance(node, ast.Call) and _call_name(node) in RAW_TOOL_PASSTHROUGH:
            return any(self.carries(a, is_source) for a in node.args)
        return False

    def bind(self, target: ast.AST) -> bool:
        before = (len(self.names), len(self.self_attrs))
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            self.self_attrs.add(target.attr)
        self.names.update(_assigned_names(target))
        return before != (len(self.names), len(self.self_attrs))


def _propagate(tree: ast.Module, taint: _Taint, is_source) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None and is_source(node.annotation, True):
            taint.names.add(node.arg)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if taint.carries(node.value, is_source):
                    changed |= any([taint.bind(t) for t in node.targets])
            elif isinstance(node, ast.AnnAssign):
                if (is_source(node.annotation, True)
                        or (node.value is not None and taint.carries(node.value, is_source))):
                    changed |= taint.bind(node.target)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                if taint.is_tainted(node.iter):
                    changed |= taint.bind(node.target)
            elif isinstance(node, ast.NamedExpr):
                if taint.carries(node.value, is_source):
                    changed |= taint.bind(node.target)


def _annotation_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ast.unparse(node)


def check_toolbox_use(tree: ast.Module, filename: str) -> tuple[list[Violation], set[str]]:
    """Attribute use of GatedToolbox instances outside tools.py. Returns
    (violations, attributes used)."""
    def is_source(node: ast.AST, annotation: bool) -> bool:
        if annotation:
            return bool(re.search(r"\bGatedToolbox\b", _annotation_text(node)))
        return isinstance(node, ast.Call) and _call_name(node) == "GatedToolbox"

    taint = _Taint()
    _propagate(tree, taint, is_source)
    out = _mangled_access(tree, filename)
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and taint.is_tainted(node.value):
            used.add(node.attr)
            if node.attr not in TOOLBOX_SURFACE:
                out.append(Violation(filename, _line(node), TOOLBOX_USE,
                                     f"toolbox attribute .{node.attr} is not on the allowlist"))
        elif isinstance(node, ast.Call) and _call_name(node) in REFLECTION_CALLS:
            if any(taint.is_tainted(a) for a in node.args):
                out.append(Violation(filename, _line(node), TOOLBOX_USE,
                                     f"{_call_name(node)}() on a toolbox"))
    return out, used


def check_raw_tool_use(tree: ast.Module, filename: str) -> list[Violation]:
    """Outside tools.py, raw tool objects (``default_tools()`` results or
    anything annotated ``Tool``) may only be read for RAW_TOOL_ATTRIBUTES and
    passed to RAW_TOOL_SINKS."""
    def is_source(node: ast.AST, annotation: bool) -> bool:
        if annotation:
            return bool(re.search(r"\bTool\b", _annotation_text(node)))
        return isinstance(node, ast.Call) and _call_name(node) == "default_tools"

    taint = _Taint()
    _propagate(tree, taint, is_source)
    out: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and taint.is_tainted(node.value):
            if node.attr not in RAW_TOOL_ATTRIBUTES:
                out.append(Violation(filename, _line(node), RAW_TOOL,
                                     f"raw tool attribute .{node.attr} used outside the toolbox"))
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            args = [*node.args, *(k.value for k in node.keywords)]
            if any(taint.is_tainted(a) for a in args) and name not in RAW_TOOL_SINKS | RAW_TOOL_PASSTHROUGH:
                out.append(Violation(filename, _line(node), RAW_TOOL,
                                     f"raw tool object passed to {name or '<call>'}()"))
    return out


# --- the suite on today's code -------------------------------------------------------

def _report(violations: list[Violation]) -> str:
    return "\n" + "\n".join(str(v) for v in violations)


def test_source_tree_is_flat_so_every_module_is_scanned():
    assert not [p for p in SRC.iterdir() if p.is_dir() and (p / "__init__.py").exists()]
    assert WRAPPER_LAYER <= set(src_modules())


def test_only_the_wrapper_layer_can_start_a_process():
    found = [v for name, tree in src_modules().items() for v in check_process(tree, name)]
    assert not found, _report(found)


def test_process_allowlists_are_not_stale():
    modules = src_modules()
    assert set(SUBPROCESS_USE_ALLOWLIST) == WRAPPER_LAYER
    for filename, scopes in SUBPROCESS_USE_ALLOWLIST.items():
        attrs = {
            (n._scope, n.attr) for n in ast.walk(modules[filename])
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "subprocess"
        }
        for scope, allowed in scopes.items():
            seen = {a for s, a in attrs if scope == "*" or s == scope}
            assert seen == set(allowed), (filename, scope, seen)
    for (filename, scope, module) in THIRD_PARTY_LAUNCHER_ALLOWLIST:
        imports = [
            n for n in ast.walk(modules[filename])
            if isinstance(n, (ast.Import, ast.ImportFrom)) and n._scope == scope
            and any((getattr(n, "module", None) or a.name).split(".")[0] == module for a in n.names)
        ]
        assert imports, (filename, scope, module)


def test_wrappers_runner_and_default_tools_are_named_only_where_allowed():
    found = [v for name, tree in src_modules().items() for v in check_wrapper_references(tree, name)]
    assert not found, _report(found)


def test_only_tools_py_imports_the_concrete_wrappers():
    for name, tree in src_modules().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or "", *(f"{node.module or ''}.{a.name}" for a in node.names),
                        *(a.name for a in node.names)]
            else:
                continue
            hits = [m for m in mods if m.split(".")[-1] in CONCRETE_WRAPPER_MODULES]
            assert not hits or name == "tools.py", (name, _line(node), hits)


def test_tools_are_invoked_only_from_execute():
    found = check_tools_module(src_modules()["tools.py"])
    assert not found, _report(found)


def test_gatedtoolbox_public_surface_is_exactly_the_allowlist():
    assert toolbox_public_surface(src_modules()["tools.py"]) == set(TOOLBOX_SURFACE)


def test_code_outside_tools_py_uses_only_the_allowed_toolbox_surface():
    found: list[Violation] = []
    used_by: dict[str, set[str]] = {}
    for name, tree in src_modules().items():
        if name == "tools.py":
            found += _mangled_access(tree, name)
            continue
        violations, used = check_toolbox_use(tree, name)
        found += violations
        if used:
            used_by[name] = used
    assert not found, _report(found)
    assert TOOLBOX_EXECUTE in used_by.get("orchestrator.py", set())
    assert TOOLBOX_EXECUTE in used_by.get("cli.py", set())
    assert set().union(*used_by.values()) <= TOOLBOX_SURFACE


def test_raw_tool_objects_never_run_outside_the_toolbox():
    found = [v for name, tree in src_modules().items() if name not in WRAPPER_LAYER
             for v in check_raw_tool_use(tree, name)]
    assert not found, _report(found)


# --- LLM planner modules (from test_llm_boundary.py) ---------------------------------

LLM_FORBIDDEN_IMPORTS = {"subprocess", "op06d.tools", "op06d.nmap_tool", "op06d.nuclei_tool", "pty", "shlex"}


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
        assert not (found & LLM_FORBIDDEN_IMPORTS), (name, sorted(found & LLM_FORBIDDEN_IMPORTS))
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
    assert used <= TOOLBOX_SURFACE, used
    assert TOOLBOX_EXECUTE in used
    assert not (_imports(SRC / "orchestrator.py") & {"subprocess", "op06d.nmap_tool", "op06d.nuclei_tool"})


def test_new_modules_are_flat_so_the_chokepoint_scan_covers_them():
    assert (SRC / "llm.py").exists() and (SRC / "redaction.py").exists()
    assert not [p for p in SRC.iterdir() if p.is_dir() and (p / "__init__.py").exists()]


# --- negative fixtures: each must make its check fail ---------------------------------

def _fixture(name: str) -> ast.Module:
    return parse(FIXTURES / name)


def _details(violations: list[Violation], rule: str) -> list[str]:
    assert violations and all(v.rule == rule for v in violations), _report(violations)
    return [v.detail for v in violations]


def test_fixture_aliased_subprocess_is_caught():
    details = _details(check_process(_fixture("aliased_subprocess.py"), "aliased_subprocess.py"), PROCESS)
    assert any("imports subprocess (as 'sp')" in d for d in details)
    assert any("from subprocess import Popen" in d for d in details)


def test_fixture_aliased_subprocess_is_caught_even_inside_the_wrapper_layer():
    for wrapper in sorted(WRAPPER_LAYER):
        details = _details(check_process(_fixture("aliased_subprocess.py"), wrapper), PROCESS)
        assert any("subprocess.run" in d for d in details), wrapper
        assert any("from subprocess import Popen" in d for d in details), wrapper


def test_fixture_from_os_import_system_is_caught():
    details = _details(check_process(_fixture("from_os_import_system.py"), "from_os_import_system.py"), PROCESS)
    assert "from os import system" in details


def test_fixture_os_attribute_access_is_caught():
    details = _details(check_process(_fixture("os_attribute_access.py"), "os_attribute_access.py"), PROCESS)
    for expected in ("os.system", "os.popen", "os.execv", "os.spawnl", "os.posix_spawn", "os.startfile"):
        assert expected in details, expected
    assert any("used as a value" in d for d in details)


def test_fixture_dynamic_import_is_caught():
    details = _details(check_process(_fixture("dynamic_import.py"), "dynamic_import.py"), DYNAMIC)
    joined = " | ".join(details)
    for expected in ("importlib", "__import__", "exec", "eval", "sys.modules"):
        assert expected in joined, expected


def test_fixture_other_process_mechanisms_are_caught():
    details = _details(check_process(_fixture("other_process_mechanisms.py"), "other_process_mechanisms.py"),
                       PROCESS)
    joined = " | ".join(details)
    for expected in ("imports pty", "multiprocessing", "create_subprocess_exec", "create_subprocess_shell",
                     "subprocess_exec", "ProcessPoolExecutor", "asyncio.subprocess"):
        assert expected in joined, expected


def test_fixture_third_party_launcher_is_caught_outside_its_allowlisted_function():
    for filename in ("third_party_launcher.py", "report_render.py"):
        details = _details(check_process(_fixture("third_party_launcher.py"), filename), LAUNCHER)
        joined = " | ".join(details)
        for expected in ("playwright", "selenium", "pexpect", "docker", "sh", "plumbum"):
            assert repr(expected) in joined, (filename, expected)


def test_fixture_probe_import_that_is_used_is_caught():
    details = _details(check_process(_fixture("launcher_probe_misuse.py"), "report_render.py"), LAUNCHER)
    assert len(details) == 1 and "'playwright'" in details[0]


def test_fixture_direct_wrapper_call_bypassing_execute_is_caught():
    tree = _fixture("direct_wrapper_call.py")
    raw = _details(check_raw_tool_use(tree, "direct_wrapper_call.py"), RAW_TOOL)
    assert any(".run" in d for d in raw) and any("passed to" in d for d in raw)
    refs = _details(check_wrapper_references(tree, "direct_wrapper_call.py"), WRAPPER_REF)
    joined = " | ".join(refs)
    for expected in ("default_tools", "NmapTool", "run_subprocess"):
        assert expected in joined, expected
    assert check_raw_tool_use(tree, "cli.py")  # an allowed default_tools caller still may not run a tool


def test_fixture_tool_invoked_from_a_second_toolbox_method_is_caught():
    tree = _fixture("tools_second_invocation.py")
    details = _details(check_tools_module(tree, "tools_second_invocation.py"), WRAPPER_CALL)
    assert any("tool invocation in GatedToolbox.run_unchecked" in d for d in details)
    assert any("GatedToolbox.run_unchecked reaches the tools" in d for d in details)
    assert "run_unchecked" in toolbox_public_surface(tree) - TOOLBOX_SURFACE


def test_fixture_second_entry_point_into_the_execute_helper_is_caught():
    tree = _fixture("tools_second_entry_point.py")
    details = _details(check_tools_module(tree, "tools_second_entry_point.py"), WRAPPER_CALL)
    assert any("reachable from ['execute', 'replay']" in d for d in details)


def test_fixture_module_level_tool_invocation_in_tools_is_caught():
    details = _details(check_tools_module(_fixture("tools_module_level_call.py"), "tools_module_level_call.py"),
                       WRAPPER_CALL)
    assert any("tool invocation in quick_scan" in d for d in details)


def test_fixture_new_toolbox_method_used_from_outside_is_caught():
    violations, used = check_toolbox_use(_fixture("new_toolbox_method_used.py"), "new_toolbox_method_used.py")
    joined = " | ".join(_details(violations, TOOLBOX_USE))
    for expected in (".run_tool", ".tools", "getattr() on a toolbox", "_GatedToolbox__tools"):
        assert expected in joined, expected
    assert {"run_tool", "tools", "execute"} <= used


def test_fixture_new_public_name_on_the_toolbox_fails_the_surface_check():
    tree = _fixture("tools_new_public_surface.py")
    assert toolbox_public_surface(tree) - TOOLBOX_SURFACE == {"tools", "peek", "DEFAULT"}
    found = check_tools_module(tree, "tools_new_public_surface.py")
    assert any(v.rule == SURFACE and "__getitem__" in v.detail for v in found)
    assert any(v.rule == WRAPPER_CALL and "GatedToolbox.peek" in v.detail for v in found)


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.py")), ids=lambda p: p.name)
def test_every_fixture_fails_at_least_one_check(path):
    tree = parse(path)
    name = path.name
    found = check_process(tree, name) + check_wrapper_references(tree, name) + check_raw_tool_use(tree, name)
    found += check_toolbox_use(tree, name)[0]
    if name.startswith("tools_"):
        found += check_tools_module(tree, name)
        if toolbox_public_surface(tree) != set(TOOLBOX_SURFACE):
            found.append(Violation(name, 0, SURFACE, "public surface differs from the allowlist"))
    assert found, name


def test_fixtures_exist():
    assert len(list(FIXTURES.glob("*.py"))) >= 12
