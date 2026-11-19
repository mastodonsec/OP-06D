# SPDX-License-Identifier: AGPL-3.0-or-later
"""The repository hygiene guard (scripts/check_repo_hygiene.py). Every sample
that should be caught is assembled from fragments, so this file stays clean
under the guard it tests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("check_repo_hygiene", ROOT / "scripts" / "check_repo_hygiene.py")
hygiene = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = hygiene  # dataclasses look their module up here
_spec.loader.exec_module(hygiene)

KEY = "R" + "C"
CAUGHT_EVERYWHERE = {
    "ticket key": f"see {KEY}-123 for details",
    "previous project name": "the " + "Red" + " Cell lab",
    "previous project name ": "a " + "red" + "-cell run",
    "previous project name  ": "RED" + "CELL",
    "product-stage wording": "the " + "M" + "VP is done",
    "reference to the internal notes file": "see " + "CON" + "TEXT.md",
}
ROADMAP = ["plan" + "ned", "road" + "map", "back" + "log", "later " + "iteration", "for " + "now",
           "future " + "tier", "active " + "development", "project " + "board"]


def _scan(tmp_path, files: dict[str, str | bytes]):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return hygiene.scan(tmp_path, list(files))


@pytest.mark.parametrize("what,line", list(CAUGHT_EVERYWHERE.items()))
@pytest.mark.parametrize("name", ["code.py", "notes.md", "conf.yml"])
def test_each_pattern_is_caught_with_file_and_line(tmp_path, what, line, name):
    problems = _scan(tmp_path, {name: f"first line\n{line}\n"})
    assert len(problems) == 1
    p = problems[0]
    assert (p.path, p.line) == (name, 2) and p.what.startswith(what.strip())
    assert str(p).startswith(f"{name}:2: ")


@pytest.mark.parametrize("phrase", ROADMAP)
def test_roadmap_wording_is_caught_in_markdown_only(tmp_path, phrase):
    line = f"This is {phrase} here."
    assert [p.what.split(":")[0] for p in _scan(tmp_path, {"doc.md": line})] == ["roadmap or status wording"]
    assert _scan(tmp_path, {"code.py": f"# {line}"}) == []


def test_a_ticket_number_in_a_path_is_caught(tmp_path):
    name = f"tests/integration/test_lab_{KEY.lower()}20.py"
    problems = _scan(tmp_path, {name: "clean\n"})
    assert [(p.path, p.line) for p in problems] == [(name, 0)]
    assert _scan(tmp_path, {f"lab/captures/_{KEY.lower()}20_ephemeral/x.txt": "clean"}) == []


@pytest.mark.parametrize("path", [
    "uv.lock", "LICENSE", "lab/captures/audit/log.jsonl", "lab/captures/notes.md",
])
def test_exclusions_are_honoured(tmp_path, path):
    bad = f"{KEY}-1 " + "Red" + "Cell " + "M" + "VP " + "CON" + "TEXT.md " + "road" + "map"
    assert _scan(tmp_path, {path: bad}) == []


def test_binary_files_are_skipped(tmp_path):
    assert _scan(tmp_path, {"image.png": b"\x89PNG\0\0" + f"{KEY}-1".encode()}) == []


def test_the_notes_file_may_be_named_in_gitignore_only(tmp_path):
    name = "CON" + "TEXT.md"
    assert _scan(tmp_path, {".gitignore": f"{name}\n"}) == []
    assert len(_scan(tmp_path, {"README.md": f"See {name}.\n"})) == 1


@pytest.mark.parametrize("ok", [
    "the rc-lab compose project",          # old-name residue, not a ticket number
    "planner: allowed_providers",          # planner is not planned work
    "mvpx and xmvp are not the word",
    "src2 and arc20 are not ticket numbers",
    "README.md is fine; context.md in lower case is another file",
])
def test_ordinary_text_is_not_caught(tmp_path, ok):
    assert _scan(tmp_path, {"doc.md": ok}) == []


def test_a_clean_tree_passes(tmp_path):
    assert _scan(tmp_path, {"a.py": "print('ok')\n", "b.md": "# Title\n\nPlain words.\n"}) == []


def test_the_repository_itself_is_clean():
    problems = hygiene.scan(ROOT, hygiene.tracked_files(ROOT))
    assert problems == [], "\n".join(map(str, problems))
