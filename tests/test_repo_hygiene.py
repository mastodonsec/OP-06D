# SPDX-License-Identifier: AGPL-3.0-or-later
"""The repository hygiene guard (scripts/check_repo_hygiene.py). Every sample
that should be caught is assembled from fragments, so this file stays clean
under the guard it tests."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
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


SAME = "un" + "changed"
HISTORY_SAMPLES = {
    "resolution marker": ("**" + "RESOL" + "VED.** It works.", "RESOL" + "VED"),
    "dated test note": ("Test" + "ed 2026 on Kali.", "Test" + "ed 2026"),
    "parenthesised date": ("Frozen " + "(2026" + "-11-05).", "(2026" + "-11-05)"),
    "past behaviour": ("It " + "used" + " to do that.", "used" + " to"),
    "stopped behaviour": ("It " + "no" + " longer does that.", "no" + " longer"),
    "since a fix": ("Since" + " the ambient-config fix, it works.", "Since" + " the ambient-config fix"),
    "pointer to later work": ("A " + "follow" + "-up will add it.", "follow" + "-up"),
    "first run": ("On the " + "first" + " run it failed.", "first" + " run"),
    "first real run": ("From the " + "first" + " real run.", "first" + " real run"),
    "future run": ("A " + "future" + " run may differ.", "future" + " run"),
    "live confirmation": ("Confirmed" + " live in the lab.", "Confirmed" + " live"),
    "strikethrough": ("~" + "~old~" + "~ new", "~" + "~"),
    "parenthesised same": ("`fixed` (default, " + SAME + ")", "(default, " + SAME + ")"),
    "are same": ("The reports are " + SAME + ".", "are " + SAME),
    "is same": ("The output is " + SAME + ".", "is " + SAME),
}


@pytest.mark.parametrize("line,matched", list(HISTORY_SAMPLES.values()), ids=list(HISTORY_SAMPLES))
def test_history_wording_is_caught_in_markdown_with_file_and_line(tmp_path, line, matched):
    problems = _scan(tmp_path, {"doc.md": f"# Title\n\n{line}\n"})
    assert [(p.path, p.line) for p in problems] == [("doc.md", 3)]
    assert problems[0].what == f"history wording: {matched!r}"


def test_a_call_out_is_caught_in_markdown_with_file_and_line(tmp_path):
    problems = _scan(tmp_path, {"doc.md": "Intro.\n\n" + ">" + " **Note:** it changed.\n"})
    assert [(p.path, p.line, p.what) for p in problems] == [("doc.md", 3, "call-out note: '>'")]


ALL_NEW = [line for line, _ in HISTORY_SAMPLES.values()] + [">" + " a call-out"]


@pytest.mark.parametrize("line", ALL_NEW)
@pytest.mark.parametrize("name", ["code.py", "conf.yml"])
def test_history_and_call_outs_are_not_caught_outside_markdown(tmp_path, line, name):
    assert _scan(tmp_path, {name: f"{line}\n"}) == []


@pytest.mark.parametrize("fence", ["```", "~~~", "````", "```bash"])
@pytest.mark.parametrize("line", ALL_NEW)
def test_fenced_code_is_not_scanned_but_prose_after_it_is(tmp_path, fence, line):
    close = fence.rstrip("bash")
    text = f"Intro.\n\n{fence}\n{line}\n{close}\n\n{line}\n"
    assert [p.line for p in _scan(tmp_path, {"doc.md": text})] == [7]


def test_a_shorter_or_other_fence_does_not_close_the_block(tmp_path):
    line = "It " + "no" + " longer works."
    text = f"````\n```\n~~~\n{line}\n````\n{line}\n"
    assert [p.line for p in _scan(tmp_path, {"doc.md": text})] == [6]


def test_an_inline_triple_backtick_span_is_not_a_fence(tmp_path):
    line = "It " + "no" + " longer works."
    text = f"``` docker compose ps ```\n{line}\n"
    assert [p.line for p in _scan(tmp_path, {"doc.md": text})] == [2]


def test_existing_markdown_rules_still_scan_fenced_code(tmp_path):
    text = "```\n" + "road" + "map\n```\n"
    assert [p.what.split(":")[0] for p in _scan(tmp_path, {"doc.md": text})] == ["roadmap or status wording"]


@pytest.mark.parametrize("ok", [
    "the overlay leaves this network " + SAME + ".",
    "the bare target is passed " + SAME + ".",
    "if a > b the gate denies",
    "the follow step comes next",
    "resolved IPs are pinned once",
    "the first scan and the run that follows",
    "a ~ in a path, or ~/.config",
])
def test_ordinary_text_is_not_caught_as_history(tmp_path, ok):
    assert _scan(tmp_path, {"doc.md": ok + "\n"}) == []


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


def _not_a_git_work_tree() -> str | None:
    if shutil.which("git") is None:
        return "git is not on PATH"
    try:
        cp = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"git rev-parse could not run: {exc}"
    if cp.returncode != 0 or cp.stdout.strip() != "true":
        return f"{ROOT} is not a git work tree"
    return None


def test_the_repository_itself_is_clean():
    reason = _not_a_git_work_tree()
    if reason:
        pytest.skip(f"needs the git work tree to list tracked files: {reason}")
    problems = hygiene.scan(ROOT, hygiene.tracked_files(ROOT))
    assert problems == [], "\n".join(map(str, problems))
