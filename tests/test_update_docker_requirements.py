# SPDX-License-Identifier: AGPL-3.0-or-later
"""The regeneration script for the image's requirement files
(scripts/update_docker_requirements.py) and its --check mode, which CI runs.

The uv.lock-derived files are exported with the real uv (offline: --frozen).
The setuptools file needs PyPI, so those tests stub uv pip compile; CI's
--check run covers the real one."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("update_docker_requirements",
                                               ROOT / "scripts" / "update_docker_requirements.py")
upd = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = upd  # dataclasses look their module up here
_spec.loader.exec_module(upd)

FILES = ["docker/requirements.txt", "docker/requirements-lab.txt", "docker/build-requirements.txt"]
FAKE_HASH = "0" * 64
REAL_UV = upd.run_uv

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv on PATH")


def _offline(target, root: Path) -> str:
    """Real uv export; a fixed body instead of uv pip compile (no network)."""
    if target.stdin is None:
        return REAL_UV(target, root)
    pin = target.stdin.strip()
    return f"{pin} \\\n    --hash=sha256:{FAKE_HASH}\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A copy of what the script reads: pyproject.toml, uv.lock, docker/."""
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy(ROOT / name, tmp_path / name)
    (tmp_path / "docker").mkdir()
    for name in FILES:
        shutil.copy(ROOT / name, tmp_path / name)
    upd.update(tmp_path, check=False, generate=_offline)  # the stubbed setuptools body
    return tmp_path


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def test_the_committed_lock_derived_files_match_uv_lock(repo):
    for name in FILES[:2]:
        assert _read(repo / name) == _read(ROOT / name), name


def test_a_regenerated_tree_passes_the_check(repo):
    assert upd.update(repo, check=True, generate=_offline) == []


def test_a_hand_edited_file_fails_and_regeneration_fixes_it(repo):
    path = repo / "docker" / "requirements.txt"
    good = _read(path)
    path.write_text(good.replace("anthropic==2.8.0", "anthropic==2.7.0"), encoding="utf-8")
    assert upd.update(repo, check=True, generate=_offline) == ["docker/requirements.txt"]
    assert "anthropic==2.7.0" in _read(path)  # --check rewrites nothing
    assert upd.update(repo, check=False, generate=_offline) == ["docker/requirements.txt"]
    assert _read(path) == good
    assert upd.update(repo, check=True, generate=_offline) == []


def test_a_uv_lock_bump_fails_until_the_files_are_regenerated(repo):
    # uv rejects a lock whose version disagrees with its artifact file names, so
    # the change here is to an artifact hash, which uv export carries through.
    lock = repo / "uv.lock"
    text = _read(lock)
    old = "13b2beaad985e05e2d6407ee4c4f35590b11f8d693a258a561055cac8f64cab7"  # annotated-types sdist
    new = "f" * 64
    assert text.count(old) == 1
    lock.write_text(text.replace(old, new), encoding="utf-8")
    assert upd.update(repo, check=True, generate=_offline) == FILES[:2]
    upd.update(repo, check=False, generate=_offline)
    assert upd.update(repo, check=True, generate=_offline) == []
    for name in FILES[:2]:
        assert f"--hash=sha256:{new}" in _read(repo / name) and old not in _read(repo / name)


def test_the_setuptools_pin_comes_from_the_file_and_can_be_bumped(repo):
    path = repo / "docker" / "build-requirements.txt"
    current = upd.current_setuptools(repo)
    assert current == upd.current_setuptools(ROOT)
    assert upd.update(repo, check=True, setuptools="99.0.0", generate=_offline) == [FILES[2]]
    upd.update(repo, check=False, setuptools="99.0.0", generate=_offline)
    text = _read(path)
    assert "#   echo setuptools==99.0.0 | uv pip compile" in text
    assert text.endswith(f"setuptools==99.0.0 \\\n    --hash=sha256:{FAKE_HASH}\n")
    assert upd.current_setuptools(repo) == "99.0.0"
    assert upd.update(repo, check=True, generate=_offline) == []


def test_crlf_line_endings_are_not_a_difference(repo):
    for name in FILES:
        path = repo / name
        path.write_bytes(_read(path).replace("\n", "\r\n").encode("utf-8"))
    assert upd.update(repo, check=True, generate=_offline) == []


def test_check_exits_1_and_names_the_stale_file_and_the_fix(repo, monkeypatch, capsys):
    monkeypatch.setattr(upd, "ROOT", repo)
    monkeypatch.setattr(upd, "run_uv", _offline)
    assert upd.main(["--check"]) == 0
    (repo / "docker" / "requirements-lab.txt").write_text("pytest==1.0\n", encoding="utf-8")
    assert upd.main(["--check"]) == 1
    out = capsys.readouterr().out
    assert "docker/requirements-lab.txt: out of date" in out
    assert "Regenerate with: uv run python scripts/update_docker_requirements.py" in out
    assert upd.main([]) == 0 and upd.main(["--check"]) == 0
