# SPDX-License-Identifier: AGPL-3.0-or-later
"""EvidenceStore.read_snapshot: reading a finished store that the reader may
not write (a lab capture the scanner wrote as root), without writing to it or
its directory and without losing rows that are still in the -wal file."""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
from pathlib import Path

import pytest

from op06d.engagement import load_engagement
from op06d.evidence import EvidenceError, EvidenceStore

EXAMPLE = Path(__file__).parent.parent / "examples" / "engagement.yaml"
ENG = load_engagement(EXAMPLE)

POSIX_PERMISSIONS = os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0
needs_posix_permissions = pytest.mark.skipif(
    not POSIX_PERMISSIONS,
    reason="needs POSIX permissions and a non-root user: Windows cannot make a directory "
           "unwritable with chmod, and root ignores permissions",
)


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


def _finished_store(directory: Path) -> tuple[Path, str]:
    directory.mkdir()
    db = directory / "evidence.db"
    store = EvidenceStore(db)
    run_id = store.start_run(ENG, audit_log_path="audit/x.audit.jsonl")
    store.record_planner(run_id, {"planner": "llm", "provider": "local"})
    store.finish_run(run_id, status="completed", audit_log_sha256="ab" * 32)
    return db, run_id


def test_a_finished_store_is_read_and_nothing_is_written_beside_it(tmp_path):
    db, run_id = _finished_store(tmp_path / "capture")
    before = _snapshot(db.parent)
    os.chmod(db, stat.S_IREAD)
    try:
        with EvidenceStore.read_snapshot(db) as store:
            assert store.path.parent != db.parent
            recon = store.reconstruct_run(run_id)
    finally:
        os.chmod(db, stat.S_IREAD | stat.S_IWRITE)
    assert recon.run.status == "completed" and recon.planner == {"planner": "llm", "provider": "local"}
    assert _snapshot(db.parent) == before
    assert not store.path.parent.exists()  # the private copy is removed on exit


@needs_posix_permissions
def test_a_store_in_a_directory_the_reader_cannot_write_is_read(tmp_path):
    db, run_id = _finished_store(tmp_path / "capture")
    before = _snapshot(db.parent)
    os.chmod(db, 0o444)
    os.chmod(db.parent, 0o555)
    try:
        with pytest.raises(sqlite3.OperationalError):
            EvidenceStore(db).list_runs()  # the writing open needs the directory
        with EvidenceStore.read_snapshot(db) as store:
            assert [r.run_id for r in store.list_runs()] == [run_id]
    finally:
        os.chmod(db.parent, 0o755)
        os.chmod(db, 0o644)
    assert _snapshot(db.parent) == before


def test_rows_still_in_the_wal_are_read_never_dropped(tmp_path):
    db = tmp_path / "capture" / "evidence.db"
    db.parent.mkdir()
    EvidenceStore(db)
    # A second connection that stays open, as a process killed mid-run would leave
    # it: the last connection to close checkpoints the -wal, so this keeps it.
    holder = sqlite3.connect(db)
    holder.execute("SELECT count(*) FROM runs").fetchone()
    try:
        store = EvidenceStore(db)
        run_ids = [store.start_run(ENG) for _ in range(3)]
        wal = db.with_name("evidence.db-wal")
        assert wal.is_file() and wal.stat().st_size > 0

        # The rows really are only in the -wal: the main file on its own lacks them.
        lone = tmp_path / "main-file-only.db"
        shutil.copyfile(db, lone)
        with sqlite3.connect(f"file:{lone.as_posix()}?immutable=1", uri=True) as raw:
            assert raw.execute("SELECT count(*) FROM runs").fetchone()[0] < len(run_ids)

        before = _snapshot(db.parent)
        with EvidenceStore.read_snapshot(db) as snap:
            assert sorted(r.run_id for r in snap.list_runs()) == sorted(run_ids)
        assert _snapshot(db.parent) == before
    finally:
        holder.close()


def test_a_missing_store_is_an_error_and_is_not_created(tmp_path):
    missing = tmp_path / "nothing" / "evidence.db"
    with pytest.raises(EvidenceError, match="no evidence store"):
        with EvidenceStore.read_snapshot(missing):
            pass
    assert not missing.parent.exists()
