# SPDX-License-Identifier: AGPL-3.0-or-later
"""Session-wide test setup.

Keeps every temp file the suite creates under pytest's basetemp (``.pytest-tmp``
in the repo, see pyproject.toml), so nothing lands in the OS temp dir (on the
dev box, %TEMP% on C:). Covers code under test that calls ``tempfile`` directly
(e.g. the nuclei wrapper's per-run config and scrubbed HOME) and any subprocess
the tests start, which inherits TMP / TEMP / TMPDIR.
"""

from __future__ import annotations

import os
import tempfile

import pytest

_TEMP_VARS = ("TMP", "TEMP", "TMPDIR")


@pytest.fixture(scope="session", autouse=True)
def _temp_under_basetemp(tmp_path_factory: pytest.TempPathFactory):
    scratch = str(tmp_path_factory.mktemp("systemp", numbered=False))
    saved_env = {name: os.environ.get(name) for name in _TEMP_VARS}
    saved_tempdir = tempfile.tempdir
    for name in _TEMP_VARS:
        os.environ[name] = scratch
    tempfile.tempdir = scratch
    try:
        yield scratch
    finally:
        tempfile.tempdir = saved_tempdir
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
