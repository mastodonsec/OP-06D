# SPDX-License-Identifier: AGPL-3.0-or-later
"""The toolchain baked into the container image (op06d.toolchain), how
`op06d run` uses it, `op06d version`, and the output-directory refusals."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from op06d import cli
from op06d.cli import OutputDirectoryError, mount_points, on_mounted_volume, prepare_output_dir
from op06d.toolchain import (
    TOOLCHAIN_ENV,
    ToolchainError,
    load_toolchain,
    resolve_run_toolchain,
    version_text,
)

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "examples" / "engagement.yaml"
BAKED = {"nmap": "7.93", "nmap_package": "7.93+dfsg1-1", "nuclei": "3.11.1",
         "templates_pin": "v10.5.1", "template_dir": "/opt/nuclei-templates"}


@pytest.fixture
def baked(tmp_path, monkeypatch):
    path = tmp_path / "toolchain.json"
    path.write_text(json.dumps(BAKED), encoding="utf-8")
    monkeypatch.setenv(TOOLCHAIN_ENV, str(path))
    return load_toolchain()


def test_no_toolchain_outside_the_image(monkeypatch):
    monkeypatch.delenv(TOOLCHAIN_ENV, raising=False)
    assert load_toolchain() is None


def test_flags_pass_through_without_a_baked_toolchain():
    chain = resolve_run_toolchain(None, template_dir="/t", templates_pin="p",
                                  nmap_version="7.94", nuclei_version=None)
    assert (chain.template_dir, chain.templates_pin, chain.tool_versions) == ("/t", "p", {"nmap": "7.94"})


def test_the_image_defaults_need_no_flags(baked):
    chain = resolve_run_toolchain(baked, template_dir=None, templates_pin=None,
                                  nmap_version=None, nuclei_version=None)
    assert chain.template_dir == "/opt/nuclei-templates"
    assert chain.templates_pin == "v10.5.1"
    assert chain.tool_versions == {"nmap": "7.93", "nuclei": "3.11.1"}


def test_flags_that_agree_with_the_image_are_accepted(baked):
    # The lab's model-relay run passes exactly these.
    chain = resolve_run_toolchain(baked, template_dir="/opt/nuclei-templates/", templates_pin="v10.5.1",
                                  nmap_version="7.93", nuclei_version="v3.11.1")
    assert chain.tool_versions == {"nmap": "7.93", "nuclei": "3.11.1"}


@pytest.mark.parametrize("flag,value", [
    ("template_dir", "/home/me/templates"),
    ("templates_pin", "v10.6.0"),
    ("nmap_version", "7.94"),
    ("nuclei_version", "3.12.0"),
])
def test_a_flag_that_contradicts_the_image_is_refused(baked, flag, value):
    kw = dict(template_dir=None, templates_pin=None, nmap_version=None, nuclei_version=None)
    kw[flag] = value
    with pytest.raises(ToolchainError, match="fixed toolchain") as exc:
        resolve_run_toolchain(baked, **kw)
    assert value in str(exc.value)


def test_a_broken_toolchain_file_is_an_error(tmp_path, monkeypatch):
    path = tmp_path / "toolchain.json"
    path.write_text(json.dumps({"nmap": "7.93"}), encoding="utf-8")
    monkeypatch.setenv(TOOLCHAIN_ENV, str(path))
    with pytest.raises(ToolchainError, match="must set"):
        load_toolchain()


def test_the_package_version_matches_pyproject():
    import tomllib

    import op06d

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert op06d.__version__ == project["version"]


def test_version_text_names_every_pin(baked):
    text = version_text(baked)
    for want in ("op06d ", "nmap 7.93", "nuclei 3.11.1", "nuclei-templates v10.5.1", "nmap_package 7.93+dfsg1-1"):
        assert want in text


@pytest.mark.parametrize("argv", [["version"], ["--version"]])
def test_the_version_command(baked, capsys, argv):
    with pytest.raises(SystemExit) if argv == ["--version"] else _nothing():
        code = cli.main(argv)
        assert code == 0
    assert "nmap 7.93" in capsys.readouterr().out


class _nothing:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_run_refuses_a_contradicting_flag_before_anything_is_written(baked, tmp_path, capsys):
    out = tmp_path / "out"
    code = cli.main(["run", "--engagement", str(EXAMPLE), "--out", str(out), "--nmap-version", "7.94"])
    assert code == 2
    assert "--nmap-version '7.94'" in capsys.readouterr().err
    assert not out.exists()


def test_run_in_the_image_records_the_baked_versions(baked, tmp_path, monkeypatch):
    seen = {}

    def fake_run(engagement, out, **kw):
        seen.update(kw)
        raise cli.PlannerPolicyError("stop here")

    monkeypatch.setattr(cli, "run_engagement", fake_run)
    assert cli.main(["run", "--engagement", str(EXAMPLE), "--out", str(tmp_path)]) == 2
    assert seen["tool_versions"] == {"nmap": "7.93", "nuclei": "3.11.1"}
    assert seen["template_dir"] == "/opt/nuclei-templates" and seen["templates_pin"] == "v10.5.1"
    assert seen["require_output_volume"] is True


# --- the output directory ------------------------------------------------------

def test_a_writable_output_directory_is_created(tmp_path):
    out = tmp_path / "a" / "b"
    prepare_output_dir(out)
    assert out.is_dir() and list(out.iterdir()) == []


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user")
def test_an_unwritable_output_directory_is_refused_before_any_action(tmp_path):
    out = tmp_path / "ro"
    out.mkdir()
    out.chmod(0o555)
    try:
        with pytest.raises(OutputDirectoryError, match="not writable"):
            prepare_output_dir(out)
    finally:
        out.chmod(0o755)


def test_an_output_path_that_cannot_be_created_is_refused(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(OutputDirectoryError, match="not writable"):
        prepare_output_dir(blocker / "out")


def test_run_engagement_refuses_before_loading_or_auditing(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(OutputDirectoryError):
        cli.run_engagement(EXAMPLE, blocker / "out", tools=[])


MOUNTINFO = """\
600 500 0:52 / / rw,relatime master:1 - overlay overlay rw
601 600 0:55 / /proc rw,nosuid - proc proc rw
602 600 0:56 / /dev rw,nosuid - tmpfs tmpfs rw
603 602 0:57 / /dev/shm rw - tmpfs shm rw
610 600 8:1 /home/me/out /out rw,relatime - ext4 /dev/sda1 rw
611 600 8:1 /var/lib/docker/containers/x/hosts /etc/hosts rw - ext4 /dev/sda1 rw
612 600 8:1 /home/me/my\\040dir /data\\040dir rw - ext4 /dev/sda1 rw
"""


def test_mount_points_are_parsed_and_unescaped():
    assert mount_points(MOUNTINFO) == ["/", "/proc", "/dev", "/dev/shm", "/out", "/etc/hosts", "/data dir"]


@pytest.mark.parametrize("path,ok", [
    ("/out", True), ("/out/run-1", True), ("/data dir/x", True),
    ("/tmp/out", False), ("/", False), ("/outside", False), ("/dev/shm/out", False),
])
def test_only_a_mounted_volume_keeps_the_output(path, ok):
    assert on_mounted_volume(path, mount_points(MOUNTINFO)) is ok


def test_in_the_image_an_unmounted_output_directory_is_refused(tmp_path):
    with pytest.raises(OutputDirectoryError, match="not on a mounted volume"):
        prepare_output_dir(tmp_path / "out", require_volume=True, mountinfo=MOUNTINFO)
