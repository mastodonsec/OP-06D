# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static checks of the GitHub Actions workflows: pinned actions, least
privilege, and an auto-close workflow that never touches pull-request code."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).parent.parent / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))


def _load(name: str) -> dict:
    data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    data["on"] = data.pop(True, data.get("on"))  # YAML 1.1 reads the key `on` as True
    return data


def _steps(wf: dict) -> list[dict]:
    return [s for job in wf["jobs"].values() for s in job.get("steps", [])]


def test_the_expected_workflows_exist():
    assert {f.name for f in FILES} == {"ci.yml", "release.yml", "close-external-prs.yml"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_action_is_pinned_by_commit_sha(path):
    uses = re.findall(r"uses:\s*(\S+)", path.read_text(encoding="utf-8"))
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), ref


def test_ci_reads_only_and_never_pushes():
    wf = _load("ci.yml")
    assert wf["permissions"] == {"contents": "read"}
    assert all("permissions" not in job for job in wf["jobs"].values())
    assert set(wf["on"]) == {"pull_request", "push"} and wf["on"]["push"] == {"branches": ["main"]}
    builds = [s for s in _steps(wf) if "build-push-action" in s.get("uses", "")]
    assert builds and all(s["with"]["push"] is False for s in builds)
    platforms = {inc["platform"] for inc in wf["jobs"]["image"]["strategy"]["matrix"]["include"]}
    assert platforms == {"linux/amd64", "linux/arm64"}
    runs = " ".join(s.get("run", "") for s in _steps(wf))
    assert "scripts/check_repo_hygiene.py" in runs and "pytest" in runs and "scripts/check_image.py" in runs
    assert "scripts/update_docker_requirements.py --check" in runs


def test_release_runs_on_tags_and_only_its_job_can_write_and_sign():
    wf = _load("release.yml")
    assert wf["on"] == {"push": {"tags": ["v*"]}}
    assert wf["permissions"] == {"contents": "read"}
    assert wf["jobs"]["release"]["permissions"] == {"contents": "read", "packages": "write", "id-token": "write"}
    build = next(s for s in _steps(wf) if "build-push-action" in s.get("uses", ""))
    assert build["with"]["platforms"] == "linux/amd64,linux/arm64" and build["with"]["sbom"] is True
    assert "-${{ env.TOOLCHAIN_TAG }}" in build["with"]["tags"]
    assert wf["env"]["TOOLCHAIN_TAG"] == "nmap7.93-nuclei3.11.1-tpl10.5.1"
    runs = " ".join(s.get("run", "") for s in _steps(wf))
    assert "cosign sign --yes" in runs and "cosign verify" in runs
    assert "secrets." not in (WORKFLOWS / "release.yml").read_text(encoding="utf-8").replace("secrets.GITHUB_TOKEN", "")


def test_auto_close_never_checks_out_or_runs_pull_request_code():
    wf = _load("close-external-prs.yml")
    assert wf["on"] == {"pull_request_target": {"types": ["opened", "reopened"]}}
    assert wf["permissions"] == {}
    (job,) = wf["jobs"].values()
    assert job["permissions"] == {"pull-requests": "write"}
    steps = job["steps"]
    assert all("run" not in s for s in steps)
    assert [s["uses"].split("@")[0] for s in steps] == ["actions/github-script"]
    text = (WORKFLOWS / "close-external-prs.yml").read_text(encoding="utf-8")
    assert "actions/checkout" not in text.split("name: close-external-prs", 1)[1]
    assert "head.sha" not in text and "head.ref" not in text


def test_auto_close_condition_spares_everyone_with_access_and_bots():
    cond = _load("close-external-prs.yml")["jobs"]["close"]["if"]
    for role in ("OWNER", "MEMBER", "COLLABORATOR"):
        assert f"github.event.pull_request.author_association != '{role}'" in cond
    assert "github.event.pull_request.user.type != 'Bot'" in cond
    assert "!endsWith(github.event.pull_request.user.login, '[bot]')" in cond
    script = _load("close-external-prs.yml")["jobs"]["close"]["steps"][0]["with"]["script"]
    assert "not accepting external pull requests" in script and "AGPL-3.0-or-later" in script
    assert 'state: "closed"' in script
