# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-36: gated lab verification of the write-method backstop against the
real pinned v10.5.1 template set - the bundled exclusion list actually
covers every write-method template nuclei has today (the "regenerated and
verified when the set is re-pinned" half of RC-36), and the read-oriented
survivors (query-style POST, GET) are untouched.

NOT part of the default suite: excluded via the `lab` marker and skipped
unless OP06D_LAB=1 is set, or docker/compose is unavailable - same gating
as the other tests/integration/test_lab_rc*.py files.

    OP06D_LAB=1 uv run pytest -m lab tests/integration/test_lab_rc36.py
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.lab

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = ROOT / "lab" / "docker-compose.yml"

sys.path.insert(0, str(ROOT / "lab"))
import lab_stack as stack  # noqa: E402
BUNDLED_EXCLUSIONS = ROOT / "src" / "op06d" / "nuclei_write_method_exclusions.json"

_AUDIT_PROBE = """
import json
from op06d.nuclei_method_audit import find_unexcluded_write_method_templates

with open({exclusions_path!r}, encoding="utf-8") as f:
    excluded = set(json.load(f)["write_method_template_ids"])

offenders = find_unexcluded_write_method_templates("/opt/nuclei-templates", excluded)
print(json.dumps({{"offenders": offenders, "excluded_count": len(excluded)}}))
"""


def _require_lab_enabled() -> None:
    if os.environ.get("OP06D_LAB") != "1":
        pytest.skip("set OP06D_LAB=1 to run the gated lab check (RC-36)")


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is not available")
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "config"],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker compose could not be invoked")
    if r.returncode != 0:
        pytest.skip(f"docker compose is not available or the compose file is invalid: {r.stderr!r}")


def _compose(*args: str, timeout: float = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
    )


def _exec(*args: str, timeout: float = 180) -> subprocess.CompletedProcess:
    return _compose("exec", "-T", *args, timeout=timeout)


@pytest.fixture(scope="module")
def lab_stack():
    _require_lab_enabled()
    _require_docker()
    with stack.lab_stack(_compose):
        time.sleep(3)  # the scanner container itself needs no app targets for this check
        yield


def test_bundled_exclusion_list_covers_every_write_method_template_in_the_pinned_set(lab_stack):
    """The real "regenerated and verified when the set is re-pinned" check:
    if this ever fails, the bundled nuclei_write_method_exclusions.json is
    stale against the lab's pinned template set and must be regenerated
    (scripts/generate_nuclei_write_method_exclusions.py)."""
    probe = _AUDIT_PROBE.format(exclusions_path="/op06d/src/op06d/nuclei_write_method_exclusions.json")
    r = _exec("scanner", "python3", "-c", probe, timeout=120)
    assert r.returncode == 0, f"probe failed:\n{r.stdout}\n{r.stderr}"
    result = json.loads(r.stdout.strip().splitlines()[-1])
    assert result["offenders"] == [], (
        f"write-method template(s) not covered by the bundled exclusion list: {result['offenders']} "
        "- regenerate it with scripts/generate_nuclei_write_method_exclusions.py"
    )
    assert result["excluded_count"] == len(
        json.loads(BUNDLED_EXCLUSIONS.read_text())["write_method_template_ids"],
    )


# One parameterized template-listing probe, using the REAL build_argv but
# with a REAL empty -config file (build_argv's own no-I/O placeholder path
# does not exist on disk, and nuclei fatals on a missing -config - an early
# version of this test passed vacuously because of exactly that). Every
# caller asserts nuclei's own returncode == 0, so a listing of 0 templates
# can only mean "excluded", never "nuclei refused to start".
_LIST_PROBE = """
import json, subprocess, tempfile, os
from op06d.nuclei_tool import NucleiTool

extra = json.loads({extra!r})
strip = set(json.loads({strip!r}))  # flags to drop together with their value

with tempfile.TemporaryDirectory() as home:
    cfg = os.path.join(home, "config.yaml")
    open(cfg, "w").close()
    t = NucleiTool(50, template_dir="/opt/nuclei-templates")
    argv = t.build_argv("nuclei", "172.31.77.11", {{}}, config_path=cfg)
    clean, skip_next = [], False
    for a in argv:
        if skip_next:
            skip_next = False
            continue
        if a in strip:
            skip_next = True
            continue
        if a in ("-jsonl", "-silent", "-stats", "-stats-json"):
            continue
        clean.append(a)
    clean += extra + ["-tl"]
    env = {{"PATH": os.environ["PATH"], "HOME": home, "XDG_CONFIG_HOME": home}}
    p = subprocess.run(clean, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120, env=env)
    lines = [l for l in p.stdout.splitlines() if l.strip().startswith("/")]
    print(json.dumps({{"returncode": p.returncode, "count": len(lines),
                      "stderr_tail": p.stderr[-300:]}}))
"""


def _list(extra=(), strip=()) -> dict:
    probe = _LIST_PROBE.format(extra=json.dumps(list(extra)), strip=json.dumps(list(strip)))
    r = _exec("scanner", "python3", "-c", probe, timeout=150)
    assert r.returncode == 0, f"probe crashed:\n{r.stdout}\n{r.stderr}"
    result = json.loads(r.stdout.strip().splitlines()[-1])
    assert result["returncode"] == 0, f"nuclei itself failed: {result['stderr_tail']}"
    return result


def test_real_nuclei_actually_excludes_a_known_write_method_template(lab_stack):
    """-eid itself really excludes, not just "is accepted".

    The tag filters are stripped in BOTH arms: a known write-method template
    like put-method-enabled also carries a danger tag, so the default
    -exclude-tags already drops it - which is exactly the tag-dependent
    accident RC-36 replaces. With the tag filters out of the picture, -eid
    is the only thing that can exclude it. Positive control first (no -eid
    -> exactly 1 template listed), so the 0 means "excluded by -eid", not
    "typo'd id" or "nuclei never started"."""
    known_id = "put-method-enabled"
    no_tag_filters = ["-tags", "-exclude-tags"]
    control = _list(extra=["-id", known_id], strip=no_tag_filters + ["-eid"])
    assert control["count"] == 1, "positive control failed - the probe can't see the template at all"

    with_backstop = _list(extra=["-id", known_id], strip=no_tag_filters)
    assert with_backstop["count"] == 0  # only -eid stands in the way, and it holds


def test_read_oriented_survivors_remain_selectable_with_the_backstop_in_place(lab_stack):
    """The default (tag-based) selection's template count is identical with
    and without the -eid list: none of the 69 write-method ids were among
    the default-tag survivors (they all also carry a danger tag
    -exclude-tags already drops), so the structural backstop removes
    nothing that wasn't already excluded - the read-oriented survivor class
    (query-style POST, GET) is untouched."""
    with_backstop = _list()
    without_backstop = _list(strip=["-eid"])
    assert with_backstop["count"] > 0
    assert with_backstop["count"] == without_backstop["count"], (
        "the write-method backstop removed a template from the default pass that "
        "wasn't already excluded by tags - check for a false-positive detection"
    )
