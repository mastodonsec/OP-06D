# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-35: gated lab replay of RUNBOOK Step 11 - a hostile ambient
~/.config/nuclei/config.yaml must not be able to re-enable redirects, inject
a header, re-enable out-of-band, or crash the scan, now that the wrapper
always passes its own -config and scrubs HOME/XDG_CONFIG_HOME.

NOT part of the default suite: excluded via the `lab` marker and skipped
unless REDCELL_LAB=1 is set, or docker/compose is unavailable - same gating
as the other tests/integration/test_lab_rc*.py files.

    REDCELL_LAB=1 uv run pytest -m lab tests/integration/test_lab_rc35.py
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.lab

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = ROOT / "lab" / "docker-compose.yml"

# Three tiny loopback-only servers, as in RUNBOOK Step 11a: PROBE answers 302
# to CANARY; CANARY and OAST just log. The hostile ambient config (11b) asks
# nuclei to follow that redirect, send a hostile header, and contact OAST as
# an interactsh server - none of which must happen once the fix is in place.
_SETUP_AND_PROBE = r"""
import http.server, json, os, socketserver, threading, time

LOG = []

def note(who, h):
    LOG.append((who, h.command, h.path, dict(h.headers)))

class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        note("PROBE", self)
        self.send_response(302); self.send_header("Location", "http://127.0.0.1:18092/redirected"); self.end_headers()
    log_message = lambda *a: None

class Canary(http.server.BaseHTTPRequestHandler):
    who = "CANARY"
    def do_GET(self):
        note(self.who, self); self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    do_POST = do_HEAD = do_GET
    log_message = lambda *a: None

class Oast(Canary):
    who = "OAST"

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

for port, h in ((18091, Probe), (18092, Canary), (18093, Oast)):
    threading.Thread(target=S(("127.0.0.1", port), h).serve_forever, daemon=True).start()
time.sleep(0.5)

TEMPLATES = "/tmp/rc35-templates"
os.makedirs(TEMPLATES, exist_ok=True)
with open(f"{TEMPLATES}/probe.yaml", "w") as f:
    f.write(
        "id: rc35-probe\n"
        "info:\n  name: rc35 probe\n  author: lab\n  severity: info\n  tags: tech\n"
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
        "    matchers:\n      - type: status\n        status:\n          - 302\n"
    )

HOSTILE_CONFIG_DIR = os.path.expanduser("~/.config/nuclei")
os.makedirs(HOSTILE_CONFIG_DIR, exist_ok=True)
with open(f"{HOSTILE_CONFIG_DIR}/config.yaml", "w") as f:
    f.write(
        "interactsh-server: 127.0.0.1:18093\n"
        "no-interactsh: false\n"
        "follow-redirects: true\n"
        "header:\n  - \"X-Hostile-Config: 1\"\n"
    )

try:
    from redcell.nuclei_tool import NucleiTool
    tool = NucleiTool(50, template_dir=TEMPLATES)
    result = tool.run("127.0.0.1", {"port": 18091, "scheme": "http"})
    seen_who = {entry[0] for entry in LOG}
    seen_headers = {k: v for entry in LOG for k, v in entry[3].items()}
    print(json.dumps({
        "status": result.status,
        "probe_hit": "PROBE" in seen_who,
        "redirect_followed": "CANARY" in seen_who,
        "hostile_header_sent": "X-Hostile-Config" in seen_headers,
        "oast_contacted": "OAST" in seen_who,
        "out_of_band": result.findings.get("out_of_band") if isinstance(result.findings, dict) else None,
    }))
finally:
    os.remove(f"{HOSTILE_CONFIG_DIR}/config.yaml")
"""


def _require_lab_enabled() -> None:
    if os.environ.get("REDCELL_LAB") != "1":
        pytest.skip("set REDCELL_LAB=1 to run the gated lab check (RC-35)")


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


def _compose(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _exec(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return _compose("exec", "-T", *args, timeout=timeout)


def _wait_for_targets(attempts: int = 30, delay: float = 2.0) -> None:
    for _ in range(attempts):
        j = _exec("scanner", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                   "http://juice-shop.lab:3000/", timeout=15)
        d = _exec("scanner", "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                   "http://dvwa.lab/", timeout=15)
        if j.stdout.strip()[:1] in ("2", "3") and d.stdout.strip()[:1] in ("2", "3"):
            return
        time.sleep(delay)
    pytest.fail("lab targets never came up in time")


@pytest.fixture(scope="module")
def lab_stack():
    _require_lab_enabled()
    _require_docker()
    up = _compose("up", "-d", timeout=180)
    try:
        if up.returncode != 0:
            pytest.fail(f"docker compose up failed:\n{up.stdout}\n{up.stderr}")
        _wait_for_targets()
        iso = _exec("scanner", "bash", "/lab/check_isolation.sh", timeout=120)
        if iso.returncode != 0:
            pytest.fail(f"ABORT: isolation did not PASS, refusing to scan:\n{iso.stdout}\n{iso.stderr}")
        yield
    finally:
        _compose("down", timeout=120)


def test_hostile_ambient_config_cannot_override_the_wrapper_against_real_nuclei(lab_stack):
    r = _exec("scanner", "python3", "-c", _SETUP_AND_PROBE, timeout=60)
    assert r.returncode == 0, f"probe failed:\n{r.stdout}\n{r.stderr}"
    result = json.loads(r.stdout.strip().splitlines()[-1])

    assert result["probe_hit"] is True  # the experiment itself reached the target
    assert result["status"] == "ok"  # no [FTL] redirect-conflict crash
    assert result["redirect_followed"] is False  # -disable-redirects still holds
    assert result["hostile_header_sent"] is False  # the ambient header was never merged in
    assert result["oast_contacted"] is False  # out-of-band stayed off
    assert result["out_of_band"] == "off"
