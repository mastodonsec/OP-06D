# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-35: nuclei: neutralize ambient config + control HOME
RC-24: Lab runbook polish + validation harness

Replay of RUNBOOK Step 11 (hostile ambient ``~/.config/nuclei/config.yaml``),
run by tests/integration/test_lab_rc35.py and lab/validation_harness.py. The
pass/fail judgement on its output is lab/lab_asserts.py's
``ambient_config_failures``.

Runs only *inside* the scanner container (it imports ``op06d`` and runs the
real pinned nuclei). Everything is on the scanner's **loopback only**: three
tiny local servers - PROBE answers 302 to CANARY; CANARY and OAST just log -
so it needs, and makes, no network connection off the box.

    python3 /lab/ambient_config_probe.py

Prints ONE JSON line: ``{"control": {...}, "wrapper": {...}, "controlled": {...}}``

* ``control``    - raw nuclei, hostile ambient config, no wrapper flags. The
                   positive control: it should show the redirect / header /
                   OAST, proving the experiment can detect them.
* ``wrapper``    - ``NucleiTool.run`` exactly as built (always its own
                   ``-config`` + scrubbed ``HOME``/``XDG_CONFIG_HOME``).
                   MUST be clean - this is the row the assertions check.
* ``controlled`` - raw nuclei with only the mitigation applied by hand (an
                   empty ``-config`` + scrubbed ``HOME``), no other wrapper
                   flags: shows the config scrub alone is what neutralizes it.

The hostile config is ALWAYS removed again (``finally``), and the servers die
with this process: nothing lingers in the scanner afterwards.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

PROBE_PORT, CANARY_PORT, OAST_PORT = 18091, 18092, 18093
TARGET = f"http://127.0.0.1:{PROBE_PORT}"

# The exact hostile config from RUNBOOK Step 11b (OAST pointed at loopback).
HOSTILE_CONFIG = (
    f"interactsh-server: 127.0.0.1:{OAST_PORT}\n"
    "no-interactsh: false\n"
    "follow-redirects: true\n"
    "header:\n  - \"X-Hostile-Config: 1\"\n"
)

# The probe template (no template-level redirects - the redirect can only
# come from the ambient config). Used by all three runs.
PROBE_TEMPLATE = (
    "id: rc35-probe\n"
    "info:\n  name: rc35 probe\n  author: lab\n  severity: info\n  tags: tech\n"
    "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
    "    matchers:\n      - type: status\n        status:\n          - 302\n"
)

# Control-only: asks for an interactsh URL so the control can show OAST contact
# against the ambient config's loopback interactsh-server.
OAST_TEMPLATE = (
    "id: rc35-oast-probe\n"
    "info:\n  name: rc35 oast probe\n  author: lab\n  severity: info\n  tags: tech\n"
    "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/?u=http://{{interactsh-url}}\"\n"
    "    matchers:\n      - type: word\n        part: interactsh_protocol\n        words:\n          - dns\n          - http\n"
)

LOG: list[tuple[str, str, str, dict]] = []
_LOG_LOCK = threading.Lock()


def _note(who: str, h: http.server.BaseHTTPRequestHandler) -> None:
    with _LOG_LOCK:
        LOG.append((who, h.command, h.path, dict(h.headers)))


class _Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        _note("PROBE", self)
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.1:{CANARY_PORT}/redirected")
        self.end_headers()

    def log_message(self, *a):  # silence
        pass


class _Canary(http.server.BaseHTTPRequestHandler):
    who = "CANARY"

    def do_GET(self):  # noqa: N802
        _note(self.who, self)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_HEAD = do_GET

    def log_message(self, *a):
        pass


class _Oast(_Canary):
    who = "OAST"


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _observed(since: int) -> dict:
    with _LOG_LOCK:
        entries = LOG[since:]
    who = {e[0] for e in entries}
    headers = {k for e in entries for k in e[3]}
    return {
        "probe_hit": "PROBE" in who,
        "redirect_followed": "CANARY" in who,
        "hostile_header_sent": "X-Hostile-Config" in headers,
        "oast_contacted": "OAST" in who,
    }


def _raw_nuclei(template_dir: str, *, extra: list[str], env: dict | None) -> dict:
    mark = len(LOG)
    argv = ["nuclei", "-u", TARGET, "-t", template_dir, "-jsonl", "-silent", "-no-color",
            "-disable-update-check", *extra]
    p = subprocess.run(argv, capture_output=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
    time.sleep(1)
    row = {"exit": p.returncode, **_observed(mark)}
    row["stderr_tail"] = p.stderr.decode(errors="replace")[-300:].strip()
    return row


def main() -> int:
    for port, handler in ((PROBE_PORT, _Probe), (CANARY_PORT, _Canary), (OAST_PORT, _Oast)):
        threading.Thread(target=_Server(("127.0.0.1", port), handler).serve_forever, daemon=True).start()
    time.sleep(0.5)

    work = tempfile.mkdtemp(prefix="rc35-")
    probe_dir = os.path.join(work, "templates-probe")
    control_dir = os.path.join(work, "templates-control")
    for d, files in ((probe_dir, {"probe.yaml": PROBE_TEMPLATE}),
                     (control_dir, {"probe.yaml": PROBE_TEMPLATE, "oast.yaml": OAST_TEMPLATE})):
        os.makedirs(d)
        for name, body in files.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(body)

    hostile_dir = os.path.expanduser("~/.config/nuclei")
    hostile_path = os.path.join(hostile_dir, "config.yaml")
    os.makedirs(hostile_dir, exist_ok=True)
    with open(hostile_path, "w", encoding="utf-8") as f:
        f.write(HOSTILE_CONFIG)

    result: dict = {}
    try:
        # A. positive control: hostile ambient config, no wrapper flags.
        result["control"] = _raw_nuclei(control_dir, extra=[], env=None)

        # B. the wrapper exactly as built (the row the assertions check).
        from op06d.nuclei_tool import NucleiTool

        mark = len(LOG)
        tool_result = NucleiTool(50, template_dir=probe_dir).run("127.0.0.1", {"port": PROBE_PORT, "scheme": "http"})
        time.sleep(1)
        findings = tool_result.findings if isinstance(tool_result.findings, dict) else {}
        result["wrapper"] = {
            "status": tool_result.status,
            **_observed(mark),
            "out_of_band": findings.get("out_of_band"),
        }

        # C. only the mitigation, by hand: empty -config + scrubbed HOME.
        empty_cfg = os.path.join(work, "empty.yaml")
        open(empty_cfg, "w").close()
        home = os.path.join(work, "home")
        os.makedirs(home)
        env = {"PATH": os.environ["PATH"], "HOME": home, "XDG_CONFIG_HOME": home}
        result["controlled"] = _raw_nuclei(probe_dir, extra=["-config", empty_cfg], env=env)
    finally:
        try:
            os.remove(hostile_path)
        except FileNotFoundError:
            pass
    result["hostile_config_removed"] = not os.path.exists(hostile_path)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
