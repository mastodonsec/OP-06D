# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replay of RUNBOOK Step 11 (hostile ambient ``~/.config/nuclei/config.yaml``),
run by tests/integration/test_lab_nuclei_ambient_config.py and lab/validation_harness.py. The
pass/fail judgement on its output is lab/lab_asserts.py's
``ambient_config_failures``.

Runs only *inside* the scanner container (it imports ``op06d`` and runs the
real pinned nuclei). Everything is on the scanner's **loopback only**: three
tiny local servers - PROBE answers 302 to CANARY; CANARY and OAST just log -
so it needs, and makes, no network connection off the box.

    python3 /lab/ambient_config_probe.py [--json]

Prints one row per run and whether the hostile config was removed. With
``--json`` it prints ONE JSON line instead:
``{"control": {...}, "wrapper": {...}, "controlled": {...}, "proxy_env": {...},
"proxy_env_scrubbed": {...}, "hostile_config_removed": bool}``

* ``control``    - raw nuclei, hostile ambient config, no wrapper flags. The
                   positive control: it should show the redirect / header /
                   OAST, proving the experiment can detect them.
* ``wrapper``    - ``NucleiTool.run`` exactly as built (always its own
                   ``-config`` + scrubbed ``HOME``/``XDG_CONFIG_HOME``).
                   MUST be clean - this is the row the assertions check.
* ``controlled`` - raw nuclei with only the mitigation applied by hand (an
                   empty ``-config`` + scrubbed ``HOME``), no other wrapper
                   flags: shows the config scrub alone is what neutralizes it.
* ``proxy_env``  - the wrapper's argv (with a real empty ``-config``) run with
                   the full environment (``HOME`` scrubbed, so nuclei does not
                   also read the hostile config and exit) plus a hostile
                   ``HTTP_PROXY`` / ``HTTPS_PROXY`` pointed at CANARY: nuclei
                   must not send traffic through it (``proxy_used`` False).
                   Only meaningful if ``probe_hit`` is True.
* ``proxy_env_scrubbed`` - the same with only the scrubbed environment
                   (``PATH``, ``HOME``) plus the same hostile proxy.

The hostile config is ALWAYS removed again (``finally``), and the servers die
with this process: nothing lingers in the scanner afterwards.
"""

from __future__ import annotations

import argparse
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

# The hostile config the runbook's Step 11 shows (OAST pointed at loopback).
HOSTILE_CONFIG = (
    f"interactsh-server: 127.0.0.1:{OAST_PORT}\n"
    "no-interactsh: false\n"
    "follow-redirects: true\n"
    "header:\n  - \"X-Hostile-Config: 1\"\n"
)

# The probe template (no template-level redirects - the redirect can only
# come from the ambient config). Used by all three runs.
PROBE_TEMPLATE = (
    "id: ambient-config-probe\n"
    "info:\n  name: ambient config probe\n  author: lab\n  severity: info\n  tags: tech\n"
    "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
    "    matchers:\n      - type: status\n        status:\n          - 302\n"
)

# Control-only: asks for an interactsh URL so the control can show OAST contact
# against the ambient config's loopback interactsh-server.
OAST_TEMPLATE = (
    "id: ambient-config-oast-probe\n"
    "info:\n  name: ambient config oast probe\n  author: lab\n  severity: info\n  tags: tech\n"
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

    do_POST = do_HEAD = do_CONNECT = do_GET

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


def _run_argv(argv: list[str], env: dict | None) -> dict:
    mark = len(LOG)
    p = subprocess.run(argv, capture_output=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
    time.sleep(1)
    row = {"exit": p.returncode, **_observed(mark)}
    row["stderr_tail"] = p.stderr.decode(errors="replace")[-300:].strip()
    return row


def _raw_nuclei(template_dir: str, *, extra: list[str], env: dict | None) -> dict:
    return _run_argv(["nuclei", "-u", TARGET, "-t", template_dir, "-jsonl", "-silent", "-no-color",
                      "-disable-update-check", *extra], env)


def _proxy_row(row: dict) -> dict:
    """With redirects disabled by the wrapper's flags, a request reaching
    CANARY can only have come through the hostile proxy."""
    return {**row, "proxy_used": row["redirect_followed"]}


def hostile_proxy(port: int = CANARY_PORT) -> dict[str, str]:
    url = f"http://127.0.0.1:{port}"
    return {"HTTP_PROXY": url, "HTTPS_PROXY": url}


def proxy_cases(argv: list[str], full_env: dict[str, str], scrubbed_env: dict[str, str],
                port: int = CANARY_PORT) -> list[tuple[str, list[str], dict[str, str]]]:
    """Runs D and E: the same wrapper argv, each plus a hostile proxy pointed
    at CANARY. D keeps the full environment except ``HOME`` /
    ``XDG_CONFIG_HOME``, which come from the scrubbed one: with the real
    ``HOME`` nuclei also reads the hostile ambient config and exits before
    scanning, so the proxy would never be tested. E has only the scrubbed
    environment."""
    proxy = hostile_proxy(port)
    clean_home = {k: scrubbed_env[k] for k in ("HOME", "XDG_CONFIG_HOME") if k in scrubbed_env}
    return [("proxy_env", list(argv), {**full_env, **clean_home, **proxy}),
            ("proxy_env_scrubbed", list(argv), {**scrubbed_env, **proxy})]


ROWS = (("control", "A. control: raw nuclei, hostile ambient config, no wrapper flags"),
        ("wrapper", "B. wrapper as built (NucleiTool.run)"),
        ("controlled", "C. raw nuclei + empty -config + scrubbed HOME"),
        ("proxy_env", "D. wrapper argv + hostile HTTP_PROXY in the full environment (HOME scrubbed)"),
        ("proxy_env_scrubbed", "E. wrapper argv + scrubbed HOME + the same hostile proxy"))
FIELDS = (("probe_hit", "probe hit"), ("redirect_followed", "redirect followed (CANARY got a request)"),
          ("hostile_header_sent", "hostile header sent"), ("oast_contacted", "oast contacted"),
          ("proxy_used", "traffic through the hostile proxy"))


def format_result(result: dict) -> str:
    lines = []
    for key, label in ROWS:
        row = result.get(key)
        if row is None:
            continue
        head = f"status={row['status']}" if "status" in row else f"exit={row.get('exit')}"
        lines.append(f"--- {label}: {head}")
        for field, text in FIELDS:
            if field in row:
                lines.append(f"    {text + ':':42} {row[field]}")
        if row.get("stderr_tail"):
            lines.append("    stderr tail: " + row["stderr_tail"].replace("\n", " | "))
    lines.append(f"hostile config removed: {result.get('hostile_config_removed')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay the hostile ambient nuclei config experiment.")
    parser.add_argument("--json", action="store_true", help="print one JSON line for the harness and the gated test")
    args = parser.parse_args(argv)

    for port, handler in ((PROBE_PORT, _Probe), (CANARY_PORT, _Canary), (OAST_PORT, _Oast)):
        threading.Thread(target=_Server(("127.0.0.1", port), handler).serve_forever, daemon=True).start()
    time.sleep(0.5)

    work = tempfile.mkdtemp(prefix="ambient-config-")
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

        # D/E. a hostile proxy in the environment, the wrapper's own argv.
        argv = NucleiTool(50, template_dir=probe_dir).build_argv(
            "nuclei", "127.0.0.1", {"port": PROBE_PORT, "scheme": "http"}, config_path=empty_cfg)
        for key, case_argv, case_env in proxy_cases(argv, dict(os.environ), env):
            result[key] = _proxy_row(_run_argv(case_argv, case_env))
    finally:
        try:
            os.remove(hostile_path)
        except FileNotFoundError:
            pass
    result["hostile_config_removed"] = not os.path.exists(hostile_path)
    print(json.dumps(result) if args.json else format_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
