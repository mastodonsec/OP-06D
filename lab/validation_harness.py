# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-24: Lab runbook polish + validation harness
RC-28: RC-20 follow-up: make the lab harness teardown idempotent (down-before-up)

One-command lab validation harness. Runs RUNBOOK.md Steps 4-13 against the
live lab in order, captures every step's output into a fresh, timestamped
evidence bundle, and prints a PASS / FAIL / NEEDS-REVIEW summary.

    OP06D_LAB=1 python lab/validation_harness.py [--json <summary-path>] [--keep-stack]

Host-side, Python 3, stdlib only, run from the repository root. Not an op06d
package module on purpose: a lab fixture, like scan_driver.py.

Safety behaviour:

* **Step 4, the isolation gate, is a hard fail-closed blocker.** Host-side
  ``.Internal`` inspect + in-scanner ``check_isolation.sh``, judged by the
  pure ``scan_driver.isolation_failure_reason`` that test_lab_rc20.py uses. Anything but
  a clean PASS - an error, an ambiguity, a non-zero exit - aborts the run
  before anything touches a target. Nothing else runs.
* **Steps 10 and 11 can never PASS on their own.** They are findings-type
  steps: the harness runs and aggregates them and reports NEEDS-REVIEW (or
  FAIL on a definite problem). The go/no-go to scan stays a human decision
  after reading the summary.
* **The stack is cleared before it is brought up** (``docker compose down``
  first, so a stack left running by a killed run does not linger), and is
  always torn down at the end, even on failure or an ``up`` timeout, unless
  ``--keep-stack`` is passed (which skips only the final teardown). See
  ``lab/lab_stack.py``.
* **The engagement window is generated per run.** After the isolation gate,
  ``lab/make_lab_engagement.py`` writes ``<bundle>/engagement.yaml`` from the
  committed ``lab/engagement.yaml`` template with a window around now; Steps
  1w, 8 and 13 use that file. The template is never modified.
* **Nothing frozen is overwritten.** Every output lands under
  ``lab/captures/validation-<UTC-timestamp>/``; the committed
  ``lab/captures/*.findings.json`` and ``tests/integration/baseline.json`` are
  read-only inputs.

Exit codes: 0 = no step FAILed (NEEDS-REVIEW steps still need a human read),
1 = at least one step FAILed or was skipped, 2 = the isolation gate did not
PASS (nothing was scanned), 3 = skipped: ``OP06D_LAB`` unset, no docker, or
an invalid compose file (prints ``RESULT: SKIPPED``; nothing ran).

Code shared with the gated tests: the scan set is
``lab/scan_driver.py``, the baseline + ambient-config assertions are
``lab/lab_asserts.py``, the Step 11 replay is ``lab/ambient_config_probe.py``.
The small docker helpers (``_compose``/``_exec``/``_wait_for_targets``) are
copied from tests/integration/test_lab_rc20.py (they call ``pytest.fail``
there, so they can't be imported into a non-pytest script).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

LAB_DIR = pathlib.Path(__file__).resolve().parent
ROOT = LAB_DIR.parent
COMPOSE_FILE = LAB_DIR / "docker-compose.yml"
NETWORK = "rc-lab_labnet"
SCANNER_IMAGE = "op06d-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1"

sys.path.insert(0, str(LAB_DIR))
import lab_asserts  # noqa: E402
import lab_stack as stack  # noqa: E402
from scan_driver import RUNS, isolation_failure_reason  # noqa: E402

PASS, FAIL, NEEDS_REVIEW, SKIP = "PASS", "FAIL", "NEEDS-REVIEW", "SKIP"
EXIT_OK, EXIT_FAIL, EXIT_ISOLATION, EXIT_SKIPPED = 0, 1, 2, 3

# (step key, label) in run order. "1w" is a preflight, not a runbook step of
# its own: RUNBOOK Step 1 tells the operator to put "now" inside the window.
STEPS: list[tuple[str, str]] = [
    ("4", "isolation"),
    ("1w", "engagement window"),
    ("5", "versions"),
    ("6", "pytest sanity"),
    ("7", "flag argv"),
    ("8", "scans vs baseline"),
    ("9", "parsers"),
    ("10", "tag audit"),
    ("11", "ambient config"),
    ("12", "nmap privilege"),
    ("13", "e2e"),
]
REVIEW_STEPS = frozenset({"10", "11"})  # findings-type: never PASS on their own


@dataclass
class StepResult:
    step: str
    name: str
    status: str
    detail: str = ""
    data: dict = field(default_factory=dict)


# ============================================================================
# Pure decision logic (docker-free; tests/test_validation_harness.py)
# ============================================================================

def classify_isolation(network_internal: str, isolation_exit_code: int) -> StepResult:
    """Fail-closed: PASS only on exactly ``internal == "true"`` AND exit 0."""
    reason = isolation_failure_reason(network_internal, isolation_exit_code)
    if reason is not None:
        return StepResult("4", "isolation", FAIL, reason)
    return StepResult("4", "isolation", PASS, "network internal, check_isolation.sh PASS")


def classify_window(now: dt.datetime, start: dt.datetime, end: dt.datetime) -> StepResult:
    if start <= now < end:
        return StepResult("1w", "engagement window", PASS, f"now inside {start.isoformat()} .. {end.isoformat()}")
    return StepResult(
        "1w", "engagement window", FAIL,
        f"now ({now.isoformat()}) is outside the generated lab window {start.isoformat()} .. {end.isoformat()} - "
        "the gate will deny every scan; check the host/container clock and lab/make_lab_engagement.py",
    )


def parse_versions(lab_versions: str, nmap_out: str, nuclei_out: str) -> dict:
    kv = dict(line.split("=", 1) for line in lab_versions.splitlines() if "=" in line)
    nmap_bin = re.search(r"Nmap version (\S+)", nmap_out)
    nuclei_bin = re.search(r"Engine Version:\s*(v?\d+\.\d+\.\d+)", nuclei_out) or re.search(
        r"\b(v\d+\.\d+\.\d+)\b", nuclei_out)
    nuclei_ver = nuclei_bin.group(1) if nuclei_bin else None
    if nuclei_ver and not nuclei_ver.startswith("v"):
        nuclei_ver = "v" + nuclei_ver
    return {
        "lab_versions": kv,
        "nmap": nmap_bin.group(1) if nmap_bin else None,
        "nuclei": nuclei_ver,
        "templates": kv.get("nuclei-templates"),
    }


def classify_versions(found: dict, pins: dict, template_hash: str | None) -> StepResult:
    problems = []
    if found.get("nmap") != pins["nmap_version"]:
        problems.append(f"nmap {found.get('nmap')!r} != {pins['nmap_version']}")
    if found.get("nuclei") != pins["nuclei_version"]:
        problems.append(f"nuclei {found.get('nuclei')!r} != {pins['nuclei_version']}")
    if found.get("templates") != pins["templates_pin"]:
        problems.append(f"templates {found.get('templates')!r} != {pins['templates_pin']}")
    lab_nmap = found.get("lab_versions", {}).get("nmap", "")
    if not lab_nmap.startswith(pins["nmap_version"]):
        problems.append(f"/opt/lab-versions.txt nmap {lab_nmap!r} disagrees with the pin")
    if not template_hash:
        problems.append("template-set hash could not be computed")
    detail = (f"nmap {found.get('nmap')}, nuclei {found.get('nuclei')}, templates {found.get('templates')}, "
              f"sha256 {template_hash or '?'}")
    if problems:
        return StepResult("5", "versions", FAIL, "; ".join(problems) + f"  ({detail})")
    return StepResult("5", "versions", PASS, detail)


def classify_pytest(exit_code: int, output_tail: str) -> StepResult:
    last = next((ln.strip() for ln in reversed(output_tail.splitlines()) if ln.strip()), "")
    return StepResult("6", "pytest sanity", PASS if exit_code == 0 else FAIL, f"exit {exit_code}: {last[:120]}")


# Step 7: flags every argv of a kind must carry, and flags that must appear
# somewhere across the 7a set (the profile / option-specific ones).
NMAP_EVERY = ("-oX", "--no-stylesheet", "-n", "--max-rate", "--host-timeout", "--")
NMAP_SOMEWHERE = ("-sn", "-F", "-sV", "-p-", "-A", "-p", "--script=")
NUCLEI_EVERY = ("-config", "-u", "-t", "-jsonl", "-silent", "-no-color", "-disable-update-check",
                "-rate-limit", "-c", "-bs", "-timeout", "-retries", "-disable-redirects",
                "-stats", "-eid", "-no-interactsh", "-severity", "-tags", "-exclude-tags")
EXPECTED_NMAP_ARGVS, EXPECTED_NUCLEI_ARGVS = 8, 2  # what the RUNBOOK 7a snippet builds


def _has_flag(argv: list[str], flag: str) -> bool:
    return any(a.startswith(flag) for a in argv) if flag.endswith("=") else flag in argv


def flag_problems(argvs: list[list[str]]) -> list[str]:
    nmap = [a for a in argvs if a and pathlib.PurePosixPath(a[0]).name == "nmap"]
    nuclei = [a for a in argvs if a and pathlib.PurePosixPath(a[0]).name == "nuclei"]
    problems = []
    if len(nmap) != EXPECTED_NMAP_ARGVS:
        problems.append(f"{len(nmap)} nmap argvs built, expected {EXPECTED_NMAP_ARGVS}")
    if len(nuclei) != EXPECTED_NUCLEI_ARGVS:
        problems.append(f"{len(nuclei)} nuclei argvs built, expected {EXPECTED_NUCLEI_ARGVS}")
    for kind, group, every in (("nmap", nmap, NMAP_EVERY), ("nuclei", nuclei, NUCLEI_EVERY)):
        for i, argv in enumerate(group, 1):
            missing = [f for f in every if not _has_flag(argv, f)]
            if missing:
                problems.append(f"{kind} argv #{i} missing {missing}")
    for f in NMAP_SOMEWHERE:
        if not any(_has_flag(a, f) for a in nmap):
            problems.append(f"no nmap argv carries {f}")
    return problems


def classify_flags(argvs: list[list[str]]) -> StepResult:
    problems = flag_problems(argvs)
    if problems:
        return StepResult("7", "flag argv", FAIL, "; ".join(problems))
    return StepResult("7", "flag argv", PASS, f"{len(argvs)} argvs, every expected flag present")


def classify_scans(summary: dict, baseline: dict) -> StepResult:
    try:
        lab_asserts.assert_scan_summary(summary, baseline)
    except lab_asserts.LabAssertionError as exc:
        return StepResult("8", "scans vs baseline", FAIL, str(exc))
    n = len(summary["runs"])
    return StepResult("8", "scans vs baseline", PASS,
                      f"{n}/{n} rows match baseline, dns_pinned ok, templates_loaded>0",
                      {"fingerprint": lab_asserts.fingerprint(summary)})


def classify_parsers(rows: list[dict]) -> StepResult:
    if not rows:
        return StepResult("9", "parsers", FAIL, "no Step 8 captures to parse")
    failed = [r["file"] for r in rows if not r.get("ok")]
    unparsed = [f"{r['file']}({r['unparsed']})" for r in rows if r.get("unparsed")]
    if failed or unparsed:
        return StepResult("9", "parsers", FAIL, f"failed: {failed or '-'}; unparsed lines: {unparsed or '-'}")
    return StepResult("9", "parsers", PASS, f"{len(rows)} files parsed, 0 unparsed lines")


def classify_tag_audit(audit: dict) -> StepResult:
    """Never PASS. FAIL only on a definite problem: a write-method template
    in the default selection that the bundled -eid backstop does not cover
    (not in the bundled -eid list), or an audit that read nothing."""
    if not audit.get("templates_scanned"):
        return StepResult("10", "tag audit", FAIL, "the audit scanned 0 templates")
    unexcluded = audit.get("write_method_unexcluded", [])
    detail = (f"{len(audit.get('non_get', []))} non-GET survivors, {len(audit.get('write_method', []))} write-method, "
              f"{len(unexcluded)} not covered by -eid - see bundle")
    if unexcluded:
        return StepResult("10", "tag audit", FAIL, detail + f"; UNCOVERED: {unexcluded[:5]}")
    return StepResult("10", "tag audit", NEEDS_REVIEW, detail)


AMBIENT_SUBCHECKS = (("redirect", "redirect_followed"), ("header", "hostile_header_sent"),
                     ("OAST", "oast_contacted"))
CLEAN, INCONCLUSIVE = "clean", "INCONCLUSIVE"


def ambient_subchecks(result: dict) -> dict[str, str]:
    """Per sub-check verdict for Step 11. A wrapper row that is clean on a
    behaviour only counts as ``clean`` if the positive control actually
    showed that behaviour; otherwise the detection itself is unproven and the
    sub-check is INCONCLUSIVE - never folded into "wrapper clean"."""
    wrapper, control = result.get("wrapper", {}), result.get("control", {})
    out = {}
    for label, key in AMBIENT_SUBCHECKS:
        if wrapper.get(key) is not False:
            out[label] = f"{FAIL} (wrapper-as-built showed it)"
        elif control.get(key) is True:
            out[label] = f"{CLEAN} (control detected it, wrapper did not)"
        else:
            out[label] = f"{INCONCLUSIVE} (control did not reach {label} - detection not proven)"
    return out


def classify_ambient(result: dict) -> StepResult:
    """Never PASS. FAIL if the wrapper-as-built run shows redirect / header /
    OAST / crash (lab_asserts.ambient_config_failures - the same judgement
    test_lab_rc35.py makes) or the hostile config lingered. Otherwise
    NEEDS-REVIEW, with each sub-check reported on its own: one the control
    could not demonstrate is INCONCLUSIVE, not clean."""
    wrapper = result.get("wrapper", {})
    problems = lab_asserts.ambient_config_failures(wrapper)
    if result.get("hostile_config_removed") is not True:
        problems.append("the hostile ~/.config/nuclei/config.yaml was not removed")
    subs = ambient_subchecks(result)
    if problems:
        return StepResult("11", "ambient config", FAIL, "; ".join(problems), {"subchecks": subs})
    detail = "; ".join(f"{k}: {v}" for k, v in subs.items())
    return StepResult("11", "ambient config", NEEDS_REVIEW, f"{detail}; see table", {"subchecks": subs})


def priv_problems(rows: dict[str, list[dict]], profiles: list[str]) -> list[str]:
    problems = []
    for mode, prof_rows in rows.items():
        seen = {r.get("profile") for r in prof_rows}
        for missing in sorted(set(profiles) - seen):
            problems.append(f"{mode}: profile {missing} returned nothing")
        for r in prof_rows:
            status = r.get("status")
            if not isinstance(status, str) or not status:
                problems.append(f"{mode}: {r.get('profile')} has no structured status")
            elif status == "wrapper_error" or r.get("traceback"):
                problems.append(f"{mode}: {r.get('profile')} status={status} {r.get('error', '')[:80]}")
    return problems


def classify_priv(rows: dict[str, list[dict]], profiles: list[str], tracebacks: list[str]) -> StepResult:
    problems = priv_problems(rows, profiles) + [f"traceback in {m}" for m in tracebacks]
    if problems:
        return StepResult("12", "nmap privilege", FAIL, "; ".join(problems))
    degraded = sorted({f"{m}:{r['profile']}" for m, rs in rows.items() for r in rs if r.get("degraded")})
    return StepResult("12", "nmap privilege", PASS,
                      f"{len(profiles)} profiles x {len(rows)} modes structured; degraded: {degraded or '-'}")


E2E_EXPECTED_KINDS = ["executed", "executed", "denied", "declined"]


def e2e_problems(r: dict) -> list[str]:
    problems = []
    if r.get("termination") != "objective_met":
        problems.append(f"termination {r.get('termination')!r} != 'objective_met'")
    kinds = [s["kind"] for s in r.get("steps", []) if s["kind"] != "done"]
    if kinds != E2E_EXPECTED_KINDS:
        problems.append(f"step kinds {kinds} != {E2E_EXPECTED_KINDS}")
    if not r.get("audit_verified"):
        problems.append("audit log did not verify / is empty")
    if not r.get("denied_out_of_scope"):
        problems.append("no gate_decision allowed=False for 1.1.1.1")
    if r.get("executed_out_of_scope"):
        problems.append("an action_executed exists for 1.1.1.1")
    pins = r.get("dns_pinned", [])
    if pins.count("dvwa.lab") != 1:
        problems.append(f"dns_pinned for dvwa.lab x{pins.count('dvwa.lab')} (expected exactly 1)")
    if "1.1.1.1" in pins:
        problems.append("1.1.1.1 produced a dns_pinned entry")
    if not r.get("planner_view_wrapped"):
        problems.append("planner's view is not wrapped in a matching <<<UNTRUSTED_TOOL_OUTPUT ... END>>> block")
    if r.get("planner_view_has_raw_xml") is not False:
        problems.append("raw nmap XML reached the planner's view (or the check did not run)")
    return problems


def classify_e2e(r: dict) -> StepResult:
    problems = e2e_problems(r)
    if problems:
        return StepResult("13", "e2e", FAIL, "; ".join(problems))
    return StepResult("13", "e2e", PASS,
                      f"objective_met; executed,executed,denied,declined; {r['audit_verified']} audit entries verified")


def skipped(reason: str, after: str = "4") -> list[StepResult]:
    keys = [k for k, _ in STEPS]
    return [StepResult(k, n, SKIP, reason) for k, n in STEPS[keys.index(after) + 1:]]


def overall(results: list[StepResult]) -> tuple[int, str]:
    """The run's exit code and final line. NEEDS-REVIEW never fails the run
    but is never reported as a clean PASS either; the go/no-go stays human."""
    by_step = {r.step: r for r in results}
    iso = by_step.get("4")
    if iso is None or iso.status != PASS:
        return EXIT_ISOLATION, "RESULT: FAIL - isolation gate did not PASS; nothing was scanned. Do not scan."
    failed = [r.step for r in results if r.status == FAIL]
    if failed:
        return EXIT_FAIL, f"RESULT: FAIL (step {', '.join(failed)}) - do not scan until fixed"
    skips = [r.step for r in results if r.status == SKIP]
    if skips:
        return EXIT_FAIL, f"RESULT: FAIL - incomplete run (step {', '.join(skips)} skipped)"
    review = [r.step for r in results if r.status == NEEDS_REVIEW]
    if review:
        return EXIT_OK, (f"RESULT: PASS, needs human review of steps {'/'.join(review)} before scanning "
                         "- the go/no-go is yours")
    return EXIT_OK, "RESULT: PASS"


def format_report(results: list[StepResult], started: str, final_line: str) -> str:
    lines = [f"=== OP-06D lab validation (RC-24) {started} ==="]
    for r in results:
        label = f"Step {r.step:<3}{r.name} "
        lines.append(f"{label:.<30} {r.status}" + (f"  ({r.detail})" if r.detail else ""))
    lines.append(final_line)
    return "\n".join(lines)


# ============================================================================
# In-container snippets (piped to `python3 -` in the scanner, like the runbook)
# ============================================================================

SNIPPET_WINDOW = r"""
import json, datetime, sys
from op06d.engagement import load_engagement
w = load_engagement(sys.argv[1]).authorization.window
print(json.dumps({"start": w[0].isoformat(), "end": w[1].isoformat(),
                  "now": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
"""

# sha256 over sorted (relative path, NUL, sha256(content)) of every file in the
# pinned template tree: stable, order-independent of the filesystem.
SNIPPET_TEMPLATE_HASH = r"""
import hashlib, json, pathlib
root = pathlib.Path("/opt/nuclei-templates")
files = sorted((p.relative_to(root).as_posix(), p) for p in root.rglob("*") if p.is_file())
h = hashlib.sha256()
for rel, p in files:
    h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(p.read_bytes()).digest())
print(json.dumps({"sha256": h.hexdigest(), "files": len(files)}))
"""

# RUNBOOK Step 7a, emitting JSON instead of joined strings.
SNIPPET_ARGV = r"""
import json
from op06d.nmap_tool import NmapTool, PROFILES
from op06d.nuclei_tool import NucleiTool
from op06d.tools import ProcessResult
seen = []
def cap(argv, timeout, **kw):  # nuclei's runner is also passed env=
    seen.append(list(argv))
    return ProcessResult(0, b"", b"")
nm = NmapTool(50, runner=cap)
for prof in PROFILES:
    nm.run("172.31.77.11", {"profile": prof})
nm.run("172.31.77.11", {"profile": "service", "ports": "80,443"})
nm.run("172.31.77.11", {"scripts": ["safe", "default", "discovery", "version", "vuln"]})
nu = NucleiTool(50, template_dir="/opt/nuclei-templates", runner=cap)
nu.run("dvwa.lab", {})
nu.run("dvwa.lab", {"tags": ["tech", "cve"], "severity": ["info", "high"]})
print(json.dumps(seen))
"""

# RUNBOOK Step 9 over the Step 8 captures, emitting JSON rows.
SNIPPET_PARSERS = r"""
import json, pathlib, sys
from op06d.nmap_tool import parse_nmap_xml
from op06d.nuclei_tool import parse_nuclei_jsonl
d = pathlib.Path(sys.argv[1])
rows = []
for p in sorted(d.glob("nmap_*.xml")):
    try:
        f = parse_nmap_xml(p.read_text(encoding="utf-8"))
        rows.append({"file": p.name, "ok": True, "unparsed": 0, "hosts": len(f["hosts"]),
                     "ports": [x["port"] for h in f["hosts"] for x in h["ports"]]})
    except Exception as e:
        rows.append({"file": p.name, "ok": False, "unparsed": 0, "error": f"{type(e).__name__}: {e}"})
for p in sorted(d.glob("nuclei_*.jsonl")):
    try:
        findings, bad = parse_nuclei_jsonl(p.read_text(encoding="utf-8"))
        rows.append({"file": p.name, "ok": True, "unparsed": bad, "findings": len(findings)})
    except Exception as e:
        rows.append({"file": p.name, "ok": False, "unparsed": 0, "error": f"{type(e).__name__}: {e}"})
print(json.dumps(rows))
"""

# Step 10: the default selection (DEFAULT_TAGS minus the -exclude-tags the
# wrapper adds) read deterministically from the YAML, as in the RUNBOOK's
# Step 10 audit; counts survivors that send a non-GET request and any
# write-method one the bundled -eid list would miss. Progress on stderr.
SNIPPET_TAG_AUDIT = r"""
import collections, json, pathlib, re, sys, yaml
from op06d.nuclei_tool import DEFAULT_TAGS, INTRUSIVE_TAGS, EXPLOIT_TAGS
from op06d.nuclei_method_audit import template_declares_write_method
ROOT = pathlib.Path("/opt/nuclei-templates")
with open("/op06d/src/op06d/nuclei_write_method_exclusions.json", encoding="utf-8") as f:
    EID = set(json.load(f)["write_method_template_ids"])
default = set(DEFAULT_TAGS)
blocked = (INTRUSIVE_TAGS | EXPLOIT_TAGS) - default
def tags_of(info):
    t = info.get("tags", [])
    if isinstance(t, str):
        t = t.split(",")
    return {str(x).strip().lower() for x in t if str(x).strip()}
files = sorted(ROOT.rglob("*.yaml"))
N = len(files)
survivors, non_get, write, unexcluded = 0, [], [], []
other = collections.Counter()
for i, p in enumerate(files, 1):
    if i % 1000 == 0:
        print(f"[{i}/{N}] scanning templates...", file=sys.stderr, flush=True)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        d = yaml.safe_load(text)
    except Exception:
        continue
    if not isinstance(d, dict) or not isinstance(d.get("info"), dict):
        continue
    tags = tags_of(d["info"])
    if not (tags & default) or (tags & blocked):
        continue
    survivors += 1
    tid, rel = str(d.get("id")), str(p.relative_to(ROOT))
    methods = set()
    for key in ("http", "requests"):
        for blk in d.get(key) or []:
            if not isinstance(blk, dict):
                continue
            if isinstance(blk.get("method"), str):
                methods.add(blk["method"].strip().upper())
            for raw in blk.get("raw") or []:
                s = str(raw).lstrip()
                m = re.match(r"([A-Z]+)\s", s.splitlines()[0]) if s else None
                if m:
                    methods.add(m.group(1))
    ng = sorted(methods - {"GET", "HEAD", "OPTIONS"})
    if ng:
        non_get.append({"id": tid, "path": rel, "methods": ng})
    if template_declares_write_method(d):
        write.append(tid)
        if tid not in EID:
            unexcluded.append(tid)
    for proto in ("code", "headless", "javascript"):
        if proto in d:
            other["protocol:" + proto] += 1
    if "interactsh" in text:
        other["uses-interactsh"] += 1
print(f"scanned {N} templates", file=sys.stderr, flush=True)
print(json.dumps({"templates_scanned": N, "default_survivors": survivors, "non_get": non_get,
                  "non_get_methods": dict(collections.Counter(m for r in non_get for m in r["methods"])),
                  "write_method": write, "write_method_unexcluded": unexcluded, "other": dict(other)}))
"""

# RUNBOOK Step 12's priv-probe, one JSON row per profile.
SNIPPET_PRIV = r"""
import json, os, traceback
from op06d.nmap_tool import NmapTool, PROFILES
t = NmapTool(50)
rows = []
for prof in PROFILES:
    try:
        r = t.run("172.31.77.11", {"profile": prof})
        f = r.findings if isinstance(r.findings, dict) else {}
        rows.append({"profile": prof, "status": r.status,
                     "scan_types": f.get("summary", {}).get("scan_types", []),
                     "degraded": bool(f.get("degraded")),
                     "degraded_capabilities": f.get("degraded_capabilities"),
                     "error": (f.get("error") or {}).get("message", "")})
    except Exception:
        rows.append({"profile": prof, "status": None, "traceback": traceback.format_exc()})
print(json.dumps({"uid": os.getuid(), "profiles": list(PROFILES), "rows": rows}))
"""

# RUNBOOK Step 13, emitting the facts the runbook says to confirm as JSON.
SNIPPET_E2E = r"""
import ast, json, re, sys
from op06d.engagement import load_engagement
from op06d.audit import AuditLog, read_log, verify_log
from op06d.gate import Gate
from op06d.tools import GatedToolbox, default_tools
from op06d.orchestrator import Orchestrator

eng = load_engagement(sys.argv[2])
log = AuditLog.for_engagement(eng, sys.argv[1])
box = GatedToolbox(eng, Gate(eng, audit_pin=log.record_dns_pin), log,
                   default_tools(eng, nuclei_template_dir="/opt/nuclei-templates", nuclei_templates_pin="v10.5.1"))

def act(tool, target, **params):
    return json.dumps({"type": "action", "tool": tool, "target": target, "parameters": params, "reason": "lab e2e"})

class ScriptedLLM:
    def __init__(self, replies): self.replies, self.seen = list(replies), []
    def complete(self, system, messages):
        self.seen.append(messages[-1]["content"])
        return self.replies.pop(0)

llm = ScriptedLLM([
    act("nmap", "172.31.77.11", profile="service", ports="80"),
    act("nuclei", "dvwa.lab"),
    act("nmap", "1.1.1.1"),
    act("nuclei", "dvwa.lab", tags=["default-login"]),
    json.dumps({"type": "done", "summary": "lab e2e finished"}),
])
result = Orchestrator(eng, llm, box, log, max_iterations=10).run()

def plain(v):
    try:
        return ast.literal_eval(v) if isinstance(v, str) else v
    except (ValueError, SyntaxError):
        return v

entries = read_log(log.path)
steps = []
for s in result.steps:
    d = s.result.decision if s.result else None
    steps.append({"iteration": s.iteration, "kind": s.kind,
                  "stage": d.stage if d else None, "reason": (d.reason[:120] if d else None)})
print(json.dumps({
    "termination": result.termination.value,
    "iterations": result.iterations,
    "steps": steps,
    "audit_verified": verify_log(log.path),
    "audit_path": str(log.path),
    "dns_pinned": [plain(e.target) for e in entries if e.event == "dns_pinned"],
    "denied_out_of_scope": any(e.event == "gate_decision" and e.allowed is False and plain(e.target) == "1.1.1.1"
                               for e in entries),
    "executed_out_of_scope": any(e.event == "action_executed" and plain(e.target) == "1.1.1.1" for e in entries),
    # the orchestrator prefixes one "Result of step N ... untrusted data." line,
    # then the sanitizer's block; the tool output must sit inside it, and no
    # raw nmap XML may reach the planner.
    "planner_view_wrapped": len(llm.seen) > 1 and bool(re.search(
        r"^<<<UNTRUSTED_TOOL_OUTPUT id=(\w+) .*?^<<<END_UNTRUSTED_TOOL_OUTPUT id=\1>>>\s*$",
        llm.seen[1], re.S | re.M)),
    "planner_view_has_raw_xml": len(llm.seen) > 1 and ("<?xml" in llm.seen[1] or "<nmaprun" in llm.seen[1]),
    "planner_view_head": llm.seen[1][:1200] if len(llm.seen) > 1 else "",
}))
"""


# ============================================================================
# Docker plumbing (copied from tests/integration/test_lab_rc20.py, minus pytest)
# ============================================================================

def _say(msg: str) -> None:
    print(msg, flush=True)


def _run(cmd: list[str], *, input_text: str | None = None, timeout: float = 120,
         stream: bool = False) -> subprocess.CompletedProcess:
    """subprocess.run, but with ``stream=True`` stderr is relayed live (so a
    long step shows its progress counter) while still being captured."""
    if not stream:
        return subprocess.run(cmd, input=input_text, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace")
    err_lines: list[str] = []

    def pump() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            err_lines.append(line)
            print("      | " + line.rstrip(), flush=True)

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    try:
        out, _ = proc.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    t.join(5)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, "".join(err_lines))


def _compose(*args: str, timeout: float = 120, **kw: Any) -> subprocess.CompletedProcess:
    return _run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], timeout=timeout, **kw)


def _exec(*args: str, timeout: float = 300, user: str | None = None, **kw: Any) -> subprocess.CompletedProcess:
    u = ["-u", user] if user else []
    return _compose("exec", "-T", *u, "scanner", *args, timeout=timeout, **kw)


def _py(snippet: str, *args: str, timeout: float = 300, user: str | None = None,
        stream: bool = False) -> subprocess.CompletedProcess:
    return _exec("python3", "-u", "-", *args, input_text=snippet, timeout=timeout, user=user, stream=stream)


def _wait_for_targets(attempts: int = 30, delay: float = 2.0) -> bool:
    for _ in range(attempts):
        j = _exec("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://juice-shop.lab:3000/", timeout=15)
        d = _exec("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://dvwa.lab/", timeout=15)
        if j.stdout.strip()[:1] in ("2", "3") and d.stdout.strip()[:1] in ("2", "3"):
            return True
        time.sleep(delay)
    return False


def _last_json(cp: subprocess.CompletedProcess) -> Any:
    lines = [ln for ln in cp.stdout.strip().splitlines() if ln.strip()]
    if cp.returncode != 0 or not lines:
        raise RuntimeError(f"exit {cp.returncode}: {(cp.stderr or cp.stdout).strip()[-600:]}")
    return json.loads(lines[-1])


def skip_reason() -> str | None:
    """Same gating as tests/integration/test_lab_rc20.py: OP06D_LAB=1, docker, a valid compose file."""
    if os.environ.get("OP06D_LAB") != "1":
        return "set OP06D_LAB=1 to run the lab validation harness (RC-24)"
    if shutil.which("docker") is None:
        return "docker is not available"
    try:
        r = _compose("config", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "docker compose could not be invoked"
    if r.returncode != 0:
        return f"docker compose is not available or the compose file is invalid: {r.stderr.strip()!r}"
    return None


# ============================================================================
# The steps (docker-backed; each returns a StepResult, captures to the bundle)
# ============================================================================

class Harness:
    def __init__(self, bundle_host: pathlib.Path, bundle_ctr: str, baseline: dict) -> None:
        self.host = bundle_host
        self.ctr = bundle_ctr
        self.baseline = baseline
        self.scans_ctr = f"{bundle_ctr}/step08-scans"
        self.scans_host = bundle_host / "step08-scans"
        self.engagement_ctr = f"{bundle_ctr}/engagement.yaml"  # generated in step1_window
        self.extra: dict = {}

    def capture(self, name: str, *parts: subprocess.CompletedProcess | str) -> None:
        with (self.host / name).open("a", encoding="utf-8", newline="\n") as f:
            for p in parts:
                if isinstance(p, str):
                    f.write(p.rstrip("\n") + "\n")
                    continue
                cmd = p.args if isinstance(p.args, str) else " ".join(map(str, p.args))
                f.write(f"$ {cmd}\n# exit {p.returncode}\n")
                if p.stdout:
                    f.write(p.stdout.rstrip("\n") + "\n")
                if p.stderr:
                    f.write("# --- stderr ---\n" + p.stderr.rstrip("\n") + "\n")
                f.write("\n")

    def step4_isolation(self) -> StepResult:
        inspect = _run(["docker", "network", "inspect", NETWORK, "--format", "{{.Internal}}"], timeout=30)
        internal = inspect.stdout.strip() if inspect.returncode == 0 else "<inspect failed>"
        iso = _exec("bash", "/lab/check_isolation.sh", timeout=180)
        self.capture("step04-isolation.txt", inspect, iso)
        return classify_isolation(internal, iso.returncode)

    def step1_window(self) -> StepResult:
        gen = stack.generate_engagement(_exec, self.engagement_ctr)
        self.capture("step01-window.txt", gen)
        if gen.returncode != 0:
            return StepResult("1w", "engagement window", FAIL,
                              "could not generate the run's engagement from lab/engagement.yaml - see step01-window.txt")
        cp = _py(SNIPPET_WINDOW, self.engagement_ctr, timeout=60)
        self.capture("step01-window.txt", cp)
        w = _last_json(cp)
        return classify_window(*(dt.datetime.fromisoformat(w[k]) for k in ("now", "start", "end")))

    def step5_versions(self) -> StepResult:
        lv = _exec("cat", "/opt/lab-versions.txt", timeout=30)
        nm = _exec("nmap", "--version", timeout=30)
        nu = _exec("nuclei", "-version", "-disable-update-check", timeout=60)
        img = _run(["docker", "image", "inspect", SCANNER_IMAGE, "--format", "{{.Id}}"], timeout=30)
        imgs = _compose("images", timeout=60)
        th = _py(SNIPPET_TEMPLATE_HASH, timeout=600)
        self.capture("step05-versions.txt", lv, nm, nu, img, imgs, th)
        (self.host / "versions.txt").write_text(
            lv.stdout + "\n" + nm.stdout + "\n" + nu.stdout + nu.stderr + "\nimage " + img.stdout,
            encoding="utf-8", newline="\n")
        try:
            th_json = _last_json(th)
        except (RuntimeError, ValueError):
            th_json = {}
        tpl_hash = th_json.get("sha256")
        (self.host / "template-set.sha256").write_text(
            f"{tpl_hash or 'UNAVAILABLE'}  /opt/nuclei-templates ({th_json.get('files', '?')} files; "
            "sha256 over sorted relpath+NUL+sha256(content))\n", encoding="utf-8", newline="\n")
        found = parse_versions(lv.stdout, nm.stdout, nu.stdout + nu.stderr)
        self.extra["versions"] = {**found, "template_set_sha256": tpl_hash,
                                  "template_files": th_json.get("files"), "image_id": img.stdout.strip()}
        return classify_versions(found, self.baseline["pins"], tpl_hash)

    def step6_pytest(self) -> StepResult:
        cp = _exec("python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "/op06d/tests", timeout=900)
        self.capture("step06-pytest.txt", cp)
        return classify_pytest(cp.returncode, cp.stdout + cp.stderr)

    def step7_flags(self) -> StepResult:
        cp = _py(SNIPPET_ARGV, timeout=120)
        self.capture("step07-argv.txt", cp)
        return classify_flags(_last_json(cp))

    def step8_scans(self) -> StepResult:
        summary_ctr = f"{self.scans_ctr}/summary.json"
        cp = _exec("python3", "-u", "/lab/scan_driver.py", self.scans_ctr, "--json", summary_ctr,
                   "--engagement", self.engagement_ctr, timeout=1800, stream=True)
        self.capture("step08-scans.txt", cp)
        if cp.returncode != 0:
            return StepResult("8", "scans vs baseline", FAIL, f"scan_driver.py exit {cp.returncode}")
        summary = json.loads((self.scans_host / "summary.json").read_text(encoding="utf-8"))
        return classify_scans(summary, self.baseline)

    def step9_parsers(self) -> StepResult:
        cp = _py(SNIPPET_PARSERS, self.scans_ctr, timeout=120)
        self.capture("step09-parsers.txt", cp)
        return classify_parsers(_last_json(cp))

    def step10_tag_audit(self) -> StepResult:
        cp = _py(SNIPPET_TAG_AUDIT, timeout=1200, stream=True)
        self.capture("step10-tag-audit.txt", cp)
        audit = _last_json(cp)
        (self.host / "step10-tag-audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
        result = classify_tag_audit(audit)
        examples = [f"{r['id']} {r['methods']}" for r in audit.get("non_get", [])[:5]]
        result.data = {"default_survivors": audit.get("default_survivors"),
                       "non_get_count": len(audit.get("non_get", [])),
                       "non_get_methods": audit.get("non_get_methods"),
                       "write_method_count": len(audit.get("write_method", [])),
                       "write_method_unexcluded": audit.get("write_method_unexcluded"),
                       "examples": examples}
        return result

    def step11_ambient(self) -> StepResult:
        try:
            cp = _exec("python3", "/lab/ambient_config_probe.py", timeout=420)
            self.capture("step11-ambient-config.txt", cp)
            result = _last_json(cp)
        finally:
            # belt and braces: the hostile config must never linger
            rm = _exec("sh", "-c", "rm -f /root/.config/nuclei/config.yaml; "
                                   "test ! -e /root/.config/nuclei/config.yaml && echo 'hostile config absent'",
                       timeout=30)
            self.capture("step11-ambient-config.txt", rm)
        (self.host / "step11-ambient-config.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        verdict = classify_ambient(result)
        if rm.returncode != 0 and verdict.status != FAIL:
            verdict = StepResult("11", "ambient config", FAIL, "could not confirm the hostile config was removed")
        verdict.data["table"] = {k: result.get(k) for k in ("control", "wrapper", "controlled")}
        return verdict

    def step12_priv(self) -> StepResult:
        rows: dict[str, list[dict]] = {}
        tracebacks = []
        for mode, user in (("root", None), ("scanner", "scanner")):
            _say(f"      ({mode}: six profiles against dvwa; `full`/`aggressive` can take minutes each)")
            cp = _py(SNIPPET_PRIV, timeout=3600, user=user)
            self.capture("step12-nmap-privilege.txt", f"=== as {mode} ===", cp)
            if "Traceback" in cp.stderr:
                tracebacks.append(mode)
            out = _last_json(cp)
            rows[mode] = out["rows"]
            profiles = out["profiles"]  # the scanner's own PROFILES: every one must report back
        return classify_priv(rows, profiles, tracebacks)

    def step13_e2e(self) -> StepResult:
        cp = _py(SNIPPET_E2E, f"{self.ctr}/step13-e2e-audit", self.engagement_ctr, timeout=1800)
        self.capture("step13-e2e.txt", cp)
        r = _last_json(cp)
        (self.host / "step13-e2e.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        return classify_e2e(r)


def run_steps(h: Harness) -> list[StepResult]:
    """Isolation first, fail-closed; then every other step, each isolated
    from the others' crashes (a harness error in one step is that step's FAIL)."""
    _say("-> Step 4  isolation gate (fail-closed)")
    try:
        iso = h.step4_isolation()
    except Exception as exc:  # any error at the gate is a FAIL, never "probably fine"
        iso = StepResult("4", "isolation", FAIL, f"isolation check errored: {type(exc).__name__}: {exc}")
    _say(f"   {iso.status}  {iso.detail}")
    if iso.status != PASS:
        return [iso, *skipped("isolation gate did not PASS - refusing to run anything else")]

    plan: list[tuple[str, str, Callable[[], StepResult]]] = [
        ("1w", "engagement window (generated for this run)", h.step1_window),
        ("5", "versions + template-set hash", h.step5_versions),
        ("6", "pytest inside the scanner", h.step6_pytest),
        ("7", "wrapper flag argv", h.step7_flags),
        ("8", "real scans vs frozen baseline (a few minutes)", h.step8_scans),
        ("9", "parsers on the Step 8 captures", h.step9_parsers),
        ("10", "tag audit (~14k templates)", h.step10_tag_audit),
        ("11", "ambient-config replay (RC-35)", h.step11_ambient),
        ("12", "nmap privilege (root vs unprivileged; slowest step)", h.step12_priv),
        ("13", "scripted-planner end to end", h.step13_e2e),
    ]
    results = [iso]
    names = dict(STEPS)
    for key, what, fn in plan:
        _say(f"-> Step {key}  {what}")
        try:
            r = fn()
        except Exception as exc:
            r = StepResult(key, names[key], FAIL, f"harness error: {type(exc).__name__}: {exc}"[:400])
        _say(f"   {r.status}  {r.detail}")
        results.append(r)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RC-24 one-command lab validation (RUNBOOK Steps 4-13).")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="also write the machine-readable summary here (it is always in the bundle)")
    parser.add_argument("--keep-stack", action="store_true", help="skip teardown (debugging only)")
    args = parser.parse_args(argv)

    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    started_iso = started.isoformat().replace("+00:00", "Z")

    reason = skip_reason()
    if reason:
        _say(f"=== OP-06D lab validation (RC-24) {started_iso} ===\nRESULT: SKIPPED - {reason}")
        return EXIT_SKIPPED

    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    bundle_host = LAB_DIR / "captures" / f"validation-{stamp}"
    bundle_host.mkdir(parents=True, exist_ok=False)
    h = Harness(bundle_host, f"/captures/validation-{stamp}", lab_asserts.load_baseline())
    _say(f"evidence bundle: {bundle_host}")

    results: list[StepResult]
    _say("-> clearing any leftover lab stack, then bringing the lab up (docker compose down; up -d)")
    try:
        with stack.lab_stack(_compose, keep=args.keep_stack, record=lambda cp: h.capture("stack.txt", cp)):
            if not _wait_for_targets():
                results = [StepResult("4", "isolation", FAIL,
                                      "lab targets never answered HTTP, so the isolation controls cannot run"),
                           *skipped("the targets never came up")]
            else:
                results = run_steps(h)
            _say("-> --keep-stack: leaving the lab running (tear down: docker compose -f lab/docker-compose.yml down)"
                 if args.keep_stack else "-> tearing the lab down")
    except (stack.LabStackError, subprocess.TimeoutExpired) as exc:
        results = [StepResult("4", "isolation", FAIL,
                              f"the stack did not come up ({type(exc).__name__}) - see stack.txt"),
                   *skipped("the stack did not come up")]

    code, final_line = overall(results)
    report = format_report(results, started_iso, final_line)
    summary = {
        "ticket": "RC-24",
        "started": started_iso,
        "bundle": str(bundle_host),
        "exit_code": code,
        "result": final_line,
        "human_review_required": [r.step for r in results if r.status == NEEDS_REVIEW],
        "steps": [asdict(r) for r in results],
        "versions": h.extra.get("versions"),
        "rc20_fingerprint": next((r.data.get("fingerprint") for r in results if r.step == "8"), None),
    }
    text = json.dumps(summary, indent=2, default=repr)
    (bundle_host / "summary.json").write_text(text, encoding="utf-8", newline="\n")
    (bundle_host / "report.txt").write_text(report + "\n", encoding="utf-8", newline="\n")
    if args.json_path:
        pathlib.Path(args.json_path).write_text(text, encoding="utf-8", newline="\n")
    _say("\n" + report)
    _say(f"evidence bundle: {bundle_host}")
    return code


if __name__ == "__main__":
    sys.exit(main())
