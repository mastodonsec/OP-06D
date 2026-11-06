# Red Cell lab runbook (RC-19)

The ordered steps **you** perform to stand up the lab, **prove it is isolated**,
validate the nmap and nuclei wrappers against the real tools, and run the whole
chain once. Nothing in this repository executes any of this for you.

> **Written without running anything.** Every command and every "expected" result
> below is unverified. If something differs, that is a finding: send me the output
> and I will adapt the code, the fixtures and these docs.

Run all commands from the repository root (`Z:\git\RedCell`) in
**PowerShell 7** (`pwsh`). Snippets are piped into the container, which needs
UTF-8 handling that Windows PowerShell 5.1 does not do reliably.

```powershell
$LAB = "lab/docker-compose.yml"
```

> **Reading this runbook.** Lines to type are in `powershell` code blocks. When a step also shows what you should see, the expected output follows under an **Expected output:** label, in its own plain block — that block is the result to compare against, never something to run.

---

## The hard rule

**No scan, and no wrapper run against any target, until Step 4 (the isolation
gate) prints PASS in this session.** The lab contains two deliberately vulnerable
applications and a scanner; if the network were quietly routable, the scanner
could reach real systems, which is exactly the harm this project exists to
prevent. Isolation is *proven*, not assumed. Re-run Step 4 at the start of every
session and after any change to `lab/docker-compose.yml` or Docker.

---

## Pinned versions

| Component | Version | Pinned by |
|---|---|---|
| OWASP Juice Shop | 20.3.0 | image digest `sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4` |
| DVWA | `vulnerables/web-dvwa` (unmaintained; no version number) | image digest `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| Scanner base image | `debian:bookworm-slim` | digest `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` |
| **nmap** | **7.93+dfsg1-1** (Debian bookworm package) | exact apt version in `lab/scanner/Dockerfile` |
| **nuclei** | **v3.11.1** | release zip, sha256 `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6` |
| **nuclei-templates** | **v10.5.1** | tag tarball, sha256 `30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb` |
| Python packages (inside the scanner) | pydantic 2.10.6, PyYAML 6.0.2, pytest 7.4.0 | `lab/scanner/requirements.txt` (compare with your host's `pip freeze`) |

The `latest` tag is not used anywhere. Step 5 records what is actually installed.

---

## Topology and how isolation is enforced

```
                         Docker network  rc-lab_labnet   (internal: true, 172.31.77.0/24)
        +---------------------------------------------------------------------------+
        |                                                                           |
        |   scanner  172.31.77.20  ----->  juice-shop 172.31.77.10  :3000           |
        |   (nmap, nuclei,         ----->  dvwa        172.31.77.11  :80            |
        |    red cell code)                                                         |
        +---------------------------------------------------------------------------+
              |  no gateway, no NAT, no published ports, no other network
              X  nothing reaches the internet, the host, or any other network
```

- **One network, declared `internal: true`.** Docker gives an internal network no
  gateway and installs no NAT, so there is no route off it. This is the same
  mechanism for all three containers.
- **Every container is on that network only.** No `network_mode: host`, no
  second network, no `ports:` publishing, no custom DNS, no `extra_hosts`, not
  privileged. (Internal networks are also not reachable from the host, so you
  drive the scanner with `docker compose exec`, not over the network.)
- **The scanner and the targets share the network on purpose.** The scanner must
  reach the targets, so they have to be on the same segment; the *segment* is
  what has no egress. There is no "scanner on a routable network" arrangement
  that would still satisfy the constraint, so there is none.
- **Build is separate from run.** `docker compose build` needs the internet
  (apt, GitHub, PyPI) and runs outside labnet. The running containers never have
  it.
- **Proof, not trust.** Step 4 checks the configuration from the host *and*
  tries to break out from inside, with positive controls so a broken test can't
  look like a pass.
- **The LLM is scripted in the lab.** A real model API needs internet, which the
  lab must not have. The end-to-end run (Step 13) therefore uses a scripted
  planner inside the scanner. Driving the lab with a real LLM would need the
  orchestrator on the host calling the tools through `docker exec`; that harness
  does not exist yet and is out of scope for this step.

---

## Step 0. Preconditions

- Docker Desktop is running (Linux containers / WSL2 engine). `docker info` works.
- About 5 GB free disk (images + templates).
- You are on a network where pulls from Docker Hub and GitHub work. Only the
  **build and pull** steps use the internet.
- Create the captures folder (it is the one writable mount):

```powershell
New-Item -ItemType Directory -Force lab\captures | Out-Null
```

## Step 1. Review before building

Read `lab/docker-compose.yml`, `lab/scanner/Dockerfile` and `lab/engagement.yaml`.
Confirm: one network with `internal: true`; no `ports:` anywhere; no service on a
second network; the digests match the table above. Edit the `window` in
`lab/engagement.yaml` so *now* is inside it (the gate refuses outside it).

Validate the file syntax without starting anything:

```powershell
docker compose -f $LAB config | Out-Null
if ($LASTEXITCODE -eq 0) { "compose file OK" }
```

Expected output:

```
compose file OK
```

## Step 2. Build the scanner image (internet required, outside the lab)

```powershell
docker compose -f $LAB build scanner
```

The build verifies the nuclei zip and the templates tarball against their
SHA-256. If a checksum fails, **stop and investigate** before changing the pin.

## Step 3. Start the stack

```powershell
docker compose -f $LAB up -d
docker compose -f $LAB ps
```

Wait until all three are running (DVWA needs about a minute for its database).
From inside the scanner:

```powershell
docker compose -f $LAB exec -T scanner curl -sS -o /dev/null -w "juice-shop HTTP %{http_code}`n" http://juice-shop.lab:3000/
docker compose -f $LAB exec -T scanner curl -sS -o /dev/null -w "dvwa HTTP %{http_code}`n" http://dvwa.lab/
```

**Step 3b (optional): initialise the DVWA database.** Only needed for the
authenticated DVWA modules (out of the MVP). Browse is not possible (no published
port); do it with curl from the scanner: fetch `/setup.php`, read the
`user_token` hidden field, then POST `create_db=Create / Reset Database` with
that token and the same session cookie. If the page changes, skip this step.

This is lab SETUP, not a scan — it is run directly, not through Red Cell.
Without it, DVWA's / redirects to /setup.php; after it, / redirects to /login.php
(its normal deployed state, which the PLANTED_VULNS baseline assumes). Record "DVWA DB initialized" as a baseline precondition: if the dvwa container
is ever recreated (down/up), the DB resets and this step must be re-run.

``` docker compose -f $LAB exec -T scanner curl -sS -X POST http://dvwa.lab/setup.php --data "create_db=1" -o /dev/null -w "dvwa setup HTTP %{http_code}`n" ```

##### Verify: / should now redirect (302) to /login.php instead of /setup.php
``` docker compose -f $LAB exec -T scanner curl -sS -o /dev/null -w "dvwa / -> HTTP %{http_code}`n" http://dvwa.lab/ ```

## Step 4. ISOLATION GATE (BLOCKING)

**Do not continue unless the following command prints PASS.**

```powershell
pwsh -File lab\check_isolation.ps1 -WithInternetControl
```

What it does:

| Part | Check | Pass means |
|---|---|---|
| A (host) | `docker network inspect rc-lab_labnet` `.Internal` | prints `true` |
| A (host) | each lab container's attached networks | only `rc-lab_labnet` |
| A (host) | each container's published ports / network mode / privileged | none / not host / not privileged |
| Control (host, `-WithInternetControl`) | throwaway container on the **default bridge** requests `https://example.com` | **succeeds**: proves the method can detect connectivity (one outbound request, from a throwaway container, not from the lab) |
| B (scanner) | `lab/check_isolation.sh`: controls inside the lab first (ping, TCP, DNS, curl to the targets must **work**) | controls ok |
| B (scanner) | no default route, one interface in 172.31.77.0/24 | yes |
| B (scanner) | ping, raw TCP, DNS, HTTP(S) to public addresses and names, IPv6, Docker host gateways | **every attempt is expected to FAIL**; each prints `PASS  blocked, as expected` |

The output you want ends with:

```
RESULT: PASS - no egress. Every outbound attempt was blocked and the in-lab controls worked.
RESULT: PASS - lab isolation confirmed (host-side and from inside). You may proceed.
```

| Result | Exit | What to do |
|---|---|---|
| `PASS` | 0 | continue |
| `FAIL ... REACHABLE` | 1 | **STOP.** `docker compose -f $LAB down`. Fix the compose file (network must be `internal: true`; one network only). Do not scan. |
| `INCONCLUSIVE` | 2 | a control failed (stack still starting, or a tool is missing). Wait and rerun; it is not a pass. |

Save the full output as evidence:

```powershell
pwsh -File lab\check_isolation.ps1 -WithInternetControl *>&1 | Tee-Object lab\captures\isolation-check.txt
```

(Optional, extra paranoia: `docker network inspect rc-lab_labnet` and confirm
`"Internal": true`, three entries under `Containers`. IPAM will show a Gateway IP (the .1); that’s normal. What matters is ```Internal: true``` and that the inside-scanner egress test finds no default route and blocks all outbound.)

## Step 5. Record the installed versions

```powershell
docker compose -f $LAB exec -T scanner cat /opt/lab-versions.txt
docker compose -f $LAB exec -T scanner nmap --version
docker compose -f $LAB exec -T scanner nuclei -version
docker image inspect redcell-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1 --format '{{.Id}}'
docker compose -f $LAB images
```

Save to `lab/captures/versions.txt`. Confirm: nmap 7.93, nuclei v3.11.1, templates
v10.5.1. Fill these into `lab/PLANTED_VULNS.md` section 5. (`nuclei -version` may
print to stderr and may mention an update check: note anything it says about
networking.)

## Step 6. Run the project's tests inside the scanner (sanity)

```powershell
docker compose -f $LAB exec -T scanner python3 -m pytest -q -p no:cacheprovider /redcell/tests
```

This proves the pinned Python packages and Python 3.11 run the existing suite.
The repo is mounted read-only; pytest needs `-p no:cacheprovider` for that. If it
fails on versions, align `lab/scanner/requirements.txt` with your host and rebuild.

## Step 7. Flag-name verification (RC-13 / RC-14)

The wrappers pass these flags. The authoritative test is that the **real tool
accepts them and does what they mean**; Step 8 runs every one for real. This step
prints exactly what the wrappers build and does a quick `--help` cross-check.

**7a. Print every command line the wrappers build (nothing is executed):** Copy and paste to the command line.

```powershell
@'
from redcell.nmap_tool import NmapTool, PROFILES
from redcell.nuclei_tool import NucleiTool
from redcell.tools import ProcessResult

seen = []
def cap(argv, timeout):
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
for argv in seen:
    print(" ".join(argv))
'@ | docker compose -f $LAB exec -T scanner python3 -
```

Save to `lab/captures/wrapper-argv.txt`.

**7b. Quick cross-check against `--help` (informational; `--` and a few flags do not appear in help):**

```powershell
docker compose -f $LAB exec -T scanner bash -c 'for f in -oX --no-stylesheet --max-rate --host-timeout -sn -F -sV -p- -A -p --script; do if nmap --help 2>&1 | grep -q -e "$f"; then echo "nmap listed      $f"; else echo "nmap NOT LISTED  $f"; fi; done'
docker compose -f $LAB exec -T scanner bash -c 'for f in -config -u -t -jsonl -silent -no-color -disable-update-check -rate-limit -c -bs -timeout -retries -disable-redirects -no-interactsh -interactsh-server -severity -tags -exclude-tags -id; do if nuclei -h 2>&1 | grep -q -e " $f"; then echo "nuclei listed     $f"; else echo "nuclei NOT LISTED $f"; fi; done'
```

**7c. Record, per flag:** accepted / rejected ("unrecognized option", "flag
provided but not defined") / accepted but renamed or ignored. The flags I am least
sure of are nuclei's `-disable-redirects`, `-no-interactsh`, `-interactsh-server`,
`-exclude-tags`, `-disable-update-check`, `-bs`, `-config`, and nmap's
`--no-stylesheet` and `--host-timeout`. A flag that is "listed" but ignored is
caught by the behavior tests in Step 11.

## Step 8. Real scans and captures (only after Step 4 passed)

This goes through the **gate and the toolbox** (not the raw tools), so the gate,
sanitizer and audit log are exercised as well. The scanner has no network beyond
the lab, and the engagement scopes only the two targets.

**RC-23 (resolve-once):** the two `nuclei` rows target hostnames
(`dvwa.lab`/`juice-shop.lab`), so this run now also exercises the resolve-once
fix end to end - this *is* the RC-23 "lab verification" acceptance check. The
gate resolves each hostname once, pins it (`Gate(..., audit_pin=
log.record_dns_pin)` below records that as a `dns_pinned` audit entry), and
the toolbox hands nuclei the pinned IP, never the hostname; nuclei gets
`-H "Host: <hostname>"` + `-sni <hostname>` so vhost routing still works.
Expect: the findings to still match the frozen baseline (same
swagger-api/owasp-juice-shop-detect/fingerprinthub/tech-detect results - IP+Host
substitution should not change what matches for a docker-DNS vhosted target);
`nuclei_*.findings.json` to carry a `target_hostname` field; and a `dns_pinned`
entry per hostname in the audit log (two total: `dvwa.lab`, `juice-shop.lab`).
The `nmap` rows already target literal IPs, so they are unaffected beyond
`-n` now always being in the argv.

```
@'
import json, pathlib
from redcell.engagement import load_engagement
from redcell.audit import AuditLog, read_log, verify_log
from redcell.gate import Gate
from redcell.tools import GatedToolbox, ToolAction, default_tools

OUT = pathlib.Path("/captures")
eng = load_engagement("/lab/engagement.yaml")
log = AuditLog.for_engagement(eng, OUT / "audit")
tools = default_tools(eng, nuclei_template_dir="/opt/nuclei-templates", nuclei_templates_pin="v10.5.1")
box = GatedToolbox(eng, Gate(eng, audit_pin=log.record_dns_pin), log, tools)

RUNS = [
    ("nmap_juice-shop_service", "nmap",   "172.31.77.10", {"profile": "service", "ports": "3000"}, "xml"),
    ("nmap_dvwa_service",       "nmap",   "172.31.77.11", {"profile": "service", "ports": "80"},   "xml"),
    ("nmap_dvwa_default",       "nmap",   "172.31.77.11", {},                                      "xml"),
    ("nmap_dvwa_safe_scripts",  "nmap",   "172.31.77.11", {"profile": "service", "ports": "80", "scripts": ["safe", "default", "discovery", "version"]}, "xml"),
    ("nuclei_dvwa_default",     "nuclei", "dvwa.lab",     {},                                      "jsonl"),
    ("nuclei_dvwa_exposure",    "nuclei", "dvwa.lab",     {"tags": ["exposure", "misconfig", "config", "panel", "tech"]}, "jsonl"),
    ("nuclei_juice-shop_3000",  "nuclei", "juice-shop.lab", {"port": 3000, "scheme": "http"},      "jsonl"),
]
for i, (name, tool, target, params, ext) in enumerate(RUNS, 1):
    print(f"[{i}/{len(RUNS)}] starting {name} ...", flush=True)
    r = box.execute(ToolAction(tool, target, params), iteration=i)
    print(f"    {name:28} outcome={r.outcome.value:12} status={r.status or '-':18} stage={r.decision.stage} risk={r.risk}", flush=True)
    if not r.executed:
        print("    not run:", r.decision.reason, flush=True)
        continue
    raw = r.raw_output if isinstance(r.raw_output, str) else json.dumps(r.raw_output, indent=2, default=repr)
    (OUT / f"{name}.{ext}").write_text(raw, encoding="utf-8")
    (OUT / f"{name}.findings.json").write_text(json.dumps(r.findings, indent=2, default=repr), encoding="utf-8")
print("audit entries verified:", verify_log(log.path), flush=True)
print("audit log:", log.path, flush=True)
for e in read_log(log.path):
    if e.event == "dns_pinned":
        print(f"    dns_pinned: {e.target} -> {e.parameters.get('resolved_ips')}", flush=True)
'@ | docker compose -f $LAB exec -T scanner python3 -u -
```

Expected: every row `outcome=executed`. The Juice Shop nuclei row now targets
`http://juice-shop.lab:3000` explicitly (RC-14 fix), so it should behave like
the DVWA rows rather than coming back empty. Also expect exactly two
`dns_pinned` lines (`dvwa.lab`, `juice-shop.lab`, each pinned once even
though each hostname is scanned in more than one row - RC-23). Anything `denied`/`declined` is
also informative: send me the printed lines.

Outputs land in `lab/captures/` (raw XML/JSONL, parsed `*.findings.json`, and the
audit log under `lab/captures/audit/`). These are the real fixtures.

## Step 9. Do the parsers handle real output unchanged?
**Purpose.** The parsers (`parse_nmap_xml`, `parse_nuclei_jsonl`) were written and
unit-tested against *hand-written* example files — our best guess at what nmap and
nuclei produce. Step 8 just captured what the real tools *actually* produce. This
step proves the parsers handle the real thing, not just our approximation of it.

**Why it is important.** Real tool output often differs from a hand-written sample in
small ways: extra XML elements (nmap emits a `<hosthint>` block), fields that are
sometimes present and sometimes absent (nuclei's `matcher-name`), or a field that's
a list in reality but was a string in the sample (`info.tags`). Any of those can
make a parser quietly drop data or fail. This step catches that before we trust the
output — it's the bridge from "passes its tests" to "works on reality."

```powershell
@'
import pathlib, json
from redcell.nmap_tool import parse_nmap_xml
from redcell.nuclei_tool import parse_nuclei_jsonl
for p in sorted(pathlib.Path("/captures").glob("nmap_*.xml")):
    try:
        f = parse_nmap_xml(p.read_text(encoding="utf-8"))
        print("OK  ", p.name, "hosts:", len(f["hosts"]), "ports:", [x["port"] for h in f["hosts"] for x in h["ports"]])
    except Exception as e:
        print("FAIL", p.name, type(e).__name__, e)
for p in sorted(pathlib.Path("/captures").glob("nuclei_*.jsonl")):
    findings, bad = parse_nuclei_jsonl(p.read_text(encoding="utf-8"))
    print("OK  " if bad == 0 else "WARN", p.name, "findings:", len(findings), "unparsed lines:", bad)
'@ | docker compose -f $LAB exec -T scanner python3 -
```

Also compare by eye the real files with `tests/fixtures/nmap_service_scan.xml`
and `nuclei_findings.jsonl`: attribute names, `<hosthint>`, `<extraports>`, how
`matched-at`/`host`/`ip` look for a host with a port, `info.tags` as a list or a
string, any fields the parser drops that RC-15 will need.

**Fixtures:** copy the real captures to `tests/fixtures/real/` (keep the names).
**Do not overwrite** the hand-written fixtures yet; send me the captures and I
will switch the tests over and fix any parser differences.

## Step 10. nuclei tag-vocabulary audit

Question: does any tag the wrapper treats as safe (`ACTIVE_TAGS`) pull a template
that is actually intrusive or state-changing? Offline, read-only analysis of the
pinned template set:

```powershell
@'
import pathlib, re, collections, yaml
from redcell.nuclei_tool import ACTIVE_TAGS, INTRUSIVE_TAGS, EXPLOIT_TAGS, DEFAULT_TAGS

ROOT = pathlib.Path("/opt/nuclei-templates")
DANGER = INTRUSIVE_TAGS | EXPLOIT_TAGS
rows = collections.defaultdict(lambda: collections.Counter())
examples = collections.defaultdict(list)

def tags_of(info):
    t = info.get("tags", [])
    if isinstance(t, str):
        t = t.split(",")
    return {str(x).strip().lower() for x in t if str(x).strip()}

for p in ROOT.rglob("*.yaml"):
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        d = yaml.safe_load(text)
    except Exception:
        continue
    if not isinstance(d, dict) or not isinstance(d.get("info"), dict):
        continue
    tags = tags_of(d["info"])
    hit = tags & ACTIVE_TAGS
    if not hit:
        continue
    reasons = []
    if tags & DANGER:
        reasons.append("also-tagged:" + ",".join(sorted(tags & DANGER)))   # the wrapper excludes these via -exclude-tags
    for proto in ("code", "headless", "javascript", "tcp", "dns", "file", "ssl", "whois"):
        if proto in d:
            reasons.append("protocol:" + proto)
    for key in ("http", "requests"):
        for blk in d.get(key) or []:
            if not isinstance(blk, dict):
                continue
            if blk.get("method") and str(blk["method"]).upper() not in ("GET", "HEAD", "OPTIONS"):
                reasons.append("method:" + str(blk["method"]).upper())
            if "fuzzing" in blk or "payloads" in blk or "attack" in blk:
                reasons.append("fuzz/payloads")
            if blk.get("redirects"):
                reasons.append("redirects")
            for raw in blk.get("raw") or []:
                m = re.match(r"\s*(POST|PUT|DELETE|PATCH)\b", str(raw))
                if m:
                    reasons.append("method:" + m.group(1))
    if "interactsh" in text:
        reasons.append("uses-interactsh")
    if str(d["info"].get("severity", "")).lower() in ("high", "critical"):
        reasons.append("severity:" + str(d["info"]["severity"]).lower())
    for t in hit:
        rows[t]["templates"] += 1
        for r in set(reasons):
            rows[t][r.split(":")[0] if r.startswith(("also-tagged", "protocol", "method", "severity")) else r] += 1
            if len(examples[(t, r)]) < 3:
                examples[(t, r)].append(str(p.relative_to(ROOT)))

print("DEFAULT_TAGS (what runs when the planner selects nothing):", DEFAULT_TAGS)
for t in sorted(rows):
    print(f"\n== {t}  ({'DEFAULT' if t in DEFAULT_TAGS else 'optional'})")
    for k, v in sorted(rows[t].items()):
        print(f"   {k:28} {v}")
print("\nExamples of concern (tag, reason -> up to 3 templates):")
for (t, r), ex in sorted(examples.items()):
    if r.startswith(("method:", "fuzz", "protocol:code", "protocol:headless", "protocol:javascript", "uses-interactsh", "redirects")):
        print(f"  [{t}] {r}: {ex}")
'@ | docker compose -f $LAB exec -T scanner python3 -
```

Also list what the **default selection really selects** (check the flag name with
`nuclei -h`; `-tl` is the v3 "list templates" flag as far as I know):

```powershell
docker compose -f $LAB exec -T scanner nuclei -t /opt/nuclei-templates -tags tech,detect,panel,exposure,misconfig,config -exclude-tags cve,kev,vuln,default-login,bruteforce,fuzz,fuzzing,xss,sqli,lfi,rfi,ssrf,rce,ssti,redirect,takeover,auth-bypass,intrusive,oast,dos,exploit -severity info,low,medium,high,critical -tl -disable-update-check | Out-File lab\captures\default-selection-templates.txt
```

**How to judge it.** A tag in `ACTIVE_TAGS` is a problem if templates under the
*default* selection (after `-exclude-tags`) still send non-GET/HEAD requests, use
payloads/fuzzing, use `code`/`headless`/`javascript`, use interactsh, or follow
redirects. Count them, list examples, and send me the output. The fix, if needed,
is to remove or demote the tag, tighten `-exclude-tags`, or exclude by protocol.
(`also-tagged:` rows are already handled by `-exclude-tags`.)

## Step 11. nuclei ambient-config precedence

Question (RC-14 follow-up): can a hostile `~/.config/nuclei` config re-enable
interactsh, redirects or headers despite the wrapper's flags? Everything below is
on the scanner's **loopback only** (three tiny local servers); it needs no network.

**11a. Servers and test templates.** `PROBE` answers 302 to `CANARY`; `CANARY`
and `OAST` just log. Anything that reaches CANARY or OAST, or carries the hostile
header, shows up in `lab/captures/cfgtest-requests.log`.

```powershell
@'
import http.server, socketserver, threading, datetime, sys
LOG = open("/captures/cfgtest-requests.log", "a", buffering=1)
def note(who, h):
    LOG.write(f"{datetime.datetime.utcnow().isoformat()}Z {who} {h.command} {h.path} headers={dict(h.headers)}\n")
class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        note("PROBE", self)
        self.send_response(302); self.send_header("Location", "http://127.0.0.1:18082/redirected"); self.end_headers()
    log_message = lambda *a: None
class Canary(http.server.BaseHTTPRequestHandler):
    who = "CANARY"
    def do_GET(self):
        note(self.who, self); self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    do_POST = do_HEAD = do_CONNECT = do_GET
    log_message = lambda *a: None
class Oast(Canary):
    who = "OAST"
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
for port, h in ((18081, Probe), (18082, Canary), (18083, Oast)):
    threading.Thread(target=S(("127.0.0.1", port), h).serve_forever, daemon=True).start()
threading.Event().wait()
'@ | docker compose -f $LAB exec -T scanner sh -c "mkdir -p /tmp/cfgtest/templates && cat > /tmp/cfgtest/servers.py"

@'
id: cfgtest-redirect-probe
info:
  name: cfgtest redirect probe
  author: lab
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    redirects: true
    max-redirects: 3
    matchers:
      - type: status
        status:
          - 200
'@ | docker compose -f $LAB exec -T scanner sh -c "cat > /tmp/cfgtest/templates/redirect-probe.yaml"

@'
id: cfgtest-oast-probe
info:
  name: cfgtest oast probe
  author: lab
  severity: info
  tags: tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/?u=http://{{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - dns
          - http
'@ | docker compose -f $LAB exec -T scanner sh -c "cat > /tmp/cfgtest/templates/oast-probe.yaml"

docker compose -f $LAB exec -d scanner python3 /tmp/cfgtest/servers.py
```

**11b. The hostile ambient config** (inside the container's `/root`):

```powershell
@'
interactsh-server: 127.0.0.1:18083
no-interactsh: false
follow-redirects: true
header:
  - "X-Hostile-Config: 1"
'@ | docker compose -f $LAB exec -T scanner sh -c "mkdir -p /root/.config/nuclei && cat > /root/.config/nuclei/config.yaml"
```

(The keys mirror nuclei's flag names; if nuclei complains about a key, adjust it
and record that.)

**11c. Control, wrapper-as-built, and wrapper with a controlled config:**

```powershell
@'
import os, subprocess, pathlib, time
from redcell.nuclei_tool import NucleiTool

LOG = pathlib.Path("/captures/cfgtest-requests.log")
pathlib.Path("/tmp/cfgtest/empty.yaml").write_text("", encoding="utf-8")
pathlib.Path("/tmp/cfgtest/home").mkdir(exist_ok=True)

def run(label, argv, env=None):
    LOG.write_text("", encoding="utf-8")
    p = subprocess.run(argv, capture_output=True, timeout=120, env=env, stdin=subprocess.DEVNULL)
    time.sleep(1)
    log = LOG.read_text(encoding="utf-8")
    print(f"--- {label}: exit={p.returncode}")
    print("    probe hit:             ", "PROBE" in log)
    print("    redirect followed (CANARY got a request):", "CANARY" in log)
    print("    hostile header sent:   ", "X-Hostile-Config" in log)
    print("    oast contacted:        ", "OAST" in log)
    print("    stderr tail:", p.stderr.decode(errors="replace")[-300:].strip().replace("\n", " | "))

TARGET = "http://127.0.0.1:18081"
control = ["nuclei", "-u", TARGET, "-t", "/tmp/cfgtest/templates", "-jsonl", "-silent", "-no-color", "-disable-update-check"]
run("A. CONTROL (hostile ambient config, no wrapper flags)", control)

tool = NucleiTool(50, template_dir="/tmp/cfgtest/templates")
argv = tool.build_argv("nuclei", "127.0.0.1", {})
argv[argv.index("-u") + 1] = TARGET          # the wrapper takes hosts only; swap in the loopback URL
run("B. WRAPPER ARGV AS BUILT (ambient config still present)", argv)

argv_c = argv + ["-config", "/tmp/cfgtest/empty.yaml"]
env_c = {"PATH": os.environ["PATH"], "HOME": "/tmp/cfgtest/home"}
run("C. WRAPPER ARGV + controlled -config + scrubbed env", argv_c, env_c)

env_d = dict(os.environ, HTTP_PROXY="http://127.0.0.1:18082", HTTPS_PROXY="http://127.0.0.1:18082")
run("D. WRAPPER ARGV with a hostile HTTP_PROXY in the environment", argv, env_d)
run("E. variant C with the same hostile proxy (does scrubbing help?)", argv_c, dict(env_c, **{k: env_d[k] for k in ("HTTP_PROXY", "HTTPS_PROXY")}))
'@ | docker compose -f $LAB exec -T scanner python3 -
```

**How to read it.**

| Run | Expected if the tool and the wrapper behave | Meaning if not |
|---|---|---|
| A control | redirect followed, header sent, OAST contacted | the experiment can't detect the behaviour; fix the experiment before drawing conclusions |
| B wrapper as built | **no** redirect, **no** hostile header, **no** OAST | if the header or OAST appears, the ambient config **does** override the wrapper: a real finding |
| C controlled config | clean | shows what the wrapper must do (always pass its own `-config`, run with a scrubbed environment) |
| D hostile proxy env | probably traffic goes via the proxy | the wrapper does not scrub the environment today: a real gap if it does |

I expect B or D to show a gap: the wrapper currently passes `-config` only when
`config_path` is set, and it does not scrub the environment. If so, the fix
(always pass a controlled `-config`, scrub env, `-disable-redirects` check) is
mine to write once I see your output.

**11d. Clean up** (important: the hostile config must not linger):

```powershell
docker compose -f $LAB exec -T scanner sh -c "rm -f /root/.config/nuclei/config.yaml; pkill -f servers.py; rm -rf /tmp/cfgtest"
```

## Step 12. nmap privilege behavior

Which profiles and scripts need root, and what the wrapper does without it.
Runs only the profiles (and read-only analysis of scripts), against the lab
target, as root and as the unprivileged `scanner` user:

```powershell
$privprobe = @'
import re, os
from redcell.nmap_tool import NmapTool, PROFILES
t = NmapTool(50)
print("uid:", os.getuid())
for prof in PROFILES:
    r = t.run("172.31.77.11", {"profile": prof})
    raw = r.raw if isinstance(r.raw, str) else ""
    m = re.search(r'<scaninfo type="(\w+)"', raw)
    err = r.findings.get("error", {}).get("message", "") if isinstance(r.findings, dict) else ""
    print(f"{prof:11} status={r.status:18} scan-type={m.group(1) if m else '-':8} {err[:150]}")
'@
"=== as root ===";            $privprobe | docker compose -f $LAB exec -T scanner python3 -
"=== as scanner (unprivileged) ==="; $privprobe | docker compose -f $LAB exec -u scanner -T scanner python3 -
```

Record, for each profile, root vs unprivileged: works? `syn` vs `connect` scan
type? error text? What I expect from nmap's documentation (verify): `ping`,
`quick`, `default`, `service`, `full` still work unprivileged using a TCP
connect scan; `aggressive` (`-A`, which includes OS detection) fails without
root with a "requires root privileges" error and a non-zero exit, which the
wrapper reports as `nmap_failed`.

Which NSE scripts need raw sockets (read-only, offline):

```powershell
docker compose -f $LAB exec -T scanner sh -c "grep -rl 'is_privileged' /usr/share/nmap/scripts | sed 's#.*/##' | sort | head -100"
```

Document the result in `docs/nmap-tool.md` (I will do this from your output).
Also confirm the wrapper returns a structured error, not an exception, when nmap
exits non-zero.

## Step 13. End to end: engagement -> loop -> gate -> real tools -> sanitize -> audit

A scripted planner (no LLM, no network) drives the real orchestrator against the
lab. It proposes allowed scans, one **out-of-scope** target (must be denied by
the gate), one **intrusive** selection (must be declined: no approver), and then
finishes.

```powershell
@'
import json
from redcell.engagement import load_engagement
from redcell.audit import AuditLog, read_log, verify_log
from redcell.gate import Gate
from redcell.tools import GatedToolbox, default_tools
from redcell.orchestrator import Orchestrator

eng = load_engagement("/lab/engagement.yaml")
log = AuditLog.for_engagement(eng, "/captures/e2e-audit")
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
    act("nmap", "1.1.1.1"),                              # out of scope: the gate must deny
    act("nuclei", "dvwa.lab", tags=["default-login"]),    # INTRUSIVE: no approver -> declined
    json.dumps({"type": "done", "summary": "lab e2e finished"}),
])
result = Orchestrator(eng, llm, box, log, max_iterations=10).run()
print("termination:", result.termination.value, "iterations:", result.iterations)
for s in result.steps:
    d = s.result.decision if s.result else None
    print(f"  step {s.iteration}: {s.kind:14}", (d.stage + ": " + d.reason[:90]) if d else "")
print("audit entries verified:", verify_log(log.path))
for e in read_log(log.path):
    print(f"  #{e.seq:<3} {e.event:16} tool={e.tool or '-':12} target={e.target or '-':18} allowed={e.allowed}  {(e.reason or '')[:70]}")
print("\nWhat the planner saw after the first scan (sanitized, wrapped):\n")
print(llm.seen[1][:1200])
'@ | docker compose -f $LAB exec -T scanner python3 -
```

Expected: `termination: objective_met`; steps `executed`, `executed`, `denied`
(scope), `declined`; every step has audit entries; the planner's view starts with
`<<<UNTRUSTED_TOOL_OUTPUT` and contains parsed findings, **not** raw XML/JSONL;
the raw files are only in the evidence (`result.evidence`), not in the planner's
context. Confirm in the audit log that the out-of-scope attempt produced a
`gate_decision` with `allowed=False` and that **no** `action_executed` exists for
`1.1.1.1`. **RC-23:** confirm exactly one `dns_pinned` entry for `dvwa.lab`
(the two `nuclei ... dvwa.lab` actions, allowed and declined alike, pin the
same hostname once - not twice) and that the `1.1.1.1` nmap action produced
no `dns_pinned` entry at all (it's an IP, nothing to resolve).

Copy `lab/captures/e2e-audit/*.audit.jsonl` somewhere safe: it is a real
end-to-end evidence trail.

## Step 14. Tear down, and what to send back

```powershell
docker compose -f $LAB down
```

(`down -v` is unnecessary; no volumes are used. Images stay cached.)
