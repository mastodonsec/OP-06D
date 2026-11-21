# OP-06D lab runbook

The maintainer's validation reference for the lab: the ordered steps that
stand up the lab, **prove it is isolated**, validate the nmap and nuclei
wrappers against the real, pinned tools, and run the whole chain once. The
steps are run by hand; [Automated runs](#automated-runs) covers the parts
that can be run in one command. The first time you run the lab, start with
the quick start, [lab/README.md](README.md); this runbook is the maintainer's
validation reference.

Related:

- [lab/hosts.md](hosts.md): host setup per platform (Windows, Kali / Linux,
  macOS, ARM).
- [lab/model-relay.md](model-relay.md): the opt-in model relay for
  `op06d run --planner llm` in the lab.
- [lab/benchmark.md](benchmark.md): the opt-in planner model benchmark.

Run all commands from the repository root. **Shells:** `powershell` blocks are
for **PowerShell 7** (`pwsh`); snippets are piped into the container, which
needs UTF-8 handling that Windows PowerShell 5.1 does not do reliably. `bash`
blocks (for Linux and macOS) are for bash or zsh; for the
`docker compose -f $LAB ...` lines in the PowerShell blocks, see
[Running the runbook from bash or zsh](hosts.md#running-the-runbook-from-bash-or-zsh).

PowerShell 7:

```powershell
$LAB = "lab/docker-compose.yml"
```

---

## The hard rule

**No scan, and no wrapper run against any target, until Step 4 (the isolation
gate) prints PASS in this session.** The lab contains two deliberately vulnerable
applications and a scanner; if the network were quietly routable, the scanner
could reach real systems, which is exactly the harm this project exists to
prevent. Isolation is *proven*, not assumed. Re-run Step 4 at the start of every
session and after any change to `lab/docker-compose.yml` or Docker.

## Automated runs

**The validation harness** (`lab/validation_harness.py`) runs Steps 5-13
and prints PASS / FAIL / NEEDS-REVIEW per step. The isolation gate (Step 4)
is a fail-closed precondition. Steps 10 and 11 are always NEEDS-REVIEW,
because a person reads them. The harness brings the stack up and tears it
down at the end (`--keep-stack` keeps it). It writes each step's output, the
tool versions, the template-set hash and `summary.json` to a new
`lab/captures/validation-<UTC-timestamp>/` folder. Exit codes: 0 nothing
failed, 1 a step failed or was skipped, 2 the gate did not pass and nothing
was scanned.

PowerShell 7:

```powershell
$env:OP06D_LAB = "1"; python lab/validation_harness.py
```

bash / zsh:

```bash
OP06D_LAB=1 python lab/validation_harness.py
```

**The gated repeatability test**
(`tests/integration/test_lab_repeatability.py`) covers Steps 4, 8 and 9: the
isolation precondition, the real scan set, and comparison with
`tests/integration/baseline.json`. It is not part of the default suite.

PowerShell 7:

```powershell
$env:OP06D_LAB = "1"; uv run pytest -m lab --basetemp .pytest-tmp tests/integration/test_lab_repeatability.py
```

bash / zsh:

```bash
OP06D_LAB=1 uv run pytest -m lab --basetemp .pytest-tmp tests/integration/test_lab_repeatability.py
```

---

## Pinned versions

| Component | Version | Pinned by |
|---|---|---|
| OWASP Juice Shop | 20.3.0 | image digest `sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4` |
| DVWA | `vulnerables/web-dvwa` (unmaintained; no version number) | image digest `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| Scanner base image | `debian:bookworm-slim` | digest `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` |
| **nmap** | **7.93+dfsg1-1** (Debian bookworm package) | exact apt version in the repository `Dockerfile` |
| **nuclei** | **v3.11.1** | release zip per architecture, sha256 amd64 `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6`, arm64 `8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07` (from the release's `nuclei_3.11.1_checksums.txt`) |
| **nuclei-templates** | **v10.5.1** | tag tarball, sha256 `30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb` |
| Python packages (inside the scanner) | OP-06D's dependencies (incl. anthropic 2.8.0, weasyprint 70.0), plus pytest in the lab stage | `docker/requirements.txt`, `docker/requirements-lab.txt` (hash-pinned, exported from `uv.lock`) |
| Model relay image (model-relay overlay only) | alpine 3.24.4, HAProxy 3.4.7, iptables 1.8.13, socat 1.8.1.3 | digest in `lab/relay/Dockerfile`; package versions recorded in `/opt/relay-versions.txt` |

The `latest` tag is not used anywhere. Step 5 records what is actually installed.

---

## Topology and how isolation is enforced

```
                         Docker network  rc-lab_labnet   (internal: true, 172.31.77.0/24)
        +---------------------------------------------------------------------------+
        |                                                                           |
        |   scanner  172.31.77.20  ----->  juice-shop 172.31.77.10  :3000           |
        |   (nmap, nuclei,         ----->  dvwa        172.31.77.11  :80            |
        |    OP-06D code)          ----->  redirect    172.31.77.12  :80            |
        +---------------------------------------------------------------------------+
              |  no route out, no NAT, no published ports, no other network
              X  nothing reaches the internet, the host, or any other network
```

- **One network, declared `internal: true`.** Docker installs no NAT and gives
  the containers no default route for an internal network, so there is no way
  off it. This is the same mechanism for every container.
- **No gateway address.** labnet also sets
  `com.docker.network.bridge.inhibit_ipv4`, so the bridge holds no address and
  IPAM lists no Gateway. Without it, `172.31.77.1` is an address of the Docker
  host (on native Linux, the host itself): any host service listening on
  `0.0.0.0` (sshd, Ollama, ...) answered from inside the lab. Step 4 probes it,
  and the host-side check requires the option.
- **No IPv6 in the containers.** The bridge still holds an IPv6
  link-local (`fe80::`) address, which reaches host services listening on
  `[::]`. Every lab service sets `net.ipv6.conf.all.disable_ipv6=1` and
  `net.ipv6.conf.default.disable_ipv6=1` in its own network namespace, so no
  container has a link-local address. Step 4 probes the all-nodes address
  `ff02::1` on every interface.
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
- **The LLM is scripted in the base lab.** A real model API needs a route out,
  which the base lab must not have. The end-to-end run (Step 13) therefore uses
  a scripted planner inside the scanner. A run with a real model
  (`op06d run --planner llm`) uses the opt-in model-relay overlay, which
  adds one relay to exactly one upstream and leaves this network unchanged;
  see [lab/model-relay.md](model-relay.md).

---

## Step 0. Preconditions

- The host is set up for your platform (Docker, `uv`): [lab/hosts.md](hosts.md).
- About 5 GB free disk (images + templates).
- You are on a network where pulls from Docker Hub and GitHub work. Only the
  **build and pull** steps use the internet.
- Create the captures folder (it is the one writable mount):

PowerShell 7:

```powershell
New-Item -ItemType Directory -Force lab\captures | Out-Null; "created lab\captures"
```

Expected output:

```
created lab\captures
```

## Step 1. Review before building

Read `lab/docker-compose.yml`, the repository `Dockerfile` (its `lab` stage is the scanner) and `lab/engagement.yaml`.
Confirm: one network with `internal: true`; no `ports:` anywhere; no service on a
second network; the digests match the table above. Do **not** edit the `window`
in `lab/engagement.yaml`: it is a template; this session's copy is generated in
Step 4b.

Validate the file syntax without starting anything:

PowerShell 7:

```powershell
docker compose -f $LAB config | Out-Null
if ($LASTEXITCODE -eq 0) { "compose file OK" }
```

bash / zsh:

```bash
LAB=lab/docker-compose.yml
docker compose -f "$LAB" config > /dev/null && echo "compose file OK"
```

Expected output, in either shell:

```
compose file OK
```

### Mounted code and the installed copy

The scanner is the OP-06D product image (the repository `Dockerfile`) plus the
isolation-check tools and pytest: its `lab` stage. OP-06D is installed in it,
and the lab also mounts the working tree read-only at `/op06d`. The lab stage
sets `PYTHONPATH=/op06d/src`, and Python puts `PYTHONPATH` ahead of the
installed packages, so **the mounted code runs**, not the installed copy.
Check it after Step 3:

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner python3 -c "import op06d; print(op06d.__file__)"
```

Expected output:

```
/op06d/src/op06d/__init__.py
```

**Release validation (the installed copy, no code mount):** set
`OP06D_LAB_CODE` to the empty directory `./installed-only` before Step 3, so
`/op06d` is empty and the import falls back to the installed copy
(`/opt/op06d/lib/python3.11/site-packages/op06d/__init__.py`):

PowerShell 7:

```powershell
$env:OP06D_LAB_CODE = "./installed-only"
```

bash / zsh: `export OP06D_LAB_CODE=./installed-only`. That mode covers the
isolation gate (Step 4), the scans and repeatability check (Step 8 and the
[gated repeatability test](#automated-runs)) and an `op06d run`; steps that read
`/op06d/tests` or `/op06d/src` need the working tree. Unset the variable
afterwards (`Remove-Item Env:OP06D_LAB_CODE` / `unset OP06D_LAB_CODE`).

The scanner runs as root with Docker's default capabilities (`user: "0:0"`),
so the lab's scans are SYN scans; Step 12 compares them with the
unprivileged `scanner` user.

## Step 2. Build the scanner image (internet required, outside the lab)

PowerShell 7:

```powershell
docker compose -f $LAB build scanner
```

The build verifies the nuclei zip and the templates tarball against their
SHA-256. If a checksum fails, **stop and investigate** before changing the pin.

## Step 3. Start the stack

PowerShell 7:

```powershell
docker compose -f $LAB up -d
```

PowerShell 7:

```powershell
docker compose -f $LAB ps
```

Wait until all four (`juice-shop`, `dvwa`, `redirect`, `scanner`) are running (DVWA needs about a minute for its database).
From inside the scanner:

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner curl -sS -o /dev/null -w "juice-shop HTTP %{http_code}`n" http://juice-shop.lab:3000/
```

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner curl -sS -o /dev/null -w "dvwa HTTP %{http_code}`n" http://dvwa.lab/
```

**Step 3b (optional): initialise the DVWA database.** Only needed for the
authenticated DVWA modules (not covered by OP-06D's unauthenticated recon). Browse is not possible (no published
port); do it with curl from the scanner: fetch `/setup.php`, read the
`user_token` hidden field, then POST `create_db=Create / Reset Database` with
that token and the same session cookie. If the page changes, skip this step.

This is lab SETUP, not a scan — it is run directly, not through OP-06D.
Without it, DVWA's / redirects to /setup.php; after it, / redirects to /login.php
(its normal deployed state, which the PLANTED_VULNS baseline assumes). Record "DVWA DB initialized" as a baseline precondition: if the dvwa container
is ever recreated (down/up), the DB resets and this step must be re-run.

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner curl -sS -X POST http://dvwa.lab/setup.php --data "create_db=1" -o /dev/null -w "dvwa setup HTTP %{http_code}`n"
```

Verify that `/` now redirects (302) to `/login.php` instead of `/setup.php`:

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner curl -sS -o /dev/null -w "dvwa / -> HTTP %{http_code}`n" http://dvwa.lab/
```

## Step 4. ISOLATION GATE (BLOCKING)

**Do not continue unless the following command prints PASS.**

PowerShell 7:

```powershell
uv run python lab/check_isolation.py --with-internet-control
```

The same command works in bash and zsh on Linux and macOS.
`pwsh -File lab\check_isolation.ps1 -WithInternetControl` is a thin wrapper
around it (same exit code). The expected services are
read from `lab/docker-compose.yml` (`docker compose config --services`).

What it does:

| Part | Check | Pass means |
|---|---|---|
| A (host) | `docker network inspect rc-lab_labnet` `.Internal` | prints `true` |
| A (host) | `docker network inspect rc-lab_labnet` `.Options` | `com.docker.network.bridge.inhibit_ipv4` is `"true"` |
| A (host) | each lab container's attached networks | only `rc-lab_labnet` |
| A (host) | each container's published ports / network mode / privileged | none / not host / not privileged |
| Control (host, `-WithInternetControl`) | throwaway container on the **default bridge** requests `https://example.com` | **succeeds**: proves the method can detect connectivity (one outbound request, from a throwaway container, not from the lab) |
| B (scanner) | `lab/check_isolation.sh`: controls inside the lab first (ping, TCP, DNS, curl to the targets must **work**) | controls ok |
| B (scanner) | no default route, one interface in 172.31.77.0/24 | yes |
| B (scanner) | ping, raw TCP, DNS, HTTP(S) to public addresses and names, IPv6, Docker host gateways, the labnet gateway `172.31.77.1` (ping; TCP 22, 80, 443, 11434; an ARP reply), a route via any gateway, an IPv6 all-nodes (`ff02::1`) reply from anything but a lab container, and TCP 22/80/443/11434 to any such responder | **every attempt is expected to FAIL**; each prints `PASS  blocked, as expected` |

The output you want ends with:

```
RESULT: PASS - no egress. Every outbound attempt was blocked and the in-lab controls worked.
RESULT: PASS - lab isolation confirmed (host-side and from inside). You may proceed.
```

| Result | Exit | What to do |
|---|---|---|
| `PASS` | 0 | continue |
| `FAIL ... REACHABLE` | 1 | **STOP.** `docker compose -f $LAB down`. Fix the compose file (network must be `internal: true` with `inhibit_ipv4`; one network only). Do not scan. If only the labnet-gateway lines FAIL, this Docker Engine ignored `inhibit_ipv4`: do not scan, report the engine version. |
| `INCONCLUSIVE` | 2 | a control failed (stack still starting, or a tool is missing). Wait and rerun; it is not a pass. |
| `NOT RUN` | 3 | Docker is unreachable, the compose file cannot be read, or the stack is not up. Nothing was checked. |

Save the full output as evidence:

PowerShell 7:

```powershell
uv run python lab/check_isolation.py --with-internet-control *>&1 | Tee-Object lab\captures\isolation-check.txt
```

bash / zsh:

```bash
uv run python lab/check_isolation.py --with-internet-control 2>&1 | tee lab/captures/isolation-check.txt
```

(Optional, extra paranoia: `docker network inspect rc-lab_labnet` and confirm
`"Internal": true`, four entries under `Containers`, the option
`"com.docker.network.bridge.inhibit_ipv4": "true"` and **no** `Gateway` under
`IPAM.Config`. What matters is that **plus** the inside-scanner result: no
default route, and every outbound attempt blocked.)

## Step 4b. Generate this session's engagement

Only after Step 4 printed PASS. `lab/engagement.yaml` is a template; this writes
a copy whose `window` is now - 5 min .. now + 4 h (everything else as in the template),
validates it through the normal engagement schema, and prints a confirmation.
The gate still refuses to act outside that window. It runs inside the scanner;
re-run it if a session outlasts the window (`--hours N`, at most 24, changes
the length):

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner python3 /lab/make_lab_engagement.py /captures/engagement.now.yaml
```

Expected output (your times):

```
wrote /captures/engagement.now.yaml (window 2026-11-10T09:55:00Z .. 2026-11-10T14:00:00Z; validated)
```

Steps 8 and 13 use `/captures/engagement.now.yaml`.

## Step 5. Record the installed versions

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner cat /opt/lab-versions.txt
```

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner nmap --version
```

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner nuclei -version
```

PowerShell 7:

```powershell
docker image inspect op06d-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1 --format '{{.Id}}'
```

PowerShell 7:

```powershell
docker compose -f $LAB images
```

Save to `lab/captures/versions.txt`. Confirm: nmap 7.93, nuclei v3.11.1, templates
v10.5.1. Fill these into `lab/PLANTED_VULNS.md` section 5. (`nuclei -version` may
print to stderr and may mention an update check: note anything it says about
networking.)

## Step 6. Run the project's tests inside the scanner (sanity)

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner python3 -m pytest -q -p no:cacheprovider /op06d/tests
```

This proves the pinned Python packages and Python 3.11 run the existing suite.
The repo is mounted read-only; pytest needs `-p no:cacheprovider` for that. The
image's packages come from `uv.lock` (`docker/requirements*.txt`); if it fails on
versions, regenerate those files with the commands in their headers and rebuild.

## Step 7. Flag-name verification (nmap and nuclei wrappers)

The wrappers pass these flags. The authoritative test is that the **real tool
accepts them and does what they mean**; Step 8 runs every one for real. This step
prints exactly what the wrappers build and does a quick `--help` cross-check.

**7a. Print every command line the wrappers build (nothing is executed):** Copy and paste to the command line.

PowerShell 7:

```powershell
@'
from op06d.nmap_tool import NmapTool, PROFILES
from op06d.nuclei_tool import NucleiTool
from op06d.tools import ProcessResult

seen = []
def cap(argv, timeout, **kw):      # **kw: nuclei's runner is also passed env=
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

Expected: eight `nmap` lines and two `nuclei` lines. The `--host-timeout`
value differs per line: the wrapper sizes it from the port count and the rate
(at 50 rps: `300s` for most profiles, `485s` for `aggressive`, `3488s` for
`full`; see "Wrapper timeouts" in Step 12).

Save to `lab/captures/wrapper-argv.txt`.

**7b. Quick cross-check against `--help` (informational; `--` and a few flags do not appear in help).** The two lines are safe to paste together:

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner bash -c 'for f in -oX --no-stylesheet --max-rate --host-timeout -sn -F -sV -p- -A -p --script; do if nmap --help 2>&1 | grep -q -e "$f"; then echo "nmap listed      $f"; else echo "nmap NOT LISTED  $f"; fi; done'
docker compose -f $LAB exec -T scanner bash -c 'for f in -config -u -t -jsonl -silent -no-color -disable-update-check -rate-limit -c -bs -timeout -retries -disable-redirects -no-interactsh -interactsh-server -severity -tags -exclude-tags -id; do if nuclei -h 2>&1 | grep -q -e " $f"; then echo "nuclei listed     $f"; else echo "nuclei NOT LISTED $f"; fi; done'
```

**7c. Record, per flag:** accepted / rejected ("unrecognized option", "flag
provided but not defined") / accepted but renamed or ignored. The flags most
likely to change between versions are nuclei's `-disable-redirects`, `-no-interactsh`, `-interactsh-server`,
`-exclude-tags`, `-disable-update-check`, `-bs`, `-config`, and nmap's
`--no-stylesheet` and `--host-timeout`. A flag that is "listed" but ignored is
caught by the behavior tests in Step 11.

## Step 8. Real scans and captures (only after Step 4 passed)

This goes through the **gate and the toolbox** (not the raw tools), so the gate,
sanitizer and audit log are exercised as well. The scanner has no network beyond
the lab, and the engagement scopes only the two targets.

**Resolve-once DNS:** the two `nuclei` rows target hostnames
(`dvwa.lab`/`juice-shop.lab`), so this run also exercises resolve-once end
to end. The gate resolves each hostname once, pins it (`Gate(..., audit_pin=
log.record_dns_pin)` below records that as a `dns_pinned` audit entry), and
the toolbox hands nuclei the pinned IP, never the hostname; nuclei gets
`-H "Host: <hostname>"` + `-sni <hostname>` so vhost routing still works.
Expect: the findings to match the frozen baseline (same
swagger-api/owasp-juice-shop-detect/fingerprinthub/tech-detect results - IP+Host
substitution does not change what matches for a docker-DNS vhosted target);
`nuclei_*.findings.json` to carry a `target_hostname` field; and a `dns_pinned`
entry per hostname in the audit log (two total: `dvwa.lab`, `juice-shop.lab`).
The `nmap` rows already target literal IPs, so they are unaffected beyond
`-n` always being in the argv.

**Shared driver:** this step runs through `lab/scan_driver.py` - the same RUNS
list and gated-execute logic the [gated repeatability test](#automated-runs)
(`tests/integration/test_lab_repeatability.py`) calls, so the two cannot drift apart.
Writing straight to `lab/captures/` here is deliberate (these are the
committed, by-hand captures); the automated test always uses a fresh,
ephemeral subdirectory instead (`lab/captures/_repeatability_ephemeral/`, wiped before
every run), so it never overwrites them.

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner python3 /lab/scan_driver.py /captures --engagement /captures/engagement.now.yaml
```

**Takes a few minutes.** Before each of the seven rows the driver prints
`starting row i/7: <name>`, then the row's result line when it completes; a
row can sit for a minute or more with no further output (nuclei loading the
template set, nmap `-sV`). That is normal, not a hang.

Expected: every row `outcome=executed`. The Juice Shop nuclei row
(`nuclei_juice-shop_3000`) passes `{port: 3000, scheme: http}` explicitly,
so nuclei is given `http://juice-shop.lab:3000` (the nuclei `port`/`scheme` parameters). Both halves
matter: without the port, nuclei probes the default ports and Juice Shop only
listens on 3000; with the port but no scheme, the wrapper defaults the scheme
to `https`, which is wrong for plain HTTP on 3000. With both, it behaves like
the DVWA rows rather than coming back empty. This matches the `RUNS` list in
`lab/scan_driver.py`. Also expect exactly two
`dns_pinned` lines (`dvwa.lab`, `juice-shop.lab`, each pinned once even
though each hostname is scanned in more than one row - resolve-once). A `denied`/`declined` row is
a deviation: keep the printed lines with the captures and find the cause
before relying on the run. Each nuclei row's
`*.findings.json` also carries `summary.templates_loaded` (template-coverage instrumentation) -
expect a real positive count (thousands, against the pinned v10.5.1 set); `0`
or missing means the coverage instrumentation itself regressed, not that the
scan was clean.

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

PowerShell 7:

```powershell
@'
import pathlib, json
from op06d.nmap_tool import parse_nmap_xml
from op06d.nuclei_tool import parse_nuclei_jsonl
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
string, any fields the parser drops that normalization needs.

**Fixtures:** the real captures stay in `lab/captures/` (keep the names); they
are the evidence and the repeatability baseline. **Do not overwrite** the hand-written
fixtures in `tests/fixtures/`. A `FAIL` or `WARN` line, or a field the parser
drops, is a parser defect: record it with the capture's file name and fix the
parser (with a test) before relying on its output.

## Step 10. nuclei tag-vocabulary audit

**Purpose.** Does any tag the wrapper treats as safe (`ACTIVE_TAGS`) pull a
template that is actually intrusive or state-changing? The wrapper selects
templates by tag, so "safe" is only as good as the community's tagging. This
is offline, read-only analysis of the pinned template set on disk; nothing is
sent anywhere.

**Why it is important.** A template tagged `tech` or `exposure` that also
sends a `POST`/`PUT`, fuzzes, or calls out to interactsh would run in the
default, no-approval pass. This step counts exactly that.

**Run.** It walks ~14,000 template files and takes a minute or two; it prints
`[i/N] scanning templates...` every 1,000 files (`-u` keeps that unbuffered)
and `scanned N templates` at the end, then the table:

PowerShell 7:

```powershell
@'
import pathlib, re, collections, sys, yaml
from op06d.nuclei_tool import ACTIVE_TAGS, INTRUSIVE_TAGS, EXPLOIT_TAGS, DEFAULT_TAGS

ROOT = pathlib.Path("/opt/nuclei-templates")
DANGER = INTRUSIVE_TAGS | EXPLOIT_TAGS
rows = collections.defaultdict(lambda: collections.Counter())
examples = collections.defaultdict(list)

def tags_of(info):
    t = info.get("tags", [])
    if isinstance(t, str):
        t = t.split(",")
    return {str(x).strip().lower() for x in t if str(x).strip()}

FILES = sorted(ROOT.rglob("*.yaml"))
N = len(FILES)
for i, p in enumerate(FILES, 1):
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

print(f"scanned {N} templates", file=sys.stderr, flush=True)
print("DEFAULT_TAGS (what runs when the planner selects nothing):", DEFAULT_TAGS)
for t in sorted(rows):
    print(f"\n== {t}  ({'DEFAULT' if t in DEFAULT_TAGS else 'optional'})")
    for k, v in sorted(rows[t].items()):
        print(f"   {k:28} {v}")
print("\nExamples of concern (tag, reason -> up to 3 templates):")
for (t, r), ex in sorted(examples.items()):
    if r.startswith(("method:", "fuzz", "protocol:code", "protocol:headless", "protocol:javascript", "uses-interactsh", "redirects")):
        print(f"  [{t}] {r}: {ex}")
'@ | docker compose -f $LAB exec -T scanner python3 -u -
```

Also list what the **default selection really selects** - the templates that
carry a default tag and none of the tags the wrapper's `-exclude-tags` drops -
read deterministically from the same YAML as the audit above:

PowerShell 7:

```powershell
@'
import pathlib, sys, yaml
from op06d.nuclei_tool import DEFAULT_TAGS, INTRUSIVE_TAGS, EXPLOIT_TAGS
ROOT = pathlib.Path("/opt/nuclei-templates")
default = set(DEFAULT_TAGS)
blocked = (INTRUSIVE_TAGS | EXPLOIT_TAGS) - default      # what the wrapper passes to -exclude-tags
out = []
for p in sorted(ROOT.rglob("*.yaml")):
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        continue
    if not isinstance(d, dict) or not isinstance(d.get("info"), dict):
        continue
    t = d["info"].get("tags", [])
    tags = {str(x).strip().lower() for x in (t.split(",") if isinstance(t, str) else t) if str(x).strip()}
    if tags & default and not tags & blocked:
        out.append(str(p.relative_to(ROOT)))
pathlib.Path("/captures/default-selection-templates.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"wrote /captures/default-selection-templates.txt ({len(out)} templates)")
'@ | docker compose -f $LAB exec -T scanner python3 -u -
```

**How to read it.** A tag in `ACTIVE_TAGS` is a problem if templates under the
*default* selection (after `-exclude-tags`) still send non-GET/HEAD requests,
use payloads/fuzzing, use `code`/`headless`/`javascript`, use interactsh, or
follow redirects. `also-tagged:` rows are already handled by `-exclude-tags`,
so they are not a problem by themselves. A `method:PUT`/`DELETE`/`PATCH`/`PURGE`
on a default-selection template is covered by the write-method `-eid` backstop (below)
only if its id is in `src/op06d/nuclei_write_method_exclusions.json`.

**What to do.** Count the templates of concern, list examples, and keep the
output with the captures. If something new shows up, the fix is to remove or demote the tag,
tighten `-exclude-tags`, exclude by protocol, or (for a write method)
regenerate the `-eid` list. The [validation harness](#automated-runs) reports this step as
NEEDS-REVIEW, never PASS, for exactly this reason: a human reads it.

**Expected against the pinned v10.5.1 set.** 14,104 templates; 52 survive
`-exclude-tags` and send a non-GET request, all query-style `POST` (GraphQL
introspection, JSON-RPC reads, API fingerprinting). None of them declares a
write method (`PUT`/`DELETE`/`PATCH`/`PURGE`), because every template that
does also carries a tag that `-exclude-tags` drops. That is tag-dependent, so
`NucleiTool` always passes `-eid`/`-exclude-id` with the 69 ids that declare a
write method in either shape (an `http`/`requests` block's `method:`, or a
`raw:` request line), bundled as
`src/op06d/nuclei_write_method_exclusions.json` (regenerate it with
`scripts/generate_nuclei_write_method_exclusions.py` on a re-pin).
`tests/test_nuclei_method_audit.py` guards against drift in CI;
`tests/integration/test_lab_nuclei_write_methods.py` (gated) checks the
bundled list against the real pinned set, checks that `-eid` really excludes
(not just accepts) a known write-method id, and that the 52 read-oriented
survivors are untouched. A different count is a finding.

## Step 11. nuclei ambient-config precedence

**Purpose.** Can a hostile `~/.config/nuclei` config
re-enable interactsh, redirects or headers despite the wrapper's flags?
Everything below is on the scanner's **loopback only** (three tiny local
servers); it needs no network.

**Why it is important.** nuclei reads `~/.config/nuclei/config.yaml` on its
own. If that file can override the wrapper's `-disable-redirects` /
`-no-interactsh`, then whoever controls the scanner's home directory controls
what a "safe" scan actually does - the gate would approve one thing and
nuclei would do another.

**Run.** 11a-11c below, then **always** 11d (clean-up). The same replay,
reduced to one command and judged automatically, is
`docker compose -f $LAB exec -T scanner python3 /lab/ambient_config_probe.py`
(shared by `tests/integration/test_lab_nuclei_ambient_config.py` and the [validation harness](#automated-runs);
it removes its hostile config itself).

**11a. Servers and test templates.** `PROBE` answers 302 to `CANARY`; `CANARY`
and `OAST` just log. Anything that reaches CANARY or OAST, or carries the hostile
header, shows up in `lab/captures/cfgtest-requests.log`.

PowerShell 7:

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
'@ | docker compose -f $LAB exec -T scanner sh -c "mkdir -p /tmp/cfgtest/templates && cat > /tmp/cfgtest/servers.py && echo 'wrote /tmp/cfgtest/servers.py'"

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
'@ | docker compose -f $LAB exec -T scanner sh -c "cat > /tmp/cfgtest/templates/redirect-probe.yaml && echo 'wrote /tmp/cfgtest/templates/redirect-probe.yaml'"

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
'@ | docker compose -f $LAB exec -T scanner sh -c "cat > /tmp/cfgtest/templates/oast-probe.yaml && echo 'wrote /tmp/cfgtest/templates/oast-probe.yaml'"

docker compose -f $LAB exec -d scanner python3 /tmp/cfgtest/servers.py; "started servers.py (detached)"
```

Expected output:

```
wrote /tmp/cfgtest/servers.py
wrote /tmp/cfgtest/templates/redirect-probe.yaml
wrote /tmp/cfgtest/templates/oast-probe.yaml
started servers.py (detached)
```

**11b. The hostile ambient config** (inside the container's `/root`):

PowerShell 7:

```powershell
@'
interactsh-server: 127.0.0.1:18083
no-interactsh: false
follow-redirects: true
header:
  - "X-Hostile-Config: 1"
'@ | docker compose -f $LAB exec -T scanner sh -c "mkdir -p /root/.config/nuclei && cat > /root/.config/nuclei/config.yaml && echo 'wrote /root/.config/nuclei/config.yaml'"
```

Expected output:

```
wrote /root/.config/nuclei/config.yaml
```

(The keys mirror nuclei's flag names; if nuclei complains about a key, adjust it
and record that.)

**11c. Control, wrapper-as-built, and wrapper with a controlled config:**

PowerShell 7:

```powershell
@'
import os, subprocess, pathlib, time
from op06d.nuclei_tool import NucleiTool

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
| D hostile proxy env | a hostile `HTTP_PROXY`/`HTTPS_PROXY` in the environment is not honored by nuclei (no traffic via the proxy) | the wrapper would need to scrub the environment: a real finding |
| E variant C + the same proxy | clean | the controlled config and scrubbed environment do not keep the proxy out: a real finding |

`build_argv` always emits `-config <placeholder>`, and that
placeholder path does not exist on disk unless the wrapper's own `run()`
creates it; so runs B and D above may exit early with a missing-config
error instead of scanning. That is an artefact of calling `build_argv` by hand
here, not a wrapper regression. The authoritative wrapper-as-built result is
the `wrapper` row of `/lab/ambient_config_probe.py` (it calls `NucleiTool.run`,
exactly as a scan does), and its `control` row is run A.

**What to do.** If run A (or the probe's `control` row) shows nothing, fix the
experiment before concluding anything. If the wrapper row shows a redirect,
the hostile header, OAST contact or a non-`ok` status, the ambient config is
overriding the wrapper: stop, keep the full output, and do not scan with
OP-06D until it is fixed (the [harness](#automated-runs) reports that as FAIL). Otherwise the step is reviewed and done - the harness reports it as
NEEDS-REVIEW, never PASS, so a human reads the table. Then run 11d.

The harness reports the redirect, header and OAST sub-checks separately: a
sub-check the control never demonstrated is `INCONCLUSIVE (... detection not
proven)`, not "clean". In this experiment the OAST sub-check is
INCONCLUSIVE: the scheme-less `interactsh-server: 127.0.0.1:18083` makes
nuclei *register* over HTTPS, and the stand-in on 18083 is a plain HTTP
logger, so the TLS handshake fails (`tls: first record does not look like a
TLS handshake`) and the interactsh client never initialises. The redirect and
header sub-checks are proven.

**Expected result.** The wrapper always passes its own `-config` (an empty
file when none is configured) and runs nuclei with `HOME`/`XDG_CONFIG_HOME`
pointed at a fresh per-run temporary directory. Against the hostile config
from 11b, the wrapper row shows no redirect followed, no hostile header sent,
no OAST contact, and `status=ok`.
`tests/integration/test_lab_nuclei_ambient_config.py` (gated) automates the
replay.

**11d. Clean up** (important: the hostile config must not linger):

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner sh -c "rm -f /root/.config/nuclei/config.yaml; pkill -f servers.py; rm -rf /tmp/cfgtest"
```

## Step 12. nmap privilege behavior

Which profiles and scripts need root, and what the wrapper does without it.
Runs only the profiles (and read-only analysis of scripts), against the lab
target, as root and as the unprivileged `scanner` user:

PowerShell 7:

```powershell
$privprobe = @'
import os
from op06d.nmap_tool import NmapTool, PROFILES
t = NmapTool(50)
print("uid:", os.getuid())
for prof in PROFILES:
    r = t.run("172.31.77.11", {"profile": prof})
    f = r.findings if isinstance(r.findings, dict) else {}
    err = f.get("error", {}).get("message", "") if f.get("error") else ""
    scan_types = ",".join(f.get("summary", {}).get("scan_types", [])) or "-"
    degraded = f.get("degraded_capabilities") if f.get("degraded") else "-"
    print(f"{prof:11} status={r.status:18} scan-types={scan_types:10} degraded={degraded} {err[:150]}")
'@
"=== as root ===";            $privprobe | docker compose -f $LAB exec -T scanner python3 -
"=== as scanner (unprivileged) ==="; $privprobe | docker compose -f $LAB exec -u scanner -T scanner python3 -
```

Record, for each profile, root vs unprivileged: works? `syn` vs `connect` scan
type? degraded? error text? **Expected:** `ping`,
`quick`, `default`, `service`, `full` work unprivileged using a TCP connect
scan, and the wrapper reports every unprivileged run as degraded:
`degraded=['syn_scan', 'host_discovery']` (`['host_discovery']` for `ping`),
because a connect scan's host discovery only tries TCP 80 and 443, so hosts
without either port open may be reported as down. `aggressive` (`-A`, which
includes OS detection) does **NOT** fail without root - nmap degrades
gracefully: connect scan instead of SYN, OS detection silently skipped, exit
0, valid XML. **stderr is empty** in both
privilege modes, so there is no error text to see either way. The wrapper
surfaces this as `status=ok`, `degraded=['syn_scan', 'host_discovery',
'os_detection']`, `scan-types=connect` - never `nmap_failed`. As root nothing
is degraded. The pass criterion for this step is "no traceback, a structured,
correctly-`degraded`-flagged status on every profile in both privilege modes".

**Wrapper timeouts.** A host nmap skips at `--host-timeout` is reported, not a
silent empty result.

The wrapper sizes `--host-timeout` per call: it estimates the scan time from the port count and the rate
(`ceil((ceil(ports * 2 / max_rps) + allowance) * 1.25) + 60` seconds; the
allowance is 120 s for `-sV`, 300 s for `-A`, plus 180 s with `scripts`) and
passes the larger of that and 300 s. The subprocess timeout is the host
timeout plus 60 s (at least 900 s). At this step's 50 rps that is `300s` for
`ping`, `quick`, `default` and `service`, `485s` for `aggressive` and `3488s`
for `full`, so `full` may run for up to an hour before nmap gives up on the
host. At 5 rps `service` gets `710s`.

Two statuses come from this:

- `profile_too_slow`: the estimate is over 3600 s (for example `full` below
  49 rps). nmap is not started; the error names the profile, port count,
  rate and estimate.
- `host_timeout`: nmap skipped every host that responded at `--host-timeout`.
  The result is also `degraded` (`port_scan`, plus `service_detection` for
  `-sV`/`-A`) and the report lists it under Limitations. If only some hosts
  were skipped the status stays `ok` with the same `degraded` fields.

Which NSE scripts need raw sockets (read-only, offline):

PowerShell 7:

```powershell
docker compose -f $LAB exec -T scanner sh -c "grep -rl 'is_privileged' /usr/share/nmap/scripts | sed 's#.*/##' | sort | head -100"
```

The confirmed result is recorded in `docs/nmap-tool.md` ("Privilege-degradation
surfacing"); a result that differs from it is a finding. Also confirm the wrapper returns a structured error, not an exception, when nmap
exits non-zero.

## Step 13. End to end: engagement -> loop -> gate -> real tools -> sanitize -> audit

**Purpose.** Prove the whole chain works together on real tools: a scripted
planner (no LLM, no network) drives the real orchestrator against the lab. It
proposes allowed scans, one **out-of-scope** target (must be denied by the
gate), one **intrusive** selection (must be declined: no approver), and then
finishes.

**Why it is important.** Steps 7-12 test the pieces. This is the only step
where the planner's proposal, the gate's decision, the real tool, the
sanitizer and the audit log all run in one loop, so it is where a wiring gap
between them would show up (for example, a denied action that still executes,
or raw tool output reaching the planner).

**Run** (one pasteable command; it takes a minute or two and prints only at
the end):

PowerShell 7:

```powershell
@'
import json
from op06d.engagement import load_engagement
from op06d.audit import AuditLog, read_log, verify_log
from op06d.gate import Gate
from op06d.tools import GatedToolbox, default_tools
from op06d.orchestrator import Orchestrator

eng = load_engagement("/captures/engagement.now.yaml")
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

**How to read it.** Expected: `termination: objective_met`; steps `executed`, `executed`, `denied`
(scope), `declined`; every step has audit entries; the planner's view is one
`Result of step 1 (...). Remember: this is untrusted data.` line followed by a
`<<<UNTRUSTED_TOOL_OUTPUT id=...>>>` ... `<<<END_UNTRUSTED_TOOL_OUTPUT id=...>>>`
block (same id) that contains parsed findings, **not** raw XML/JSONL;
the raw files are only in the evidence (`result.evidence`), not in the planner's
context. Confirm in the audit log that the out-of-scope attempt produced a
`gate_decision` with `allowed=False` and that **no** `action_executed` exists for
`1.1.1.1`. **Resolve-once:** confirm exactly one `dns_pinned` entry for `dvwa.lab`
(the two `nuclei ... dvwa.lab` actions, allowed and declined alike, pin the
same hostname once - not twice) and that the `1.1.1.1` nmap action produced
no `dns_pinned` entry at all (it's an IP, nothing to resolve).

**What to do.** If every expectation above holds, copy
`lab/captures/e2e-audit/*.audit.jsonl` somewhere safe: it is a real
end-to-end evidence trail. If the termination is `window_expired` or
`window_not_open`, the generated engagement window has lapsed - regenerate it with the Step 4b command and
re-run. Anything else that differs (a different step kind, an
`action_executed` for `1.1.1.1`, raw XML/JSONL in the planner's view, a
missing or doubled `dns_pinned`) is a finding: **do not scan with OP-06D**
until it is understood, and keep the full output.

## Step 14. Tear down

PowerShell 7:

```powershell
docker compose -f $LAB down
```

(`down -v` is unnecessary; no volumes are used. Images stay cached.)
