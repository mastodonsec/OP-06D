# OP-06D operator runbook

The ordered procedure for running an OP-06D engagement against a live, authorized
target, from the paperwork to the record you keep. It is written for the operator the
README's [Prerequisites](../README.md#prerequisites) describe: someone who already
scopes engagements, works to rules of engagement, holds written authorization and
reads nmap and nuclei output. It does not teach penetration testing.

Each step repeats only what you need at that point and links to the component docs
for the detail. This operator runbook is separate from the lab runbook,
[lab/RUNBOOK.md](../lab/RUNBOOK.md), which proves a setup against the isolated lab.
Run the lab quick start ([lab/README.md](../lab/README.md)) once before your
engagement work, so you know what a normal run, report and audit log look like.

Every command below uses the v0.0.3 release image by digest:
`ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55`.

## 1. Before you scan

OP-06D enforces what the engagement file says; it cannot tell whether what the file
says is what the client agreed. Have all of this before you write the engagement file:

- **Signed authorization** from the owner of every system in scope. Its reference
  goes in `authorization.signed_scope_ref`, and `authorized_by` names who signed it.
  Both are written to the audit log and the report; OP-06D does not check that the
  document exists.
- **An agreed window**, in UTC, with a start and an end. The gate refuses every
  action outside it.
- **An agreed source IP** the client can recognise in their logs: the address your
  scan leaves from. It decides where you run OP-06D (step 2).
- **A stop contact and a stop procedure**: who at the client can ask you to stop, how
  they reach you during the window, and how you confirm that you have stopped
  (step 5, [Stopping a run](#stopping-a-run)).
- **The client's out-of-scope list**: third-party services, excluded hosts and
  ranges. It becomes `scope.out_of_scope`.
- **The cloud provider's testing policy** for any target hosted in a cloud. A signed
  client scope does not override a provider's or another third party's policy.
- **Agreement to third-party processing**, only if you plan with the hosted model:
  findings about the client's systems are sent to the model provider (step 3).

Agree the rules of engagement and the stop procedure with the client in your usual
way; OP-06D provides neither.

## 2. Choose and prepare the scanning host

**Choose the host** from [Where to run OP-06D](../README.md#where-to-run-op-06d): the
scan has to leave from the agreed source IP, so for an external attack surface that is
normally a clean Linux VM with a fixed address, and for an internal network a Linux host
inside it. Check the host's clock: the gate compares the window with the container's
clock, which is the host's.

**Pull the image by digest.**

PowerShell 7:

```powershell
docker pull ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55
```

bash / zsh:

```bash
docker pull ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55
```

**Verify its signature** with [cosign](https://github.com/sigstore/cosign). A valid
signature prints the verified claims as JSON and exits 0; anything else is a failed
verification, and you do not use the image.

PowerShell 7:

```powershell
cosign verify ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  --certificate-identity "https://github.com/mastodonsec/OP-06D/.github/workflows/release.yml@refs/tags/v0.0.3" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

bash / zsh:

```bash
cosign verify ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  --certificate-identity "https://github.com/mastodonsec/OP-06D/.github/workflows/release.yml@refs/tags/v0.0.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Without cosign installed, run it from its own image, as in the README's
[Install](../README.md#install) step 2. The SBOM and build provenance checks are in
[container.md](container.md#verify-the-image).

**Check what the image runs.**

PowerShell 7:

```powershell
docker run --rm ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 version
```

bash / zsh:

```bash
docker run --rm ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 version
```

**Expected output:**

```
op06d 0.0.3
nmap 7.93
nuclei 3.11.1
nuclei-templates v10.5.1 (/opt/nuclei-templates, read-only)
base_image debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
nmap_package 7.93+dfsg1-1
nmap_raw /usr/lib/op06d/nmap-raw
```

**Make a fresh working directory for each run**, holding the run's `engagement.yaml`
and an empty `out` directory owned by your user. If Docker creates `out`, it is owned by
root and the run is refused. Never reuse an `out` directory: a second run with the same
`out` appends to the same audit log and evidence store, which breaks the audit check in
step 6.

Create `out`.

bash (Linux):

```bash
mkdir -p out
```

PowerShell 7:

```powershell
New-Item -ItemType Directory -Force out | Out-Null
```

bash / zsh (macOS):

```bash
mkdir -p out
```

**Raw scans need Linux.** On Linux the run uses host networking and the
`NET_RAW` and `NET_ADMIN` capabilities, so nmap does SYN scans and full host discovery
as your own user. Docker Desktop (Windows and macOS) can't send raw packets to your
network, so the run there has neither, and nmap does a TCP connect scan. The report's
Limitations then carry this, once per nmap action:

```
nmap_degraded: nmap ran without raw-socket privileges, so it used a TCP connect scan instead of a SYN scan, and host discovery used only TCP connections to ports 80 and 443: hosts without either port open may have been reported as down. Run nmap as root or, in the container image, with --cap-add NET_RAW --cap-add NET_ADMIN for a SYN scan and full host discovery.
```

On Docker Desktop that line is expected; it is not a fault. If the engagement needs
SYN scans or full host discovery, run it from Linux. Details:
[container.md](container.md).

## 3. Write the engagement file

The engagement file is the authorization boundary: the gate enforces exactly what it
says, and the file is validated strictly when the run starts (any unknown key, bad
value or malformed entry stops the run before any action). The format and every rule
are in [engagement-parser.md](engagement-parser.md), with an annotated example in the
README's [Engagement file](../README.md#engagement-file). Put no secrets in it.

**`engagement`** is the engagement ID: 1-128 characters of `A-Z a-z 0-9 . _ -`,
starting with a letter or digit. It names the audit log
(`out/audit/<engagement>.audit.jsonl`) and the report.

**`authorization`**: `client`, `signed_scope_ref` and `authorized_by` from step 1.

**`scope`** ([scope-allowlist.md](scope-allowlist.md)):

- Plain hostname entries are exact. `acme.com` does not cover `www.acme.com`, and
  `*.acme.com` covers any subdomain but not `acme.com` itself. List what the
  authorization names.
- An `out_of_scope` entry always wins over an `in_scope` match, including wildcard
  and CIDR overlaps. A hostname whose resolved address falls inside an out-of-scope
  range is refused.
- A hostname is in scope only through a matching host entry, never because it
  resolves into an in-scope range.
- Each hostname is resolved once, from the scanning host, the first time it is
  checked, and every action on it uses that address.
- CIDRs must be strict network addresses, no broader than /8 (IPv4) or /32 (IPv6).
- The fixed planner does not scan `*.` wildcard entries: a wildcard is a scope
  pattern, not a host. List each host you want scanned.

**`authorization.window`**: two times with a timezone; write them in UTC with `Z`, for
example `["2026-11-10T02:00Z", "2026-11-10T06:00Z"]`. The window is `[start, end)`.
It is checked when each action is decided: an action started just before the end is
not cut off at the end but runs to its own timeout, so leave room for the last scan
inside the agreed window ([gate-rate-and-window.md](gate-rate-and-window.md)).

**`intensity.max_rps`** (1 to 10000) is one budget for the whole engagement. The gate
admits at most that many actions per second, nmap runs with `--max-rate <max_rps>`
(packets per second, shared by the hosts of a range scanned in parallel) and nuclei
with `-rate-limit <max_rps>`. Size it for the link and for what the client's systems
and monitoring can take. A lower rate makes each scan slower: nmap's host timeout is
sized from the port count and `max_rps`, and the table in
[nmap-tool.md](nmap-tool.md#host-timeouts-and-timeout-sizing) shows what to expect.

A scan that cannot finish within nmap's 3600 s limit at that rate is refused before
nmap starts, as the tool error `profile_too_slow`. The fixed planner's `service`
profile always fits (1000 ports: about 2710 s even at `max_rps` 1). Only the LLM
planner can reach `profile_too_slow`: with the `full` profile (all 65535 ports) below
`max_rps` 49, or with a long `ports` list.

**`intensity.destructive`**: leave it `false` unless the rules of engagement
authorize destructive testing. With `false`, any action the tool wrappers class as
destructive is refused. The fixed planner never proposes one.

**`intensity.name_and_ip`** decides nuclei for a host listed both by name and by IP.
nmap scans the shared address once in both modes.

- `once` (the default): nuclei scans the hostname only, which reaches the named
  virtual host. The IP's default virtual host is not assessed, and the report's
  Limitations say so (`nuclei_default_vhost_not_scanned`, step 6).
- `both`: nuclei also scans the IP. That adds one nuclei run, and its time, for each
  such address.

**`objective`**: one line saying what the engagement is for; it appears in the report
and, for the LLM planner, in the model's instructions.

**`planner:`** matters only for `--planner llm` ([llm-planner.md](llm-planner.md)).
Without the block only the local provider may plan. Listing `anthropic` lets the
hosted model plan, and then the engagement ID, objective, scope lists, window, rate
cap and every sanitized tool finding (open ports, banners, nuclei matches) leave the
host for the model provider, under its data-retention terms. List it only when the
authorization allows that third-party processing.

**`interactsh_server`**: leave it out unless you run your own interactsh server and
the rules of engagement allow out-of-band checks. Without it nuclei always runs with
`-no-interactsh`. With it, the value must be a plain hostname of a server you control:
public interactsh servers, IP addresses, wildcards, URLs and paths are refused
([nuclei-tool.md](nuclei-tool.md#2-out-of-band-interactsh-is-off-by-default)).

## 4. Preflight

There is no dry run. The `op06d` command has three subcommands, `version`, `run` and
`report`, and `run` starts acting as soon as the window is open: the first action is
decided right after the `plan:` line is printed.

Starting a run before the window opens does not preview it. Before the window the
gate resolves nothing, so the fixed planner plans every entry on its own (no address
grouping, no `scope:` lines) and every action is refused at the gate; the LLM planner
ends at once with `window_not_open`. Either way the run writes an audit log, an
evidence store and a report into `out`, none of which shows what the real run will do.

The preflight is therefore a set of checks you make by eye.

Before you start the run, against the signed authorization:

- `engagement`, `client`, `signed_scope_ref` and `authorized_by` are this engagement's.
- `window` is the agreed window, in UTC, and the scanning host's clock is right.
- Every `in_scope` entry is in the authorization, written exactly (step 3's scope
  rules), and every host you mean to scan is listed by name or address, not only by
  wildcard.
- `out_of_scope` holds the client's whole out-of-scope list.
- `max_rps`, `destructive`, `name_and_ip`, `planner:` and `interactsh_server` are
  what was agreed.
- You are on the agreed source IP, `out` is new, empty and yours, and the stop
  contact can reach you.

As the run starts (fixed planner), read the lines printed before any action:

```
scope: juice-shop.lab and 172.31.77.10 resolve to the same address; nmap scans it once, nuclei scans juice-shop.lab (172.31.77.10 default vhost not scanned; set name_and_ip: both to include it)
scope: dvwa.lab and 172.31.77.11 resolve to the same address; nmap scans it once, nuclei scans dvwa.lab (172.31.77.11 default vhost not scanned; set name_and_ip: both to include it)
plan: 2 nmap + 2 nuclei
```

- One `scope:` line appears for each set of entries that share an address, and for
  each entry inside a listed range. A host you listed by name and by IP that has no
  `scope:` line did not resolve to that IP from the scanning host.
- `plan:` counts the actions: one nmap per address or range, and nuclei per hostname
  (and per IP, as `name_and_ip` decides). A count higher than you expect usually means
  a hostname did not resolve or the window is not open; those actions are refused at
  the gate.
- The audit log's opening entries (step 5) show what the gate pinned:
  `log_opened` carries the authorization, scope and intensity in force, and each
  `dns_pinned` entry the address a hostname resolved to. Check those addresses are
  the client's.

If anything is wrong, stop the run at once (step 5) and tell the stop contact if any
action had already been allowed.

## 5. Run and monitor

Run from the working directory holding `engagement.yaml` and `out`. These are the
commands from the README's [Usage](../README.md#usage).

**Fixed planner** (the default).

bash (Linux):

```bash
docker run --rm \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  run --engagement engagement.yaml --out /out
```

PowerShell 7:

```powershell
docker run --rm `
  -v "${PWD}/engagement.yaml:/work/engagement.yaml:ro" `
  -v "${PWD}/out:/out" `
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  run --engagement engagement.yaml --out /out
```

bash / zsh (macOS):

```bash
docker run --rm \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  run --engagement engagement.yaml --out /out
```

**LLM planner.** The model may propose actions at or above the approval threshold
(for example nmap's `aggressive` profile or intrusive nuclei tags), and those wait for
your approval. The prompt appears only when the run's stdin and stdout are both
terminals, so these commands use `-it`. Without `-it`, or with `--non-interactive`,
every such action is declined without a prompt.

For the hosted provider, pass the API key with `--env-file`: a file readable only by
you, holding the line `ANTHROPIC_API_KEY=<your key>`, here `anthropic.env` in the
working directory. The engagement must list `anthropic` in `planner.allowed_providers`.

bash (Linux):

```bash
docker run --rm -it \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --user "$(id -u):$(id -g)" \
  --env-file anthropic.env \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  run --engagement engagement.yaml --out /out --planner llm --llm-provider anthropic
```

PowerShell 7:

```powershell
docker run --rm -it `
  --env-file anthropic.env `
  -v "${PWD}/engagement.yaml:/work/engagement.yaml:ro" `
  -v "${PWD}/out:/out" `
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  run --engagement engagement.yaml --out /out --planner llm --llm-provider anthropic
```

bash / zsh (macOS):

```bash
docker run --rm -it \
  --env-file anthropic.env \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  run --engagement engagement.yaml --out /out --planner llm --llm-provider anthropic
```

A local model (Ollama) keeps findings on the host. On Linux, with host networking,
the default endpoint reaches an Ollama listening on 127.0.0.1:

bash (Linux):

```bash
docker run --rm -it \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  run --engagement engagement.yaml --out /out --planner llm --llm-provider local
```

On Docker Desktop the host is `host.docker.internal`, 192.168.65.254 on current
versions ([container.md](container.md#windows-and-macos-docker-desktop) shows how to
check), and the endpoint must be an IP literal:

PowerShell 7:

```powershell
docker run --rm -it `
  -v "${PWD}/engagement.yaml:/work/engagement.yaml:ro" `
  -v "${PWD}/out:/out" `
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  run --engagement engagement.yaml --out /out --planner llm --llm-provider local `
  --llm-endpoint http://192.168.65.254:11434 --llm-allow-private 192.168.65.254
```

bash / zsh (macOS):

```bash
docker run --rm -it \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  run --engagement engagement.yaml --out /out --planner llm --llm-provider local \
  --llm-endpoint http://192.168.65.254:11434 --llm-allow-private 192.168.65.254
```

Models, context size and the run limits (`--max-actions`, `--max-wall-clock`,
`--max-cost-usd` and the rest) are in [llm-planner.md](llm-planner.md#flags).

### What the console shows

A fixed-planner run prints the `scope:` and `plan:` lines, then nothing until it ends.
An LLM-planner run prints nothing before its actions; the console shows only approval
prompts until it ends. Either run ends with a summary like this one (lab quick start,
Docker Desktop):

```
run_id: fe58117c-2efa-4db7-9985-e5648c97bf2e
actions: executed=4 denied=0 declined=0 tool_errors=0
findings by severity: info=8
report (html): /out/rc-lab-2026-11-fe58117c-2efa-4db7-9985-e5648c97bf2e.html
evidence store: /out/evidence.db
audit log:      /out/audit/rc-lab-2026-11.audit.jsonl
```

An LLM run adds `planner: llm (termination: <reason>)` after the `run_id:` line; the
reasons are in [llm-planner.md](llm-planner.md#flags). `denied` counts refused
actions (window, scope, rate, destructive or invalid), `declined` actions you did not
approve, `tool_errors` actions that ran and failed. The paths are inside the container: `/out` is your `out` directory.

A problem found before any action (an invalid engagement file, a refused planner or
provider, an unusable output directory) prints one `error: ...` line and exits with
status 2.

An approval prompt looks like this, with the action's values; only `y` or `yes`
approves, and anything else, or no answer within `--approval-timeout` (120 s by
default), declines:

```
--- OP-06D: operator approval required ---
iteration : <n>
tool      : <tool>
target    : <target>
parameters: <parameters>
risk      : <risk>
reason    : <the planner's reason>
Approve? [y/N] (times out after <seconds>s and denies):
```

### Follow the audit log

Every gate decision, approval and executed action is written to the audit log as one
JSON line and synced to disk before the run goes on, so the audit log is how you watch
a run. The file appears when the run opens it, just before the `scope:` and `plan:`
lines. Follow it from a second terminal in the working directory, with your
engagement ID in the file name:

PowerShell 7:

```powershell
Get-Content out/audit/<engagement>.audit.jsonl -Wait
```

bash / zsh:

```bash
tail -F out/audit/<engagement>.audit.jsonl
```

The events, in the order a run writes them:

| `event` | Written when |
|---|---|
| `log_opened` | the run starts: the authorization, scope, intensity and objective in force |
| `dns_pinned` | a hostname is resolved, once per hostname: `resolved_ips` |
| `address_group` | fixed planner: one per `scope:` line |
| `planner_config` | LLM planner: provider, model and limits |
| `iteration` | LLM planner: the model's proposal for one step |
| `gate_decision` | the gate decides an action: `allowed` and `reason` |
| `approval` | you approve or decline an action |
| `action_executed` | an allowed action has finished: `reason` starts with `ok` or the tool's error code |
| `injection_flag` | tool output looked like an instruction to the planner (it is treated as data) |
| `loop_terminated` | LLM planner: why the loop stopped |

An allowed action and its result, from the lab:

```
{"v":1,"seq":6,"ts":"2026-11-26T00:07:46.363Z","engagement":"rc-lab-2026-11","event":"gate_decision","target":"'juice-shop.lab'","tool":"nmap","parameters":{"iteration":1,"params":{"profile":"service"}},"allowed":true,"reason":"allow: host in scope; within authorized window; within rate cap of 50 rps","prev_hash":"a3b514c7fbcf3a1d5487fefca6b92c008bf59e0f571cc325063bdcb3011b9fb1","hash":"ad9f52051b09e8ad7edc8686a85d45b807aa821d4dc5ff82ee470fa0a303f952"}
{"v":1,"seq":7,"ts":"2026-11-26T00:08:17.684Z","engagement":"rc-lab-2026-11","event":"action_executed","target":"'juice-shop.lab'","tool":"nmap","parameters":{"iteration":1,"params":{"profile":"service"}},"allowed":null,"reason":"ok: risk=ACTIVE_RECON output=2375 chars sha256=cbfe1215baf3814438b9faaafd9a90f7332b5a0c0967c7bd853f876ce9e27944 raw_sha256=6684e68a877193b2429f19b56829aab61126adabc23f55c789753c81b5c18904 scanned_ip=172.31.77.10","prev_hash":"ad9f52051b09e8ad7edc8686a85d45b807aa821d4dc5ff82ee470fa0a303f952","hash":"7698a41f2d4eeca245da36df5e2221bc2dcaf82cbdbedb2f22b318a2b401c63f"}
```

An action refused because the window is closed, from the example engagement:

```
{"v":1,"seq":2,"ts":"2026-11-26T00:02:19.969Z","engagement":"acme-saas-external-2026-11","event":"gate_decision","target":"'app.acme.com'","tool":"nmap","parameters":{"iteration":1,"params":{"profile":"service"}},"allowed":false,"reason":"deny: outside authorized window (at or after end 2026-11-10T06:00:00+00:00)","prev_hash":"7e1c1095a8a10f3f08332828cb39d6fa8d8576282e3309a894023c80da5c7bf8","hash":"4d0cf4f019cc125d0a31a7dcb685bffb84d2076b30fcdcf4cae548cf61fca1bf"}
```

Other refusals are `gate_decision` entries with `"allowed":false` and a `reason`
starting `deny:`, for example:

- before the window: `deny: outside authorized window (before start <time>)`
- out of scope: `deny: host matches out-of-scope entry 'billing.acme.com'`, or
  `deny: resolved <address> is in out-of-scope <range>`
- rate: `deny: rate cap of <max_rps> rps exceeded (retry after <seconds>s)`
- destructive: `deny: action is destructive and the engagement does not permit destructive actions`

A declined approval is an `approval` entry with `"allowed":false` and the reason
`operator declined <risk> action`. A tool error is an `action_executed` entry whose
`reason` starts with the error code instead of `ok`, for example `timeout`,
`host_timeout`, `host_unreachable`, `nuclei_failed` or `profile_too_slow`; the same
code and its message appear in the report's Limitations. Out-of-window refusals during
a run mean the window closed while actions remained: the fixed planner goes on
refusing the rest, the LLM planner ends with `window_expired`, and either way the
report is written.

### Stopping a run

OP-06D has no stop command and no handler for a stop signal. Both ways of stopping end
the run at once:

- **Ctrl+C** in the terminal running `docker run` (with or without `-it`) sends SIGINT
  to op06d. Python raises `KeyboardInterrupt`, the running nmap or nuclei process is
  killed, and the run exits with status 130 after printing a traceback ending in
  `KeyboardInterrupt`.
- **`docker stop <container>`** from another terminal (`docker ps` lists the
  container) sends SIGTERM, which op06d, as the container's main process, does not
  act on. Docker then kills the container with SIGKILL when `docker stop`'s timeout
  runs out (Docker's default, or `--timeout <seconds>`), and the run exits with
  status 137. Ctrl+C is the quicker of the two.

After either, nothing more is sent to the targets once the container has gone:
check that `docker ps` does not list it. What is left in `out`:

- **No summary and no report.** The `run_id` is printed only at the end, so it was not
  printed.
- **The audit log**, intact up to the stop: each entry was synced as it was written.
  The action that was running has its `gate_decision` entry and no `action_executed`
  entry.
- **The evidence store** holds the run with status `running` and no audit log hash.
  With the fixed planner it holds every action that finished before the stop; with
  the LLM planner it holds no actions, because those are stored when the loop ends.

To render a report of a stopped fixed-planner run, read the `run_id` from the
evidence store (the image's Python reads it):

bash (Linux):

```bash
docker run --rm --user "$(id -u):$(id -g)" --entrypoint python3 \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  -c "import sqlite3; [print(*r) for r in sqlite3.connect('/out/evidence.db').execute('SELECT run_id, status, started_at FROM runs')]"
```

PowerShell 7:

```powershell
docker run --rm --entrypoint python3 `
  -v "${PWD}/out:/out" `
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  -c "import sqlite3; [print(*r) for r in sqlite3.connect('/out/evidence.db').execute('SELECT run_id, status, started_at FROM runs')]"
```

bash / zsh (macOS):

```bash
docker run --rm --entrypoint python3 \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  -c "import sqlite3; [print(*r) for r in sqlite3.connect('/out/evidence.db').execute('SELECT run_id, status, started_at FROM runs')]"
```

It prints one line per run, for example
`baac167e-8d86-48b8-9efe-7a86379cfe90 running 2026-11-26T00:05:24.147111+00:00`.
Then render that run:

bash (Linux):

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  report --db /out/evidence.db --run <run_id> --out /out
```

PowerShell 7:

```powershell
docker run --rm `
  -v "${PWD}/out:/out" `
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  report --db /out/evidence.db --run <run_id> --out /out
```

bash / zsh (macOS):

```bash
docker run --rm \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  report --db /out/evidence.db --run <run_id> --out /out
```

It prints `wrote /out/<engagement>-<run_id>.html`. That report covers the actions that
finished, carries no audit log hash, and does not say the run was stopped: say so
yourself when you review it. For a stopped LLM-planner run the report has no actions;
the audit log is the record of what was proposed and done.

Tell the client's stop contact, as your stop procedure says: the time the run stopped
(UTC, the `ts` of the last audit entry), what was running then (the tool and target of
the last `gate_decision` with no `action_executed` after it), and that no further
traffic is being sent. If you start again within the window, use a new working
directory and keep the stopped run's `out` as part of the record.

## 6. After the run

`out` holds the whole record of the run:

| File | What it is |
|---|---|
| `out/<engagement>-<run_id>.html` | the report (a `.pdf` too with `--format pdf` or `both`) |
| `out/evidence.db` | the evidence store the report is rendered from (SQLite, with its `-wal` and `-shm` files while in use) |
| `out/audit/<engagement>.audit.jsonl` | the audit log: every decision, approval and executed action, hash-chained |

### Check the audit log against the report

When a run completes, OP-06D stores the SHA-256 of the whole audit log file in the
evidence store, and the report shows it in **Assessment Activity**:

```
Audit log: /out/audit/acme-saas-external-2026-11.audit.jsonl (sha256 cec2fe83c44188181074a737e6f9b6ebc8cbda838ce54c2f1159766749d00034)
```

There is no verify command. Check it by hand, in two parts. First, hash the file and
compare with the report's value; they must match exactly.

PowerShell 7:

```powershell
(Get-FileHash out/audit/<engagement>.audit.jsonl -Algorithm SHA256).Hash.ToLower()
```

bash (Linux):

```bash
sha256sum out/audit/<engagement>.audit.jsonl
```

bash / zsh (macOS):

```bash
shasum -a 256 out/audit/<engagement>.audit.jsonl
```

Second, check the hash chain inside the file (each entry's hash, the link to the entry
before it, and the sequence numbers) with the image's own audit module:

bash (Linux):

```bash
docker run --rm --user "$(id -u):$(id -g)" --entrypoint python3 \
  -v "$PWD/out:/out:ro" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  -c "from op06d.audit import verify_log; print('audit entries verified:', verify_log('/out/audit/<engagement>.audit.jsonl'))"
```

PowerShell 7:

```powershell
docker run --rm --entrypoint python3 `
  -v "${PWD}/out:/out:ro" `
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 `
  -c "from op06d.audit import verify_log; print('audit entries verified:', verify_log('/out/audit/<engagement>.audit.jsonl'))"
```

bash / zsh (macOS):

```bash
docker run --rm --entrypoint python3 \
  -v "$PWD/out:/out:ro" \
  ghcr.io/mastodonsec/op06d@sha256:872be01c01dafbd7d489358730af4f7f0cfff0a46f5bc50db04366f21f221f55 \
  -c "from op06d.audit import verify_log; print('audit entries verified:', verify_log('/out/audit/<engagement>.audit.jsonl'))"
```

**Expected output:** `audit entries verified: <n>`. An edited, reordered or truncated
log raises an error naming the line instead.

Both checks hold only when the run had its own `out` directory. A second run with the
same `out` appends to the same audit log, so the hash in the earlier run's report no
longer matches the file. A stopped run's report carries no hash; the chain check
still applies. The chain is tamper-evidence, not tamper-proofing: anyone who can write
the file can rewrite all of it, so copy `out` off the scanning host when the run ends.

### Read Limitations before calling a target clean

"Findings: none", or a host with no findings, is not a clean result until the report's
**Limitations & Notes** section says nothing that undermines it. Each entry there is
`<kind>: <detail>`. Look for these in particular:

- `nuclei_low_template_coverage`: nuclei loaded no templates, or the count could not
  be read, so it is not known what was checked:
  `nuclei on <target> loaded 0 templates. "No findings" from this action does not mean the target is clean.`
  or
  `nuclei on <target>: the number of templates loaded could not be read, so it is not known what this scan checked. "No findings" from this action does not mean the target is clean.`
- `nuclei_failed`: nuclei exited with an error and its results are missing:
  `nuclei exited with <code>: <nuclei's error output>`.
- `nmap_degraded`: nmap ran in a reduced mode. On Docker Desktop this is the connect
  scan (step 2). When nmap gave up on hosts it reads
  `nmap skipped <n> host(s) (<addresses>) at --host-timeout <seconds>s before the scan finished (profile '<profile>', <ports> ports per host, max_rps <max_rps>). No port or service results were recorded for them, so the absence of findings does not mean no ports are open. Rerun with fewer ports (the 'quick' profile or a 'ports' list) or a higher max_rps.`
- `host_timeout`: every host that answered timed out:
  `every host that responded was skipped at --host-timeout <seconds>s; the scan is incomplete and reported no ports`.
- `nuclei_default_vhost_not_scanned`: with `name_and_ip: once`, the IP's default
  virtual host was not assessed:
  `<ip>: nuclei scanned <hostname> on this address, so the default virtual host of <ip> was not assessed by nuclei. Setting intensity.name_and_ip: both in the engagement file covers it.`

Any other tool error code (`timeout`, `host_unreachable`, `profile_too_slow`,
`off_target_activity` and the rest) means that action's results are missing or were
cut; [nmap-tool.md](nmap-tool.md) and [nuclei-tool.md](nuclei-tool.md) explain each.
Also compare the Assessment Activity table with the `plan:` line: every action in the
plan should be there, and a refused one says why.

### Review and keep

The report is a draft until you have reviewed it: confirm or discard each finding,
add what the Limitations mean for this client, and say so if the run was stopped.
OP-06D does not do that judgment for you.

Keep the whole `out` directory, with the engagement file you ran, as the engagement
record: the report, the evidence store and the audit log belong together, and the
audit check above needs all of them.
