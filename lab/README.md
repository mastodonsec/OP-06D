# OP-06D lab quick start

The lab is a sealed Docker network with deliberately vulnerable targets and a scanner
built from the OP-06D image. You run OP-06D against it to see real scans, a real report
and a real audit log without touching anything you aren't allowed to test. What it is
for, and why it's built this way: [The lab](../README.md#the-lab) in the main README.

## Topology

```
  Docker network rc-lab_labnet   (internal: true, 172.31.77.0/24)
  +-----------------------------------------------------------------+
  |  scanner 172.31.77.20  ---->  juice-shop  172.31.77.10  :3000   |
  |  (OP-06D image,        ---->  dvwa        172.31.77.11  :80     |
  |   lab stage)           ---->  redirect    172.31.77.12  :80     |
  |                               (nginx redirector)                |
  +-----------------------------------------------------------------+
        X  no route out: not to the internet, your network or your host

  Opt-in, for --planner llm only: a model relay adds one path to exactly
  one upstream (Anthropic's API, or Ollama on your host).
```

What's planted in the targets, and what OP-06D is expected to find:
[PLANTED_VULNS.md](PLANTED_VULNS.md).

Run every command from the repository root. PowerShell blocks are for PowerShell 7
(`pwsh`); bash blocks are for bash or zsh on Linux, Kali and macOS.

## 1. Prerequisites

- Docker with Compose v2 (`docker compose`, with a space): Docker Desktop on Windows and
  macOS, Docker Engine plus the Compose plugin on Linux.
- git.
- [uv](https://github.com/astral-sh/uv), which runs the isolation check and the helper
  scripts.
- About 5 GB of free disk.
- On Linux, be in the `docker` group (or prefix every docker and
  `uv run python lab/...` command with `sudo`). Add yourself once, then log out and back
  in:

  ```bash
  sudo usermod -aG docker "$USER"
  ```

  Membership of `docker` is equivalent to root on that machine.

Check the tools:

PowerShell 7:

```powershell
docker compose version
git --version
uv --version
```

bash / zsh:

```bash
docker compose version
git --version
uv --version
```

**Expected output:** a version line from each; `docker compose version` must print v2
or later.

Kali needs a few more steps to get Compose v2; see
[Linux and macOS hosts](RUNBOOK.md#linux-and-macos-hosts) in the runbook.

## 2. Get the code and build the lab

Building needs the internet (Docker Hub, GitHub, PyPI); the running lab never has it.

PowerShell 7:

```powershell
git clone https://github.com/mastodonsec/OP-06D.git
cd OP-06D
docker compose -f lab/docker-compose.yml build scanner
```

bash / zsh:

```bash
git clone https://github.com/mastodonsec/OP-06D.git
cd OP-06D
docker compose -f lab/docker-compose.yml build scanner
```

**Expected output:** the build ends with
`Image op06d-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1 Built`. The build
checks the nuclei download and the template set against pinned SHA-256 sums; if a
checksum fails, stop.

## 3. Start it

PowerShell 7:

```powershell
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps --format "{{.Service}} {{.State}}"
```

bash / zsh:

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps --format "{{.Service}} {{.State}}"
```

**Expected output:**

```
dvwa running
juice-shop running
redirect running
scanner running
```

DVWA needs about a minute for its database before it answers.

## 4. Check the isolation

Nothing scans until this prints PASS.

PowerShell 7:

```powershell
uv run python lab/check_isolation.py --with-internet-control
```

bash / zsh:

```bash
uv run python lab/check_isolation.py --with-internet-control
```

**Expected output:** it ends with

```
RESULT: PASS - lab isolation confirmed (host-side and from inside). You may proceed.
```

If it prints anything else, stop. `INCONCLUSIVE` usually means the stack is still
starting: wait and run it again. `FAIL ... REACHABLE` means the lab is not sealed: run
step 9 and don't scan. The runbook's
[Step 4](RUNBOOK.md#step-4-isolation-gate-blocking) explains every result.

## 5. Generate this session's engagement

`lab/engagement.yaml` scopes the run to the two lab targets. This writes a copy whose
window runs from five minutes ago to four hours from now, so the gate lets the scans
through.

PowerShell 7:

```powershell
docker compose -f lab/docker-compose.yml exec -T scanner python3 /lab/make_lab_engagement.py /captures/engagement.now.yaml
```

bash / zsh:

```bash
docker compose -f lab/docker-compose.yml exec -T scanner python3 /lab/make_lab_engagement.py /captures/engagement.now.yaml
```

**Expected output** (your times):

```
wrote /captures/engagement.now.yaml (window 2026-11-20T02:25:04Z .. 2026-11-20T06:30:04Z; validated)
```

If a session outlasts the window, run it again.

## 6. Run OP-06D

The fixed planner runs an nmap service scan and a nuclei default-tag scan for each
in-scope host and IP, through the gate.

PowerShell 7:

```powershell
docker compose -f lab/docker-compose.yml exec -T scanner op06d run --engagement /captures/engagement.now.yaml --out /captures/quickstart
```

bash / zsh:

```bash
docker compose -f lab/docker-compose.yml exec -T scanner op06d run --engagement /captures/engagement.now.yaml --out /captures/quickstart
```

**Expected output** (it takes a minute or two; your run id differs):

```
run_id: db5d11b6-df40-456a-b820-ab4b5aa46ec3
actions: executed=8 denied=0 declined=0 tool_errors=0
findings by severity: info=16
report (html): /captures/quickstart/rc-lab-2026-11-db5d11b6-df40-456a-b820-ab4b5aa46ec3.html
evidence store: /captures/quickstart/evidence.db
audit log:      /captures/quickstart/audit/rc-lab-2026-11.audit.jsonl
```

## 7. Read the report and the audit log

`/captures` in the scanner is `lab/captures/` on your machine, so the run's files are in
`lab/captures/quickstart/`:

- `rc-lab-2026-11-<run id>.html`: the report. Open it in a browser. Read the Scope and
  Methodology sections, then Findings, Assessment Activity (every action and the gate's
  decision) and Limitations & Notes.
- `audit/rc-lab-2026-11.audit.jsonl`: the audit log, one JSON entry per line. Look for
  `gate_decision` entries (each with `allowed` and a `reason`), the `action_executed`
  entry that follows each allowed one, and the `dns_pinned` entries for the two
  hostnames.
- `evidence.db`: the evidence store the report is rendered from.

Check that the audit log's hash chain is intact:

PowerShell 7:

```powershell
docker compose -f lab/docker-compose.yml exec -T scanner python3 -c "from op06d.audit import verify_log; print('audit entries verified:', verify_log('/captures/quickstart/audit/rc-lab-2026-11.audit.jsonl'))"
```

bash / zsh:

```bash
docker compose -f lab/docker-compose.yml exec -T scanner python3 -c "from op06d.audit import verify_log; print('audit entries verified:', verify_log('/captures/quickstart/audit/rc-lab-2026-11.audit.jsonl'))"
```

**Expected output:** `audit entries verified: <n>` with the number of entries in the
log; an altered or truncated log raises an error instead.

`lab/captures/quickstart/` is git-ignored. A later run with the same `--out` adds to
the same evidence store and audit log.

## 8. Optional: the LLM planner

To let a model plan the actions, the model relay overlay opens one path to one upstream.
With Ollama running on your host (setup per platform in the runbook's model relay
section), the local mode is:

PowerShell 7:

```powershell
uv run python lab/model_relay.py build local
uv run python lab/model_relay.py up local
uv run python lab/model_relay.py check local
uv run python lab/model_relay.py run local
uv run python lab/model_relay.py down
```

bash / zsh:

```bash
uv run python lab/model_relay.py build local
uv run python lab/model_relay.py up local
uv run python lab/model_relay.py check local
uv run python lab/model_relay.py run local
uv run python lab/model_relay.py down
```

**Expected output:** `check local` must print `RESULT: PASS` before `run local`. `run`
re-checks the isolation, runs OP-06D with `--planner llm` and verifies the report; its
files land in `lab/captures/_relay_ephemeral/local/run/`. `down` removes the relay and
the lab; run step 4 again before any run without the relay.

The hosted (Anthropic) mode, the API key handling and what `check` proves:
[Model relay](RUNBOOK.md#model-relay-opt-in-op06d-run---planner-llm-in-the-lab).

## 9. Tear down

PowerShell 7:

```powershell
docker compose -f lab/docker-compose.yml down
```

bash / zsh:

```bash
docker compose -f lab/docker-compose.yml down
```

**Expected output:** each container and the `rc-lab_labnet` network reported as
removed. The images stay cached for the next session.

The full validation procedure is [RUNBOOK.md](RUNBOOK.md), including
[Automated runs](RUNBOOK.md#automated-runs).
