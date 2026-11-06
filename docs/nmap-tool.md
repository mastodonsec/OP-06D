# nmap tool wrapper (RC-13)

Modules: [`src/redcell/nmap_tool.py`](../src/redcell/nmap_tool.py) ·
[`src/redcell/tools.py`](../src/redcell/tools.py) ·
Tests: [`tests/test_nmap_tool.py`](../tests/test_nmap_tool.py) ·
Fixture: [`tests/fixtures/nmap_service_scan.xml`](../tests/fixtures/nmap_service_scan.xml)

## Purpose

The first real tool behind `GatedToolbox` (see [orchestrator.md](orchestrator.md)).
It lets the orchestrator run an nmap scan against a **gate-approved** target and
get **structured findings**, with the raw XML kept separately as evidence.

Nothing outside the toolbox constructs or calls it: `redcell.tools.default_tools`
is the only place `redcell.nmap_tool` is imported (a test asserts this). By the
time `NmapTool.run` is called the action has already passed
`validate -> Gate.check -> approval`.

## Scope of RC-13

**In scope:** the nmap `Tool`, argv construction, XML parsing, per-invocation
risk, error handling, and the toolbox features it needed (per-invocation
risk/destructiveness, parameter validation hook, secret redaction, structured
`ToolOutput`).

**Not here:**

| Concern | Ticket |
|---|---|
| nuclei wrapper | RC-14 |
| Normalizing findings into the report schema | RC-15 |
| Persisting raw output as evidence | RC-16 |
| Real lab to validate against a live nmap | RC-19 |
| MCP transport (the wrapper is a plain Python `Tool` behind the toolbox) | later |

## How a scan flows

```
planner: {"type":"action","tool":"nmap","target":"203.0.113.5","parameters":{"profile":"service","ports":"22,80,443"}}
   |
   v  GatedToolbox.execute
   |- allowed parameters only (profile, ports, scripts); NmapTool.validate_parameters
   |- risk_for(params)  -> invocation risk;   destructive_for(params)
   |- Gate.check        -> window / scope / rate
   |- approval          -> only if invocation risk >= threshold (default INTRUSIVE)
   |- NmapTool.run      -> argv list, no shell, -oX -, --max-rate <max_rps>
   |- parse XML         -> structured findings   (raw XML kept as evidence)
   |- sanitize findings -> wrapped for the planner (RC-12)
   `- audit record      -> status, risk, output sha256, raw sha256
```

## Parameters

The planner can set exactly three, none of which can carry a host:

| Parameter | Values | Notes |
|---|---|---|
| `profile` | `ping`, `quick`, `default` (default), `service`, `full`, `aggressive` | see table below |
| `ports` | e.g. `"22,80,8000-8100"`, each 1 to 65535 | only with profiles `default` and `service` |
| `scripts` | list of NSE **categories** | categories only: never script names, files, expressions or `--script-args` |

| Profile | nmap flags | Risk |
|---|---|---|
| `ping` | `-sn` | ACTIVE_RECON |
| `quick` | `-F` | ACTIVE_RECON |
| `default` | (none) | ACTIVE_RECON |
| `service` | `-sV` | ACTIVE_RECON |
| `full` | `-p- -sV` | ACTIVE_RECON |
| `aggressive` | `-A` | **INTRUSIVE** |

## Security properties

### argv, never a shell
`run_subprocess` calls `subprocess.run(argv, shell=False, stdin=DEVNULL,
timeout=...)` with a list. The command is always:

```
nmap -oX - --no-stylesheet --max-rate <max_rps> --host-timeout 300s <profile flags>
     [-p <ports>] [--script=<cat,cat>] -- <target>
```

The target is one argv element placed after `--`, so it can never be read as an
option. Before that the wrapper refuses (as `invalid_input`, without starting
nmap) any target that is not a hostname, IP or CIDR: shell metacharacters,
whitespace, newlines, leading `-`, comma lists, wildcards, and nmap octet ranges
such as `203.0.113.1-20` (which would scan many hosts).

### Parameter allow-list
`allowed_parameters = {profile, ports, scripts}`. The toolbox denies anything else
**before the gate** (e.g. `targets`, `iL`, `exclude`, `script_args`,
`extra_args`), and `validate_parameters` checks values against strict patterns.
`--script-args` is deliberately not exposed: scripts can add targets through
arguments like `newtargets`, which the gate would never see.

### Rate propagation
`NmapTool.from_engagement(engagement)` takes `intensity.max_rps` and always
passes it as `--max-rate`, so the packets nmap itself emits are bounded, not just
how often scans start. nmap's `--max-rate` is packets per second, which is at
least as strict as requests per second for a single probe type. `--min-rate` is
never passed.

### Risk comes from the invocation
`risk_for(parameters)` classifies the actual scan:

| Selection | Risk | Effect |
|---|---|---|
| plain / service / full / ping / quick, or categories `safe`, `default`, `discovery`, `version` | ACTIVE_RECON | runs after the gate |
| categories `vuln`, `intrusive`, `brute`, `auth`, `external`, `fuzzer`, `malware`, `broadcast`, or profile `aggressive` | **INTRUSIVE** | trips the RC-8 approval threshold |
| categories `dos`, `exploit` | **EXPLOIT** and destructive | needs approval **and** an engagement with `destructive: true` |

The highest of the profile and category risks wins. If `risk_for` fails, the
toolbox treats the action as EXPLOIT (the most dangerous).

### Secrets never reach the audit log
The audit log is handed to clients as evidence. The toolbox redacts parameters
before they reach any audit record, approval request or loop record:

- keys a tool lists in `sensitive_parameters`, and
- any key that looks like a secret (matching `pass`, `secret`, `token`, `key`,
  `cred`, `auth`, `cookie`, `session`, `bearer`, `signature`, `otp`)

become `[REDACTED]`. This includes **refused** actions, so a password in a denied
request does not leak either. Non-secret values are kept. nmap itself needs no
credentials; the mechanism is generic for later tools. Secrets should still
never be given to the planner at all (use references, per CONTEXT.md).

### Errors do not crash the loop
`run` never raises. Every failure returns a `ToolOutput` with a non-ok `status`
and a structured error that the loop feeds back to the planner as a tool error:

| Status | Cause |
|---|---|
| `invalid_input` | target or parameters rejected by the wrapper |
| `nmap_not_found` | nmap is not installed or not executable (clear message, nothing runs) |
| `timeout` | exceeded `run_timeout_s` (default 900 s); partial output kept as evidence |
| `resolution_failed` | nmap reported it could not resolve the target (defense in depth; `-n` means this should not occur in practice - RC-23) |
| `host_unreachable` | no host came up (down, filtered or unreachable) |
| `nmap_failed` | non-zero exit with no output |
| `malformed_output` | not valid nmap XML, or contains DTD entity declarations |
| `output_too_large` | over 5 MB |
| `exec_failed`, `wrapper_error` | OS error starting nmap; unexpected wrapper bug |

`NmapTool.check_available()` raises `FileNotFoundError` with an install hint; call
it at startup to fail early.

## Output

`run` returns `ToolOutput(findings, raw, status)`:

- `findings` is parsed, structured data (the planner sees only its sanitized
  form; RC-15 will normalize it):

```json
{"scanner": "nmap", "version": "7.94",
 "hosts": [{"status": "up", "addresses": [{"address": "203.0.113.5", "type": "ipv4"}],
            "hostnames": ["app.acme.com"],
            "ports": [{"port": 22, "protocol": "tcp", "state": "open", "reason": "syn-ack",
                       "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1 Ubuntu 3ubuntu0.4",
                                   "extrainfo": "...", "cpe": ["cpe:/a:openbsd:openssh:8.9p1"]}}]}],
 "summary": {"hosts_up": 1, "hosts_down": 0, "hosts_total": 1, "elapsed_seconds": 12.34}}
```

- `raw` is the unmodified XML, kept in `ExecutionResult.raw_output` for evidence.
  The execution audit record carries `raw_sha256` so the log ties to it, plus
  `risk=` and the sanitized-output hash.

The parser uses the standard library after rejecting DTD entities and oversized
documents. Every string field is clipped (2000 characters; fewer for short
fields), and host, port and script counts are capped.

## Usage

```python
from redcell.tools import GatedToolbox, default_tools

toolbox = GatedToolbox(eng, gate, log, default_tools(eng), approver=my_approver)
```

`default_tools(eng)` builds `NmapTool` with `max_rps` taken from the engagement.
For tests, inject the process runner and the nmap lookup:

```python
NmapTool(20, runner=fake_runner, which=lambda name: "/usr/bin/nmap")
```

Run the tests (no real nmap is started):

```bash
uv run --extra dev pytest tests/test_nmap_tool.py
```

## Resolve-once (RC-23)

`run`/`build_argv` take an optional `hostname` keyword, set only by
`GatedToolbox` and only when `target` is the IP the gate resolved and pinned
for an originally-hostname action (see
[gate-rate-and-window.md](gate-rate-and-window.md#resolve-once-rc-23)). nmap
never resolves anything itself: `-n` (disabling nmap's own forward *and*
reverse DNS) is always in `build_argv`'s output, for every profile. This
closes what used to be a real gap - nmap used to resolve a hostname target
independently of the gate, so a DNS change between the gate's check and
nmap's own lookup could make it scan an address the gate never saw.
`hostname`, when given, is only recorded in the result (`target_hostname`,
for the report); nmap has no vhost/SNI concept to preserve the way nuclei
does, so nothing else is done with it.

## Known limits

- **The fixture is hand-written** in nmap 7.94 format, not captured from a live
  scan. Replace it with a real capture once the lab exists (RC-19), and run the
  wrapper against a real nmap there.
- Some options (`-A`, OS detection, SYN scans) need root or administrator rights;
  without them nmap falls back or fails, and the failure comes back as a tool
  error.
- The window is checked between actions; a long scan is bounded by
  `run_timeout_s` and `--host-timeout`, not by the end of the window.
- The secret-key pattern is name-based. A secret in a parameter with an innocuous
  name is not detected, which is why secrets must not be given to the planner.
- Output is plain text/XML; there is no MCP transport yet.
