# nuclei tool wrapper (RC-14)

Modules: [`src/redcell/nuclei_tool.py`](../src/redcell/nuclei_tool.py) ·
[`src/redcell/tools.py`](../src/redcell/tools.py) ·
[`src/redcell/engagement.py`](../src/redcell/engagement.py) ·
Tests: [`tests/test_nuclei_tool.py`](../tests/test_nuclei_tool.py) ·
Fixture: [`tests/fixtures/nuclei_findings.jsonl`](../tests/fixtures/nuclei_findings.jsonl)

## Purpose

The second real tool behind `GatedToolbox`, after nmap ([nmap-tool.md](nmap-tool.md)).
It runs templated web and service checks against a **gate-approved** target and
returns **structured findings**, with nuclei's raw JSONL kept separately as
evidence. It reuses the toolbox scaffolding built for RC-13: `ToolOutput`,
per-invocation risk, the parameter-validation hook and secret redaction.

Like nmap, it is imported only by `redcell.tools.default_tools` (a test asserts
this), so nothing outside the toolbox can construct or call it.

## Scope of RC-14

**In scope:** the nuclei `Tool`, argv construction, JSONL parsing, curated
template selection, risk derivation, the out-of-band and redirect controls,
template pinning, the shared helpers moved into `tools.py`, and the optional
`interactsh_server` engagement field.

**Not here:**

| Concern | Ticket |
|---|---|
| Normalizing findings into the report schema | RC-15 |
| Persisting raw output as evidence | RC-16 |
| A real lab, a real nuclei capture, verifying flags against the pinned version | RC-19 |
| Repeatability tests across runs | RC-20 |
| Maintaining and updating the curated template set (an operator task, outside a run) | operator |

## How a scan flows

```
planner: {"type":"action","tool":"nuclei","target":"app.acme.com","parameters":{"tags":["tech","exposure"],"severity":["info","low","medium"]}}
   |
   v  GatedToolbox.execute
   |- allowed parameters only (severity, tags, template_ids); NucleiTool.validate_parameters
   |- risk_for(params) -> invocation risk;  destructive_for(params)
   |- Gate.check       -> window / scope / rate
   |- approval         -> only if invocation risk >= threshold (default INTRUSIVE)
   |- NucleiTool.run   -> argv list, no shell, -jsonl, -rate-limit <max_rps>
   |- parse JSONL      -> structured findings; drop and flag anything off the approved target
   |- sanitize         -> wrapped for the planner (RC-12)
   `- audit record     -> status, risk, output sha256, raw sha256
```

## Parameters

Five, none of which can carry a host, URL or path:

| Parameter | Values |
|---|---|
| `severity` | non-empty list from `info`, `low`, `medium`, `high`, `critical` (default: all) |
| `tags` | non-empty list from the curated vocabulary below (default: the low-impact detection tags) |
| `template_ids` | list of ids from the operator's curated manifest; refused unless a manifest is configured |
| `port` | a strict integer, 1-65535 (default: none - nuclei probes 80/443 against the bare target) |
| `scheme` | `http` or `https` (default: `https` if `port` is given and `scheme` is not; otherwise the bare target is passed unchanged) |

### `port` / `scheme` (RC-14 follow-up)

The gate approves a bare host, IP or CIDR (never a port), so by default nuclei
is pointed at the bare target and only reaches 80/443. That misses anything on
a non-default port - the lab's Juice Shop listens on 3000 (RC-19). `port` and
`scheme` close that gap without opening a host-smuggling path: `port` is a
strict `int` (never a string, so it cannot carry `;` or a second host) and
`scheme` is the fixed two-value enum `http`/`https` (never a URL). The wrapper
builds the request URL itself, `scheme://target[:port]`, always from the
gate-approved `target` - neither parameter can ever supply the host part.
IPv6 targets are bracketed automatically (`https://[2001:db8::1]:3000`).
Omitting both keeps the prior behavior exactly (the bare target passed to
`-u`), so existing engagements are unaffected.

Tag vocabulary and risk:

| Risk | Tags |
|---|---|
| ACTIVE_RECON | `tech`, `detect`, `panel`, `exposure`, `misconfig`, `config`, `ssl`, `dns`, `waf`, `favicon` |
| INTRUSIVE (needs approval) | `cve`, `kev`, `vuln`, `default-login`, `bruteforce`, `fuzz`, `fuzzing`, `xss`, `sqli`, `lfi`, `rfi`, `ssrf`, `rce`, `ssti`, `redirect`, `takeover`, `auth-bypass`, `intrusive`, `oast` |
| EXPLOIT (needs approval **and** `destructive: true`) | `dos`, `exploit` |

The default selection (nothing chosen) is `tech, detect, panel, exposure,
misconfig, config`. Severity alone never escalates risk: a `critical` filter
with the default tags is still ACTIVE_RECON because the tags bound what runs.
The risk of a selection is the highest risk among its tags (and curated ids).

## The nuclei-specific controls

### 1. No arbitrary templates
A custom template can request any URL, carry out-of-band payloads, or target
other hosts, which routes around the gate's target check. Therefore:

- templates are chosen only by severity, a **fixed tag vocabulary**, or ids from
  an operator-supplied **curated manifest** (`curated_ids`, id to `Risk`;
  empty by default, so id selection is off);
- no parameter can hold a path or URL; `-w` workflows, template URLs, headers,
  variables, lists and `-config` are not reachable by the planner;
- the only `-t` in the command is the operator's **pinned template directory**.

When tags are used, the command also passes `-exclude-tags` with every
intrusive and exploit tag the planner did **not** explicitly request, so a
template that carries both a safe tag and, say, `fuzz`, will not run in a
low-impact scan.

### 2. Out-of-band (interactsh) is off by default
By default nuclei talks to a public interactsh server, which would send callback
data about the client's systems to a third party. This wrapper always passes
`-no-interactsh` unless the engagement sets a **self-hosted** server:

```yaml
interactsh_server: oast.lab.example-redteam.net   # optional; omit to keep out-of-band off
```

The engagement schema (RC-6) rejects public servers (`oast.pro`, `oast.live`,
`oast.site`, `oast.online`, `oast.fun`, `oast.me`, `interact.sh`,
`interactsh.com` and their subdomains), URLs, paths, wildcards and IP addresses;
the wrapper checks again. The server is operator infrastructure and is not
treated as a scan target. Results report `out_of_band: "off"` or `"self-hosted"`.

### 3. Redirects are never followed
`-disable-redirects` is always passed and there is no parameter to change it.
As a second layer, after parsing, every finding's `host` and `matched-at` must
be the approved target (an IP or hostname match, or an address inside the
approved CIDR) - since RC-23, `target` here is the gate-pinned IP for an
originally-hostname action, so this comparison is against that pinned IP, not
the hostname. A subdomain or look-alike host does not count. Anything else is
**removed from the findings** and the run returns status `off_target_activity`
with the host list. That is a tool error, so it is visible to the loop and in
the audit log; the raw JSONL keeps everything as evidence. Note the request to
that host has already happened by then, so this is a tripwire, not prevention.

### 4. The ambient `~/.config/nuclei` config is never read (RC-35)
nuclei reads `~/.config/nuclei/config.yaml` (and `~/.config/nuclei/.nuclei-ignore`)
by default. Confirmed live in the RC-19 lab (RUNBOOK Step 11): a stray or
hostile one is a real problem for the controls above - a conflicting
`follow-redirects: true` makes nuclei **fatal** on every scan (fail-closed only
by accident), while a non-conflicting setting (an injected `header:`, nothing
in `build_argv` conflicts with it) would silently take effect, and a hostile
`.nuclei-ignore` could silently drop templates (the RC-26 coverage blind spot).

Two independent layers now close this:

- `-config` is **always** passed - a wrapper-owned file, never the ambient
  one. If the operator set `config_path`, that file is used as-is (unchanged
  behavior); otherwise the wrapper writes a fresh, empty config into a
  per-run temporary directory (validated safe against the lab's hostile
  config - RUNBOOK Step 11 run C).
- `run` executes nuclei with `HOME` and `XDG_CONFIG_HOME` pointed at that same
  per-run temporary directory instead of the real ones, so nuclei cannot find
  the ambient config or ignore-file even if `-config` were somehow bypassed.
  `redcell.tools.run_subprocess` gained an `env=` parameter for this; it
  defaults to `None` (inherit), so nmap's call path is unchanged.

The directory is created fresh for each `run()` call and removed afterward
(`tempfile.TemporaryDirectory`, cleaned up even on a timeout or exec error) -
nothing persists or leaks between runs. A hostile `HTTP_PROXY`/`HTTPS_PROXY`
in the ambient environment was also tested (lab run D/E): nuclei does not
honor a proxy variable on its own, so scrubbing `HOME`, not the whole
environment, is the targeted fix - `PATH` is still passed through unchanged
so nuclei itself can be found and executed.

## Carried over from RC-13

| Property | In nuclei |
|---|---|
| argv, never a shell | `subprocess.run(argv, shell=False, stdin=DEVNULL, timeout=...)`; the target is the value after `-u`; targets that are URLs, contain `-` first, whitespace, metacharacters, commas or octet ranges are refused before nuclei runs |
| Rate propagation | `-rate-limit <max_rps>` always, from `intensity.max_rps`; `-c` is `min(max_rps, 10)` (at least 1) and `-bs 1` |
| Risk from the selection | see the tag table; the toolbox uses `risk_for`, so an intrusive selection trips RC-8 approval |
| Secret redaction | done by the toolbox for every audit record, approval request and loop record, including refused actions |
| Errors do not crash the loop | `run` never raises; failures return a structured non-ok result |

Statuses: `invalid_input`, `nuclei_not_found`, `templates_not_found`, `timeout`
(partial output kept), `exec_failed`, `nuclei_failed` (non-zero exit),
`malformed_output` (only non-JSON lines), `output_too_large` (over 5 MB),
`off_target_activity`, `wrapper_error`. No findings with exit 0 is a normal `ok`
result with an empty list, unlike nmap where a down host is an error.

## Resolve-once (RC-23)

nuclei has no `-n`-style flag to turn off its own DNS the way nmap does, so
instead the toolbox never gives it a hostname to resolve in the first place:
`target` is always a literal address - either the original target if it was
already an IP/CIDR, or the IP the gate resolved and pinned once for the whole
engagement, if it was a hostname (see
[gate-rate-and-window.md](gate-rate-and-window.md#resolve-once-rc-23)). `-u`
is therefore always built from a literal address, so nuclei makes no
request-time lookup.

The one thing a literal-IP target loses is vhost/SNI routing - a name-based
vhost (the lab's `juice-shop.lab`/`dvwa.lab` included) would otherwise answer
as the wrong site, or TLS would hand back the default certificate. `run`/
`build_argv` take an optional `hostname` keyword, set by `GatedToolbox` only
when `target` is a pinned IP standing in for that hostname; when given, the
wrapper adds `-H "Host: <hostname>"` and `-sni <hostname>` so the request
still goes to the IP the gate approved, addressed - and TLS-negotiated - as
the right site. `hostname` is also recorded in the result (`target_hostname`,
for the report). It is never resolved and can never itself become the
connection target: it only ever reaches the fixed `-H`/`-sni` flags, never a
parameter the planner controls.

## Template pinning (repeatability)

Templates are never downloaded or updated by the tool: `-disable-update-check`
is always passed and no update flags exist. The operator supplies a template
directory (the guard refuses with a clear error if it does not exist) and an
optional label `templates_pin` that is recorded in every result's findings, so
two runs are comparable (RC-20). Updating the community templates remains
possible, but as a separate operator step between engagements, not mid-run.

## Output

`run` returns `ToolOutput(findings, raw, status)`. `findings` (what the planner
sees, after sanitization):

```json
{"scanner": "nuclei", "templates_pin": "templates-2026-11-01",
 "selection": {"severity": ["info","low","medium","high","critical"], "tags": ["tech","detect","..."], "template_ids": []},
 "out_of_band": "off",
 "findings": [{"template_id": "git-config", "name": "Git Configuration - Detect", "severity": "medium",
               "tags": ["config","git","exposure"], "host": "app.acme.com",
               "matched_at": "https://app.acme.com/.git/config", "ip": "203.0.113.5",
               "extracted": ["[core]"], "references": ["..."], "cve": "", "cvss_score": 5.3, "timestamp": "..."}],
 "summary": {"findings": 1, "off_target": 0, "unparsed_lines": 0, "templates_loaded": 2820}}
```

`raw` is the unmodified JSONL, kept in `ExecutionResult.raw_output`; the
execution audit record carries `raw_sha256`. Request and response bodies are not
requested from nuclei and are not copied into the findings.

### Template-coverage instrumentation (RC-26)

`summary.templates_loaded` is nuclei's own count of how many templates it
actually loaded for the scan, captured from `-stats -stats-json -si 1`
(always passed; stats are emitted as periodic JSON lines on **stderr** only -
findings on stdout stay pure JSONL, so `parse_nuclei_jsonl` is unaffected).
`parse_templates_loaded` reads the last such line (nuclei reports `templates`
as a numeric string, e.g. `"templates":"2820"`; both that and a real integer
are accepted) and falls back to the plain-text `Templates loaded for scan: N`
line nuclei prints if `-stats-json` never ticked (a very short scan). Missing
or garbled stats parse to `None`, never a crash.

If `templates_loaded` is `0` or `None`, the result also carries
`coverage_warning`, e.g.:

```json
"coverage_warning": "nuclei reported no templates loaded for this scan - any 'no findings' result here is NOT evidence of a clean scan."
```

This exists so a scan that quietly loaded nothing (a bad `-tags`/`-exclude-tags`
combination, a missing template directory for a given selection, a nuclei
version mismatch) can never be read as "ran clean, found nothing" - a report
consumer that ignores it does so in spite of an explicit signal, not for lack
of one. It does not change `status`/`ToolOutput.status` on its own (a loaded-
but-empty default scan is not itself a tool failure); `off_target_activity`
and other existing error statuses still take precedence when they also apply.

## Usage

```python
from redcell.tools import GatedToolbox, default_tools

tools = default_tools(
    eng,
    nuclei_template_dir="/opt/redcell/nuclei-templates",   # pinned, curated set
    nuclei_templates_pin="templates-2026-11-01",
    nuclei_curated_ids=None,                                # or {"my-check": Risk.ACTIVE_RECON}
)
toolbox = GatedToolbox(eng, gate, log, tools, approver=my_approver)
```

nuclei is registered only when `nuclei_template_dir` is given. For tests, inject
`runner`, `which` and `isdir`. Run the tests (no real nuclei is started):

```bash
uv run --extra dev pytest tests/test_nuclei_tool.py
```

## Known limits

- **The default tag selection does not cover every template its tags imply**
  (RC-26, investigated live in the lab against the pinned v10.5.1 set).
  `http-missing-security-headers` and `cors-misconfig` - both legitimately
  `misconfig`/`exposure` checks - are excluded from the default run because
  they are ALSO tagged `vuln` upstream, and this wrapper's `-exclude-tags`
  (every intrusive/exploit tag not explicitly selected) always wins over
  `-tags` in nuclei, regardless of a template's other tags. Dropping `vuln`
  from the exclude list to recover these two was tested and rejected: against
  the pinned set it pulls in ~1,479 additional templates, including malware
  C2-panel fingerprints and ~100 templates that use POST/fuzzing/redirects -
  an unreviewed, unacceptable widening of what "low-impact default" means.
  **This is an accepted, documented coverage limit, not a bug to route
  around with a blanket tag change.** An operator who specifically wants
  these two (or other individually-audited `vuln`-tagged-but-safe) checks
  can add them to `curated_ids` and have the planner select them by
  `template_ids` - that path does not touch the default tag selection at
  all. See `lab/PLANTED_VULNS.md` correction C-2 for the full investigation.
- **`summary.templates_loaded` can legitimately be `None`** for a very short
  scan if nuclei's `-stats-json` never ticks before the scan ends and the
  plain-text fallback line also wasn't printed (see RC-26 above) - treat a
  `coverage_warning` as "look closer", not necessarily as "nothing ran."
- **The JSONL fixture is hand-written** in nuclei v3 format, not captured from a
  live run. Replace it with a real capture in the lab (RC-19).
- **Flags are unverified against a real binary.** The wrapper passes the nuclei
  v3 long flag names (`-disable-redirects`, `-no-interactsh`,
  `-interactsh-server`, `-exclude-tags`, `-disable-update-check`, `-rate-limit`,
  `-c`, `-bs`). Tests prove they are passed, not that your pinned version
  accepts and honors them. Verify in the lab, including that redirects really
  stay off and that no traffic reaches a public interactsh server.
- A user-level nuclei config file could still influence nuclei. Run it under a
  dedicated account or with an empty config; `config_path` passes `-config`.
- The curated set is as safe as its contents: a template can still do more than
  its tags suggest. Review what goes in the pinned directory; the tag mapping is
  a classification, not a sandbox.
- The off-target check detects after the fact; it cannot stop a request.
- The window is checked between actions; a run is bounded by `run_timeout_s`
  (default 900 s) and the per-request timeout.
