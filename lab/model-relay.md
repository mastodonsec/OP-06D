# Model relay (OPT-IN): `op06d run --planner llm` in the lab

The opt-in overlay that gives `op06d run --planner llm` in the lab one path
to one model upstream. It adds to the base lab of [RUNBOOK.md](RUNBOOK.md) on a
host prepared as in [hosts.md](hosts.md).

The base lab in [RUNBOOK.md](RUNBOOK.md) never changes. For an LLM-planner run, an overlay adds one
relay container and one more internal network:

```
scanner 172.31.77.20 (labnet) + 172.31.78.20 (relaynet)
   └─ relaynet (internal) ─> model-relay 172.31.78.2  ─ relay_egress ─> ONE upstream
juice-shop, dvwa: labnet only (never on relaynet)
```

| Mode | Overlay | Relay listens | Upstream | Scanner points op06d at |
|---|---|---|---|---|
| `local` | `lab/model-relay.local.yml` | `172.31.78.2:11434` | `host.docker.internal:11434` (host Ollama) | `--llm-endpoint http://172.31.78.2:11434 --llm-allow-private 172.31.78.2` |
| `anthropic` | `lab/model-relay.anthropic.yml` | `172.31.78.2:443` | `api.anthropic.com:443`, raw TCP passthrough | the pinned hosted endpoint; inside the scanner `api.anthropic.com` resolves to the relay |

- **One upstream per stack.** The two overlays define the same relay; the
  launcher refuses to start one mode while the other is running.
- **The relay** (`lab/relay/`): alpine 3.24.4 pinned by digest, HAProxy in TCP
  mode. Its entrypoint resolves the one upstream, installs iptables rules that
  allow only that address and port (IPv6: nothing), then runs HAProxy as an
  unprivileged user with every capability dropped. In `anthropic` mode it
  forwards a connection only if the TLS ClientHello's SNI is
  `api.anthropic.com`; TLS is never terminated, so the certificate is
  validated end to end by the scanner against the real host.
- **Why the SNI filter:** the address `api.anthropic.com` resolves to also
  serves other names (through plain passthrough, valid certificates come back
  for `example.com`, `claude.ai` and `anthropic.com`). Without the filter the
  scanner could reach those. A mismatched `Host` header behind the right SNI
  gets `403 Forbidden` from the edge.
- **The scanner image** in the overlay is the base lab scanner, unchanged: the
  OP-06D image already contains the anthropic SDK (pins and hashes from
  `uv.lock`).
- **The API key** is never in a compose file, image, `.env` or the container's
  configuration. `run anthropic` passes it to one `docker compose exec` by
  name (`-e ANTHROPIC_API_KEY`), and Docker reads the value from your shell.
- **Engagement policy:** `lab/engagement.yaml` has no `planner:` block, so only
  `local` is allowed. `anthropic` needs `lab/engagement-llm-hosted.yaml` (the
  same engagement plus `planner.allowed_providers: [local, anthropic]`), named
  explicitly; the launcher refuses otherwise, and op06d refuses again inside.

## Ollama on the host (Docker Desktop, Windows)

Measured on Docker Desktop (WSL2 backend, Docker 29.9.3): a container reaches
a host service bound to **127.0.0.1 only** through `host.docker.internal`
(192.168.65.254); the host sees the connection as coming from 127.0.0.1. So
Ollama does **not** need to listen on the network for the relay:

- Leave `OLLAMA_HOST` unset (default `127.0.0.1:11434`), and in the Ollama app
  turn **off** Settings > "Expose Ollama to the network" (that toggle makes it
  listen on `0.0.0.0` and `[::]`, i.e. on the LAN). Quit and restart Ollama.
- Confirm: `Get-NetTCPConnection -LocalPort 11434 -State Listen | Select-Object LocalAddress`
  must show only `127.0.0.1` (and/or `::1`).
- Defence in depth if you ever do need it exposed: an inbound block rule for
  the LAN (elevated PowerShell):
  `New-NetFirewallRule -DisplayName "Ollama 11434 block inbound" -Direction Inbound -Protocol TCP -LocalPort 11434 -RemoteAddress Any -Action Block`
  (Docker Desktop's path arrives as loopback, so this does not break the relay.)
- Pull the planner's default local model once: `ollama pull llama3.1:8b-instruct-q5_K_M`

## Ollama on the host (native Linux, e.g. Kali)

Native Linux Docker has no `host.docker.internal`. The local overlay maps it,
for the relay container only, to `host-gateway`, which on Linux is the
`docker0` bridge address (normally `172.17.0.1`), not loopback. A
127.0.0.1-only Ollama is therefore not reachable from the relay, and
`0.0.0.0` would put it on the LAN. Bind it to the bridge address instead:

bash (Linux):

```bash
ip -4 -br addr show docker0
```

bash (Linux):

```bash
sudo systemctl edit ollama
```

In the editor, add (with the address `ip` printed):

```
[Unit]
After=docker.service
[Service]
Environment="OLLAMA_HOST=172.17.0.1:11434"
```

bash (Linux):

```bash
sudo systemctl restart ollama
```

bash (Linux):

```bash
export OLLAMA_HOST=172.17.0.1:11434
```

bash (Linux):

```bash
ss -ltnH 'sport = :11434'
```

- `ss` must list only `172.17.0.1:11434`: no `0.0.0.0`, `*`, `[::]` or LAN
  address. Ollama starts after Docker because the address exists only once
  `docker0` is up.
- `export OLLAMA_HOST` in the shell you run `ollama pull` and
  `lab/model_relay.py` from: the launcher's host-side model probe reads it
  (unset, it probes `127.0.0.1:11434`). The variable does not persist: re-run
  `export OLLAMA_HOST=...` in every new terminal.
- `check local` does not need a model pulled; `run local` does.
- Any container on a non-internal Docker network can reach that address too;
  the lab targets and the scanner cannot (internal networks without a gateway
  address; `check local` probes it).
- Linux accepts traffic for `172.17.0.1` on any interface, so a LAN machine
  that routes `172.17.0.0/16` through yours could reach it. Defence in depth:
  `sudo iptables -I INPUT -i <your LAN interface> -p tcp --dport 11434 -j DROP`.

## Ollama on the host (macOS)

Same as on Windows:
leave `OLLAMA_HOST` unset, keep Ollama on `127.0.0.1`, and confirm with
`lsof -nP -iTCP:11434 -sTCP:LISTEN` (only `127.0.0.1`).

## Commands (repository root)

Start from a torn-down lab. `up` brings up its own copy of the lab, asks Docker
what is running first, and starts nothing over a running stack. Over the base
lab it prints:

```
refused: the base lab is already running (dvwa, juice-shop, redirect, scanner). The relay starts its own copy of the lab: tear the base lab down first with `docker compose -f lab/docker-compose.yml down`, then run `up` again
```

Over a relay stack (here a local one) it prints:

```
refused: a local relay stack is already running. Tear it down first with `uv run python lab/model_relay.py down`, then run `up` again
```

The `uv run ...` and `ollama ...` lines are the same in PowerShell 7 and
bash/zsh. The `$env:...`, `Read-Host` and `Remove-Item Env:...` lines, and
the backtick line continuations, are PowerShell only. `check anthropic` and
`run anthropic` are untested on Linux and macOS.

Build once (internet needed; builds the base scanner if missing, then the
overlay scanner and the relay):

PowerShell 7 or bash / zsh:

```bash
uv run python lab/model_relay.py build local
```

**local** (host Ollama):

PowerShell 7 or bash / zsh:

```bash
uv run python lab/model_relay.py up local
```

PowerShell 7 or bash / zsh:

```bash
uv run python lab/model_relay.py check local
```

Continue only if it printed `RESULT: PASS`.

`run` re-checks isolation, then runs op06d and verifies the report:

PowerShell 7 or bash / zsh:

```bash
uv run python lab/model_relay.py run local
```

PowerShell 7 or bash / zsh:

```bash
uv run python lab/model_relay.py down
```

**anthropic** (egress via the relay only):

PowerShell 7:

```powershell
$env:ANTHROPIC_API_KEY = Read-Host -MaskInput "Anthropic API key"
```

Check the key's length before going on; see **Pasting the key** below.

PowerShell 7:

```powershell
uv run python lab/model_relay.py up anthropic --engagement lab/engagement-llm-hosted.yaml
```

PowerShell 7:

```powershell
uv run python lab/model_relay.py check anthropic
```

Continue only if it printed `RESULT: PASS`.

PowerShell 7:

```powershell
uv run python lab/model_relay.py run anthropic --engagement lab/engagement-llm-hosted.yaml
```

PowerShell 7:

```powershell
uv run python lab/model_relay.py down
```

PowerShell 7:

```powershell
Remove-Item Env:ANTHROPIC_API_KEY
```

**Pasting the key.** `Read-Host -MaskInput` reads Ctrl+V as a single
character, not as a paste, so the variable ends up one character long. Paste
with a right-click or Ctrl+Shift+V, then check the length before going on (a
real key is around 100 characters and starts with `sk-ant-`):

PowerShell 7:

```powershell
$env:ANTHROPIC_API_KEY.Length
```

`up anthropic`, `run anthropic` and `op06d run --llm-provider anthropic`
refuse a key that is empty, shorter than 40 characters or does not start with
`sk-ant-`, before any stack, run or evidence exists; the error gives the
length, never the value. The leak scan at the end of `run` refuses to scan
(exit 2, neither PASS nor FAIL) if the key it is told to look for is shorter
than 20 characters, because a value that short matches unrelated bytes.

If a run ends with `model_failure`, the cause is recorded without key
material: the audit log's loop-end entry carries `cause` (error class, HTTP
status, API error type), and the report's Planner section shows a "Failure
cause" row, for example `authentication_error (HTTP 401)`.

`up` returns only once both lab targets answer HTTP from the scanner (it polls
for up to 180 s), so `check` can follow it directly. If a target never answers,
or its container has exited, `up` prints `failed: ...` naming the target and
exits 1, leaving the stack up for inspection; run `down` afterwards.

`run` limits the acceptance run (`--max-iterations 12 --max-actions 6
--max-wall-clock 1800 --max-tokens 300000` by default; each is a flag). The
report, evidence store and audit log land in
`lab/captures/_relay_ephemeral/<mode>/run/` (git-ignored); `run` fails if the
report has no Planner section, nothing executed through the gate, a target
was out of scope, the audit log does not verify, or key material appears in
any file there.

`check` runs three layers and needs all to PASS:

1. host side (`docker inspect`): labnet and relaynet internal, relay_egress the
   only routable network with only the relay on it; exact network membership
   of every container; no published ports, privileges or host networking; the
   relay's command is the one mode; the scanner's name override is exactly
   `api.anthropic.com -> 172.31.78.2` (anthropic) or none (local); the relay's
   is exactly `host.docker.internal:host-gateway` (local) or none (anthropic);
   no key in the scanner's container configuration;
2. inside the scanner (`lab/check_relay_isolation.sh`): every outbound attempt
   of `lab/check_isolation.sh` (a default-suite test keeps them identical), the
   relaynet gateway `172.31.78.1` (relaynet also sets `inhibit_ipv4`), the
   relay's other ports, the relay's outward address, name resolution, and in
   anthropic mode the SNI filter;
3. inside the relay, as its unprivileged user (`check_relay_egress.sh`): only
   the upstream is reachable, HAProxy holds no capabilities; plus a probe from
   the dvwa target to the relay network, which must fail.

With the overlay up, `lab/check_isolation.sh` FAILS by design (the scanner has
two interfaces). After `down`, rerun [Step 4](RUNBOOK.md#step-4-isolation-gate-blocking) before any non-relay scan.

## Automated acceptance and the live-model gate

Lab acceptance, one upstream per invocation. Local:

PowerShell 7:

```powershell
$env:OP06D_LAB = "1"; $env:OP06D_LLM_PROVIDER = "local"
```

PowerShell 7:

```powershell
uv run pytest -m lab -rs --basetemp .pytest-tmp tests/integration/test_lab_relay_planner_run.py
```

Anthropic:

PowerShell 7:

```powershell
$env:OP06D_LLM_PROVIDER = "anthropic"; $env:ANTHROPIC_API_KEY = Read-Host -MaskInput "Anthropic API key"
```

PowerShell 7:

```powershell
uv run pytest -m lab -rs --basetemp .pytest-tmp tests/integration/test_lab_relay_planner_run.py
```

PowerShell 7:

```powershell
Remove-Item Env:OP06D_LLM_PROVIDER, Env:ANTHROPIC_API_KEY
```

Live-model gate through the relay (overlay up, see above), local:

PowerShell 7 or bash / zsh:

```bash
docker compose -f lab/docker-compose.yml -f lab/model-relay.local.yml exec -T -e OP06D_LIVE_MODEL=1 -e OP06D_LIVE_PROVIDER=local -e OP06D_LLM_ENDPOINT=http://172.31.78.2:11434 -e OP06D_LLM_ALLOW_PRIVATE=172.31.78.2 scanner python3 -m pytest -p no:cacheprovider --basetemp /tmp/live-gate -rs /op06d/tests/test_live_model_gate.py
```

... and anthropic (key from your shell, by name):

PowerShell 7:

```powershell
docker compose -f lab/docker-compose.yml -f lab/model-relay.anthropic.yml exec -T `
  -e OP06D_LIVE_MODEL=1 -e OP06D_LIVE_PROVIDER=anthropic -e ANTHROPIC_API_KEY `
  scanner python3 -m pytest -p no:cacheprovider --basetemp /tmp/live-gate -rs /op06d/tests/test_live_model_gate.py
```

The integration test brings the stack down at the end; for manual runs,
always finish with `uv run python lab/model_relay.py down` (it also removes the
relay and its networks; a plain `docker compose -f lab/docker-compose.yml down`
would leave the relay running as an orphan).
