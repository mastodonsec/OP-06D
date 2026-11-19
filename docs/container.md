# Running OP-06D from the container image

The image `ghcr.io/mastodonsec/op06d` holds OP-06D and the toolchain validated
in the isolated lab:

| Component | Version |
|---|---|
| nmap | 7.93 (Debian package `7.93+dfsg1-1`) |
| nuclei | v3.11.1 |
| nuclei-templates | v10.5.1, at `/opt/nuclei-templates`, read-only |
| Python dependencies | hash-pinned from `uv.lock`, including the hosted LLM provider (`llm-anthropic`) and PDF reports (weasyprint) |

It is built for `linux/amd64` and `linux/arm64` from the repository
`Dockerfile`; the lab's scanner is the same image plus test tools (see
[lab/RUNBOOK.md](../lab/RUNBOOK.md)). It fetches nothing at run time: nuclei's
update check is off and the template set is read-only.

Tags: `<version>` and `<version>-nmap7.93-nuclei3.11.1-tpl10.5.1`. Pin by digest
(`ghcr.io/mastodonsec/op06d@sha256:...`) and verify the signature first (see
[Verify the image](#verify-the-image)).

## What the image does for you

- **Entrypoint `op06d`.** `docker run IMAGE version` prints OP-06D's version and
  the tool pins; `docker run IMAGE run ...` runs an engagement.
- **Baked toolchain.** `op06d run` uses the image's template directory and
  records the image's nmap, nuclei and template versions in the report, so you
  pass none of `--template-dir`, `--templates-pin`, `--nmap-version`,
  `--nuclei-version`. A flag that names something else is refused (the report
  must not claim versions that did not run).
- **Non-root.** The image runs as uid 10001 by default; on Linux run it as your
  own user (`--user`).
- **Output safety.** `--out` must be a writable directory on a mounted volume.
  Otherwise `op06d run` refuses before any action: the audit log written there
  is the liability record, and a `--rm` container must not take it with it.

## Mounts

| Mount | Mode | In the container |
|---|---|---|
| the engagement file | read-only | `/work/engagement.yaml` (pass `--engagement engagement.yaml`) |
| one output directory | read-write | `/out` (pass `--out /out`): report, `evidence.db`, `audit/` |

Create the output directory before the run, owned by the user the container
runs as; if Docker creates it, it is owned by root and the run is refused.

Secrets are passed only at run time, never baked into the image: put
`ANTHROPIC_API_KEY=...` in a file readable only by you and add
`--env-file <that file>` for `--planner llm --llm-provider anthropic`.

## Linux (engagements)

Host networking plus two capabilities give nmap raw sockets for SYN scans and
full host discovery, as your own user. Never use `--privileged`.

```bash
mkdir -p out
docker run --rm \
  --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:<digest> \
  run --engagement engagement.yaml --out /out
```

How raw scanning works as a non-root user: the image carries a second copy of
nmap, `/usr/lib/op06d/nmap-raw`, with the file capabilities `cap_net_raw` and
`cap_net_admin`. OP-06D runs it, with `NMAP_PRIVILEGED=1`, only when the
container holds both capabilities (`--cap-add NET_RAW --cap-add NET_ADMIN`)
and `no-new-privileges` is not set; otherwise it runs the plain
`/usr/bin/nmap`. (Starting a binary whose file capabilities exceed the
container's capabilities fails outright, so the capable copy is never started
without them.) Without the capabilities nmap still works, as a TCP connect
scan, and the report's Limitations say so: host discovery then used only TCP
80 and 443, so hosts without either port open may have been reported as down.
Do not add `--security-opt no-new-privileges`: it disables the file
capabilities, and the scan falls back to a connect scan.

Local LLM (Ollama on the same host, `--planner llm --llm-provider local`):
with `--network host` the container shares the host's loopback, so the
default endpoint `http://127.0.0.1:11434` reaches an Ollama bound to
127.0.0.1. See [llm-planner.md](llm-planner.md).

## Windows and macOS (Docker Desktop)

Docker Desktop runs containers in a VM. Its host networking forwards TCP and
UDP only, so nmap cannot send raw packets to your network: run without the
capabilities and without `--network host`. nmap then does a TCP connect scan,
and the report's Limitations say so (see above). This is supported for the lab
and for connect-scan recon; use Linux for engagements that need SYN scans. Do
not add `--cap-add NET_RAW --cap-add NET_ADMIN` here: raw packets would leave
the VM through Docker Desktop's user-space network stack, and the results
would not be reliable.

PowerShell 7:

```powershell
New-Item -ItemType Directory -Force out | Out-Null
docker run --rm `
  -v "${PWD}/engagement.yaml:/work/engagement.yaml:ro" `
  -v "${PWD}/out:/out" `
  ghcr.io/mastodonsec/op06d@sha256:<digest> `
  run --engagement engagement.yaml --out /out
```

macOS (zsh), Apple Silicon runs the native arm64 image:

```zsh
mkdir -p out
docker run --rm \
  -v "$PWD/engagement.yaml:/work/engagement.yaml:ro" \
  -v "$PWD/out:/out" \
  ghcr.io/mastodonsec/op06d@sha256:<digest> \
  run --engagement engagement.yaml --out /out
```

Docker Desktop maps bind-mount ownership to your user, so `--user` is not
needed there. Local LLM: inside a Docker Desktop container the host is
`host.docker.internal` (192.168.65.254 on current versions; check with
`docker run --rm --entrypoint getent IMAGE hosts host.docker.internal`). The
local endpoint must be an IP literal, so pass
`--llm-endpoint http://192.168.65.254:11434 --llm-allow-private 192.168.65.254`.

## Antivirus detections

The image contains nuclei templates and nmap NSE scripts with exploit-detection
payloads, so desktop antivirus may flag files when the image's layers are
unpacked or scanned on the host (for example by an image scanner). These are
expected detections of the scan content, not of OP-06D. Verify the image's
signature (see [Verify the image](#verify-the-image)) rather than disabling
antivirus, and if needed exclude only the folder where the scanner unpacks
layers.

## Verify the image

Each release image is signed keyless with cosign by the repository's release
workflow (GitHub OIDC; no signing key exists) and carries an SBOM and build
provenance as attestations. The signature covers the image index, which
references the SBOM and provenance.

```bash
cosign verify ghcr.io/mastodonsec/op06d@sha256:<digest> \
  --certificate-identity "https://github.com/mastodonsec/OP-06D/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A valid signature prints the verified claims as JSON and exits 0; anything else
is a failed verification. Then read the SBOM (SPDX, per platform):

```bash
docker buildx imagetools inspect ghcr.io/mastodonsec/op06d@sha256:<digest> \
  --format '{{ json (index .SBOM "linux/amd64").SPDX }}'
```

and the provenance with `--format '{{ json (index .Provenance "linux/amd64") }}'`.

## Licenses in the image

`/usr/share/doc/op06d/licenses/`: OP-06D (AGPL-3.0-or-later), nmap (the
Debian copyright file, NPSL), nuclei and nuclei-templates (MIT). The Python
dependencies' licenses are in their `dist-info` directories under `/opt/op06d`.

## Building it yourself

```bash
docker buildx build --platform linux/amd64 --load -t op06d:local .
docker run --rm op06d:local version
python3 scripts/check_image.py op06d:local
```

`scripts/check_image.py` checks that the image runs non-root, prints the baked
pins, holds no secret-like environment variable or key-shaped file content, and
that only the `nmap-raw` copy carries capabilities. The build verifies every
download against a pinned SHA-256 and fails on a mismatch.
