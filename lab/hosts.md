# OP-06D lab hosts

Host setup for the lab on each platform, done once before
[Step 0](RUNBOOK.md#step-0-preconditions) of the [runbook](RUNBOOK.md).

## Windows

- Docker Desktop is running (Linux containers / WSL2 engine). `docker info` works.
- `uv` is installed (it runs the host-side checks in [Step 4](RUNBOOK.md#step-4-isolation-gate-blocking)).

## Kali / Linux

- **Docker Engine plus the Compose v2 plugin.** Commands are `docker compose`
  (a space), never `docker-compose` (v1, Python, unsupported). Check:
  `docker compose version` must print v2 or later.
- **Kali (and Debian testing):** `sudo apt install -y docker.io docker-compose docker-buildx`,
  then `sudo systemctl enable --now docker`. Kali's `docker-compose` package
  is meant to be Compose v2 and to install the `docker compose` plugin.
- **If `docker compose version` does not print v2 or later on Kali,** replace
  Kali's packages with Docker's own: package `docker-compose-plugin` (with
  `docker-ce docker-ce-cli containerd.io docker-buildx-plugin`) from Docker's
  Debian repository `https://download.docker.com/linux/debian`, suite
  `trixie`, component `stable`. Kali rolling has no suite of its own there,
  so it uses Debian's current stable one. Run one command at a time:

bash (Kali):

```bash
sudo apt remove -y docker.io docker-compose docker-buildx
```

bash (Kali):

```bash
sudo apt install -y ca-certificates curl
```

bash (Kali):

```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

bash (Kali):

```bash
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
```

bash (Kali):

```bash
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

bash (Kali):

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" | sudo tee /etc/apt/sources.list.d/docker.list
```

bash (Kali):

```bash
sudo apt update
```

bash (Kali):

```bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

bash (Kali):

```bash
sudo systemctl enable --now docker
```

bash (Kali):

```bash
docker compose version
```

`docker compose version` must print v2 or later.

- **docker group vs sudo:** either prefix every docker command (and
  `uv run python lab/check_isolation.py`) with `sudo`, or add yourself to the
  `docker` group once: `sudo usermod -aG docker "$USER"`, then reboot the VM
  or log out and back in; a terminal opened before that still fails with
  permission denied on `/var/run/docker.sock`. Membership of `docker` is
  equivalent to root on that machine.
- **uv:** `curl -LsSf https://astral.sh/uv/install.sh | sh` (or `pipx install uv`).
  If `uv --version` works after the installer, there is nothing to source.
  (On Kali `~/.local/bin` is already on `PATH`, and the `~/.local/bin/env`
  file the installer mentions may not exist.)

The captures folder for [Step 0](RUNBOOK.md#step-0-preconditions):

On Linux and macOS: `mkdir -p lab/captures && echo "created lab/captures"`.

## macOS

Docker Desktop, as on [Windows](#windows). The Compose v2 check, uv and the
captures folder are as in [Kali / Linux](#kali--linux).

## ARM hosts

- **ARM hosts (Apple Silicon, ARM Linux):** dvwa is pinned to `linux/amd64`
  (its image has no arm64 build) and runs under emulation; the scanner is built
  for the host's own architecture (the arm64 nuclei build on ARM), and
  juice-shop, nginx and the relay are multi-arch: they all run natively.
  Docker Desktop for Mac emulates amd64 out of the box (Settings > General >
  "Use Rosetta for x86_64/amd64 emulation on Apple Silicon" makes it faster).
  On ARM Linux install `qemu-user-static binfmt-support` first. Expect DVWA to
  be slower than on amd64.

## Running the runbook from bash or zsh

Every `docker compose -f $LAB ...` line in [the runbook](RUNBOOK.md) works the same in bash
or zsh once the variable is set the shell's way (`LAB=lab/docker-compose.yml`),
except that PowerShell's escaped newline (backtick n) inside `-w "..."` is
`\n` there.
