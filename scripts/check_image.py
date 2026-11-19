#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check a built OP-06D image. Standard library only; needs docker.

    python scripts/check_image.py op06d:dev [--platform linux/arm64]

Checks, each in a throwaway container with no network:
  * `op06d version` runs and prints the baked nmap, nuclei and template pins;
  * the image runs as a non-root user;
  * no environment variable in the image has a secret-like name;
  * no key-shaped string (API key, private key) under the paths the image adds
    for OP-06D;
  * the capability-carrying nmap holds exactly cap_net_admin and cap_net_raw,
    and the plain nmap holds none.
Exit 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

EXPECTED_PINS = ("nmap 7.93", "nuclei 3.11.1", "nuclei-templates v10.5.1")
SECRET_NAME = r"(?i)(api_?key|token|secret|passw|credential)"
SCANNED = ("/opt/op06d", "/usr/share/op06d", "/usr/share/doc/op06d", "/work", "/usr/lib/op06d")

# Runs inside the image with its own python: env names, key-shaped strings and
# file capabilities (security.capability xattr, VFS_CAP_REVISION_2 layout).
INSIDE = r"""
import os, re, struct, sys
problems = []
if os.geteuid() == 0:
    problems.append("the image runs as root")
names = [k for k in os.environ if re.search(SECRET_NAME, k)]
if names:
    problems.append(f"secret-like environment variables: {names}")
key = re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
for root in SCANNED:
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            try:
                with open(p, "rb") as fh:
                    if key.search(fh.read()):
                        problems.append(f"key-shaped content in {p}")
            except OSError:
                pass
def caps(path):
    try:
        raw = os.getxattr(path, "security.capability")
    except OSError:
        return set()
    magic, lo, _ilo, hi, _ihi = struct.unpack("<IIIII", raw[:20])
    bits = lo | (hi << 32)
    names = {12: "cap_net_admin", 13: "cap_net_raw"}
    return {names.get(b, str(b)) for b in range(64) if bits >> b & 1} | ({"effective"} if magic & 1 else set())
if caps("/usr/lib/op06d/nmap-raw") != {"cap_net_admin", "cap_net_raw", "effective"}:
    problems.append(f"/usr/lib/op06d/nmap-raw capabilities: {sorted(caps('/usr/lib/op06d/nmap-raw'))}")
if caps("/usr/bin/nmap"):
    problems.append(f"/usr/bin/nmap has capabilities: {sorted(caps('/usr/bin/nmap'))}")
print("\n".join(problems) if problems else "OK")
sys.exit(1 if problems else 0)
"""


def run(image: str, platform: str | None, entrypoint: str | None, *args: str) -> subprocess.CompletedProcess:
    argv = ["docker", "run", "--rm", "--network", "none"]
    if platform:
        argv += ["--platform", platform]
    if entrypoint:
        argv += ["--entrypoint", entrypoint]
    return subprocess.run([*argv, image, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=600)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check a built OP-06D image.")
    p.add_argument("image")
    p.add_argument("--platform", default=None)
    args = p.parse_args(argv)
    failed = False

    v = run(args.image, args.platform, None, "version")
    print(v.stdout.strip())
    missing = [pin for pin in EXPECTED_PINS if pin not in v.stdout]
    if v.returncode != 0 or missing:
        print(f"FAIL  op06d version (exit {v.returncode}; missing {missing}) {v.stderr.strip()}")
        failed = True
    else:
        print("PASS  op06d version prints the baked pins")

    code = INSIDE.replace("SECRET_NAME", repr(SECRET_NAME)).replace("SCANNED", repr(SCANNED))
    c = run(args.image, args.platform, "python3", "-c", code)
    if c.returncode == 0:
        print("PASS  non-root, no secret-like env, no key-shaped content, nmap capabilities as expected")
    else:
        print(f"FAIL  {c.stdout.strip()} {c.stderr.strip()}")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
