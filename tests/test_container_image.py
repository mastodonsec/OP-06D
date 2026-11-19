# SPDX-License-Identifier: AGPL-3.0-or-later
"""Static checks of the container image definition: pinned inputs, a minimal
build context, no secrets baked in, and the lab stage running the mounted code.
The image itself is checked by scripts/check_image.py (CI and local)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
LOCKED = {p["name"].lower(): p["version"]
          for p in tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]}
SECRET_WORDS = re.compile(r"(?i)(api[_-]?key|token|secret|passw|credential|private[_-]?key)")


def _pins(text: str) -> dict[str, str]:
    return dict(re.findall(r"^([A-Za-z0-9_.\-]+)==([^\s;\\]+)", text, re.M))


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-lab.txt"])
def test_image_requirements_are_hash_pinned_from_uv_lock(name):
    text = (ROOT / "docker" / name).read_text(encoding="utf-8")
    pins = _pins(text)
    assert {"pydantic", "pyyaml", "anthropic", "weasyprint"} <= {n.lower() for n in pins}
    for pkg, version in pins.items():
        assert LOCKED.get(pkg.lower().replace("_", "-")) == version, pkg
    assert text.count("--hash=sha256:") >= len(pins)
    assert "op06d" not in {n.lower() for n in pins}  # the project itself is built from the checkout


def test_lab_requirements_add_only_test_tools():
    image = _pins((ROOT / "docker" / "requirements.txt").read_text(encoding="utf-8"))
    lab = _pins((ROOT / "docker" / "requirements-lab.txt").read_text(encoding="utf-8"))
    assert {k: v for k, v in lab.items() if k in image} == image
    assert "pytest" in lab


def test_build_requirements_are_hash_pinned():
    text = (ROOT / "docker" / "build-requirements.txt").read_text(encoding="utf-8")
    assert re.search(r"^setuptools==[0-9.]+ \\$", text, re.M) and "--hash=sha256:" in text


def test_every_stage_starts_from_the_recorded_base_image():
    # Dependabot bumps the digest on the FROM lines only; the recorded ARG must follow.
    base = re.search(r"^ARG BASE_IMAGE=(\S+)$", DOCKERFILE, re.M).group(1)
    froms = re.findall(r"^FROM\s+(\S+)", DOCKERFILE, re.M)
    stages = set(re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", DOCKERFILE, re.M))
    images = [ref for ref in froms if ref not in stages]
    assert len(images) == 3 and set(images) == {base}, (base, images)


def test_every_downloaded_input_is_pinned_and_verified():
    assert re.search(r"^ARG BASE_IMAGE=debian:bookworm-slim@sha256:[0-9a-f]{64}$", DOCKERFILE, re.M)
    for arg in ("NUCLEI_ZIP_SHA256_AMD64", "NUCLEI_ZIP_SHA256_ARM64", "TEMPLATES_TARBALL_SHA256"):
        assert re.search(rf"^ARG {arg}=[0-9a-f]{{64}}$", DOCKERFILE, re.M), arg
    assert DOCKERFILE.count("sha256sum -c -") == 2
    assert "nmap=${NMAP_PACKAGE}" in DOCKERFILE and "ARG NMAP_PACKAGE=7.93+dfsg1-1" in DOCKERFILE
    assert "--require-hashes" in DOCKERFILE and ":latest" not in DOCKERFILE


def test_the_build_context_holds_only_what_the_image_needs():
    ignore = [ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
              if ln.strip() and not ln.startswith("#")]
    assert ignore[0] == "*"
    assert {ln[1:] for ln in ignore if ln.startswith("!")} == {"pyproject.toml", "LICENSE", "NOTICE", "src/", "docker/"}
    sources = re.findall(r"^COPY (?!--from)(.+) \S+$", DOCKERFILE, re.M)
    copied = {s for line in sources for s in line.split()}
    assert copied <= {"pyproject.toml", "LICENSE", "NOTICE", "src", "docker/requirements.txt",
                      "docker/build-requirements.txt", "docker/requirements-lab.txt"}


def test_no_secret_is_baked_into_the_image_definition():
    for line in DOCKERFILE.splitlines():
        if re.match(r"^\s*(ARG|ENV|LABEL)\b", line) or re.match(r"^\s+[A-Z_]+=", line):
            assert not SECRET_WORDS.search(line), line
    assert "--secret" not in DOCKERFILE and "ANTHROPIC" not in DOCKERFILE


def test_the_image_runs_non_root_with_op06d_as_entrypoint():
    product = DOCKERFILE.split("AS product", 1)[1].split("AS lab", 1)[0]
    assert "USER 10001:10001" in product
    assert 'ENTRYPOINT ["op06d"]' in product
    assert "setcap cap_net_raw,cap_net_admin+eip /usr/lib/op06d/nmap-raw" in product
    assert "OP06D_NMAP_RAW=/usr/lib/op06d/nmap-raw" in product and "NMAP_PRIVILEGED" not in product.split("ENV", 1)[1]


def test_the_lab_stage_runs_the_mounted_code_first():
    lab = DOCKERFILE.split("AS lab", 1)[1]
    assert 'ENV PYTHONPATH="/op06d/src"' in lab
    assert lab.rstrip().endswith("FROM product")  # the default target is the product image
