# SPDX-License-Identifier: AGPL-3.0-or-later
"""The toolchain baked into the OP-06D container image.

The image records, at build time, the nmap and nuclei versions it installed
and the pinned nuclei template set, in a JSON file named by the environment
variable ``OP06D_TOOLCHAIN``. ``op06d run`` inside the image uses those values
by default (template directory, template pin, tool versions in the report), so
an operator does not pass them. A flag that contradicts a baked value is
refused: the report must never claim versions that did not run.

Outside the image (no ``OP06D_TOOLCHAIN``) nothing is baked and the flags
behave as before.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from op06d import __version__

TOOLCHAIN_ENV = "OP06D_TOOLCHAIN"
# The keys the image's toolchain file must carry.
REQUIRED_KEYS = ("nmap", "nuclei", "templates_pin", "template_dir")


class ToolchainError(Exception):
    """The baked toolchain is unreadable, or a flag contradicts it."""


@dataclass(frozen=True)
class Toolchain:
    nmap: str
    nuclei: str
    templates_pin: str
    template_dir: str
    extra: Mapping[str, str]


def load_toolchain(environ: Mapping[str, str] | None = None) -> Toolchain | None:
    """The baked toolchain, or None when not running in the image."""
    environ = os.environ if environ is None else environ
    path = environ.get(TOOLCHAIN_ENV)
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ToolchainError(f"cannot read the image toolchain file {path}: {exc}") from None
    if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k] for k in REQUIRED_KEYS):
        raise ToolchainError(f"the image toolchain file {path} must set {', '.join(REQUIRED_KEYS)}")
    extra = {k: str(v) for k, v in data.items() if k not in REQUIRED_KEYS}
    return Toolchain(data["nmap"], data["nuclei"], data["templates_pin"], data["template_dir"], extra)


def _same_version(a: str, b: str) -> bool:
    return a.strip().lower().removeprefix("v") == b.strip().lower().removeprefix("v")


def _same_path(a: str, b: str) -> bool:
    return os.path.normpath(a) == os.path.normpath(b)


@dataclass(frozen=True)
class RunToolchain:
    template_dir: str | None
    templates_pin: str
    tool_versions: dict[str, str]


def resolve_run_toolchain(
    baked: Toolchain | None,
    *,
    template_dir: str | None,
    templates_pin: str | None,
    nmap_version: str | None,
    nuclei_version: str | None,
) -> RunToolchain:
    """What ``op06d run`` records and uses. Without a baked toolchain, the
    flags as given. With one, the baked values, and a refusal for any flag
    that names something else."""
    if baked is None:
        versions = {k: v for k, v in (("nmap", nmap_version), ("nuclei", nuclei_version)) if v}
        return RunToolchain(template_dir, templates_pin or "", versions)
    conflicts = []
    for flag, given, have, same in (
        ("--template-dir", template_dir, baked.template_dir, _same_path),
        ("--templates-pin", templates_pin, baked.templates_pin, _same_version),
        ("--nmap-version", nmap_version, baked.nmap, _same_version),
        ("--nuclei-version", nuclei_version, baked.nuclei, _same_version),
    ):
        if given and not same(given, have):
            conflicts.append(f"{flag} {given!r} (the image has {have!r})")
    if conflicts:
        raise ToolchainError(
            "this image runs a fixed toolchain, and these flags name something else: "
            + "; ".join(conflicts)
            + ". Omit them (the image's values are used and recorded in the report), or use an "
            "image built with the versions you want."
        )
    return RunToolchain(baked.template_dir, baked.templates_pin,
                        {"nmap": baked.nmap, "nuclei": baked.nuclei})


def version_text(baked: Toolchain | None) -> str:
    lines = [f"op06d {__version__}"]
    if baked is None:
        lines.append("toolchain: not baked (host install): nmap and nuclei are whatever is on PATH")
        return "\n".join(lines)
    lines += [
        f"nmap {baked.nmap}",
        f"nuclei {baked.nuclei}",
        f"nuclei-templates {baked.templates_pin} ({baked.template_dir}, read-only)",
    ]
    lines += [f"{k} {v}" for k, v in sorted(baked.extra.items())]
    return "\n".join(lines)
