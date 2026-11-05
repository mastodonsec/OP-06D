"""Engagement-file schema and loader (RC-6).

The engagement file is the safety boundary: the guardrail gate reads scope,
window and intensity from it. It is therefore validated strictly on load and
the resulting models are immutable. Any problem raises ``EngagementError``;
there is no partial or "best effort" load.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

# RFC 1123 hostname label; an optional leading "*." wildcard is allowed.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?:\*\.)?{_LABEL}(?:\.{_LABEL})*$")

# Networks broader than this are almost certainly a mistake in a scope file.
_MIN_PREFIX_V4 = 8
_MIN_PREFIX_V6 = 32

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class EngagementError(Exception):
    """The engagement file could not be read or failed validation."""


def normalize_target(raw: str) -> str:
    """Validate one scope entry; return it normalized (lowercased hosts,
    canonical IP/CIDR form). Accepts hostnames, ``*.`` wildcards, IPs, CIDRs."""
    value = raw.strip().lower()
    if not value:
        raise ValueError("empty scope entry")

    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR {raw!r}: {exc}") from None
        floor = _MIN_PREFIX_V4 if net.version == 4 else _MIN_PREFIX_V6
        if net.prefixlen < floor:
            raise ValueError(f"CIDR {raw!r} is too broad (minimum /{floor})")
        return str(net)

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    host = value.rstrip(".")
    if len(host) > 253 or not _HOST_RE.match(host):
        raise ValueError(f"invalid hostname or address {raw!r}")
    if host.startswith("*.") and host.count(".") < 2:
        # "*.com" would cover an entire TLD.
        raise ValueError(f"wildcard {raw!r} is too broad")
    return host


class _Frozen(BaseModel):
    # extra=forbid: a typo like "out_of_scop" must fail, not silently widen scope.
    model_config = ConfigDict(extra="forbid", frozen=True)


class Authorization(_Frozen):
    client: NonEmptyStr
    signed_scope_ref: NonEmptyStr
    authorized_by: NonEmptyStr
    window: tuple[datetime, datetime]

    @field_validator("window")
    @classmethod
    def _check_window(cls, v: tuple[datetime, datetime]) -> tuple[datetime, datetime]:
        for dt in v:
            if dt.tzinfo is None or dt.utcoffset() is None:
                raise ValueError("window times must include a timezone (e.g. 'Z')")
        start, end = (dt.astimezone(timezone.utc) for dt in v)
        if end <= start:
            raise ValueError("window end must be after window start")
        return start, end


class Scope(_Frozen):
    in_scope: list[NonEmptyStr] = Field(min_length=1)
    out_of_scope: list[NonEmptyStr] = Field(default_factory=list)

    @field_validator("in_scope", "out_of_scope")
    @classmethod
    def _check_targets(cls, v: list[str]) -> list[str]:
        return [normalize_target(item) for item in v]


class Intensity(_Frozen):
    max_rps: int = Field(gt=0, le=10_000)
    destructive: bool = False


# Public out-of-band (interactsh) servers: callback data about a client's systems
# must never go to a third party, so these are refused outright.
PUBLIC_INTERACTSH_DOMAINS = (
    "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
    "interact.sh", "interactsh.com",
)


def _is_public_interactsh(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in PUBLIC_INTERACTSH_DOMAINS)


class Engagement(_Frozen):
    engagement: NonEmptyStr
    authorization: Authorization
    scope: Scope
    intensity: Intensity
    objective: NonEmptyStr
    # Optional self-hosted interactsh server for out-of-band checks. Absent means
    # out-of-band detection stays OFF (nuclei is run with -no-interactsh).
    interactsh_server: NonEmptyStr | None = None

    @field_validator("interactsh_server")
    @classmethod
    def _check_interactsh(cls, v: str | None) -> str | None:
        if v is None:
            return None
        host = normalize_target(v)
        if "/" in host or host.startswith("*") or _is_public_interactsh(host):
            raise ValueError(
                "interactsh_server must be a plain self-hosted hostname, never a public "
                "interactsh server"
            )
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        raise ValueError("interactsh_server must be a hostname, not an IP address")

    @model_validator(mode="after")
    def _no_exact_overlap(self) -> Engagement:
        dup = set(self.scope.in_scope) & set(self.scope.out_of_scope)
        if dup:
            raise ValueError(
                f"entries listed as both in_scope and out_of_scope: {sorted(dup)}"
            )
        return self


def parse_engagement(text: str) -> Engagement:
    """Parse and validate engagement YAML text."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise EngagementError(f"invalid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise EngagementError("engagement file must be a YAML mapping")
    try:
        return Engagement.model_validate(data)
    except ValidationError as exc:
        raise EngagementError(_format_errors(exc)) from None


def load_engagement(path: str | Path) -> Engagement:
    """Load and validate an engagement file from disk."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise EngagementError(f"cannot read {p}: {exc}") from None
    return parse_engagement(text)


def _format_errors(exc: ValidationError) -> str:
    lines = ["engagement file failed validation:"]
    for err in exc.errors():
        loc = ".".join(str(x) for x in err["loc"]) or "<root>"
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)
