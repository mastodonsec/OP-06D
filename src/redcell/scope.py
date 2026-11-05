"""Scope allowlist enforcement (RC-9).

The single decision point for "may we touch this target?". The LLM is asked;
this module decides. Rules (non-negotiable):

* Deny wins: a match against any out-of-scope entry is a deny, always.
* Fail closed: no in-scope entries -> deny everything.
* Default deny: malformed target, bad scope data, unexpected types, DNS
  failure, audit failure -> deny. The bias is always toward blocking.
* Host AND IP: a hostname must match a host entry in scope, and every address
  it resolves to must not be out of scope.

Target forms accepted: hostname, IP address, or CIDR network.

Matching semantics:
* Hostnames: exact match, or ``*.example.com`` which matches any subdomain
  (at least one label) but not ``example.com`` itself. A plain ``example.com``
  entry does NOT cover subdomains.
* IPs: containment in an in-scope network (IPv4-mapped IPv6 is treated as
  IPv4).
* CIDR targets: allowed only if wholly inside one in-scope network AND not
  overlapping any out-of-scope network.
* A hostname never becomes in scope merely because it resolves into an
  in-scope range; it must match a host entry.

Structure: ``evaluate_scope`` is pure (no I/O). ``check_scope`` adds the one
documented side-effecting step (DNS, only for hostnames that passed the name
checks) and the audit call. ``is_in_scope`` is the boolean convenience.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from redcell.audit import AuditSink, log_decision
from redcell.engagement import Scope, normalize_target

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Sequence[str]]


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str
    resolved_ips: tuple[str, ...] = ()
    # True only for a provisional deny: the hostname passed name checks and
    # the caller must supply resolved addresses to finish the decision.
    needs_resolution: bool = False


def _deny(target: object, reason: str, ips: tuple[str, ...] = ()) -> ScopeDecision:
    return ScopeDecision(_label(target), False, reason, ips)


def _label(target: object) -> str:
    return target if isinstance(target, str) else f"<{type(target).__name__}>"


# --- parsing ---------------------------------------------------------------

@dataclass(frozen=True)
class _Entries:
    hosts: tuple[str, ...]
    nets: tuple[IPNetwork, ...]


def _parse_entries(raw: Iterable[object]) -> _Entries:
    """Split scope entries into host patterns and networks. Raises ValueError
    on anything unparseable (the caller turns that into a deny)."""
    hosts: list[str] = []
    nets: list[IPNetwork] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"scope entry has unexpected type {type(item).__name__}")
        value = normalize_target(item)
        if "/" in value:
            nets.append(ipaddress.ip_network(value, strict=True))
            continue
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            hosts.append(value)
        else:
            nets.append(ipaddress.ip_network(addr))
    return _Entries(tuple(hosts), tuple(nets))


def _canon_ip(addr: IPAddress) -> IPAddress:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


@dataclass(frozen=True)
class _Target:
    kind: str  # "host" | "ip" | "net"
    host: str | None = None
    ip: IPAddress | None = None
    net: IPNetwork | None = None


def _parse_target(target: object) -> _Target:
    if not isinstance(target, str):
        raise ValueError(f"target has unexpected type {type(target).__name__}")
    if "*" in target:
        raise ValueError("wildcards are not valid targets")
    value = normalize_target(target)  # rejects URLs, spaces, bad hosts/CIDRs
    if "/" in value:
        net = ipaddress.ip_network(value, strict=True)
        if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped:
            raise ValueError("IPv4-mapped IPv6 networks are not supported")
        return _Target("net", net=net)
    try:
        ip = _canon_ip(ipaddress.ip_address(value))
    except ValueError:
        pass
    else:
        if target.strip().endswith("."):
            raise ValueError("IP address with trailing dot is ambiguous")
        return _Target("ip", ip=ip)
    # Hostnames never end in a numeric label. This rejects shorthand IPs such
    # as "127.1" or "2130706433" that resolvers would silently expand.
    if value.rsplit(".", 1)[-1].isdigit():
        raise ValueError(f"ambiguous numeric hostname {target!r}")
    return _Target("host", host=value)


# --- matching --------------------------------------------------------------

def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])  # ".example.com": needs >= 1 label
    return host == pattern


def _first_host_match(host: str, patterns: Iterable[str]) -> str | None:
    return next((p for p in patterns if _host_matches(host, p)), None)


def _first_ip_match(ip: IPAddress, nets: Iterable[IPNetwork]) -> IPNetwork | None:
    return next((n for n in nets if ip.version == n.version and ip in n), None)


def _parse_resolved(raw: Iterable[object]) -> tuple[IPAddress, ...]:
    ips: list[IPAddress] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError("resolver returned a non-string address")
        ips.append(_canon_ip(ipaddress.ip_address(item.strip())))
    return tuple(dict.fromkeys(ips))


# --- the decision (pure) ---------------------------------------------------

def evaluate_scope(
    target: object,
    scope: object,
    resolved_ips: Iterable[object] | None = None,
) -> ScopeDecision:
    """Pure scope decision. Never raises; every failure path is a deny.

    ``resolved_ips`` is only consulted for hostname targets. If a hostname
    passes the name checks and ``resolved_ips`` is None, the result is a
    provisional deny with ``needs_resolution=True``.
    """
    try:
        return _evaluate(target, scope, resolved_ips)
    except Exception as exc:  # default deny: anything unexpected blocks
        return _deny(target, f"deny: evaluation error ({type(exc).__name__}: {exc})")


def _evaluate(
    target: object, scope: object, resolved_ips: Iterable[object] | None
) -> ScopeDecision:
    if not isinstance(scope, Scope):
        return _deny(target, "deny: scope is missing or not a Scope")
    try:
        allow = _parse_entries(scope.in_scope)
        block = _parse_entries(scope.out_of_scope)
    except (ValueError, TypeError) as exc:
        return _deny(target, f"deny: invalid scope entry ({exc})")

    if not allow.hosts and not allow.nets:
        return _deny(target, "deny: in-scope allowlist is empty (fail closed)")

    try:
        t = _parse_target(target)
    except ValueError as exc:
        return _deny(target, f"deny: malformed target ({exc})")
    label = _label(target)

    if t.kind == "host":
        assert t.host is not None
        hit = _first_host_match(t.host, block.hosts)
        if hit:
            return _deny(target, f"deny: host matches out-of-scope entry {hit!r}")
        if not _first_host_match(t.host, allow.hosts):
            return _deny(target, "deny: host matches no in-scope host entry")
        if resolved_ips is None:
            return ScopeDecision(
                label, False, "deny: resolution required", needs_resolution=True
            )
        try:
            ips = _parse_resolved(resolved_ips)
        except (ValueError, TypeError) as exc:
            return _deny(target, f"deny: bad resolved address ({exc})")
        if not ips:
            return _deny(target, "deny: hostname resolved to no addresses")
        shown = tuple(str(i) for i in ips)
        for ip in ips:
            net = _first_ip_match(ip, block.nets)
            if net:
                return _deny(
                    target, f"deny: resolved {ip} is in out-of-scope {net}", shown
                )
        return ScopeDecision(label, True, "allow: host in scope", shown)

    if t.kind == "ip":
        assert t.ip is not None
        net = _first_ip_match(t.ip, block.nets)
        if net:
            return _deny(target, f"deny: IP is in out-of-scope {net}")
        net = _first_ip_match(t.ip, allow.nets)
        if not net:
            return _deny(target, "deny: IP matches no in-scope network")
        return ScopeDecision(label, True, f"allow: IP in in-scope {net}")

    assert t.net is not None  # CIDR target
    for o in block.nets:
        if o.version == t.net.version and t.net.overlaps(o):
            return _deny(target, f"deny: network overlaps out-of-scope {o}")
    for n in allow.nets:
        if n.version == t.net.version and t.net.subnet_of(n):
            return ScopeDecision(label, True, f"allow: network inside in-scope {n}")
    return _deny(target, "deny: network not wholly inside one in-scope network")


# --- orchestration (DNS + audit) -------------------------------------------

def system_resolver(host: str) -> Sequence[str]:
    """Resolve A/AAAA records via the OS resolver."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0].split("%", 1)[0] for info in infos]


def check_scope(
    target: object,
    scope: object,
    *,
    resolver: Resolver = system_resolver,
    audit: AuditSink = log_decision,
) -> ScopeDecision:
    """Decide, audit, return. DNS happens only for hostnames that already
    passed the name checks. Every decision is audited; if auditing fails the
    result is a deny (an unrecorded action must not proceed)."""
    decision = evaluate_scope(target, scope)
    if decision.needs_resolution:
        try:
            ips = list(resolver(str(target).strip().lower().rstrip(".")))
        except Exception as exc:
            decision = _deny(target, f"deny: resolution failed ({type(exc).__name__})")
        else:
            decision = evaluate_scope(target, scope, ips)
    try:
        audit(decision.target, decision.allowed, decision.reason)
    except Exception:
        return _deny(target, "deny: audit logging failed", decision.resolved_ips)
    return decision


def is_in_scope(
    target: object,
    scope: object,
    *,
    resolver: Resolver = system_resolver,
    audit: AuditSink = log_decision,
) -> bool:
    """True only when the target is explicitly allowed; every other path is False."""
    return check_scope(target, scope, resolver=resolver, audit=audit).allowed
