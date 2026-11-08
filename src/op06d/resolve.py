# SPDX-License-Identifier: AGPL-3.0-or-later
"""Centralized DNS resolution and the resolve-once pin (RC-23).

**The only place in OP-06D that may perform a DNS lookup.** The gap this
closes: the gate (RC-9) used to resolve a hostname once to decide scope, and
the tool (nmap/nuclei) re-resolved the same hostname independently when it
ran. If DNS changed in between - attacker-controlled rebinding, a short-TTL
failover, or ordinary drift - the tool would scan an address the gate never
saw, let alone approved: a time-of-check/time-of-use bypass of the scope
control. ``nmap_tool.py`` and ``nuclei_tool.py`` must never call DNS; they are
always handed the literal IP the gate already pinned (see ``tools.py``,
``GatedToolbox.__execute``).

``DnsPinner`` resolves each hostname **at most once per engagement** (one
pinner per ``Gate``, one ``Gate`` per engagement run): the first resolution
wins and is cached for the pinner's lifetime, so a later DNS change can never
affect an engagement already under way. ``Gate`` is the only caller.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable, Sequence

Resolver = Callable[[str], Sequence[str]]
# Called exactly once per newly pinned host, with the resolved addresses.
PinAuditor = Callable[[str, Sequence[str]], None]


def system_resolver(host: str) -> Sequence[str]:
    """Resolve A/AAAA records via the OS resolver."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0].split("%", 1)[0] for info in infos]


class DnsPinner:
    """Resolve-once, for the whole life of this pinner (one per engagement).

    ``resolve(host)`` calls the underlying resolver on the first lookup for a
    given hostname and caches the result; every later call for that same
    host returns the identical, cached addresses without touching DNS again.
    This is what "pinned" means: the pin is immutable once set, so nothing
    that happens to DNS later in the engagement can change what a hostname
    resolves to here.

    ``on_pin``, if given, is invoked exactly once per hostname, the moment it
    is first pinned, so the caller can audit it (the RC-23 ``dns_pinned``
    event). If ``on_pin`` raises, that exception propagates out of
    ``resolve`` on that call - the caller (``Gate``) treats any exception
    from resolution as "resolution failed", so an audit failure here denies
    the action rather than silently proceeding unaudited.
    """

    def __init__(self, resolver: Resolver = system_resolver, *, on_pin: PinAuditor | None = None) -> None:
        self._resolver = resolver
        self._on_pin = on_pin
        self._lock = threading.Lock()
        self._pins: dict[str, tuple[str, ...]] = {}

    def resolve(self, host: str) -> tuple[str, ...]:
        key = str(host).strip().lower().rstrip(".")
        with self._lock:
            cached = self._pins.get(key)
        if cached is not None:
            return cached  # already pinned: no new DNS lookup, ever

        ips = tuple(self._resolver(host))
        with self._lock:
            pinned = self._pins.setdefault(key, ips)
            first_writer = pinned is ips
        if first_writer and self._on_pin is not None:
            self._on_pin(key, pinned)  # let a failure here propagate (see docstring)
        return pinned

    def pinned(self) -> dict[str, tuple[str, ...]]:
        """A snapshot of every hostname pinned so far (for reporting/tests)."""
        with self._lock:
            return dict(self._pins)
