# SPDX-License-Identifier: AGPL-3.0-or-later
"""The fixed planner's targets: each address is port-scanned once.

A scope often lists one host by name and by address. Scanning every entry
would scan that host twice for the same results. ``plan_targets`` groups the
in-scope entries that resolve to the same address and plans:

* nmap once per address. A listed range is scanned as a range, so an address
  inside it (and a smaller range inside it) gets no separate nmap.
* nuclei per entry, by the engagement's ``intensity.name_and_ip``:
  ``once`` (default) runs it on each listed hostname and skips a listed IP that
  a listed hostname resolves to (the hostname reaches the named virtual host);
  ``both`` runs it on each hostname and on the IP (its default virtual host).

Addresses come from ``Gate.preview``: the gate's own resolve-once pin, so the
plan and enforcement see the same address. An entry the gate would refuse
(window closed, out of scope) is planned as itself and refused at the gate as
usual. Planning allows nothing: every action still goes through
``GatedToolbox.execute``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Callable

from op06d.engagement import Engagement
from op06d.tools import ToolAction

# target -> the addresses the gate would hand a tool, () for an IP/CIDR, None if refused.
Preview = Callable[[str], "tuple[str, ...] | None"]


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _join(items: tuple[str, ...] | list[str]) -> str:
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


@dataclass(frozen=True)
class AddressGroup:
    """Scope entries that share one address (or one range inside another)."""

    address: str
    entries: tuple[str, ...]
    nmap_target: str | None  # the entry nmap runs against; None when a listed range covers it
    covering_range: str | None
    nuclei_targets: tuple[str, ...]
    skipped_ips: tuple[str, ...]  # listed IPs nuclei does not scan (name_and_ip: once)

    def notice(self) -> str:
        names = _join(self.entries)
        if len(self.entries) > 1:
            subject = f"scope: {names} resolve to the same address"
            if self.covering_range:
                subject += f", inside {self.covering_range}"
        else:
            subject = f"scope: {names} is inside {self.covering_range}"
        nmap = (f"nmap scans it as part of {self.covering_range}" if self.covering_range
                else "nmap scans it once")
        if not self.nuclei_targets:
            return f"{subject}; {nmap}"
        n = len(self.nuclei_targets)
        if len(self.entries) > 1 and n == len(self.entries):
            nuclei = f"nuclei scans {'both' if n == 2 else f'all {n}'} ({n} nuclei runs for this address)"
        else:
            nuclei = f"nuclei scans {_join(self.nuclei_targets)}"
        if self.skipped_ips:
            nuclei += (f" ({_join(self.skipped_ips)} default vhost not scanned; "
                       "set name_and_ip: both to include it)")
        return f"{subject}; {nmap}, {nuclei}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address, "entries": list(self.entries),
            "nmap_target": self.nmap_target, "covering_range": self.covering_range,
            "nuclei_targets": list(self.nuclei_targets), "skipped_ips": list(self.skipped_ips),
        }


@dataclass(frozen=True)
class TargetPlan:
    mode: str
    actions: tuple[ToolAction, ...]
    groups: tuple[AddressGroup, ...]  # only groups that changed what is scanned

    def plan_line(self) -> str:
        nmap = sum(a.tool == "nmap" for a in self.actions)
        nuclei = sum(a.tool == "nuclei" for a in self.actions)
        return f"plan: {nmap} nmap + {nuclei} nuclei"

    def as_dict(self) -> dict[str, Any]:
        return {"name_and_ip": self.mode, "groups": [g.as_dict() for g in self.groups]}


def _nmap(entry: str) -> ToolAction:
    if "/" in entry:
        return ToolAction("nmap", entry, {"profile": "service"}, reason="recon: service scan of in-scope range")
    return ToolAction("nmap", entry, {"profile": "service"}, reason="recon: service scan")


def _nuclei(entry: str) -> ToolAction:
    return ToolAction("nuclei", entry, {}, reason="recon: default-tag detection")


def plan_targets(engagement: Engagement, preview: Preview | None = None) -> TargetPlan:
    """Plan nmap and nuclei for ``engagement.scope.in_scope``. Without
    ``preview`` nothing is resolved, so nothing is grouped: one nmap and one
    nuclei per hostname or IP, one nmap per range. A ``*.`` wildcard is a scope
    pattern, not a host, so it is not scanned; nuclei cannot target a range."""
    mode = engagement.intensity.name_and_ip
    look: Preview = preview or (lambda target: None)
    entries = list(dict.fromkeys(engagement.scope.in_scope))

    ranges = [(e, ipaddress.ip_network(e)) for e in entries if "/" in e and look(e) is not None]

    def covering(net, exclude: str | None = None) -> str | None:
        for entry, outer in ranges:
            if entry != exclude and outer.version == net.version and net.subnet_of(outer):
                return entry
        return None

    groups: list[AddressGroup] = []
    nested: dict[str, AddressGroup] = {}
    for entry, net in ranges:
        outer = covering(net, exclude=entry)
        if outer:
            nested[entry] = AddressGroup(entry, (entry,), None, outer, (), ())

    by_address: dict[str, list[str]] = {}
    for entry in entries:
        if "/" in entry or entry.startswith("*."):
            continue
        resolved = look(entry)
        if resolved is None:
            continue
        addr = _ip(entry) if _ip(entry) is not None else (_ip(resolved[0]) if resolved else None)
        if addr is not None:
            by_address.setdefault(str(addr), []).append(entry)

    member: dict[str, AddressGroup] = {}
    for address, members in by_address.items():
        hosts = tuple(e for e in members if _ip(e) is None)
        ips = tuple(e for e in members if _ip(e) is not None)
        outer = covering(ipaddress.ip_network(address))
        if mode == "both" or not hosts:
            nuclei, skipped = tuple(members), ()
        else:
            nuclei, skipped = hosts, ips
        group = AddressGroup(address, tuple(members), None if outer else members[0], outer, nuclei, skipped)
        for e in members:
            member[e] = group
        if len(members) > 1 or outer:
            groups.append(group)

    actions: list[ToolAction] = []
    for entry in entries:
        if "/" in entry:
            if entry not in nested:
                actions.append(_nmap(entry))
        elif entry.startswith("*."):
            continue
        elif entry in member:
            group = member[entry]
            if group.nmap_target == entry:
                actions.append(_nmap(entry))
            if entry in group.nuclei_targets:
                actions.append(_nuclei(entry))
        else:
            actions += [_nmap(entry), _nuclei(entry)]

    ordered = sorted([*nested.values(), *groups], key=lambda g: entries.index(g.entries[0]))
    return TargetPlan(mode, tuple(actions), tuple(ordered))
