# SPDX-License-Identifier: AGPL-3.0-or-later
"""The fixed plan's address grouping (op06d.targets): one nmap per address,
nuclei by intensity.name_and_ip, planned from the gate's own resolve-once pin."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import yaml

from op06d.cli import plan_recon
from op06d.engagement import parse_engagement
from op06d.gate import Gate
from op06d.targets import plan_targets

NOW = datetime.now(timezone.utc)


def _engagement(in_scope, *, mode=None, out_of_scope=(), window=None):
    start, end = window or (NOW - timedelta(hours=1), NOW + timedelta(hours=1))
    intensity = {"max_rps": 20}
    if mode is not None:
        intensity["name_and_ip"] = mode
    return parse_engagement(yaml.safe_dump({
        "engagement": "targets-test",
        "authorization": {
            "client": "Test", "signed_scope_ref": "SOW-1", "authorized_by": "t@example.com",
            "window": [start.isoformat(), end.isoformat()],
        },
        "scope": {"in_scope": list(in_scope), "out_of_scope": list(out_of_scope)},
        "intensity": intensity,
        "objective": "test",
    }))


class Resolver:
    def __init__(self, table):
        self.table = table
        self.calls: list[str] = []

    def __call__(self, host):
        self.calls.append(host)
        return self.table[host]


def _plan(eng, table):
    resolver = Resolver(table)
    gate = Gate(eng, resolver=resolver)
    return plan_targets(eng, gate.preview), gate, resolver


def _actions(plan):
    return [(a.tool, a.target) for a in plan.actions]


# --- a host listed by name and by IP ----------------------------------------

def test_name_and_ip_once_scans_the_address_once_and_nuclei_the_name():
    eng = _engagement(["juice-shop.lab", "172.31.77.10"])
    plan, _, _ = _plan(eng, {"juice-shop.lab": ["172.31.77.10"]})

    assert _actions(plan) == [("nmap", "juice-shop.lab"), ("nuclei", "juice-shop.lab")]
    [group] = plan.groups
    assert group.address == "172.31.77.10" and group.skipped_ips == ("172.31.77.10",)
    assert group.notice() == (
        "scope: juice-shop.lab and 172.31.77.10 resolve to the same address; nmap scans it once, "
        "nuclei scans juice-shop.lab (172.31.77.10 default vhost not scanned; "
        "set name_and_ip: both to include it)"
    )
    assert plan.plan_line() == "plan: 1 nmap + 1 nuclei"


def test_name_and_ip_both_also_runs_nuclei_on_the_ip():
    eng = _engagement(["juice-shop.lab", "172.31.77.10"], mode="both")
    plan, _, _ = _plan(eng, {"juice-shop.lab": ["172.31.77.10"]})

    assert _actions(plan) == [
        ("nmap", "juice-shop.lab"), ("nuclei", "juice-shop.lab"), ("nuclei", "172.31.77.10"),
    ]
    [group] = plan.groups
    assert group.skipped_ips == ()
    assert group.notice() == (
        "scope: juice-shop.lab and 172.31.77.10 resolve to the same address; nmap scans it once, "
        "nuclei scans both (2 nuclei runs for this address)"
    )
    assert plan.plan_line() == "plan: 1 nmap + 2 nuclei"


def test_the_lab_scope_plans_four_actions_by_default_and_six_with_both():
    table = {"juice-shop.lab": ["172.31.77.10"], "dvwa.lab": ["172.31.77.11"]}
    scope = ["juice-shop.lab", "172.31.77.10", "dvwa.lab", "172.31.77.11"]
    once, _, _ = _plan(_engagement(scope), table)
    both, _, _ = _plan(_engagement(scope, mode="both"), table)
    assert once.plan_line() == "plan: 2 nmap + 2 nuclei"
    assert both.plan_line() == "plan: 2 nmap + 4 nuclei"
    assert len(once.groups) == len(both.groups) == 2


# --- two names on one IP ------------------------------------------------------

@pytest.mark.parametrize("mode, nuclei", [
    ("once", ["a.lab", "b.lab"]),
    ("both", ["a.lab", "b.lab", "10.0.0.5"]),
])
def test_two_names_on_one_ip_each_get_nuclei(mode, nuclei):
    eng = _engagement(["a.lab", "b.lab", "10.0.0.5"], mode=mode)
    plan, _, _ = _plan(eng, {"a.lab": ["10.0.0.5"], "b.lab": ["10.0.0.5"]})

    assert [t for tool, t in _actions(plan) if tool == "nmap"] == ["a.lab"]
    assert [t for tool, t in _actions(plan) if tool == "nuclei"] == nuclei
    [group] = plan.groups
    assert group.entries == ("a.lab", "b.lab", "10.0.0.5")
    assert group.skipped_ips == (("10.0.0.5",) if mode == "once" else ())


def test_two_names_without_the_ip_listed_scan_both_names():
    eng = _engagement(["a.lab", "b.lab"])
    plan, _, _ = _plan(eng, {"a.lab": ["10.0.0.5"], "b.lab": ["10.0.0.5"]})
    assert _actions(plan) == [("nmap", "a.lab"), ("nuclei", "a.lab"), ("nuclei", "b.lab")]
    [group] = plan.groups
    assert group.skipped_ips == ()
    assert group.notice().endswith("nmap scans it once, nuclei scans both (2 nuclei runs for this address)")


# --- ranges -------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["once", "both"])
def test_a_range_covers_the_listed_ips_and_hosts_inside_it(mode):
    eng = _engagement(["10.0.0.0/24", "10.0.0.0/28", "app.lab", "10.0.0.7", "10.0.0.9"], mode=mode)
    plan, _, _ = _plan(eng, {"app.lab": ["10.0.0.7"]})

    nmap = [t for tool, t in _actions(plan) if tool == "nmap"]
    nuclei = [t for tool, t in _actions(plan) if tool == "nuclei"]
    assert nmap == ["10.0.0.0/24"]  # the /28, app.lab's address and both IPs are inside it
    assert nuclei == (["app.lab", "10.0.0.9"] if mode == "once" else ["app.lab", "10.0.0.7", "10.0.0.9"])
    notices = [g.notice() for g in plan.groups]
    assert notices[0] == "scope: 10.0.0.0/28 is inside 10.0.0.0/24; nmap scans it as part of 10.0.0.0/24"
    assert any(n.startswith("scope: app.lab and 10.0.0.7 resolve to the same address, inside 10.0.0.0/24; "
                            "nmap scans it as part of 10.0.0.0/24") for n in notices)
    assert "scope: 10.0.0.9 is inside 10.0.0.0/24; nmap scans it as part of 10.0.0.0/24, nuclei scans 10.0.0.9" in notices


def test_an_address_outside_every_range_keeps_its_own_nmap():
    eng = _engagement(["10.0.0.0/28", "10.0.1.5"])
    plan, _, _ = _plan(eng, {})
    assert _actions(plan) == [("nmap", "10.0.0.0/28"), ("nmap", "10.0.1.5"), ("nuclei", "10.0.1.5")]
    assert plan.groups == ()


def test_a_range_the_gate_refuses_covers_nothing():
    eng = _engagement(["10.0.0.0/24", "10.0.0.9"], out_of_scope=["10.0.0.128/25"])
    plan, _, _ = _plan(eng, {})
    assert _actions(plan) == [("nmap", "10.0.0.0/24"), ("nmap", "10.0.0.9"), ("nuclei", "10.0.0.9")]
    assert plan.groups == ()


# --- what is not merged -------------------------------------------------------

def test_entries_on_different_addresses_are_not_merged():
    eng = _engagement(["a.lab", "b.lab", "10.0.0.9"])
    plan, _, _ = _plan(eng, {"a.lab": ["10.0.0.5"], "b.lab": ["10.0.0.6"]})
    assert _actions(plan) == [
        ("nmap", "a.lab"), ("nuclei", "a.lab"), ("nmap", "b.lab"), ("nuclei", "b.lab"),
        ("nmap", "10.0.0.9"), ("nuclei", "10.0.0.9"),
    ]
    assert plan.groups == ()


def test_a_host_the_gate_refuses_is_planned_on_its_own_and_left_to_the_gate():
    eng = _engagement(["app.lab", "10.0.0.5"], out_of_scope=["192.0.2.0/24"])
    plan, _, _ = _plan(eng, {"app.lab": ["192.0.2.10"]})
    assert _actions(plan) == [
        ("nmap", "app.lab"), ("nuclei", "app.lab"), ("nmap", "10.0.0.5"), ("nuclei", "10.0.0.5"),
    ]
    assert plan.groups == ()


def test_outside_the_window_nothing_is_resolved_or_merged():
    eng = _engagement(["juice-shop.lab", "172.31.77.10"],
                      window=(NOW - timedelta(hours=3), NOW - timedelta(hours=2)))
    plan, _, resolver = _plan(eng, {"juice-shop.lab": ["172.31.77.10"]})
    assert resolver.calls == []
    assert len(plan.actions) == 4 and plan.groups == ()


def test_without_a_preview_every_entry_is_planned_on_its_own():
    eng = _engagement(["juice-shop.lab", "172.31.77.10", "10.0.0.0/24", "*.wild.lab"])
    assert [(a.tool, a.target) for a in plan_recon(eng)] == [
        ("nmap", "juice-shop.lab"), ("nuclei", "juice-shop.lab"),
        ("nmap", "172.31.77.10"), ("nuclei", "172.31.77.10"), ("nmap", "10.0.0.0/24"),
    ]


# --- the plan and the gate share one pin ----------------------------------------

def test_the_plan_uses_the_gates_pin_so_enforcement_sees_the_same_address():
    eng = _engagement(["juice-shop.lab", "172.31.77.10"])
    answers = iter([["172.31.77.10"], ["198.51.100.66"]])  # DNS would change after the first lookup
    calls = []

    def changing(host):
        calls.append(host)
        return next(answers)

    gate = Gate(eng, resolver=changing)
    plan = plan_targets(eng, gate.preview)
    decision = gate.check("juice-shop.lab", audit=lambda t, a, r: None)

    assert calls == ["juice-shop.lab"]
    assert plan.groups[0].address == "172.31.77.10"
    assert decision.allowed and decision.resolved_ips == ("172.31.77.10",)


def test_preview_takes_no_rate_token_and_writes_no_decision():
    eng = _engagement(["10.0.0.5"])
    gate = Gate(eng, resolver=Resolver({}))
    for _ in range(100):
        assert gate.preview("10.0.0.5") == ()
    written = []
    assert gate.check("10.0.0.5", audit=lambda t, a, r: written.append(a)).allowed
    assert written == [True]
    assert gate.preview("192.0.2.1") is None
