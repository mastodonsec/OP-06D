# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs

Docker-free checks of the opt-in model-relay overlays and their launcher
(lab/model_relay.py): overlay structure and the one-upstream rule, the
engagement-policy refusal, drift guards against the base lab, and a scan of
lab/ for API-key material. The live overlay is exercised by
tests/integration/test_lab_rc47.py (-m lab).
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tomllib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
sys.path.insert(0, str(LAB))

import model_relay as relay  # noqa: E402

MODES = ("local", "anthropic")


def _yaml(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _overlay(mode: str) -> dict:
    return _yaml(LAB / f"model-relay.{mode}.yml")


# --- the base lab is untouched ------------------------------------------------------

def test_base_compose_has_no_relay_and_scanner_stays_on_labnet_only():
    base = _yaml(LAB / "docker-compose.yml")
    assert set(base["services"]) == {"juice-shop", "dvwa", "scanner"}
    assert set(base["networks"]) == {"labnet"} and base["networks"]["labnet"]["internal"] is True
    for svc in base["services"].values():
        assert set(svc["networks"]) == {"labnet"}
        assert "extra_hosts" not in svc and "ports" not in svc


def test_base_isolation_script_still_requires_exactly_one_interface():
    text = (LAB / "check_isolation.sh").read_text(encoding="utf-8")
    assert 'if [ "$iface_count" -eq 1 ]' in text and "relay" not in text.lower()


# --- overlay structure -----------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_overlay_networks_and_membership(mode):
    o = _overlay(mode)
    assert o["name"] == "rc-lab"
    assert set(o["services"]) == {"scanner", "model-relay"}  # targets are not in the overlay
    nets = o["networks"]
    assert nets["relaynet"]["internal"] is True
    assert nets["relaynet"]["ipam"]["config"] == [{"subnet": "172.31.78.0/24"}]
    assert nets["relay_egress"]["internal"] is False
    assert set(o["services"]["scanner"]["networks"]) == {"relaynet"}
    assert set(o["services"]["model-relay"]["networks"]) == {"relaynet", "relay_egress"}
    on_egress = [s for s, v in o["services"].items() if "relay_egress" in v.get("networks", {})]
    assert on_egress == ["model-relay"]


@pytest.mark.parametrize("mode", MODES)
def test_overlay_relay_is_locked_down_and_has_one_upstream(mode):
    r = _overlay(mode)["services"]["model-relay"]
    assert r["command"] == [mode]
    assert r["cap_drop"] == ["ALL"]
    assert set(r["cap_add"]) == {c.removeprefix("CAP_") for c in relay.RELAY_ALLOWED_CAPS}
    assert r["security_opt"] == ["no-new-privileges:true"] and r["read_only"] is True
    assert r["networks"]["relaynet"]["ipv4_address"] == relay.RELAY_IP
    assert r["environment"] == {"RELAY_NET": "172.31.78.0/24", "RELAY_BIND": relay.RELAY_IP}
    for key in ("ports", "privileged", "network_mode", "extra_hosts", "volumes", "env_file"):
        assert key not in r, key


@pytest.mark.parametrize("mode", MODES)
def test_overlay_scanner_gets_no_secret_and_only_the_expected_name_override(mode):
    s = _overlay(mode)["services"]["scanner"]
    assert "environment" not in s and "env_file" not in s and "ports" not in s
    expected = [h.replace(":", ":", 1) for h in relay.EXPECTED_EXTRA_HOSTS[mode]]
    assert s.get("extra_hosts", []) == expected
    assert s["networks"]["relaynet"]["ipv4_address"] == "172.31.78.20"


def test_both_overlays_use_the_same_relay_identity_so_combining_them_cannot_add_a_second_upstream():
    a, b = (_overlay(m)["services"]["model-relay"] for m in MODES)
    assert a["image"] == b["image"] and a["networks"] == b["networks"] and a["environment"] == b["environment"]


def test_relay_entrypoint_takes_exactly_one_mode_and_pins_each_upstream():
    text = (LAB / "relay" / "relay-entrypoint.sh").read_text(encoding="utf-8")
    assert '[ "$#" -eq 1 ] || die' in text
    assert 'local)     UP_HOST="host.docker.internal"; UP_PORT=11434' in text
    assert 'anthropic) UP_HOST="api.anthropic.com";    UP_PORT=443' in text
    assert "req.ssl_sni -m str api.anthropic.com" in text and "tcp-request content reject" in text
    assert text.index("iptables -P OUTPUT DROP") < text.index("exec setpriv")
    assert "--bounding-set=-all" in text and "--no-new-privs" in text and "--reuid=relay" in text
    assert "ssl" not in text.split("exec setpriv")[1].replace("ssl_sni", "")  # no TLS termination options


def test_relay_image_is_pinned_by_digest():
    text = (LAB / "relay" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM alpine:[0-9.]+@sha256:[0-9a-f]{64}$", text, re.M)


# --- drift guards ------------------------------------------------------------------------

def _blocked_lines(path: pathlib.Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("expect_blocked ")]


def test_relay_isolation_check_keeps_every_base_egress_attempt():
    base = _blocked_lines(LAB / "check_isolation.sh")
    relay_check = set(_blocked_lines(LAB / "check_relay_isolation.sh"))
    assert len(base) == 18
    assert [b for b in base if b not in relay_check] == []


def test_hosted_engagement_template_differs_from_the_lab_template_only_by_the_planner_block():
    base = _yaml(LAB / "engagement.yaml")
    hosted = _yaml(LAB / "engagement-llm-hosted.yaml")
    assert hosted.pop("planner") == {"allowed_providers": ["local", "anthropic"]}
    assert hosted == base
    assert "planner" not in base


def test_scanner_llm_requirements_match_uv_lock():
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = {p["name"].lower(): p["version"] for p in lock["package"]}
    reqs = (LAB / "relay" / "scanner-llm-requirements.txt").read_text(encoding="utf-8")
    pins = dict(re.findall(r"^([A-Za-z0-9_.\-]+)==([^\s;\\]+)", reqs, re.M))
    assert "anthropic" in pins
    for name, version in pins.items():
        assert locked.get(name.lower().replace("_", "-")) == version, name
    assert reqs.count("--hash=sha256:") >= len(pins)


# --- launcher policy ---------------------------------------------------------------------

class NoDocker:
    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_anthropic_without_an_explicit_engagement_is_refused_before_docker():
    d = NoDocker()
    with pytest.raises(relay.PolicyRefused, match="explicitly allows"):
        relay.up("anthropic", None, run=d)
    assert d.calls == []


def test_anthropic_with_the_default_lab_engagement_is_refused_before_docker():
    d = NoDocker()
    with pytest.raises(relay.PolicyRefused, match="does not allow the 'anthropic' provider"):
        relay.up("anthropic", "lab/engagement.yaml", run=d)
    assert d.calls == []


def test_anthropic_with_the_hosted_template_is_allowed_and_uses_only_its_overlay():
    d = NoDocker()
    path = relay.up("anthropic", "lab/engagement-llm-hosted.yaml", run=d)
    assert path.name == "engagement-llm-hosted.yaml"
    up_call = d.calls[-1]
    assert up_call[-3:] == ["up", "-d", "--remove-orphans"]
    files = [up_call[i + 1] for i, a in enumerate(up_call) if a == "-f"]
    assert [pathlib.Path(f).name for f in files] == ["docker-compose.yml", "model-relay.anthropic.yml"]


def test_local_uses_the_lab_engagement_by_default():
    d = NoDocker()
    assert relay.up("local", None, run=d).name == "engagement.yaml"


def test_engagement_outside_lab_is_refused(tmp_path):
    other = tmp_path / "e.yaml"
    other.write_text((LAB / "engagement-llm-hosted.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(relay.RelayError, match="under lab/"):
        relay.check_policy("anthropic", other)


def test_a_running_relay_of_the_other_mode_blocks_up():
    class Running(NoDocker):
        def __call__(self, argv, timeout):
            self.calls.append(list(argv))
            if argv[-3:] == ["ps", "-q", "model-relay"]:
                return subprocess.CompletedProcess(argv, 0, "abc123\n", "")
            if argv[:3] == ["docker", "container", "inspect"]:
                return subprocess.CompletedProcess(
                    argv, 0, '[{"State": {"Running": true}, "Config": {"Cmd": ["anthropic"]}}]', "")
            return subprocess.CompletedProcess(argv, 0, "", "")

    d = Running()
    with pytest.raises(relay.RelayError, match="one upstream per stack"):
        relay.up("local", None, run=d)
    assert not any("up" in c for c in d.calls)


def test_unknown_mode_is_refused():
    with pytest.raises(relay.RelayError):
        relay.compose_argv("openai")


def test_acceptance_command_points_local_at_the_relay_and_never_carries_the_key():
    local = relay.op06d_run_argv("local", "/x/e.yaml", "/x/run", model=None, limits=relay.ACCEPTANCE_LIMITS)
    assert local[local.index("--llm-endpoint") + 1] == f"http://{relay.RELAY_IP}:11434"
    assert local[local.index("--llm-allow-private") + 1] == relay.RELAY_IP
    hosted = relay.op06d_run_argv("anthropic", "/x/e.yaml", "/x/run", model="m", limits=relay.ACCEPTANCE_LIMITS)
    assert "--llm-endpoint" not in hosted and "--llm-allow-private" not in hosted
    assert "--non-interactive" in hosted and hosted[hosted.index("--planner") + 1] == "llm"


def test_anthropic_acceptance_without_key_is_refused_before_docker():
    d = NoDocker()
    with pytest.raises(relay.RelayError, match="ANTHROPIC_API_KEY"):
        relay.run_acceptance("anthropic", "lab/engagement-llm-hosted.yaml", run=d, environ={})
    assert d.calls == []


# --- no key material in lab/ -----------------------------------------------------------------

KEY_PATTERNS = [
    re.compile(rb"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(rb"(?i)anthropic_api_key\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}"),
    re.compile(rb"(?i)x-api-key\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}"),
    re.compile(rb"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{20,}[\"']"),
]


def test_no_api_key_material_anywhere_under_lab():
    hits = []
    for path in sorted(LAB.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.name == ".env" or path.name.startswith(".env."):
            hits.append(f"{path.relative_to(ROOT)}: env file")
            continue
        data = path.read_bytes()
        for rx in KEY_PATTERNS:
            m = rx.search(data)
            if m:
                hits.append(f"{path.relative_to(ROOT)}: {m.group(0)[:24]!r}...")
    assert hits == []


def test_the_key_scan_is_not_vacuous(tmp_path):
    sample = b"ANTHROPIC_API_KEY=" + b"sk-ant-" + b"api03-" + b"x" * 30
    assert any(rx.search(sample) for rx in KEY_PATTERNS)
    benign = (b"environment: [ANTHROPIC_API_KEY]\n-e ANTHROPIC_API_KEY scanner\n"
              b"$env:ANTHROPIC_API_KEY = Read-Host -MaskInput")
    assert not any(rx.search(benign) for rx in KEY_PATTERNS)
    assert any(rx.search(b"ANTHROPIC_API_KEY=abcdefghijklmnop1234") for rx in KEY_PATTERNS)


# --- launcher host-side checks against fake `docker inspect` output -----------------------

import copy  # noqa: E402
import json  # noqa: E402

NAMES = {"juice-shop": "rc-lab-juice-shop-1", "dvwa": "rc-lab-dvwa-1",
         "scanner": "rc-lab-scanner-1", "model-relay": "rc-lab-model-relay-1"}


def _topology(mode: str) -> dict:
    lab, rel, egr = relay.NET_LAB, relay.NET_RELAY, relay.NET_EGRESS

    def container(svc, nets, **extra):
        info = {
            "Name": "/" + NAMES[svc],
            "State": {"Running": True},
            "Config": {"Cmd": extra.pop("cmd", None), "Env": extra.pop("env", ["PATH=/usr/bin"])},
            "HostConfig": {"NetworkMode": "rc-lab_default", "Privileged": False,
                           "CapAdd": extra.pop("caps", None), "ExtraHosts": extra.pop("extra_hosts", None)},
            "NetworkSettings": {"Ports": {}, "Networks": {n: {"IPAddress": ip} for n, ip in nets.items()}},
        }
        return info

    containers = {
        "juice-shop": container("juice-shop", {lab: "172.31.77.10"}),
        "dvwa": container("dvwa", {lab: "172.31.77.11"}),
        "scanner": container("scanner", {lab: "172.31.77.20", rel: "172.31.78.20"}, cmd=["sleep", "infinity"],
                             extra_hosts=list(relay.EXPECTED_EXTRA_HOSTS[mode]) or None),
        "model-relay": container("model-relay", {rel: "172.31.78.2", egr: "172.18.0.2"}, cmd=[mode],
                                 caps=["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"]),
    }
    networks = {
        lab: {"Internal": True, "Containers": {f"id-{s}": {"Name": NAMES[s]} for s in ("juice-shop", "dvwa", "scanner")}},
        rel: {"Internal": True, "Containers": {f"id-{s}": {"Name": NAMES[s]} for s in ("scanner", "model-relay")}},
        egr: {"Internal": False, "Containers": {"id-model-relay": {"Name": NAMES["model-relay"]}}},
    }
    return {"containers": containers, "networks": networks}


class FakeDocker:
    def __init__(self, topo: dict, exec_codes: dict[str, int] | None = None):
        self.topo = topo
        self.exec_codes = exec_codes or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout):
        argv = list(argv)
        self.calls.append(argv)
        cp = lambda code, out="": subprocess.CompletedProcess(argv, code, out, "")  # noqa: E731
        if argv[:3] == ["docker", "network", "inspect"]:
            net = self.topo["networks"].get(argv[3])
            return cp(0, json.dumps([net])) if net else cp(1)
        if argv[:3] == ["docker", "container", "inspect"]:
            svc = argv[3].removeprefix("cid-")
            info = self.topo["containers"].get(svc)
            return cp(0, json.dumps([info])) if info else cp(1)
        if "ps" in argv and "-q" in argv:
            svc = argv[-1]
            return cp(0, f"cid-{svc}\n" if svc in self.topo["containers"] else "")
        if "exec" in argv:
            joined = " ".join(argv)
            for key, code in self.exec_codes.items():
                if key in joined:
                    return cp(code, f"{key} output")
            if " dvwa " in f" {joined} ":
                return cp(1)  # the target cannot reach the relay network
            return cp(0, "RESULT: PASS")
        return cp(0)


@pytest.mark.parametrize("mode", MODES)
def test_check_passes_on_the_expected_topology(mode):
    report = relay.check(mode, run=FakeDocker(_topology(mode)))
    assert report.exit_code == 0, "\n".join(report.lines)
    joined = "\n".join(report.lines)
    assert "scanner-side isolation" in joined and "relay-side egress" in joined
    assert "target dvwa cannot reach the relay network" in joined


def _broken(mode, mutate):
    topo = copy.deepcopy(_topology(mode))
    mutate(topo)
    return relay.check(mode, run=FakeDocker(topo))


def test_check_fails_when_a_target_joins_the_relay_network():
    def mutate(t):
        t["containers"]["dvwa"]["NetworkSettings"]["Networks"][relay.NET_RELAY] = {"IPAddress": "172.31.78.11"}
        t["networks"][relay.NET_RELAY]["Containers"]["id-dvwa"] = {"Name": NAMES["dvwa"]}
    report = _broken("local", mutate)
    assert report.exit_code == 1
    assert any("dvwa is attached to" in line for line in report.lines)


def test_check_fails_when_the_relay_network_is_routable():
    report = _broken("local", lambda t: t["networks"][relay.NET_RELAY].update(Internal=False))
    assert report.exit_code == 1


def test_check_fails_when_the_relay_runs_the_other_upstream():
    report = _broken("local", lambda t: t["containers"]["model-relay"]["Config"].update(Cmd=["anthropic"]))
    assert report.exit_code == 1 and any("relay command is" in line for line in report.lines)


def test_check_fails_when_the_key_is_in_the_scanner_configuration():
    leak = "ANTHROPIC_API_KEY=" + "x" * 20
    report = _broken("anthropic", lambda t: t["containers"]["scanner"]["Config"]["Env"].append(leak))
    assert report.exit_code == 1 and any("API key material" in line for line in report.lines)


def test_check_fails_on_a_published_port_or_extra_name_override():
    def mutate(t):
        t["containers"]["model-relay"]["NetworkSettings"]["Ports"] = {"443/tcp": [{"HostPort": "443"}]}
        t["containers"]["scanner"]["HostConfig"]["ExtraHosts"] = ["api.anthropic.com:172.31.78.2"]
    report = _broken("local", mutate)
    assert report.exit_code == 1
    assert any("publishes ports" in line for line in report.lines)
    assert any("extra hosts" in line for line in report.lines)


def test_check_fails_when_a_target_reaches_the_relay():
    fake = FakeDocker(_topology("local"))
    original = fake.__call__

    def reach(argv, timeout):
        cp = original(argv, timeout)
        if "dvwa" in argv and "exec" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return cp

    report = relay.check("local", run=reach)
    assert report.exit_code == 1 and any("REACHED" in line for line in report.lines)


@pytest.mark.parametrize("code,expected", [(1, 1), (2, 2)])
def test_inner_check_failures_propagate(code, expected):
    fake = FakeDocker(_topology("anthropic"), exec_codes={"check_relay_egress.sh": code})
    assert relay.check("anthropic", run=fake).exit_code == expected


def test_check_is_inconclusive_when_the_overlay_is_not_up():
    topo = _topology("local")
    del topo["networks"][relay.NET_RELAY]
    report = relay.check("local", run=FakeDocker(topo))
    assert report.exit_code == 2
