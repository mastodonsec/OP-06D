# SPDX-License-Identifier: AGPL-3.0-or-later
"""RC-28: RC-20 follow-up: make the lab harness teardown idempotent (down-before-up)

Docker-free tests of lab/make_lab_engagement.py against the committed
lab/engagement.yaml template: the generated window contains now and is
bounded, nothing but the window changes, the output loads through
load_engagement, and broken templates are refused."""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest
import yaml

from op06d.engagement import load_engagement

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE_PATH = ROOT / "lab" / "engagement.yaml"
sys.path.insert(0, str(ROOT / "lab"))

import make_lab_engagement as mle  # noqa: E402

NOW = dt.datetime(2026, 11, 10, 9, 30, 15, 123456, tzinfo=dt.timezone.utc)


def _template() -> dict:
    return yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))


def _parse(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, mle.TIME_FORMAT).replace(tzinfo=dt.timezone.utc)


def test_window_contains_now_and_is_bounded():
    start_s, end_s = mle.make_engagement(_template(), NOW)["authorization"]["window"]
    start, end = _parse(start_s), _parse(end_s)
    assert start <= NOW < end
    assert end > start
    assert end - start == dt.timedelta(hours=4, minutes=5)
    assert start_s.endswith("Z") and end_s.endswith("Z")


def test_hours_is_configurable():
    start_s, end_s = mle.make_engagement(_template(), NOW, hours=1.5)["authorization"]["window"]
    assert _parse(end_s) - _parse(start_s) == dt.timedelta(hours=1, minutes=35)


@pytest.mark.parametrize("hours", [0, -1])
def test_non_positive_hours_refused(hours):
    with pytest.raises(ValueError):
        mle.make_engagement(_template(), NOW, hours=hours)


def test_naive_now_refused():
    with pytest.raises(ValueError):
        mle.make_engagement(_template(), NOW.replace(tzinfo=None))


def test_only_the_window_differs_from_the_template():
    template = _template()
    generated = mle.make_engagement(template, NOW)
    assert generated["authorization"]["window"] != template["authorization"]["window"]
    for key in template:
        if key != "authorization":
            assert generated[key] == template[key], key
    for key in template["authorization"]:
        if key != "window":
            assert generated["authorization"][key] == template["authorization"][key], key
    assert set(generated) == set(template)
    assert set(generated["authorization"]) == set(template["authorization"])


def test_template_is_not_mutated():
    template = _template()
    before = yaml.safe_dump(template)
    mle.make_engagement(template, NOW)
    assert yaml.safe_dump(template) == before


def test_difference_outside_window_is_detected():
    template = _template()
    tampered = mle.make_engagement(template, NOW)
    tampered["scope"]["in_scope"].append("203.0.113.9")
    with pytest.raises(mle.TemplateError):
        mle.assert_only_window_differs(template, tampered)


@pytest.mark.parametrize("mutate", [
    lambda t: t.pop("authorization"),
    lambda t: t["authorization"].pop("window"),
    lambda t: t.__setitem__("authorization", "not a mapping"),
], ids=["no-authorization", "no-window", "authorization-not-mapping"])
def test_template_missing_authorization_or_window_is_refused(mutate):
    template = _template()
    mutate(template)
    with pytest.raises(mle.TemplateError):
        mle.make_engagement(template, NOW)


def test_non_mapping_template_is_refused():
    with pytest.raises(mle.TemplateError):
        mle.make_engagement(["not", "a", "mapping"], NOW)


def test_written_file_loads_through_load_engagement(tmp_path):
    out = tmp_path / "captures" / "engagement.yaml"
    now = dt.datetime.now(dt.timezone.utc)
    mle.write_engagement(TEMPLATE_PATH, out, now=now)
    eng = load_engagement(out)
    start, end = eng.authorization.window
    assert start <= now < end
    template_eng = load_engagement(TEMPLATE_PATH)
    assert eng.model_dump(exclude={"authorization": {"window"}}) == \
        template_eng.model_dump(exclude={"authorization": {"window"}})


def test_output_that_fails_schema_validation_is_deleted_and_raises(tmp_path):
    bad_template = tmp_path / "template.yaml"
    t = _template()
    t["unexpected_top_level_key"] = True  # the schema forbids unknown keys
    bad_template.write_text(yaml.safe_dump(t), encoding="utf-8")
    out = tmp_path / "out.yaml"
    with pytest.raises(Exception):
        mle.write_engagement(bad_template, out, now=NOW)
    assert not out.exists()


def test_refuses_to_overwrite_the_template(tmp_path):
    template = tmp_path / "engagement.yaml"
    template.write_text(TEMPLATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    original = template.read_text(encoding="utf-8")
    with pytest.raises(mle.TemplateError):
        mle.write_engagement(template, template, now=NOW)
    assert template.read_text(encoding="utf-8") == original


def test_cli_success_and_failure(tmp_path, capsys):
    out = tmp_path / "engagement.now.yaml"
    assert mle.main([str(out), "--template", str(TEMPLATE_PATH), "--hours", "2"]) == 0
    assert f"wrote {out}" in capsys.readouterr().out
    load_engagement(out)

    broken = tmp_path / "broken.yaml"
    broken.write_text("engagement: x\n", encoding="utf-8")
    assert mle.main([str(tmp_path / "never.yaml"), "--template", str(broken)]) == 1
    assert "ERROR" in capsys.readouterr().err
    assert not (tmp_path / "never.yaml").exists()


def test_committed_template_itself_is_unchanged_by_generation(tmp_path):
    before = TEMPLATE_PATH.read_bytes()
    mle.write_engagement(TEMPLATE_PATH, tmp_path / "e.yaml", now=NOW)
    assert TEMPLATE_PATH.read_bytes() == before
