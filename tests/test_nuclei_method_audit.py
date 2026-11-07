# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for redcell.nuclei_method_audit (RC-36): the write-method
detection shared by NucleiTool, the exclusion-list generator, and the
CI-enforced audit test (the real "drift" guarantee) below.
"""

from __future__ import annotations

from redcell.nuclei_method_audit import (
    find_unexcluded_write_method_templates,
    scan_template_dir_for_write_methods,
    template_declares_write_method,
)

DELETE_TEMPLATE = {
    "id": "evil-delete",
    "info": {"name": "x", "severity": "info", "tags": "tech"},
    "http": [{"method": "DELETE", "path": ["{{BaseURL}}/x"]}],
}

RAW_PUT_TEMPLATE = {
    "id": "evil-raw-put",
    "info": {"name": "x", "severity": "info", "tags": "tech"},
    "http": [{"raw": ["PUT /x HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"]}],
}

QUERY_POST_TEMPLATE = {
    "id": "query-post",
    "info": {"name": "x", "severity": "info", "tags": "tech"},
    "http": [{"method": "POST", "path": ["{{BaseURL}}/graphql"]}],
}

GET_TEMPLATE = {
    "id": "plain-get",
    "info": {"name": "x", "severity": "info", "tags": "tech"},
    "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}],
}


def _write(tmp_path, name, doc):
    import yaml
    (tmp_path / name).write_text(yaml.safe_dump(doc), encoding="utf-8")


# --- template_declares_write_method (pure, in-memory) -------------------------

def test_method_delete_is_detected():
    assert template_declares_write_method(DELETE_TEMPLATE) is True


def test_raw_put_request_line_is_detected():
    assert template_declares_write_method(RAW_PUT_TEMPLATE) is True


def test_query_style_post_is_not_detected():
    assert template_declares_write_method(QUERY_POST_TEMPLATE) is False


def test_plain_get_is_not_detected():
    assert template_declares_write_method(GET_TEMPLATE) is False


def test_non_dict_input_is_not_detected_never_raises():
    assert template_declares_write_method(None) is False
    assert template_declares_write_method("not a dict") is False
    assert template_declares_write_method([]) is False


def test_malformed_blocks_do_not_crash():
    assert template_declares_write_method({"http": "not a list"}) is False
    assert template_declares_write_method({"http": ["not a dict"]}) is False
    assert template_declares_write_method({"http": [{"raw": [123]}]}) is False


# --- scan_template_dir_for_write_methods (filesystem) --------------------------

def test_scan_finds_both_shapes_and_skips_safe_ones(tmp_path):
    _write(tmp_path, "a.yaml", DELETE_TEMPLATE)
    _write(tmp_path, "b.yaml", RAW_PUT_TEMPLATE)
    _write(tmp_path, "c.yaml", QUERY_POST_TEMPLATE)
    _write(tmp_path, "d.yaml", GET_TEMPLATE)
    assert scan_template_dir_for_write_methods(tmp_path) == ["evil-delete", "evil-raw-put"]


def test_scan_skips_unreadable_or_malformed_files_without_crashing(tmp_path):
    (tmp_path / "garbage.yaml").write_text("{{{ not yaml at all", encoding="utf-8")
    (tmp_path / "not_a_dict.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    _write(tmp_path, "real.yaml", DELETE_TEMPLATE)
    assert scan_template_dir_for_write_methods(tmp_path) == ["evil-delete"]


def test_scan_of_empty_directory_is_empty(tmp_path):
    assert scan_template_dir_for_write_methods(tmp_path) == []


def test_scan_ignores_a_template_with_no_id(tmp_path):
    doc = dict(DELETE_TEMPLATE)
    del doc["id"]
    _write(tmp_path, "noid.yaml", doc)
    assert scan_template_dir_for_write_methods(tmp_path) == []


# --- the CI-enforced audit, proven non-vacuous ---------------------------------

def test_ci_audit_catches_a_selectable_write_method_template(tmp_path):
    _write(tmp_path, "evil.yaml", DELETE_TEMPLATE)
    offenders = find_unexcluded_write_method_templates(tmp_path, excluded_ids=set())
    assert offenders == ["evil-delete"]  # the audit DOES catch it - not vacuous


def test_ci_audit_passes_once_the_id_is_excluded(tmp_path):
    _write(tmp_path, "evil.yaml", DELETE_TEMPLATE)
    offenders = find_unexcluded_write_method_templates(tmp_path, excluded_ids={"evil-delete"})
    assert offenders == []


def test_ci_audit_passes_a_clean_tree_with_no_write_method_templates(tmp_path):
    _write(tmp_path, "c.yaml", QUERY_POST_TEMPLATE)
    _write(tmp_path, "d.yaml", GET_TEMPLATE)
    assert find_unexcluded_write_method_templates(tmp_path, excluded_ids=set()) == []
