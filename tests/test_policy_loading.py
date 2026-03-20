"""Tests for policy file loading and schema validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from csc_runner.policy import PolicyError, load_policy

POLICIES_DIR = Path(__file__).resolve().parent.parent / "examples" / "policies"


def test_load_valid_policy():
    policy = load_policy(str(POLICIES_DIR / "dev-readonly.yaml"))
    assert policy["name"] == "dev-readonly"
    assert policy["policy_schema_version"] == "csc.policy.v0.1"


def test_load_rejects_duplicate_keys(tmp_path):
    dup = tmp_path / "dup.yaml"
    dup.write_text(
        "policy_schema_version: csc.policy.v0.1\n"
        "name: dup\n"
        "name: dup-again\n"
        "allow_commands: [git]\n"
        "allowed_effect_types: [observe]\n"
        "allowed_risk_classes: [low]\n"
        "max_timeout_sec: 30\n"
        "network: deny\n"
        "allow_secret_refs: false\n"
        "allowed_cwd_prefixes: [/workspace]\n"
        "allowed_read_prefixes: [/workspace]\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="duplicate key"):
        load_policy(str(dup))


def test_load_rejects_missing_required_field(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "policy_schema_version: csc.policy.v0.1\nname: incomplete\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="schema validation failed"):
        load_policy(str(bad))


def test_load_rejects_wrong_schema_version(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "policy_schema_version: csc.policy.v9.9\n"
        "name: wrong-version\n"
        "allow_commands: [git]\n"
        "allowed_effect_types: [observe]\n"
        "allowed_risk_classes: [low]\n"
        "max_timeout_sec: 30\n"
        "network: deny\n"
        "allow_secret_refs: false\n"
        "allowed_cwd_prefixes: [/workspace]\n"
        "allowed_read_prefixes: [/workspace]\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="schema validation failed"):
        load_policy(str(bad))


def test_load_rejects_unknown_field(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "policy_schema_version: csc.policy.v0.1\n"
        "name: has-extra\n"
        "allow_commands: [git]\n"
        "allowed_effect_types: [observe]\n"
        "allowed_risk_classes: [low]\n"
        "max_timeout_sec: 30\n"
        "network: deny\n"
        "allow_secret_refs: false\n"
        "allowed_cwd_prefixes: [/workspace]\n"
        "allowed_read_prefixes: [/workspace]\n"
        "totally_bogus_field: true\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="schema validation failed"):
        load_policy(str(bad))


def test_load_rejects_empty_allow_commands(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "policy_schema_version: csc.policy.v0.1\n"
        "name: empty-commands\n"
        "allow_commands: []\n"
        "allowed_effect_types: [observe]\n"
        "allowed_risk_classes: [low]\n"
        "max_timeout_sec: 30\n"
        "network: deny\n"
        "allow_secret_refs: false\n"
        "allowed_cwd_prefixes: [/workspace]\n"
        "allowed_read_prefixes: [/workspace]\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="schema validation failed"):
        load_policy(str(bad))


def test_load_rejects_invalid_yaml(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("foo: [1, 2\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(str(bad))


def test_load_rejects_nonexistent_file(tmp_path):
    with pytest.raises(PolicyError, match="failed to read"):
        load_policy(str(tmp_path / "missing.yaml"))


def test_load_rejects_non_mapping(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="must contain a YAML mapping"):
        load_policy(str(bad))


def test_load_rejects_relative_path_prefix(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "policy_schema_version: csc.policy.v0.1\n"
        "name: relative-prefix\n"
        "allow_commands: [git]\n"
        "allowed_effect_types: [observe]\n"
        "allowed_risk_classes: [low]\n"
        "max_timeout_sec: 30\n"
        "network: deny\n"
        "allow_secret_refs: false\n"
        "allowed_cwd_prefixes: [relative/path]\n"
        "allowed_read_prefixes: [/workspace]\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="schema validation failed"):
        load_policy(str(bad))
