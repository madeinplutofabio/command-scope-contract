"""Tests for JSON Schema validation of CSC objects."""

from __future__ import annotations

import copy

import pytest
from jsonschema import ValidationError

from tests.helpers import validate_against_schema

CONTRACT_SCHEMA = "csc.contract.v0.1.schema.json"

VALID_CONTRACT = {
    "version": "csc.v0.1",
    "contract_id": "test-contract-001",
    "intent": "run unit tests",
    "actor": {
        "agent_id": "worker-1",
        "session_id": "sess-001",
        "initiating_user": "fabio",
        "delegation_scope": "repo-maintainer",
    },
    "commands": [
        {
            "id": "cmd_1",
            "exec": {"argv": ["git", "status"]},
            "cwd": "/workspace/repo",
            "read_paths": ["/workspace/repo/**"],
            "write_paths": [],
            "network": "deny",
            "env_allow": [],
            "secret_refs": [],
            "timeout_sec": 10,
            "proposed_effect_type": "observe",
        }
    ],
    "risk_class": "low",
    "approval_mode": "policy_only",
    "expected_outputs": [],
    "justification": "testing schema validation",
}


def test_valid_contract_accepted():
    validate_against_schema(VALID_CONTRACT, CONTRACT_SCHEMA)


def test_missing_required_field_rejected():
    invalid = copy.deepcopy(VALID_CONTRACT)
    del invalid["contract_id"]
    with pytest.raises(ValidationError, match="contract_id"):
        validate_against_schema(invalid, CONTRACT_SCHEMA)


def test_invalid_risk_class_rejected():
    invalid = copy.deepcopy(VALID_CONTRACT)
    invalid["risk_class"] = "dangerous"
    with pytest.raises(ValidationError, match="dangerous"):
        validate_against_schema(invalid, CONTRACT_SCHEMA)


def test_invalid_effect_type_rejected():
    invalid = copy.deepcopy(VALID_CONTRACT)
    invalid["commands"][0]["proposed_effect_type"] = "hack_everything"
    with pytest.raises(ValidationError, match="hack_everything"):
        validate_against_schema(invalid, CONTRACT_SCHEMA)


def test_contract_with_both_exec_and_pipeline_rejected():
    invalid = copy.deepcopy(VALID_CONTRACT)
    invalid["commands"][0]["pipeline"] = {
        "segments": [{"argv": ["echo", "a"]}, {"argv": ["cat"]}]
    }
    with pytest.raises(ValidationError):
        validate_against_schema(invalid, CONTRACT_SCHEMA)


def test_too_many_commands_rejected():
    invalid = copy.deepcopy(VALID_CONTRACT)
    invalid["commands"] = invalid["commands"] * 21
    with pytest.raises(ValidationError):
        validate_against_schema(invalid, CONTRACT_SCHEMA)


def test_relative_cwd_rejected():
    invalid = copy.deepcopy(VALID_CONTRACT)
    invalid["commands"][0]["cwd"] = "workspace/repo"
    with pytest.raises(ValidationError):
        validate_against_schema(invalid, CONTRACT_SCHEMA)
