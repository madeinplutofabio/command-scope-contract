"""Conformance test runner — executes all fixtures in tests/conformance/.

Each fixture file is loaded and every entry is run as a parameterized test case.
Schema fixtures validate inputs against JSON Schema.
Decision fixtures evaluate contracts against policies and check outcomes.
Loader fixtures test policy file loading behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from csc_runner.models import (
    Actor,
    Command,
    CommandContract,
    ExecSpec,
    PipelineSegment,
    PipelineSpec,
)
from csc_runner.policy import PolicyError, evaluate_contract, load_policy
from tests.helpers import validate_against_schema

CONFORMANCE_DIR = Path(__file__).resolve().parent / "conformance"


# ---------------------------------------------------------------------------
# Fixture loading helpers
# ---------------------------------------------------------------------------


def _load_fixtures(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_id(fixture: dict) -> str:
    return fixture["id"]


# ---------------------------------------------------------------------------
# Schema validation fixtures
# ---------------------------------------------------------------------------

CONTRACT_SCHEMA = "csc.contract.v0.1.schema.json"
POLICY_SCHEMA = "csc.policy.v0.1.schema.json"
RECEIPT_SCHEMA = "csc.execution-receipt.v0.1.schema.json"

_contract_valid = _load_fixtures(CONFORMANCE_DIR / "contracts" / "valid.json")
_contract_invalid = _load_fixtures(CONFORMANCE_DIR / "contracts" / "invalid.json")
_policy_schema_fixtures = _load_fixtures(CONFORMANCE_DIR / "policies" / "schema.json")
_receipt_valid = _load_fixtures(CONFORMANCE_DIR / "receipts" / "valid.json")
_receipt_invalid = _load_fixtures(CONFORMANCE_DIR / "receipts" / "invalid.json")


@pytest.mark.parametrize("fixture", _contract_valid, ids=_fixture_id)
def test_contract_valid(fixture):
    validate_against_schema(fixture["input"], CONTRACT_SCHEMA)


@pytest.mark.parametrize("fixture", _contract_invalid, ids=_fixture_id)
def test_contract_invalid(fixture):
    with pytest.raises(ValidationError):
        validate_against_schema(fixture["input"], CONTRACT_SCHEMA)


@pytest.mark.parametrize(
    "fixture",
    [f for f in _policy_schema_fixtures if f["valid"]],
    ids=_fixture_id,
)
def test_policy_schema_valid(fixture):
    validate_against_schema(fixture["input"], POLICY_SCHEMA)


@pytest.mark.parametrize(
    "fixture",
    [f for f in _policy_schema_fixtures if not f["valid"]],
    ids=_fixture_id,
)
def test_policy_schema_invalid(fixture):
    with pytest.raises(ValidationError):
        validate_against_schema(fixture["input"], POLICY_SCHEMA)


@pytest.mark.parametrize("fixture", _receipt_valid, ids=_fixture_id)
def test_receipt_valid(fixture):
    validate_against_schema(fixture["input"], RECEIPT_SCHEMA)


@pytest.mark.parametrize("fixture", _receipt_invalid, ids=_fixture_id)
def test_receipt_invalid(fixture):
    with pytest.raises(ValidationError):
        validate_against_schema(fixture["input"], RECEIPT_SCHEMA)


# ---------------------------------------------------------------------------
# Policy loader fixtures
# ---------------------------------------------------------------------------

_loader_fixtures = _load_fixtures(CONFORMANCE_DIR / "policies" / "loader.json")


@pytest.mark.parametrize(
    "fixture",
    [f for f in _loader_fixtures if f["valid"]],
    ids=_fixture_id,
)
def test_policy_loader_valid(fixture, tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(fixture["raw_text"], encoding="utf-8")
    policy = load_policy(str(policy_file))
    assert isinstance(policy, dict)
    assert policy["policy_schema_version"] == "csc.policy.v0.1"


@pytest.mark.parametrize(
    "fixture",
    [f for f in _loader_fixtures if not f["valid"]],
    ids=_fixture_id,
)
def test_policy_loader_invalid(fixture, tmp_path):
    if fixture.get("source") == "missing_file":
        path = str(tmp_path / "missing.yaml")
    else:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(fixture["raw_text"], encoding="utf-8")
        path = str(policy_file)

    with pytest.raises(PolicyError, match=fixture["expected_error_contains"]):
        load_policy(path)


# ---------------------------------------------------------------------------
# Decision fixtures
# ---------------------------------------------------------------------------

_decision_fixtures = _load_fixtures(CONFORMANCE_DIR / "decisions" / "decisions.json")


def _build_command(cmd_data: dict) -> Command:
    """Build a Command model from a fixture dict."""
    exec_spec = None
    pipeline_spec = None

    if "exec" in cmd_data:
        exec_spec = ExecSpec(argv=cmd_data["exec"]["argv"])

    if "pipeline" in cmd_data:
        segments = [PipelineSegment(argv=s["argv"]) for s in cmd_data["pipeline"]["segments"]]
        pipeline_spec = PipelineSpec(segments=segments)

    return Command(
        id=cmd_data["id"],
        exec=exec_spec,
        pipeline=pipeline_spec,
        cwd=cmd_data["cwd"],
        read_paths=cmd_data["read_paths"],
        write_paths=cmd_data["write_paths"],
        network=cmd_data["network"],
        env_allow=cmd_data["env_allow"],
        secret_refs=cmd_data["secret_refs"],
        timeout_sec=cmd_data["timeout_sec"],
        proposed_effect_type=cmd_data["proposed_effect_type"],
    )


def _build_contract(contract_data: dict) -> CommandContract:
    """Build a CommandContract model from a fixture dict."""
    actor_data = contract_data["actor"]
    actor = Actor(
        agent_id=actor_data["agent_id"],
        session_id=actor_data["session_id"],
        initiating_user=actor_data["initiating_user"],
        delegation_scope=actor_data["delegation_scope"],
    )
    commands = [_build_command(c) for c in contract_data["commands"]]
    return CommandContract(
        version=contract_data["version"],
        contract_id=contract_data["contract_id"],
        intent=contract_data["intent"],
        actor=actor,
        commands=commands,
        risk_class=contract_data["risk_class"],
        approval_mode=contract_data["approval_mode"],
        justification=contract_data["justification"],
        expected_outputs=contract_data.get("expected_outputs", []),
    )


@pytest.mark.parametrize("fixture", _decision_fixtures, ids=_fixture_id)
def test_decision(fixture):
    validate_against_schema(fixture["contract"], CONTRACT_SCHEMA)
    validate_against_schema(fixture["policy"], POLICY_SCHEMA)

    contract = _build_contract(fixture["contract"])
    policy = fixture["policy"]

    result = evaluate_contract(contract, policy)

    assert result.decision == fixture["expected_decision"], (
        f"{fixture['id']}: expected decision {fixture['expected_decision']!r}, "
        f"got {result.decision!r} (reasons: {result.reasons})"
    )

    assert result.reason_codes == fixture["expected_reason_codes"], (
        f"{fixture['id']}: expected reason_codes {fixture['expected_reason_codes']!r}, got {result.reason_codes!r}"
    )

    if "expected_classified_effects" in fixture:
        actual_effects = {tuple(sorted(e.items())) for e in result.classified_effects}
        expected_effects = {tuple(sorted(e.items())) for e in fixture["expected_classified_effects"]}
        assert actual_effects == expected_effects, (
            f"{fixture['id']}: expected classified_effects "
            f"{fixture['expected_classified_effects']!r}, "
            f"got {result.classified_effects!r}"
        )
