"""Tests for receipt integrity — deterministic structure, hash binding,
blocked-vs-failed field semantics, and schema validation."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from csc_runner.executor import run_contract
from csc_runner.models import (
    Actor,
    Command,
    CommandContract,
    ExecSpec,
)
from csc_runner.utils import hash_contract

PYTHON = sys.executable

_CWD = os.path.realpath(os.getcwd())

_ACTOR = Actor(
    agent_id="worker-1",
    session_id="sess-001",
    initiating_user="fabio",
    delegation_scope="test",
)

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "csc.execution-receipt.v0.1.schema.json"
_RECEIPT_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(_RECEIPT_SCHEMA)


def _make_policy(**overrides) -> dict:
    defaults = {
        "name": "test-policy",
        "policy_schema_version": "csc.policy.v0.1",
        "allowed_cwd_prefixes": [_CWD],
        "allowed_read_prefixes": [],
        "allowed_write_prefixes": [],
    }
    defaults.update(overrides)
    return defaults


_POLICY = _make_policy()


def _make_contract(commands: list[Command], **overrides) -> CommandContract:
    defaults = {
        "version": "csc.v0.1",
        "contract_id": "receipt-test-001",
        "intent": "receipt integrity test",
        "actor": _ACTOR,
        "commands": commands,
        "risk_class": "low",
        "approval_mode": "policy_only",
        "justification": "testing receipt integrity",
    }
    defaults.update(overrides)
    return CommandContract(**defaults)


def _make_exec_command(argv: list[str], **overrides) -> Command:
    defaults = {
        "id": "cmd_1",
        "exec": ExecSpec(argv=argv),
        "cwd": _CWD,
        "read_paths": [],
        "write_paths": [],
        "network": "deny",
        "env_allow": [],
        "secret_refs": [],
        "timeout_sec": 10,
        "proposed_effect_type": "observe",
    }
    defaults.update(overrides)
    return Command(**defaults)


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Deterministic hashing
# ---------------------------------------------------------------------------


def test_same_contract_same_sha256():
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])
    receipt1 = run_contract(contract, "test-policy", _POLICY)
    receipt2 = run_contract(contract, "test-policy", _POLICY)
    assert receipt1["contract_sha256"] == receipt2["contract_sha256"]


def test_contract_sha256_matches_independent_hash():
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["contract_sha256"] == hash_contract(contract)


# ---------------------------------------------------------------------------
# Schema validation for every failure mode
# ---------------------------------------------------------------------------


def test_success_receipt_validates():
    cmd = _make_exec_command([PYTHON, "-c", "print('ok')"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


def test_failed_receipt_validates():
    cmd = _make_exec_command([PYTHON, "-c", "import sys; sys.exit(1)"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


@pytest.mark.timeout(10)
def test_timeout_receipt_validates():
    cmd = _make_exec_command(
        [PYTHON, "-c", "import time; time.sleep(30)"],
        timeout_sec=1,
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


def test_file_not_found_receipt_validates():
    cmd = _make_exec_command(["nonexistent_command_xyz"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


def test_limits_blocked_receipt_validates():
    contract = CommandContract.model_construct(
        version="csc.v0.1",
        contract_id="receipt-test-limits",
        intent="test",
        actor=_ACTOR,
        commands=[_make_exec_command([PYTHON, "-c", "pass"], id=f"cmd_{i}") for i in range(21)],
        risk_class="low",
        approval_mode="policy_only",
        justification="test",
    )
    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


def test_path_escape_blocked_receipt_validates(tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    policy = _make_policy(allowed_cwd_prefixes=[str(allowed)])
    cmd = _make_exec_command([PYTHON, "-c", "pass"], cwd=str(outside))
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", policy)
    _VALIDATOR.validate(receipt)


def test_cwd_not_found_receipt_validates(tmp_path):
    nonexistent = str(tmp_path / "missing")
    policy = _make_policy(allowed_cwd_prefixes=[str(tmp_path)])
    cmd = _make_exec_command([PYTHON, "-c", "pass"], cwd=nonexistent)
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", policy)
    _VALIDATOR.validate(receipt)


def test_permission_error_receipt_validates(monkeypatch):
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])

    def _deny(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr("csc_runner.executor.subprocess.Popen", _deny)

    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


def test_internal_error_receipt_validates(monkeypatch):
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])

    def _boom(*args, **kwargs):
        raise RuntimeError("synthetic internal error")

    monkeypatch.setattr("csc_runner.executor._run_exec", _boom)

    receipt = run_contract(contract, "test-policy", _POLICY)
    _VALIDATOR.validate(receipt)


# ---------------------------------------------------------------------------
# Blocked vs failed field semantics
# ---------------------------------------------------------------------------


def test_limits_blocked_has_no_exit_code():
    contract = CommandContract.model_construct(
        version="csc.v0.1",
        contract_id="receipt-test-limits-2",
        intent="test",
        actor=_ACTOR,
        commands=[_make_exec_command([PYTHON, "-c", "pass"], id=f"cmd_{i}") for i in range(21)],
        risk_class="low",
        approval_mode="policy_only",
        justification="test",
    )
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "blocked"
    assert "exit_code" not in receipt
    assert "stdout_hash" not in receipt
    assert "stderr_hash" not in receipt


def test_path_escape_blocked_has_exit_code_126(tmp_path):
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()

    policy = _make_policy(allowed_cwd_prefixes=[str(allowed)])
    cmd = _make_exec_command([PYTHON, "-c", "pass"], cwd=str(outside))
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", policy)
    assert receipt["status"] == "blocked"
    assert receipt["exit_code"] == 126


def test_failed_receipt_always_has_exit_code():
    cmd = _make_exec_command([PYTHON, "-c", "import sys; sys.exit(42)"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "failed"
    assert "exit_code" in receipt
    assert receipt["exit_code"] == 42


def test_success_receipt_has_exit_code_zero():
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "success"
    assert receipt["exit_code"] == 0


# ---------------------------------------------------------------------------
# stdout_hash fidelity
# ---------------------------------------------------------------------------


def test_stdout_hash_matches_full_output():
    cmd = _make_exec_command([PYTHON, "-c", "print('hello')"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt.get("stdout_truncated") is not True
    nl = os.linesep.encode()
    expected = b"hello" + nl
    assert receipt["stdout_hash"] == _sha256_bytes(expected)


def test_stdout_hash_matches_captured_prefix_when_truncated(monkeypatch):
    cap = 100
    monkeypatch.setattr("csc_runner.executor.MAX_STDOUT_CAPTURE_BYTES", cap)

    size = 500
    cmd = _make_exec_command([PYTHON, "-c", f"import sys; sys.stdout.buffer.write(b'Z' * {size})"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)

    _VALIDATOR.validate(receipt)
    assert receipt["stdout_truncated"] is True
    assert receipt["stdout_hash"] == _sha256_bytes(b"Z" * cap)
    assert receipt["stdout_hash"] != _sha256_bytes(b"Z" * size)


# ---------------------------------------------------------------------------
# Required fields and types
# ---------------------------------------------------------------------------


def test_success_receipt_required_fields():
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert isinstance(receipt["receipt_version"], str)
    assert isinstance(receipt["contract_id"], str)
    assert isinstance(receipt["execution_id"], str)
    assert isinstance(receipt["contract_sha256"], str)
    assert len(receipt["contract_sha256"]) == 64
    assert isinstance(receipt["status"], str)
    assert isinstance(receipt["started_at"], str)
    assert isinstance(receipt["ended_at"], str)
    assert isinstance(receipt["policy_profile"], str)
    assert isinstance(receipt["runner_version"], str)
    assert isinstance(receipt["execution_mode"], str)
    assert isinstance(receipt["completed_command_ids"], list)


def test_policy_provenance_in_receipt():
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["policy_schema_version"] == "csc.policy.v0.1"
    assert isinstance(receipt["policy_sha256"], str)
    assert len(receipt["policy_sha256"]) == 64
