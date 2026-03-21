"""Tests for command executor.

These tests use python -c for cross-platform subprocess verification.
They test the executor directly, not through the policy layer.
"""

from __future__ import annotations

import hashlib
import os
import sys

import pytest

from csc_runner.executor import run_contract
from csc_runner.limits import MAX_STDOUT_CAPTURE_BYTES
from csc_runner.models import (
    Actor,
    Command,
    CommandContract,
    ExecSpec,
    PipelineSegment,
    PipelineSpec,
)

PYTHON = sys.executable

_CWD = os.path.realpath(os.getcwd())

_ACTOR = Actor(
    agent_id="worker-1",
    session_id="sess-001",
    initiating_user="fabio",
    delegation_scope="test",
)


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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


def _make_contract(commands: list[Command]) -> CommandContract:
    return CommandContract(
        version="csc.v0.1",
        contract_id="exec-test-001",
        intent="executor test",
        actor=_ACTOR,
        commands=commands,
        risk_class="low",
        approval_mode="policy_only",
        justification="testing executor",
    )


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


# ---------------------------------------------------------------------------
# Existing tests (updated for new signature)
# ---------------------------------------------------------------------------


def test_successful_command_receipt():
    cmd = _make_exec_command([PYTHON, "-c", "print('hello')"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "success"
    assert receipt["exit_code"] == 0
    assert receipt["completed_command_ids"] == ["cmd_1"]
    assert receipt["failed_command_id"] is None


def test_failing_command_receipt():
    cmd = _make_exec_command([PYTHON, "-c", "import sys; sys.exit(1)"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 1
    assert receipt["completed_command_ids"] == []
    assert receipt["failed_command_id"] == "cmd_1"


@pytest.mark.timeout(10)
def test_timeout_respected():
    cmd = _make_exec_command(
        [PYTHON, "-c", "import time; time.sleep(30)"],
        timeout_sec=1,
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 124
    assert "timed out" in receipt["error"]


def test_env_filtered_to_allowlist():
    cmd = _make_exec_command(
        [
            PYTHON,
            "-c",
            "import os; print(os.environ.get('CSC_TEST_VAR', 'missing')); "
            "print(os.environ.get('CSC_TEST_BLOCKED', 'missing'))",
        ],
        env_allow=["CSC_TEST_VAR"],
    )

    previous_var = os.environ.get("CSC_TEST_VAR")
    previous_blocked = os.environ.get("CSC_TEST_BLOCKED")
    os.environ["CSC_TEST_VAR"] = "present"
    os.environ["CSC_TEST_BLOCKED"] = "should_not_appear"
    try:
        contract = _make_contract([cmd])
        receipt = run_contract(contract, "test-policy", _POLICY)
        assert receipt["status"] == "success"
        nl = os.linesep.encode()
        expected = b"present" + nl + b"missing" + nl
        assert receipt["stdout_hash"] == _sha256_bytes(expected)
    finally:
        if previous_var is None:
            os.environ.pop("CSC_TEST_VAR", None)
        else:
            os.environ["CSC_TEST_VAR"] = previous_var
        if previous_blocked is None:
            os.environ.pop("CSC_TEST_BLOCKED", None)
        else:
            os.environ["CSC_TEST_BLOCKED"] = previous_blocked


def test_completed_and_failed_command_ids():
    cmd1 = _make_exec_command([PYTHON, "-c", "print('ok')"], id="cmd_1")
    cmd2 = _make_exec_command(
        [PYTHON, "-c", "import sys; sys.exit(1)"],
        id="cmd_2",
    )
    contract = _make_contract([cmd1, cmd2])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "failed"
    assert receipt["completed_command_ids"] == ["cmd_1"]
    assert receipt["failed_command_id"] == "cmd_2"


def test_pipeline_execution():
    cmd = Command(
        id="cmd_1",
        pipeline=PipelineSpec(
            segments=[
                PipelineSegment(argv=[PYTHON, "-c", "print('hello world')"]),
                PipelineSegment(argv=[PYTHON, "-c", "import sys; print(sys.stdin.read().upper())"]),
            ]
        ),
        cwd=_CWD,
        read_paths=[],
        write_paths=[],
        network="deny",
        env_allow=[],
        secret_refs=[],
        timeout_sec=10,
        proposed_effect_type="observe",
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "success"
    assert receipt["completed_command_ids"] == ["cmd_1"]
    nl = os.linesep.encode()
    expected = b"HELLO WORLD" + nl + nl
    assert receipt["stdout_hash"] == _sha256_bytes(expected)


def test_file_not_found_receipt():
    cmd = _make_exec_command(["nonexistent_command_that_does_not_exist_xyz"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 127
    assert receipt["failed_command_id"] == "cmd_1"


def test_receipt_provenance_success():
    cmd = _make_exec_command([PYTHON, "-c", "print('ok')"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["receipt_version"] == "csc.receipt.v0.1"
    assert receipt["runner_version"] is not None
    assert receipt["execution_mode"] == "local"


def test_receipt_provenance_failed():
    cmd = _make_exec_command([PYTHON, "-c", "import sys; sys.exit(1)"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["receipt_version"] == "csc.receipt.v0.1"
    assert receipt["runner_version"] is not None
    assert receipt["execution_mode"] == "local"


@pytest.mark.timeout(10)
def test_receipt_provenance_timeout():
    cmd = _make_exec_command(
        [PYTHON, "-c", "import time; time.sleep(30)"],
        timeout_sec=1,
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["receipt_version"] == "csc.receipt.v0.1"
    assert receipt["runner_version"] is not None
    assert receipt["execution_mode"] == "local"


# ---------------------------------------------------------------------------
# Stage 1b: limits and path enforcement
# ---------------------------------------------------------------------------


def test_limits_blocked_receipt():
    contract = CommandContract.model_construct(
        version="csc.v0.1",
        contract_id="exec-test-limits",
        intent="test",
        actor=_ACTOR,
        commands=[_make_exec_command([PYTHON, "-c", "pass"], id=f"cmd_{i}") for i in range(21)],
        risk_class="low",
        approval_mode="policy_only",
        justification="test",
    )
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "blocked"
    assert "commands" in receipt["error"]
    assert receipt["completed_command_ids"] == []
    assert receipt["failed_command_id"] is None
    assert "exit_code" not in receipt


def test_path_escape_blocked(tmp_path):
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
    assert receipt["failed_command_id"] == "cmd_1"


def test_cwd_not_found(tmp_path):
    nonexistent = str(tmp_path / "does_not_exist")
    policy = _make_policy(allowed_cwd_prefixes=[str(tmp_path)])
    cmd = _make_exec_command([PYTHON, "-c", "pass"], cwd=nonexistent)
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", policy)
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 126
    assert receipt["failed_command_id"] == "cmd_1"
    assert "not a directory" in receipt["error"] or "does not exist" in receipt["error"]


def test_policy_provenance_in_receipt():
    cmd = _make_exec_command([PYTHON, "-c", "print('ok')"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["policy_schema_version"] == "csc.policy.v0.1"
    assert "policy_sha256" in receipt
    assert len(receipt["policy_sha256"]) == 64


def test_blocked_preserves_completed_ids():
    cmd1 = _make_exec_command([PYTHON, "-c", "pass"], id="cmd_1")
    cmd2 = _make_exec_command(
        [PYTHON, "-c", "pass"],
        id="cmd_2",
        read_paths=["/outside/scope/**"],
    )
    contract = _make_contract([cmd1, cmd2])
    policy = _make_policy(allowed_read_prefixes=["/workspace"])
    receipt = run_contract(contract, "test-policy", policy)
    assert receipt["status"] == "blocked"
    assert receipt["exit_code"] == 126
    assert receipt["completed_command_ids"] == ["cmd_1"]
    assert receipt["failed_command_id"] == "cmd_2"


# ---------------------------------------------------------------------------
# Stage 1b: failure mode coverage
# ---------------------------------------------------------------------------


def test_permission_error_receipt(monkeypatch, tmp_path):
    policy = _make_policy(allowed_cwd_prefixes=[str(tmp_path)])
    cmd = _make_exec_command([PYTHON, "-c", "pass"], cwd=str(tmp_path))
    contract = _make_contract([cmd])

    def _deny(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr("csc_runner.executor.subprocess.Popen", _deny)

    receipt = run_contract(contract, "test-policy", policy)
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 126
    assert receipt["failed_command_id"] == "cmd_1"
    assert "permission denied" in receipt["error"].lower()


def test_catch_all_internal_error(monkeypatch):
    cmd = _make_exec_command([PYTHON, "-c", "pass"])
    contract = _make_contract([cmd])

    def _boom(*args, **kwargs):
        raise RuntimeError("synthetic internal error")

    monkeypatch.setattr("csc_runner.executor._run_exec", _boom)
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 1
    assert "internal runner error" in receipt["error"]
    assert "synthetic internal error" in receipt["error"]


# ---------------------------------------------------------------------------
# Stage 1b: capped output capture
# ---------------------------------------------------------------------------


def test_large_stdout_not_truncated():
    size = 200_000
    assert size < MAX_STDOUT_CAPTURE_BYTES
    cmd = _make_exec_command(
        [PYTHON, "-c", f"import sys; sys.stdout.buffer.write(b'x' * {size})"],
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "success"
    assert receipt.get("stdout_truncated") is not True
    expected = b"x" * size
    assert receipt["stdout_hash"] == _sha256_bytes(expected)


def test_stdout_truncated_flag(monkeypatch):
    monkeypatch.setattr("csc_runner.executor.MAX_STDOUT_CAPTURE_BYTES", 100)
    size = 500
    cmd = _make_exec_command(
        [PYTHON, "-c", f"import sys; sys.stdout.buffer.write(b'A' * {size})"],
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "success"
    assert receipt["stdout_truncated"] is True


def test_stdout_hash_covers_captured_prefix(monkeypatch):
    cap = 100
    monkeypatch.setattr("csc_runner.executor.MAX_STDOUT_CAPTURE_BYTES", cap)
    size = 500
    cmd = _make_exec_command(
        [PYTHON, "-c", f"import sys; sys.stdout.buffer.write(b'B' * {size})"],
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy", _POLICY)
    assert receipt["status"] == "success"
    assert receipt["stdout_truncated"] is True
    prefix = b"B" * cap
    assert receipt["stdout_hash"] == _sha256_bytes(prefix)
    full = b"B" * size
    assert receipt["stdout_hash"] != _sha256_bytes(full)
