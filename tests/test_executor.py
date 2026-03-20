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
from csc_runner.models import (
    Actor,
    Command,
    CommandContract,
    ExecSpec,
    PipelineSegment,
    PipelineSpec,
)

PYTHON = sys.executable


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _make_contract(commands: list[Command]) -> CommandContract:
    return CommandContract(
        version="csc.v0.1",
        contract_id="exec-test-001",
        intent="executor test",
        actor=Actor(
            agent_id="worker-1",
            session_id="sess-001",
            initiating_user="fabio",
            delegation_scope="test",
        ),
        commands=commands,
        risk_class="low",
        approval_mode="policy_only",
        justification="testing executor",
    )


def _make_exec_command(argv: list[str], **overrides) -> Command:
    defaults = {
        "id": "cmd_1",
        "exec": ExecSpec(argv=argv),
        "cwd": ".",
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


def test_successful_command_receipt():
    cmd = _make_exec_command([PYTHON, "-c", "print('hello')"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy")
    assert receipt["status"] == "success"
    assert receipt["exit_code"] == 0
    assert receipt["completed_command_ids"] == ["cmd_1"]
    assert receipt["failed_command_id"] is None


def test_failing_command_receipt():
    cmd = _make_exec_command([PYTHON, "-c", "import sys; sys.exit(1)"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy")
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
    receipt = run_contract(contract, "test-policy")
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
        receipt = run_contract(contract, "test-policy")
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
    receipt = run_contract(contract, "test-policy")
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
        cwd=".",
        read_paths=[],
        write_paths=[],
        network="deny",
        env_allow=[],
        secret_refs=[],
        timeout_sec=10,
        proposed_effect_type="observe",
    )
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy")
    assert receipt["status"] == "success"
    assert receipt["completed_command_ids"] == ["cmd_1"]
    nl = os.linesep.encode()
    expected = b"HELLO WORLD" + nl + nl
    assert receipt["stdout_hash"] == _sha256_bytes(expected)


def test_file_not_found_receipt():
    cmd = _make_exec_command(["nonexistent_command_that_does_not_exist_xyz"])
    contract = _make_contract([cmd])
    receipt = run_contract(contract, "test-policy")
    assert receipt["status"] == "failed"
    assert receipt["exit_code"] == 127
    assert receipt["failed_command_id"] == "cmd_1"
