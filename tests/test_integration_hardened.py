"""End-to-end hardened mode integration tests.

These tests verify the full hardened execution path:
contract → policy → approval → sandbox → execution → signed receipt.

Requirements:
- Linux with bubblewrap, setpriv, prlimit installed
- /workspace directory exists
- Designed to run inside the CSC hardened Docker container

On other platforms, when tools are missing, or when /workspace
does not exist, tests are skipped.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
from pathlib import Path

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
from csc_runner.sandbox import SandboxConfig, SandboxError, verify_hardened_runtime
from csc_runner.signing import (
    StaticKeyResolver,
    generate_test_keypair,
    verify_receipt_signature,
)

# Skip entire module if not on Linux, tools missing, or workspace absent.
_REQUIRED_TOOLS = ("bwrap", "setpriv", "prlimit")
_TOOLS_AVAILABLE = all(shutil.which(t) is not None for t in _REQUIRED_TOOLS)
_IS_LINUX = platform.system() == "Linux"
_WORKSPACE = "/workspace"
_WORKSPACE_EXISTS = Path(_WORKSPACE).is_dir()

pytestmark = pytest.mark.skipif(
    not (_IS_LINUX and _TOOLS_AVAILABLE and _WORKSPACE_EXISTS),
    reason=("hardened integration tests require Linux with bwrap, setpriv, prlimit, and /workspace directory"),
)

_ACTOR = Actor(
    agent_id="integration-1",
    session_id="sess-int",
    initiating_user="ci",
    delegation_scope="test",
)


def _make_policy(**overrides) -> dict:
    defaults = {
        "name": "integration-test",
        "policy_schema_version": "csc.policy.v0.1",
        "allowed_cwd_prefixes": [_WORKSPACE],
        "allowed_read_prefixes": [_WORKSPACE],
        "allowed_write_prefixes": [_WORKSPACE],
    }
    defaults.update(overrides)
    return defaults


def _make_contract(commands: list[Command], **overrides) -> CommandContract:
    defaults = {
        "version": "csc.v0.1",
        "contract_id": "integration-test-001",
        "intent": "hardened integration test",
        "actor": _ACTOR,
        "commands": commands,
        "risk_class": "low",
        "approval_mode": "policy_only",
        "justification": "integration testing",
    }
    defaults.update(overrides)
    return CommandContract(**defaults)


def _make_exec_command(argv: list[str], **overrides) -> Command:
    defaults = {
        "id": "cmd_1",
        "exec": ExecSpec(argv=argv),
        "cwd": _WORKSPACE,
        "read_paths": [f"{_WORKSPACE}/**"],
        "write_paths": [],
        "network": "deny",
        "env_allow": [],
        "secret_refs": [],
        "timeout_sec": 30,
        "proposed_effect_type": "observe",
    }
    defaults.update(overrides)
    return Command(**defaults)


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture()
def keypair():
    priv, pub = generate_test_keypair()
    return priv, pub


@pytest.fixture()
def sandbox_config():
    """Sandbox config without privilege drop (non-root container user)."""
    return SandboxConfig(
        require_network_disabled=False,  # CI may not have --network=none
    )


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


class TestHardenedPreflight:
    def test_verify_hardened_runtime_passes(self, sandbox_config):
        verify_hardened_runtime(sandbox_config)

    def test_verify_rejects_non_linux(self, monkeypatch, sandbox_config):
        monkeypatch.setattr("csc_runner.sandbox.platform.system", lambda: "Windows")
        with pytest.raises(SandboxError, match="requires Linux"):
            verify_hardened_runtime(sandbox_config)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


class TestHardenedExecution:
    def test_workspace_command_success(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/ls", _WORKSPACE])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "success"
        assert receipt["execution_mode"] == "hardened"
        assert "signature" in receipt

    def test_signed_receipt_verifiable(self, keypair, sandbox_config):
        priv, pub = keypair
        cmd = _make_exec_command(["/bin/echo", "hello"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        resolver = StaticKeyResolver(keys={"test-key": pub})
        assert verify_receipt_signature(receipt, resolver=resolver) is True

    def test_command_not_found_receipt(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/nonexistent_binary_xyz"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "failed"
        assert "signature" in receipt


# ---------------------------------------------------------------------------
# Sandbox filesystem boundaries
# ---------------------------------------------------------------------------


class TestSandboxFilesystem:
    def test_write_inside_workspace_succeeds(self, keypair, sandbox_config):
        priv, _ = keypair
        target = f"{_WORKSPACE}/integration_test_output.txt"
        cmd = _make_exec_command(
            ["/bin/touch", target],
            write_paths=[f"{_WORKSPACE}/**"],
        )
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "success"
        assert Path(target).exists()
        Path(target).unlink(missing_ok=True)

    def test_write_outside_workspace_fails(self, keypair, sandbox_config):
        priv, _ = keypair
        outside_target = "/outside_workspace/should_not_exist"
        cmd = _make_exec_command(
            ["/bin/touch", outside_target],
            write_paths=[f"{_WORKSPACE}/**"],
        )
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "failed"
        assert receipt["exit_code"] != 0
        assert not Path(outside_target).exists()

    def test_read_workspace_visible(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/ls", _WORKSPACE])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "success"


# ---------------------------------------------------------------------------
# Network enforcement
# ---------------------------------------------------------------------------


class TestNetworkEnforcement:
    def test_only_loopback_inside_sandbox(self, keypair, sandbox_config):
        """bwrap --unshare-net creates a network namespace with only loopback.

        /proc/net/dev lists network interfaces. Lines with ":" are
        interface entries (header lines use "|"). With only loopback,
        grep -c ":" should output exactly "1" (just the lo: line).

        This is a structural namespace verification, not a behavioral
        connectivity test.
        """
        priv, _ = keypair
        cmd = _make_exec_command(
            ["/bin/grep", "-c", ":", "/proc/net/dev"],
            read_paths=["/proc/**"],
        )
        contract = _make_contract([cmd])
        policy = _make_policy(
            allowed_read_prefixes=[_WORKSPACE, "/proc"],
        )

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "success"
        # grep -c outputs the count followed by newline.
        # Exactly 1 interface line (lo:) means only loopback.
        assert receipt["stdout_hash"] == _sha256_bytes(b"1\n")


# ---------------------------------------------------------------------------
# no_new_privs enforcement
# ---------------------------------------------------------------------------


class TestNoNewPrivs:
    def test_no_new_privs_set_inside_sandbox(self, keypair, sandbox_config):
        """setpriv --no-new-privs is always applied.

        /proc/self/status contains a NoNewPrivs field. Use grep -c to
        count lines matching "NoNewPrivs:.*1". If no_new_privs is set,
        exactly one line matches, producing "1" on stdout.

        This avoids depending on exact whitespace formatting.
        """
        priv, _ = keypair
        cmd = _make_exec_command(
            ["/bin/grep", "-c", "NoNewPrivs:.*1", "/proc/self/status"],
            read_paths=["/proc/**"],
        )
        contract = _make_contract([cmd])
        policy = _make_policy(
            allowed_read_prefixes=[_WORKSPACE, "/proc"],
        )

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "success"
        # grep -c outputs count + newline. Exactly 1 match expected.
        assert receipt["stdout_hash"] == _sha256_bytes(b"1\n")


# ---------------------------------------------------------------------------
# Sandbox command blocking
# ---------------------------------------------------------------------------


class TestSandboxBlocking:
    def test_pipeline_blocked_in_hardened(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = Command(
            id="cmd_1",
            pipeline=PipelineSpec(
                segments=[
                    PipelineSegment(argv=["/bin/echo", "hi"]),
                    PipelineSegment(argv=["/bin/cat"]),
                ]
            ),
            cwd=_WORKSPACE,
            read_paths=[],
            write_paths=[],
            network="deny",
            env_allow=[],
            secret_refs=[],
            timeout_sec=10,
            proposed_effect_type="observe",
        )
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "blocked"
        assert "pipeline" in receipt["error"].lower()

    def test_blocked_command_rejected(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/bash", "-c", "echo hi"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "blocked"
        assert "blocked" in receipt["error"].lower()


# ---------------------------------------------------------------------------
# Signing enforcement
# ---------------------------------------------------------------------------


class TestSigningEnforcement:
    def test_hardened_without_signing_blocked(self, sandbox_config):
        cmd = _make_exec_command(["/bin/echo", "hi"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
        )

        assert receipt["status"] == "blocked"
        assert "signing" in receipt["error"].lower()
        assert "signature" not in receipt

    def test_hardened_with_empty_key_id_blocked(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/echo", "hi"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="",
        )

        assert receipt["status"] == "blocked"
        assert "signing" in receipt["error"].lower()


# ---------------------------------------------------------------------------
# Approval enforcement
# ---------------------------------------------------------------------------


class TestApprovalEnforcement:
    def test_approval_required_but_absent(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/echo", "hi"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            approval_required=True,
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "blocked"
        assert "approval" in receipt["error"].lower()
        assert "signature" in receipt

    def test_approval_hash_mismatch_blocked(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/echo", "hi"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        wrong_approval = {
            "approval_version": "csc.approval.v0.1",
            "approval_id": "approval-int-001",
            "contract_sha256": "ab" * 32,
            "approver": {"identity": "ci@test", "method": "cli"},
            "approved_at": "2026-03-23T11:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
            "scope": "single_execution",
        }

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            approval=wrong_approval,
            approval_required=True,
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "blocked"
        assert "mismatch" in receipt["error"].lower()

    def test_expired_approval_blocked(self, keypair, sandbox_config):
        priv, _ = keypair
        cmd = _make_exec_command(["/bin/echo", "hi"])
        contract = _make_contract([cmd])
        policy = _make_policy()

        from csc_runner.utils import hash_contract

        contract_sha = hash_contract(contract)

        expired_approval = {
            "approval_version": "csc.approval.v0.1",
            "approval_id": "approval-int-expired",
            "contract_sha256": contract_sha,
            "approver": {"identity": "ci@test", "method": "cli"},
            "approved_at": "2020-01-01T00:00:00Z",
            "expires_at": "2020-01-01T01:00:00Z",
            "scope": "single_execution",
        }

        receipt = run_contract(
            contract,
            "integration-test",
            policy,
            mode="hardened",
            approval=expired_approval,
            approval_required=True,
            sandbox_config=sandbox_config,
            private_key_bytes=priv,
            signing_key_id="test-key",
        )

        assert receipt["status"] == "blocked"
        assert "expired" in receipt["error"].lower()
