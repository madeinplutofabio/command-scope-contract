"""Tests for policy evaluation logic."""

from __future__ import annotations

from csc_runner.models import Actor, Command, CommandContract, ExecSpec
from csc_runner.policy import evaluate_contract


def _make_actor() -> Actor:
    return Actor(
        agent_id="worker-1",
        session_id="sess-001",
        initiating_user="fabio",
        delegation_scope="repo-maintainer",
    )


def _make_contract(commands: list[Command], **overrides) -> CommandContract:
    defaults = {
        "version": "csc.v0.1",
        "contract_id": "test-contract-001",
        "intent": "test",
        "actor": _make_actor(),
        "commands": commands,
        "risk_class": "low",
        "approval_mode": "policy_only",
        "justification": "testing policy",
    }
    defaults.update(overrides)
    return CommandContract(**defaults)


def _make_exec_command(argv: list[str], **overrides) -> Command:
    defaults = {
        "id": "cmd_1",
        "exec": ExecSpec(argv=argv),
        "cwd": "/workspace/repo",
        "read_paths": ["/workspace/repo/**"],
        "write_paths": [],
        "network": "deny",
        "env_allow": [],
        "secret_refs": [],
        "timeout_sec": 10,
        "proposed_effect_type": "observe",
    }
    defaults.update(overrides)
    return Command(**defaults)


DEV_READONLY = {
    "name": "dev-readonly",
    "allow_commands": ["git", "ls", "cat", "grep", "rg", "find", "jq", "python3"],
    "deny_argv_prefixes": [["bash", "-lc"], ["sh", "-c"], ["python3", "-c"], ["node", "-e"]],
    "allowed_effect_types": ["observe"],
    "allowed_risk_classes": ["low"],
    "max_timeout_sec": 30,
    "network": "deny",
    "allow_secret_refs": False,
    "require_write_paths_empty": True,
    "allowed_cwd_prefixes": ["/workspace"],
    "allowed_read_prefixes": ["/workspace"],
}

DEV_TEST_NO_NETWORK = {
    "name": "dev-test-no-network",
    "allow_commands": ["git", "npm", "node", "python3", "pytest", "make", "cat", "jq"],
    "deny_argv_prefixes": [["bash", "-lc"], ["sh", "-c"], ["python3", "-c"], ["node", "-e"]],
    "allowed_effect_types": ["observe", "transform_local", "mutate_repo"],
    "allowed_risk_classes": ["low", "medium"],
    "max_timeout_sec": 600,
    "network": "deny",
    "allow_secret_refs": False,
    "allowed_cwd_prefixes": ["/workspace"],
    "allowed_read_prefixes": ["/workspace"],
    "allowed_write_prefixes": ["/workspace"],
}

REGULATED_RESTRICTED = {
    "name": "regulated-restricted",
    "allow_commands": ["python3", "cat", "jq", "curl"],
    "deny_argv_prefixes": [["bash", "-lc"], ["sh", "-c"], ["python3", "-c"], ["node", "-e"]],
    "allowed_effect_types": ["observe", "fetch_external"],
    "manual_approval_for_classified_effect_types": ["financial_action", "health_data_action"],
    "allowed_risk_classes": ["low", "medium"],
    "max_timeout_sec": 60,
    "network": "allowlisted",
    "allow_secret_refs": False,
    "allowed_cwd_prefixes": ["/workspace"],
    "allowed_read_prefixes": ["/workspace"],
    "allowed_write_prefixes": ["/workspace/out"],
    "allowed_egress_hosts": ["api.sandbox.stripe.com", "example-internal-gateway.local"],
}


def test_allow_git_status():
    cmd = _make_exec_command(["git", "status", "--short"])
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, DEV_READONLY)
    assert result.decision == "allow"


def test_deny_python3_c():
    cmd = _make_exec_command(["python3", "-c", "print('x')"])
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, DEV_READONLY)
    assert result.decision == "deny"
    assert "argv prefix denied" in result.reasons[0]


def test_deny_writes_under_readonly():
    cmd = _make_exec_command(
        ["git", "status"],
        write_paths=["/workspace/repo/out/file.txt"],
    )
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, DEV_READONLY)
    assert result.decision == "deny"
    assert "writes not allowed" in result.reasons[0]


def test_allow_npm_test():
    cmd = _make_exec_command(
        ["npm", "test", "--", "auth.spec.ts"],
        cwd="/workspace/app",
        read_paths=["/workspace/app/**"],
        write_paths=["/workspace/app/test-results/**"],
        timeout_sec=180,
        proposed_effect_type="transform_local",
    )
    contract = _make_contract([cmd], risk_class="medium")
    result = evaluate_contract(contract, DEV_TEST_NO_NETWORK)
    assert result.decision == "allow"


def test_deny_network_exceeds_policy_max():
    cmd = _make_exec_command(
        ["cat", "/workspace/app/file.txt"],
        cwd="/workspace/app",
        read_paths=["/workspace/app/**"],
        network="full",
    )
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, DEV_TEST_NO_NETWORK)
    assert result.decision == "deny"
    assert "network mode exceeds" in result.reasons[0]


def test_needs_approval_financial_action():
    cmd = _make_exec_command(
        ["curl", "-X", "POST", "https://api.sandbox.stripe.com/v1/charges"],
        cwd="/workspace/app",
        read_paths=["/workspace/app/**"],
        network="allowlisted",
        proposed_effect_type="fetch_external",
    )
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, REGULATED_RESTRICTED)
    assert result.decision == "needs_approval"
    assert "financial_action" in result.reasons[0]


def test_allow_deny_network_under_allowlisted_max():
    cmd = _make_exec_command(
        ["cat", "/workspace/data.json"],
        network="deny",
    )
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, REGULATED_RESTRICTED)
    assert result.decision == "allow"


def test_approval_mode_human_required():
    cmd = _make_exec_command(["git", "status"])
    contract = _make_contract([cmd], approval_mode="human_required")
    result = evaluate_contract(contract, DEV_READONLY)
    assert result.decision == "needs_approval"
    assert "approval mode" in result.reasons[0]


def test_path_traversal_denied():
    cmd = _make_exec_command(
        ["cat", "/workspace-evil/secrets.txt"],
        cwd="/workspace-evil",
        read_paths=["/workspace-evil/**"],
    )
    contract = _make_contract([cmd])
    result = evaluate_contract(contract, DEV_READONLY)
    assert result.decision == "deny"
    assert "cwd not allowed" in result.reasons[0]
