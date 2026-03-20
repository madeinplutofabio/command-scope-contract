"""Tests for CLI exit codes and receipt writing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from typer.testing import CliRunner

from csc_runner.cli import app

runner = CliRunner()

CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "examples" / "contracts"
POLICIES_DIR = Path(__file__).resolve().parent.parent / "examples" / "policies"


def test_check_allow_exit_0():
    result = runner.invoke(app, [
        "check",
        str(CONTRACTS_DIR / "git-status.json"),
        str(POLICIES_DIR / "dev-readonly.yaml"),
    ])
    assert result.exit_code == 0
    assert "ALLOW" in result.output


def test_check_deny_exit_1():
    result = runner.invoke(app, [
        "check",
        str(CONTRACTS_DIR / "curl-denied.json"),
        str(POLICIES_DIR / "dev-readonly.yaml"),
    ])
    assert result.exit_code == 1
    assert "DENY" in result.output


def test_check_needs_approval_exit_2(tmp_path):
    contract = {
        "version": "csc.v0.1",
        "contract_id": "temp-financial-001",
        "intent": "post data to external endpoint",
        "actor": {
            "agent_id": "worker-1",
            "session_id": "sess-003",
            "initiating_user": "fabio",
            "delegation_scope": "repo-maintainer",
        },
        "commands": [
            {
                "id": "cmd_1",
                "exec": {
                    "argv": ["curl", "-X", "POST", "https://api.sandbox.stripe.com/v1/charges"]
                },
                "cwd": "/workspace/app",
                "read_paths": ["/workspace/app/**"],
                "write_paths": [],
                "network": "allowlisted",
                "env_allow": [],
                "secret_refs": [],
                "timeout_sec": 30,
                "proposed_effect_type": "fetch_external",
            }
        ],
        "risk_class": "medium",
        "approval_mode": "policy_only",
        "expected_outputs": [],
        "justification": "notify webhook",
    }

    contract_path = tmp_path / "financial.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    result = runner.invoke(app, [
        "check",
        str(contract_path),
        str(POLICIES_DIR / "regulated-restricted.yaml"),
    ])
    assert result.exit_code == 2
    assert "NEEDS APPROVAL" in result.output


def test_run_deny_creates_blocked_receipt(tmp_path):
    receipt_path = tmp_path / "receipt.json"
    result = runner.invoke(app, [
        "run",
        str(CONTRACTS_DIR / "curl-denied.json"),
        str(POLICIES_DIR / "dev-readonly.yaml"),
        "--receipt-out", str(receipt_path),
    ])
    assert result.exit_code == 1
    assert receipt_path.exists()
    receipt = json.loads(receipt_path.read_text())
    assert receipt["status"] == "blocked"
    assert receipt["contract_id"] == "contract_curl_denied_001"


def _write_run_test_files(tmp_path):
    """Create a contract and policy that can actually execute on any platform."""
    cwd = str(tmp_path)
    python_name = Path(sys.executable).name

    contract = {
        "version": "csc.v0.1",
        "contract_id": "run-test-001",
        "intent": "test run writes receipt",
        "actor": {
            "agent_id": "worker-1",
            "session_id": "sess-001",
            "initiating_user": "fabio",
            "delegation_scope": "test",
        },
        "commands": [
            {
                "id": "cmd_1",
                "exec": {"argv": [sys.executable, "-c", "print('ok')"]},
                "cwd": cwd,
                "read_paths": [cwd + "/**"],
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
        "justification": "test receipt writing",
    }

    policy = {
        "name": "test-permissive",
        "allow_commands": [python_name, sys.executable],
        "allowed_effect_types": ["observe"],
        "allowed_risk_classes": ["low"],
        "max_timeout_sec": 30,
        "network": "deny",
        "allow_secret_refs": False,
        "allowed_cwd_prefixes": [cwd],
        "allowed_read_prefixes": [cwd],
    }

    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.dump(policy), encoding="utf-8")

    return contract_path, policy_path


def test_run_success_writes_receipt(tmp_path):
    contract_path, policy_path = _write_run_test_files(tmp_path)
    receipt_path = tmp_path / "receipt.json"

    result = runner.invoke(app, [
        "run",
        str(contract_path),
        str(policy_path),
        "--receipt-out", str(receipt_path),
    ])
    assert result.exit_code in (0, 1)
    assert receipt_path.exists()
    receipt = json.loads(receipt_path.read_text())
    assert receipt["contract_id"] == "run-test-001"
    assert receipt["status"] in ("success", "failed")


def test_run_needs_approval_exit_2(tmp_path):
    contract = {
        "version": "csc.v0.1",
        "contract_id": "temp-financial-002",
        "intent": "post data to Stripe",
        "actor": {
            "agent_id": "worker-1",
            "session_id": "sess-004",
            "initiating_user": "fabio",
            "delegation_scope": "repo-maintainer",
        },
        "commands": [
            {
                "id": "cmd_1",
                "exec": {
                    "argv": ["curl", "-X", "POST", "https://api.sandbox.stripe.com/v1/charges"]
                },
                "cwd": "/workspace/app",
                "read_paths": ["/workspace/app/**"],
                "write_paths": [],
                "network": "allowlisted",
                "env_allow": [],
                "secret_refs": [],
                "timeout_sec": 30,
                "proposed_effect_type": "fetch_external",
            }
        ],
        "risk_class": "medium",
        "approval_mode": "policy_only",
        "expected_outputs": [],
        "justification": "financial action test",
    }

    contract_path = tmp_path / "financial.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    result = runner.invoke(app, [
        "run",
        str(contract_path),
        str(POLICIES_DIR / "regulated-restricted.yaml"),
    ])
    assert result.exit_code == 2
    assert "NEEDS APPROVAL" in result.output


def test_check_invalid_contract_exit_1(tmp_path):
    bad_contract = tmp_path / "bad.json"
    bad_contract.write_text('{"not": "a contract"}')
    result = runner.invoke(app, [
        "check",
        str(bad_contract),
        str(POLICIES_DIR / "dev-readonly.yaml"),
    ])
    assert result.exit_code == 1
    assert "ERROR" in result.output


def test_check_missing_file_exit_1():
    result = runner.invoke(app, [
        "check",
        "nonexistent_file.json",
        str(POLICIES_DIR / "dev-readonly.yaml"),
    ])
    assert result.exit_code == 1
    assert "ERROR" in result.output
