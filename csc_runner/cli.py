from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import ValidationError
from rich import print

from csc_runner.executor import RECEIPT_VERSION, run_contract, runner_version
from csc_runner.limits import MAX_CONTRACT_SIZE_BYTES, truncate_error
from csc_runner.models import CommandContract
from csc_runner.policy import PolicyError, evaluate_contract, load_policy
from csc_runner.receipts import write_receipt

app = typer.Typer(help="CSC reference runner", no_args_is_help=True)


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _format_reasons(reasons: list[str]) -> str:
    return "; ".join(reasons)


def _hash_policy(policy: dict) -> str:
    """Compute raw SHA-256 hex of the canonical JSON form of a policy dict."""
    canonical = json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _load_contract(path: str) -> CommandContract:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_CONTRACT_SIZE_BYTES:
        raise ValueError(f"contract file is {len(raw)} bytes (max {MAX_CONTRACT_SIZE_BYTES})")
    contract_data = json.loads(raw.decode("utf-8"))
    return CommandContract.model_validate(contract_data)


def _blocked_receipt_dict(
    contract: CommandContract,
    decision_sha256: str,
    policy_profile: str,
    policy: dict,
    error: str,
) -> dict:
    """Build a blocked receipt dict for CLI deny/needs_approval paths."""
    now = _iso_now()
    receipt = {
        "receipt_version": RECEIPT_VERSION,
        "contract_id": contract.contract_id,
        "execution_id": f"exec_{contract.contract_id}",
        "contract_sha256": decision_sha256,
        "status": "blocked",
        "started_at": now,
        "ended_at": now,
        "policy_profile": policy_profile,
        "runner_version": runner_version(),
        "execution_mode": "local",
        "policy_sha256": _hash_policy(policy),
        "completed_command_ids": [],
        "failed_command_id": None,
        "error": truncate_error(error),
    }
    schema_ver = policy.get("policy_schema_version")
    if schema_ver:
        receipt["policy_schema_version"] = schema_ver
    return receipt


@app.command()
def check(
    contract_path: str = typer.Argument(..., help="Path to contract JSON file"),
    policy_path: str = typer.Argument(..., help="Path to policy YAML file"),
) -> None:
    """Validate a contract against a policy without executing."""
    try:
        contract = _load_contract(contract_path)
        policy = load_policy(policy_path)
        result = evaluate_contract(contract, policy)
    except (OSError, json.JSONDecodeError, ValidationError, PolicyError, ValueError) as exc:
        print(f"[red]ERROR[/red] — {exc}")
        raise typer.Exit(code=1) from exc

    message = _format_reasons(result.reasons)

    if result.decision == "allow":
        print(f"[green]ALLOW[/green] — {message}")
        return
    if result.decision == "needs_approval":
        print(f"[yellow]NEEDS APPROVAL[/yellow] — {message}")
        raise typer.Exit(code=2)

    print(f"[red]DENY[/red] — {message}")
    raise typer.Exit(code=1)


@app.command()
def run(
    contract_path: str = typer.Argument(..., help="Path to contract JSON file"),
    policy_path: str = typer.Argument(..., help="Path to policy YAML file"),
    receipt_out: str = typer.Option("./out/receipt.json", help="Path to write receipt JSON"),
) -> None:
    """Evaluate a contract against policy, execute if allowed, and write a receipt."""
    try:
        contract = _load_contract(contract_path)
        policy = load_policy(policy_path)
        decision = evaluate_contract(contract, policy)
    except (OSError, json.JSONDecodeError, ValidationError, PolicyError, ValueError) as exc:
        print(f"[red]ERROR[/red] — {exc}")
        raise typer.Exit(code=1) from exc

    message = _format_reasons(decision.reasons)

    if decision.decision == "deny":
        print(f"[red]DENY[/red] — {message}")
        write_receipt(
            _blocked_receipt_dict(
                contract,
                decision.contract_sha256,
                decision.policy_profile,
                policy,
                message,
            ),
            receipt_out,
        )
        raise typer.Exit(code=1)

    if decision.decision == "needs_approval":
        print(f"[yellow]NEEDS APPROVAL[/yellow] — {message}")
        write_receipt(
            _blocked_receipt_dict(
                contract,
                decision.contract_sha256,
                decision.policy_profile,
                policy,
                message,
            ),
            receipt_out,
        )
        raise typer.Exit(code=2)

    receipt = run_contract(contract, decision.policy_profile, policy)
    write_receipt(receipt, receipt_out)

    if receipt["status"] == "success":
        print(f"[green]SUCCESS[/green] — receipt written to {receipt_out}")
        return

    print(f"[red]FAILED[/red] — exit code {receipt['exit_code']}, receipt written to {receipt_out}")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
