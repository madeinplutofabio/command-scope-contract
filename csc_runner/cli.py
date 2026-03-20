from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import ValidationError
from rich import print

from csc_runner.executor import RECEIPT_VERSION, run_contract, runner_version
from csc_runner.models import CommandContract
from csc_runner.policy import PolicyError, evaluate_contract, load_policy
from csc_runner.receipts import write_receipt

app = typer.Typer(help="CSC reference runner", no_args_is_help=True)


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _format_reasons(reasons: list[str]) -> str:
    return "; ".join(reasons)


def _load_contract(path: str) -> CommandContract:
    contract_data = json.loads(Path(path).read_text(encoding="utf-8"))
    return CommandContract.model_validate(contract_data)


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
    except (OSError, json.JSONDecodeError, ValidationError, PolicyError) as exc:
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
    except (OSError, json.JSONDecodeError, ValidationError, PolicyError) as exc:
        print(f"[red]ERROR[/red] — {exc}")
        raise typer.Exit(code=1) from exc

    message = _format_reasons(decision.reasons)

    if decision.decision == "deny":
        now = _iso_now()
        print(f"[red]DENY[/red] — {message}")
        write_receipt(
            {
                "receipt_version": RECEIPT_VERSION,
                "contract_id": contract.contract_id,
                "execution_id": f"exec_{contract.contract_id}",
                "contract_sha256": decision.contract_sha256,
                "status": "blocked",
                "started_at": now,
                "ended_at": now,
                "policy_profile": decision.policy_profile,
                "runner_version": runner_version(),
                "execution_mode": "local",
                "completed_command_ids": [],
                "failed_command_id": None,
                "error": message,
            },
            receipt_out,
        )
        raise typer.Exit(code=1)

    if decision.decision == "needs_approval":
        print(f"[yellow]NEEDS APPROVAL[/yellow] — {message}")
        raise typer.Exit(code=2)

    receipt = run_contract(contract, decision.policy_profile)
    write_receipt(receipt, receipt_out)

    if receipt["status"] == "success":
        print(f"[green]SUCCESS[/green] — receipt written to {receipt_out}")
        return

    print(f"[red]FAILED[/red] — exit code {receipt['exit_code']}, receipt written to {receipt_out}")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
