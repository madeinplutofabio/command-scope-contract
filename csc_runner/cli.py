from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import ValidationError
from rich import print

from csc_runner.executor import RECEIPT_VERSION, run_contract, runner_version
from csc_runner.limits import MAX_CONTRACT_SIZE_BYTES, truncate_error
from csc_runner.models import CommandContract
from csc_runner.pathutil import (
    CwdNotFoundError,
    PathEscapeError,
    _glob_literal_prefix,
    check_cwd_exists,
    normalize_and_check_scope,
    resolve_and_check_cwd,
)
from csc_runner.policy import PolicyError, evaluate_contract, load_policy
from csc_runner.receipts import write_receipt

app = typer.Typer(help="CSC reference runner", no_args_is_help=True)

_VALID_MODES = ("local", "hardened")


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


def _load_signing_key(path: str) -> bytes:
    """Load signing key bytes from a file path.

    Validates the path is an existing regular file before reading.
    Raises OSError on any I/O failure.
    """
    key_path = Path(path)
    if not key_path.is_file():
        raise OSError(f"signing key path is not a file: {path}")
    return key_path.read_bytes()


def _extract_literal_prefix(path: str) -> str:
    """Extract the literal directory prefix before any glob metacharacter."""
    return _glob_literal_prefix(path)


def _blocked_receipt_dict(
    contract: CommandContract,
    decision_sha256: str,
    policy_profile: str,
    policy: dict,
    error: str,
    mode: str = "local",
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
        "execution_mode": mode,
        "policy_sha256": _hash_policy(policy),
        "completed_command_ids": [],
        "failed_command_id": None,
        "error": truncate_error(error),
    }
    schema_ver = policy.get("policy_schema_version")
    if schema_ver:
        receipt["policy_schema_version"] = schema_ver
    return receipt


def _sign_receipt_if_configured(
    receipt: dict,
    private_key_bytes: bytes | None,
    signing_key_id: str | None,
) -> dict:
    """Sign a receipt if signing config is fully provided.

    Both absent (None) → return unsigned.
    Both present → sign.
    Partial → raise SigningError.
    """
    if private_key_bytes is None and signing_key_id is None:
        return receipt

    from csc_runner.signing import SigningError, sign_receipt

    if private_key_bytes is None or not signing_key_id:
        raise SigningError("signing requires both private_key_bytes and non-empty signing_key_id")

    return sign_receipt(
        receipt,
        private_key_bytes=private_key_bytes,
        key_id=signing_key_id,
    )


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
    except (
        OSError,
        json.JSONDecodeError,
        ValidationError,
        PolicyError,
        ValueError,
    ) as exc:
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
    mode: str = typer.Option(
        "local",
        help="Execution mode: 'local' (default) or 'hardened'",
    ),
    approval_path: str = typer.Option(None, "--approval", help="Path to approval artifact JSON file"),
    sign: bool = typer.Option(
        False,
        "--sign",
        help="Enable receipt signing (requires --signing-key and --key-id)",
    ),
    signing_key_path: str = typer.Option(
        None,
        "--signing-key",
        help="Path to Ed25519 private key file (requires --sign)",
    ),
    signing_key_id: str = typer.Option(
        None,
        "--key-id",
        help="Key ID for receipt signing (requires --sign)",
    ),
    sandbox_debug: bool = typer.Option(
        False,
        "--sandbox-debug",
        help="Print composed hardened launcher argv and exit without executing",
    ),
) -> None:
    """Evaluate a contract against policy, execute if allowed, and write a receipt."""
    # --- Validate mode FIRST ---
    if mode not in _VALID_MODES:
        print(f"[red]ERROR[/red] — mode must be 'local' or 'hardened', got {mode!r}")
        raise typer.Exit(code=1)

    # --- Signing config SECOND (before any receipt path) ---
    private_key_bytes = None

    if sign:
        if signing_key_path is None or not signing_key_id:
            print("[red]ERROR[/red] — --sign requires both --signing-key and --key-id")
            raise typer.Exit(code=1)
        try:
            private_key_bytes = _load_signing_key(signing_key_path)
        except OSError as exc:
            print(f"[red]ERROR[/red] — cannot load signing key: {exc}")
            raise typer.Exit(code=1) from exc
        try:
            from csc_runner.signing import _load_private_key

            _load_private_key(private_key_bytes)
        except Exception as exc:
            print(f"[red]ERROR[/red] — invalid signing key: {exc}")
            raise typer.Exit(code=1) from exc
    else:
        if signing_key_path is not None or signing_key_id is not None:
            print("[red]ERROR[/red] — --signing-key and --key-id require --sign flag")
            raise typer.Exit(code=1)

    if mode == "hardened" and not sign:
        print("[red]ERROR[/red] — hardened mode requires --sign --signing-key PATH --key-id ID")
        raise typer.Exit(code=1)

    # --- Load contract + policy ---
    try:
        contract = _load_contract(contract_path)
        policy = load_policy(policy_path)
        decision = evaluate_contract(contract, policy)
    except (
        OSError,
        json.JSONDecodeError,
        ValidationError,
        PolicyError,
        ValueError,
    ) as exc:
        print(f"[red]ERROR[/red] — {exc}")
        raise typer.Exit(code=1) from exc

    message = _format_reasons(decision.reasons)

    # --- Policy deny ---
    if decision.decision == "deny":
        print(f"[red]DENY[/red] — {message}")
        receipt = _blocked_receipt_dict(
            contract,
            decision.contract_sha256,
            decision.policy_profile,
            policy,
            message,
            mode=mode,
        )
        try:
            receipt = _sign_receipt_if_configured(receipt, private_key_bytes, signing_key_id)
        except Exception as exc:
            print(f"[red]ERROR[/red] — signing failed: {exc}")
            raise typer.Exit(code=1) from exc
        write_receipt(receipt, receipt_out)
        raise typer.Exit(code=1)

    # --- Needs approval ---
    approval = None
    approval_required = decision.decision == "needs_approval"

    if approval_path is not None:
        try:
            from csc_runner.approval import load_approval

            approval = load_approval(approval_path)
        except Exception as exc:
            print(f"[red]ERROR[/red] — cannot load approval: {exc}")
            raise typer.Exit(code=1) from exc

    if approval_required and approval is None:
        print(f"[yellow]NEEDS APPROVAL[/yellow] — {message}")
        receipt = _blocked_receipt_dict(
            contract,
            decision.contract_sha256,
            decision.policy_profile,
            policy,
            message,
            mode=mode,
        )
        try:
            receipt = _sign_receipt_if_configured(receipt, private_key_bytes, signing_key_id)
        except Exception as exc:
            print(f"[red]ERROR[/red] — signing failed: {exc}")
            raise typer.Exit(code=1) from exc
        write_receipt(receipt, receipt_out)
        raise typer.Exit(code=2)

    # --- Build sandbox config (hardened mode) ---
    sandbox_config = None
    if mode == "hardened":
        from csc_runner.sandbox import SandboxConfig

        sandbox_config = SandboxConfig()

    # --- Sandbox debug ---
    if sandbox_debug:
        if mode != "hardened":
            print("[red]ERROR[/red] — --sandbox-debug requires --mode hardened")
            raise typer.Exit(code=1)

        from csc_runner.sandbox import (
            SandboxError,
            build_hardened_command,
            check_command_allowed,
            verify_hardened_runtime,
        )

        try:
            verify_hardened_runtime(sandbox_config)
        except SandboxError as exc:
            print(f"[red]ERROR[/red] — sandbox preflight failed: {exc}")
            raise typer.Exit(code=1) from exc

        allowed_cwd = policy.get("allowed_cwd_prefixes", [])
        allowed_read = policy.get("allowed_read_prefixes", [])
        allowed_write = policy.get("allowed_write_prefixes", [])

        for command in contract.commands:
            cmd_id = command.id

            if command.exec is None:
                sys.stderr.write(f"BLOCKED {cmd_id}: pipelines are not supported in hardened mode\n")
                continue

            try:
                resolved_cwd = resolve_and_check_cwd(command.cwd, allowed_cwd)
            except PathEscapeError as exc:
                sys.stderr.write(f"BLOCKED {cmd_id}: {exc}\n")
                continue

            try:
                check_cwd_exists(resolved_cwd)
            except CwdNotFoundError as exc:
                sys.stderr.write(f"BLOCKED {cmd_id}: {exc}\n")
                continue

            blocked = False

            for path in command.read_paths:
                try:
                    normalize_and_check_scope(path, allowed_read, label="read_paths")
                except PathEscapeError as exc:
                    sys.stderr.write(f"BLOCKED {cmd_id}: {exc}\n")
                    blocked = True
                    break

            if blocked:
                continue

            for path in command.write_paths:
                try:
                    normalize_and_check_scope(path, allowed_write, label="write_paths")
                except PathEscapeError as exc:
                    sys.stderr.write(f"BLOCKED {cmd_id}: {exc}\n")
                    blocked = True
                    break

            if blocked:
                continue

            try:
                check_command_allowed(command.exec.argv, sandbox_config)
            except SandboxError as exc:
                sys.stderr.write(f"BLOCKED {cmd_id}: {exc}\n")
                continue

            read_bind = [_extract_literal_prefix(p) for p in command.read_paths if _extract_literal_prefix(p)]
            write_bind = [_extract_literal_prefix(p) for p in command.write_paths if _extract_literal_prefix(p)]

            try:
                argv = build_hardened_command(
                    command.exec.argv,
                    cwd=resolved_cwd,
                    read_bind_prefixes=read_bind,
                    write_bind_prefixes=write_bind,
                    config=sandbox_config,
                )
                sys.stderr.write(f"{cmd_id}: {' '.join(argv)}\n")
            except SandboxError as exc:
                sys.stderr.write(f"ERROR {cmd_id}: {exc}\n")

        raise typer.Exit(code=0)

    # --- Execute ---
    try:
        receipt = run_contract(
            contract,
            decision.policy_profile,
            policy,
            mode=mode,
            approval=approval,
            approval_required=approval_required,
            sandbox_config=sandbox_config,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
        )
    except ValueError as exc:
        print(f"[red]ERROR[/red] — {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        print(f"[red]ERROR[/red] — {exc}")
        raise typer.Exit(code=1) from exc

    write_receipt(receipt, receipt_out)

    if receipt["status"] == "success":
        print(f"[green]SUCCESS[/green] — receipt written to {receipt_out}")
        return

    if receipt["status"] == "blocked":
        print(f"[yellow]BLOCKED[/yellow] — {receipt.get('error', '')}, receipt written to {receipt_out}")
        raise typer.Exit(code=1)

    print(f"[red]FAILED[/red] — exit code {receipt['exit_code']}, receipt written to {receipt_out}")
    raise typer.Exit(code=1)


@app.command()
def verify_receipt(
    receipt_path: str = typer.Argument(..., help="Path to signed receipt JSON"),
    public_key_path: str = typer.Option(
        ...,
        "--public-key",
        help="Path to Ed25519 public key file (32 bytes raw)",
    ),
    key_id: str = typer.Option(..., "--key-id", help="Key ID to verify against"),
) -> None:
    """Verify a signed receipt's Ed25519 signature."""
    try:
        receipt_data = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[red]ERROR[/red] — cannot load receipt: {exc}")
        raise typer.Exit(code=1) from exc

    try:
        public_key_bytes = Path(public_key_path).read_bytes()
    except OSError as exc:
        print(f"[red]ERROR[/red] — cannot load public key: {exc}")
        raise typer.Exit(code=1) from exc

    from csc_runner.signing import (
        StaticKeyResolver,
        VerificationError,
        verify_receipt_signature,
    )

    resolver = StaticKeyResolver(keys={key_id: public_key_bytes})

    try:
        verify_receipt_signature(receipt_data, resolver=resolver)
    except VerificationError as exc:
        print(f"[red]INVALID[/red] — {exc}")
        raise typer.Exit(code=1) from exc

    print("[green]VALID[/green] — receipt signature verified")


if __name__ == "__main__":
    app()
