from __future__ import annotations

import hashlib
import os
import subprocess
import time
from datetime import UTC, datetime
from importlib.metadata import version as pkg_version
from typing import Any

from csc_runner.models import CommandContract
from csc_runner.utils import hash_contract

RECEIPT_VERSION = "csc.receipt.v0.1"


def runner_version() -> str:
    try:
        return pkg_version("csc-runner")
    except Exception:
        return "unknown"


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _build_env(env_allow: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}

    # Preserve minimal runtime essentials so non-absolute executables can resolve.
    for key in ("PATH", "SystemRoot", "COMSPEC", "PATHEXT"):
        if key in os.environ:
            env[key] = os.environ[key]

    for key in env_allow:
        if key in os.environ:
            env[key] = os.environ[key]

    return env


def _run_exec(
    argv: list[str],
    cwd: str,
    env: dict[str, str],
    timeout_sec: float,
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
        text=False,
        timeout=timeout_sec,
        shell=False,
        check=False,
    )


def _run_pipeline(
    segments: list[list[str]],
    cwd: str,
    env: dict[str, str],
    timeout_sec: int,
) -> subprocess.CompletedProcess[bytes]:
    deadline = time.monotonic() + timeout_sec
    current_input: bytes | None = None
    last_result: subprocess.CompletedProcess[bytes] | None = None

    for argv in segments:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout_sec)

        last_result = _run_exec(argv, cwd, env, remaining, stdin=current_input)
        if last_result.returncode != 0:
            return last_result
        current_input = last_result.stdout

    assert last_result is not None
    return last_result


def _base_receipt(contract: CommandContract, policy_profile: str, start: str) -> dict[str, Any]:
    """Return the fields shared by every receipt."""
    return {
        "receipt_version": RECEIPT_VERSION,
        "contract_id": contract.contract_id,
        "execution_id": f"exec_{contract.contract_id}",
        "contract_sha256": hash_contract(contract),
        "policy_profile": policy_profile,
        "runner_version": runner_version(),
        "execution_mode": "local",
        "started_at": start,
    }


def run_contract(contract: CommandContract, policy_profile: str) -> dict[str, Any]:
    start = _iso_now()
    last_result: subprocess.CompletedProcess[bytes] | None = None
    completed_command_ids: list[str] = []
    failed_command_id: str | None = None

    try:
        for command in contract.commands:
            env = _build_env(command.env_allow)

            if command.exec is not None:
                last_result = _run_exec(
                    command.exec.argv,
                    command.cwd,
                    env,
                    command.timeout_sec,
                )
            else:
                segments = [segment.argv for segment in command.pipeline.segments]
                last_result = _run_pipeline(
                    segments,
                    command.cwd,
                    env,
                    command.timeout_sec,
                )

            if last_result.returncode == 0:
                completed_command_ids.append(command.id)
            else:
                failed_command_id = command.id
                break

    except subprocess.TimeoutExpired as exc:
        failed_command_id = failed_command_id or (
            contract.commands[len(completed_command_ids)].id
            if len(completed_command_ids) < len(contract.commands)
            else None
        )
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        receipt = _base_receipt(contract, policy_profile, start)
        receipt.update(
            {
                "status": "failed",
                "ended_at": _iso_now(),
                "exit_code": 124,
                "stdout_hash": _sha256_bytes(stdout),
                "stderr_hash": _sha256_bytes(stderr),
                "artifacts": [],
                "effect_summary": {
                    "files_written": 0,
                    "network_used": any(cmd.network != "deny" for cmd in contract.commands),
                    "secrets_used": sum(len(cmd.secret_refs) for cmd in contract.commands),
                },
                "completed_command_ids": completed_command_ids,
                "failed_command_id": failed_command_id,
                "error": f"command timed out after {exc.timeout} seconds",
            }
        )
        return receipt

    except FileNotFoundError as exc:
        failed_command_id = failed_command_id or (
            contract.commands[len(completed_command_ids)].id
            if len(completed_command_ids) < len(contract.commands)
            else None
        )
        receipt = _base_receipt(contract, policy_profile, start)
        receipt.update(
            {
                "status": "failed",
                "ended_at": _iso_now(),
                "exit_code": 127,
                "stdout_hash": _sha256_bytes(b""),
                "stderr_hash": _sha256_bytes(str(exc).encode("utf-8")),
                "artifacts": [],
                "effect_summary": {
                    "files_written": 0,
                    "network_used": any(cmd.network != "deny" for cmd in contract.commands),
                    "secrets_used": sum(len(cmd.secret_refs) for cmd in contract.commands),
                },
                "completed_command_ids": completed_command_ids,
                "failed_command_id": failed_command_id,
                "error": str(exc),
            }
        )
        return receipt

    end = _iso_now()

    stdout = last_result.stdout if last_result else b""
    stderr = last_result.stderr if last_result else b""
    exit_code = last_result.returncode if last_result else 1
    status = "success" if exit_code == 0 else "failed"

    receipt = _base_receipt(contract, policy_profile, start)
    receipt.update(
        {
            "status": status,
            "ended_at": end,
            "exit_code": exit_code,
            "stdout_hash": _sha256_bytes(stdout),
            "stderr_hash": _sha256_bytes(stderr),
            "artifacts": [],
            "effect_summary": {
                "files_written": 0,
                "network_used": any(cmd.network != "deny" for cmd in contract.commands),
                "secrets_used": sum(len(cmd.secret_refs) for cmd in contract.commands),
            },
            "completed_command_ids": completed_command_ids,
            "failed_command_id": failed_command_id,
            "error": stderr.decode("utf-8", errors="replace")[:4000] if exit_code != 0 else "",
        }
    )
    return receipt
