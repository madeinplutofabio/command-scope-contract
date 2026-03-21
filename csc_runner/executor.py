from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version as pkg_version
from typing import Any

from csc_runner.limits import (
    MAX_STDERR_CAPTURE_BYTES,
    MAX_STDOUT_CAPTURE_BYTES,
    truncate_error,
    validate_contract_limits,
)
from csc_runner.models import CommandContract
from csc_runner.pathutil import (
    CwdNotFoundError,
    PathEscapeError,
    check_cwd_exists,
    normalize_and_check_scope,
    resolve_and_check_cwd,
)
from csc_runner.utils import hash_contract

RECEIPT_VERSION = "csc.receipt.v0.1"

_EMPTY_HASH = "sha256:" + hashlib.sha256(b"").hexdigest()


def runner_version() -> str:
    try:
        return pkg_version("csc-runner")
    except Exception:
        return "unknown"


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _hash_policy(policy: dict) -> str:
    """Compute raw SHA-256 hex of the canonical JSON form of a policy dict."""
    canonical = json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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


# ---------------------------------------------------------------------------
# Capped output capture
# ---------------------------------------------------------------------------


@dataclass
class CapturedOutput:
    """Result of capped stream capture."""

    data: bytes
    hash_hex: str
    truncated: bool


def _empty_capture() -> CapturedOutput:
    return CapturedOutput(data=b"", hash_hex=_EMPTY_HASH, truncated=False)


class _CappedCapture:
    """Incrementally captures output up to a byte cap.

    Only captured bytes (up to the cap) are hashed.  Bytes beyond the
    cap are drained from the pipe to prevent subprocess blocking but
    are not retained or hashed.

    Thread-safe: multiple drain threads may call feed() concurrently
    (used for aggregating stderr from all pipeline segments into one
    shared capture).
    """

    def __init__(self, max_bytes: int) -> None:
        self._max = max_bytes
        self._buf = bytearray()
        self._hasher = hashlib.sha256()
        self._captured = 0
        self._truncated = False
        self._lock = threading.Lock()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            remaining = self._max - self._captured
            if remaining > 0:
                to_keep = chunk[:remaining]
                self._buf.extend(to_keep)
                self._hasher.update(to_keep)
                self._captured += len(to_keep)
            if len(chunk) > max(remaining, 0):
                self._truncated = True

    def result(self) -> CapturedOutput:
        with self._lock:
            return CapturedOutput(
                data=bytes(self._buf),
                hash_hex="sha256:" + self._hasher.hexdigest(),
                truncated=self._truncated,
            )


def _drain_stream(stream, capture: _CappedCapture) -> None:
    """Read a stream to completion, feeding into a CappedCapture.

    Owns the stream: closes it when done or on error.
    """
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            capture.feed(chunk)
    finally:
        stream.close()


# ---------------------------------------------------------------------------
# Pipeline cleanup
# ---------------------------------------------------------------------------


def _cleanup_pipeline(
    procs: list[subprocess.Popen],
    stderr_threads: list[threading.Thread],
    t_final_out: threading.Thread | None,
    *,
    terminate: bool,
) -> None:
    """Clean up a pipeline without racing the final stdout reader.

    Ownership model:
    - _drain_stream() owns and closes any stream it is draining.
    - Parent code may close intermediate proc.stdout handles after they are
      handed off to the next child.
    - Parent code must NOT close procs[-1].stdout if t_final_out exists;
      the final stdout drain thread owns that stream.
    """
    if terminate:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()

        kill_deadline = time.monotonic() + 5
        for proc in procs:
            if proc.poll() is not None:
                continue
            remaining = max(kill_deadline - time.monotonic(), 0.1)
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()

        for proc in procs:
            if proc.poll() is None:
                proc.wait()

    # Join the final stdout reader first. It owns procs[-1].stdout.
    if t_final_out is not None:
        t_final_out.join(timeout=10)

    # Join stderr readers. Each owns its proc.stderr.
    for t in stderr_threads:
        t.join(timeout=10)

    # Close any intermediate stdout handles still open in the parent.
    for proc in procs[:-1]:
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()

    # If no final stdout reader was ever started, the parent still owns the
    # last proc.stdout and must close it here.
    if t_final_out is None and procs:
        last_stdout = procs[-1].stdout
        if last_stdout and not last_stdout.closed:
            last_stdout.close()


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


def _run_exec(
    argv: list[str],
    cwd: str,
    env: dict[str, str],
    timeout_sec: float,
) -> tuple[int, CapturedOutput, CapturedOutput]:
    """Run a single command with capped output capture.

    Returns (returncode, stdout_captured, stderr_captured).
    Raises subprocess.TimeoutExpired (with .stdout/.stderr as
    CapturedOutput) or FileNotFoundError.
    """
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )

    stdout_cap = _CappedCapture(MAX_STDOUT_CAPTURE_BYTES)
    stderr_cap = _CappedCapture(MAX_STDERR_CAPTURE_BYTES)

    t_out = threading.Thread(target=_drain_stream, args=(proc.stdout, stdout_cap), daemon=True)
    t_err = threading.Thread(target=_drain_stream, args=(proc.stderr, stderr_cap), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        timed_out = True
    finally:
        t_out.join(timeout=10)
        t_err.join(timeout=10)

    stdout_result = stdout_cap.result()
    stderr_result = stderr_cap.result()

    if timed_out:
        exc = subprocess.TimeoutExpired(argv, timeout_sec)
        exc.stdout = stdout_result
        exc.stderr = stderr_result
        raise exc

    return proc.returncode, stdout_result, stderr_result


def _run_pipeline(
    segments: list[list[str]],
    cwd: str,
    env: dict[str, str],
    timeout_sec: int,
) -> tuple[int, CapturedOutput, CapturedOutput]:
    """Run a pipeline of commands with OS pipes between segments.

    Intermediate stdout flows through kernel pipe buffers — never
    capped or buffered in Python.  Only the final segment's stdout
    is captured.  Stderr from ALL segments is aggregated into one
    shared capture (interleaving across segments is nondeterministic).

    Returns (returncode, stdout_captured, stderr_captured).
    Raises subprocess.TimeoutExpired, FileNotFoundError, or PermissionError.
    """
    deadline = time.monotonic() + timeout_sec
    procs: list[subprocess.Popen] = []
    stderr_threads: list[threading.Thread] = []

    # Create captures before process creation so they exist even if
    # a later segment fails to spawn.
    pipeline_stderr_cap = _CappedCapture(MAX_STDERR_CAPTURE_BYTES)
    final_stdout_cap = _CappedCapture(MAX_STDOUT_CAPTURE_BYTES)
    t_final_out: threading.Thread | None = None

    try:
        for i, argv in enumerate(segments):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exc = subprocess.TimeoutExpired(argv, timeout_sec)
                exc.stdout = final_stdout_cap.result()
                exc.stderr = pipeline_stderr_cap.result()
                raise exc

            is_first = i == 0
            stdin_src = subprocess.DEVNULL if is_first else procs[i - 1].stdout

            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=stdin_src,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            procs.append(proc)

            # Once the next child has inherited the previous stdout pipe,
            # the parent must close its copy so EOF can propagate correctly.
            if not is_first:
                prev_stdout = procs[i - 1].stdout
                if prev_stdout and not prev_stdout.closed:
                    prev_stdout.close()

            t_err = threading.Thread(
                target=_drain_stream,
                args=(proc.stderr, pipeline_stderr_cap),
                daemon=True,
            )
            t_err.start()
            stderr_threads.append(t_err)

        t_final_out = threading.Thread(
            target=_drain_stream,
            args=(procs[-1].stdout, final_stdout_cap),
            daemon=True,
        )
        t_final_out.start()

        for proc in procs:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exc = subprocess.TimeoutExpired(segments[-1], timeout_sec)
                exc.stdout = final_stdout_cap.result()
                exc.stderr = pipeline_stderr_cap.result()
                raise exc
            proc.wait(timeout=remaining)

        _cleanup_pipeline(
            procs,
            stderr_threads,
            t_final_out,
            terminate=False,
        )

        for proc in procs:
            if proc.returncode != 0:
                return (
                    proc.returncode,
                    final_stdout_cap.result(),
                    pipeline_stderr_cap.result(),
                )

        return (
            procs[-1].returncode,
            final_stdout_cap.result(),
            pipeline_stderr_cap.result(),
        )

    except subprocess.TimeoutExpired as exc:
        _cleanup_pipeline(
            procs,
            stderr_threads,
            t_final_out,
            terminate=True,
        )
        exc.stdout = final_stdout_cap.result()
        exc.stderr = pipeline_stderr_cap.result()
        raise

    except (FileNotFoundError, PermissionError) as exc:
        _cleanup_pipeline(
            procs,
            stderr_threads,
            t_final_out,
            terminate=True,
        )
        exc.stdout = final_stdout_cap.result()
        exc.stderr = pipeline_stderr_cap.result()
        raise

    except Exception:
        _cleanup_pipeline(
            procs,
            stderr_threads,
            t_final_out,
            terminate=True,
        )
        raise


# ---------------------------------------------------------------------------
# Receipt helpers
# ---------------------------------------------------------------------------


def _base_receipt(
    contract: CommandContract,
    policy_profile: str,
    policy: dict,
    start: str,
) -> dict[str, Any]:
    """Return the fields shared by every receipt."""
    receipt: dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "contract_id": contract.contract_id,
        "execution_id": f"exec_{contract.contract_id}",
        "contract_sha256": hash_contract(contract),
        "policy_profile": policy_profile,
        "runner_version": runner_version(),
        "execution_mode": "local",
        "started_at": start,
    }
    schema_ver = policy.get("policy_schema_version")
    if schema_ver:
        receipt["policy_schema_version"] = schema_ver
    receipt["policy_sha256"] = _hash_policy(policy)
    return receipt


def _effect_summary(contract: CommandContract) -> dict[str, Any]:
    return {
        "files_written": 0,
        "network_used": any(cmd.network != "deny" for cmd in contract.commands),
        "secrets_used": sum(len(cmd.secret_refs) for cmd in contract.commands),
    }


def _blocked_receipt(
    contract: CommandContract,
    policy_profile: str,
    policy: dict,
    start: str,
    error: str,
    exit_code: int | None = None,
    completed_ids: list[str] | None = None,
    failed_cmd_id: str | None = None,
) -> dict[str, Any]:
    """Build a receipt for a blocked (pre-execution denial) contract."""
    receipt = _base_receipt(contract, policy_profile, policy, start)
    receipt.update(
        {
            "status": "blocked",
            "ended_at": _iso_now(),
            "completed_command_ids": completed_ids if completed_ids is not None else [],
            "failed_command_id": failed_cmd_id,
            "error": truncate_error(error),
        }
    )
    if exit_code is not None:
        receipt["exit_code"] = exit_code
    return receipt


def _failed_receipt(
    contract: CommandContract,
    policy_profile: str,
    policy: dict,
    start: str,
    failed_cmd_id: str | None,
    completed_ids: list[str],
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    exit_code: int,
    error: str,
) -> dict[str, Any]:
    """Build a receipt for a failed execution."""
    receipt = _base_receipt(contract, policy_profile, policy, start)
    receipt.update(
        {
            "status": "failed",
            "ended_at": _iso_now(),
            "exit_code": exit_code,
            "stdout_hash": stdout.hash_hex,
            "stderr_hash": stderr.hash_hex,
            "artifacts": [],
            "effect_summary": _effect_summary(contract),
            "completed_command_ids": completed_ids,
            "failed_command_id": failed_cmd_id,
            "error": truncate_error(error),
        }
    )
    if stdout.truncated:
        receipt["stdout_truncated"] = True
    if stderr.truncated:
        receipt["stderr_truncated"] = True
    return receipt


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_contract(
    contract: CommandContract,
    policy_profile: str,
    policy: dict,
) -> dict[str, Any]:
    start = _iso_now()

    # --- Pre-execution: resource limits ---
    violations = validate_contract_limits(contract)
    if violations:
        return _blocked_receipt(contract, policy_profile, policy, start, "; ".join(violations))

    rc: int | None = None
    last_stdout = _empty_capture()
    last_stderr = _empty_capture()
    completed_command_ids: list[str] = []
    failed_command_id: str | None = None

    try:
        for command in contract.commands:
            # --- Pre-execution: path enforcement ---
            allowed_cwd = policy.get("allowed_cwd_prefixes", [])
            allowed_read = policy.get("allowed_read_prefixes", [])
            allowed_write = policy.get("allowed_write_prefixes", [])

            try:
                resolved_cwd = resolve_and_check_cwd(command.cwd, allowed_cwd)
            except PathEscapeError as exc:
                return _blocked_receipt(
                    contract,
                    policy_profile,
                    policy,
                    start,
                    str(exc),
                    exit_code=126,
                    completed_ids=completed_command_ids,
                    failed_cmd_id=command.id,
                )

            try:
                check_cwd_exists(resolved_cwd)
            except CwdNotFoundError as exc:
                return _failed_receipt(
                    contract,
                    policy_profile,
                    policy,
                    start,
                    command.id,
                    completed_command_ids,
                    last_stdout,
                    last_stderr,
                    exit_code=126,
                    error=str(exc),
                )

            for path in command.read_paths:
                try:
                    normalize_and_check_scope(path, allowed_read, label="read_paths")
                except PathEscapeError as exc:
                    return _blocked_receipt(
                        contract,
                        policy_profile,
                        policy,
                        start,
                        str(exc),
                        exit_code=126,
                        completed_ids=completed_command_ids,
                        failed_cmd_id=command.id,
                    )

            for path in command.write_paths:
                try:
                    normalize_and_check_scope(path, allowed_write, label="write_paths")
                except PathEscapeError as exc:
                    return _blocked_receipt(
                        contract,
                        policy_profile,
                        policy,
                        start,
                        str(exc),
                        exit_code=126,
                        completed_ids=completed_command_ids,
                        failed_cmd_id=command.id,
                    )

            # --- Execution ---
            env = _build_env(command.env_allow)

            if command.exec is not None:
                rc, last_stdout, last_stderr = _run_exec(
                    command.exec.argv,
                    resolved_cwd,
                    env,
                    command.timeout_sec,
                )
            else:
                segments = [seg.argv for seg in command.pipeline.segments]
                rc, last_stdout, last_stderr = _run_pipeline(
                    segments,
                    resolved_cwd,
                    env,
                    command.timeout_sec,
                )

            if rc == 0:
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
        tout = getattr(exc, "stdout", None)
        terr = getattr(exc, "stderr", None)
        stdout_out = tout if isinstance(tout, CapturedOutput) else last_stdout
        stderr_out = terr if isinstance(terr, CapturedOutput) else last_stderr
        return _failed_receipt(
            contract,
            policy_profile,
            policy,
            start,
            failed_command_id,
            completed_command_ids,
            stdout_out,
            stderr_out,
            exit_code=124,
            error=f"command timed out after {exc.timeout} seconds",
        )

    except FileNotFoundError as exc:
        failed_command_id = failed_command_id or (
            contract.commands[len(completed_command_ids)].id
            if len(completed_command_ids) < len(contract.commands)
            else None
        )
        tout = getattr(exc, "stdout", None)
        terr = getattr(exc, "stderr", None)
        stdout_out = tout if isinstance(tout, CapturedOutput) else last_stdout
        stderr_out = terr if isinstance(terr, CapturedOutput) else last_stderr
        return _failed_receipt(
            contract,
            policy_profile,
            policy,
            start,
            failed_command_id,
            completed_command_ids,
            stdout_out,
            stderr_out,
            exit_code=127,
            error=str(exc),
        )

    except PermissionError as exc:
        failed_command_id = failed_command_id or (
            contract.commands[len(completed_command_ids)].id
            if len(completed_command_ids) < len(contract.commands)
            else None
        )
        tout = getattr(exc, "stdout", None)
        terr = getattr(exc, "stderr", None)
        stdout_out = tout if isinstance(tout, CapturedOutput) else last_stdout
        stderr_out = terr if isinstance(terr, CapturedOutput) else last_stderr
        return _failed_receipt(
            contract,
            policy_profile,
            policy,
            start,
            failed_command_id,
            completed_command_ids,
            stdout_out,
            stderr_out,
            exit_code=126,
            error=str(exc),
        )

    except Exception as exc:
        failed_command_id = failed_command_id or (
            contract.commands[len(completed_command_ids)].id
            if len(completed_command_ids) < len(contract.commands)
            else None
        )
        return _failed_receipt(
            contract,
            policy_profile,
            policy,
            start,
            failed_command_id,
            completed_command_ids,
            last_stdout,
            last_stderr,
            exit_code=1,
            error=f"internal runner error: {exc}",
        )

    # --- Success or non-zero exit ---
    end = _iso_now()
    exit_code = rc if rc is not None else 1
    status = "success" if exit_code == 0 else "failed"

    receipt = _base_receipt(contract, policy_profile, policy, start)
    receipt.update(
        {
            "status": status,
            "ended_at": end,
            "exit_code": exit_code,
            "stdout_hash": last_stdout.hash_hex,
            "stderr_hash": last_stderr.hash_hex,
            "artifacts": [],
            "effect_summary": _effect_summary(contract),
            "completed_command_ids": completed_command_ids,
            "failed_command_id": failed_command_id,
            "error": truncate_error(last_stderr.data.decode("utf-8", errors="replace")) if exit_code != 0 else "",
        }
    )
    if last_stdout.truncated:
        receipt["stdout_truncated"] = True
    if last_stderr.truncated:
        receipt["stderr_truncated"] = True
    return receipt
