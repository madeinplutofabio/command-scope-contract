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
from typing import Any, Protocol, runtime_checkable

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
    _glob_literal_prefix,
    check_cwd_exists,
    normalize_and_check_scope,
    resolve_and_check_cwd,
)
from csc_runner.utils import hash_contract

RECEIPT_VERSION = "csc.receipt.v0.1"

_EMPTY_HASH = "sha256:" + hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Approval consumption store
# ---------------------------------------------------------------------------


@runtime_checkable
class ApprovalStore(Protocol):
    """Tracks consumed single-execution approvals.

    Stage 2 ships with InMemoryApprovalStore (process-local).
    Persistent backends (SQLite, Redis, etc.) can implement this
    protocol for durable replay prevention across restarts.
    """

    def is_consumed(self, approval_id: str) -> bool: ...
    def mark_consumed(self, approval_id: str) -> None: ...


class InMemoryApprovalStore:
    """Process-local approval consumption store.

    Suitable for the Stage 2 pilot only. Replay prevention is
    per-runner-process — consumed approvals are lost on restart.

    Note: is_consumed() + mark_consumed() is not atomic. Concurrent
    executions in the same process could race. For concurrent use,
    replace with an atomic consume_if_unused(approval_id) -> bool.
    """

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def is_consumed(self, approval_id: str) -> bool:
        return approval_id in self._consumed

    def mark_consumed(self, approval_id: str) -> None:
        self._consumed.add(approval_id)

    def reset(self) -> None:
        """For testing only."""
        self._consumed.clear()


# Default store instance for the runner process.
_default_approval_store = InMemoryApprovalStore()


def get_default_approval_store() -> InMemoryApprovalStore:
    """Return the default process-local approval store."""
    return _default_approval_store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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

    for key in ("PATH", "SystemRoot", "COMSPEC", "PATHEXT"):
        if key in os.environ:
            env[key] = os.environ[key]

    for key in env_allow:
        if key in os.environ:
            env[key] = os.environ[key]

    return env


def _extract_literal_prefix(path: str) -> str:
    return _glob_literal_prefix(path)


# ---------------------------------------------------------------------------
# Capped output capture
# ---------------------------------------------------------------------------


@dataclass
class CapturedOutput:
    data: bytes
    hash_hex: str
    truncated: bool


def _empty_capture() -> CapturedOutput:
    return CapturedOutput(data=b"", hash_hex=_EMPTY_HASH, truncated=False)


class _CappedCapture:
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

    if t_final_out is not None:
        t_final_out.join(timeout=10)

    for t in stderr_threads:
        t.join(timeout=10)

    for proc in procs[:-1]:
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()

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
    deadline = time.monotonic() + timeout_sec
    procs: list[subprocess.Popen] = []
    stderr_threads: list[threading.Thread] = []

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

        _cleanup_pipeline(procs, stderr_threads, t_final_out, terminate=False)

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
        _cleanup_pipeline(procs, stderr_threads, t_final_out, terminate=True)
        exc.stdout = final_stdout_cap.result()
        exc.stderr = pipeline_stderr_cap.result()
        raise

    except (FileNotFoundError, PermissionError) as exc:
        _cleanup_pipeline(procs, stderr_threads, t_final_out, terminate=True)
        exc.stdout = final_stdout_cap.result()
        exc.stderr = pipeline_stderr_cap.result()
        raise

    except Exception:
        _cleanup_pipeline(procs, stderr_threads, t_final_out, terminate=True)
        raise


# ---------------------------------------------------------------------------
# Receipt helpers
# ---------------------------------------------------------------------------


def _base_receipt(
    contract: CommandContract,
    policy_profile: str,
    policy: dict,
    start: str,
    mode: str = "local",
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "contract_id": contract.contract_id,
        "execution_id": f"exec_{contract.contract_id}",
        "contract_sha256": hash_contract(contract),
        "policy_profile": policy_profile,
        "runner_version": runner_version(),
        "execution_mode": mode,
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
    mode: str = "local",
) -> dict[str, Any]:
    receipt = _base_receipt(contract, policy_profile, policy, start, mode=mode)
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
    mode: str = "local",
) -> dict[str, Any]:
    receipt = _base_receipt(contract, policy_profile, policy, start, mode=mode)
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
# Receipt finalization (signing)
# ---------------------------------------------------------------------------


def _finalize_receipt(
    receipt: dict[str, Any],
    *,
    mode: str,
    private_key_bytes: bytes | None,
    signing_key_id: str | None,
) -> dict[str, Any]:
    """Optionally sign a receipt. All receipts go through this path.

    Signing behavior:
    - Both keys absent (None) → return unsigned receipt.
    - Both present → sign. Failure handling depends on mode.
    - Partial config (one present, one absent/empty) → always error.

    Mode-specific failure handling:
    - hardened: signing failure returns a fresh schema-valid failed receipt.
    - local: signing failure raises SigningError to the caller.
    """
    if private_key_bytes is None and signing_key_id is None:
        return receipt

    from csc_runner.signing import SigningError, sign_receipt

    if private_key_bytes is None or not signing_key_id:
        raise SigningError("signing requires both private_key_bytes and non-empty signing_key_id")

    try:
        return sign_receipt(
            receipt,
            private_key_bytes=private_key_bytes,
            key_id=signing_key_id,
        )
    except SigningError:
        if mode == "hardened":
            failed: dict[str, Any] = {
                "receipt_version": receipt.get("receipt_version", RECEIPT_VERSION),
                "contract_id": receipt.get("contract_id", ""),
                "execution_id": receipt.get("execution_id", ""),
                "contract_sha256": receipt.get("contract_sha256", ""),
                "policy_profile": receipt.get("policy_profile", ""),
                "runner_version": receipt.get("runner_version", runner_version()),
                "execution_mode": "hardened",
                "started_at": receipt.get("started_at", ""),
                "ended_at": _iso_now(),
                "status": "failed",
                "exit_code": 1,
                "stdout_hash": receipt.get("stdout_hash", _EMPTY_HASH),
                "stderr_hash": receipt.get("stderr_hash", _EMPTY_HASH),
                "artifacts": [],
                "effect_summary": receipt.get("effect_summary", {}),
                "completed_command_ids": receipt.get("completed_command_ids", []),
                "failed_command_id": receipt.get("failed_command_id"),
                "error": truncate_error("receipt signing failed in hardened mode"),
            }
            if "policy_sha256" in receipt:
                failed["policy_sha256"] = receipt["policy_sha256"]
            if "policy_schema_version" in receipt:
                failed["policy_schema_version"] = receipt["policy_schema_version"]
            return failed
        raise


# ---------------------------------------------------------------------------
# Approval consumption helper
# ---------------------------------------------------------------------------


def _consume_approval(approval: dict, store: ApprovalStore) -> None:
    if approval.get("scope") == "single_execution":
        store.mark_consumed(approval.get("approval_id", ""))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_contract(
    contract: CommandContract,
    policy_profile: str,
    policy: dict,
    *,
    mode: str = "local",
    approval: dict | None = None,
    approval_required: bool = False,
    approval_store: ApprovalStore | None = None,
    sandbox_config: Any | None = None,
    private_key_bytes: bytes | None = None,
    signing_key_id: str | None = None,
) -> dict[str, Any]:
    """Execute a contract and return a receipt.

    Returns:
        Receipt dict. In hardened mode, always signed — except when
        signing config is missing/invalid (unsigned blocked receipt)
        or signing fails after receipt construction (unsigned failed
        receipt). In local mode, signed if keys provided; raises
        SigningError on signing failure or partial config.
    """
    start = _iso_now()

    if mode not in ("local", "hardened"):
        raise ValueError(f"mode must be 'local' or 'hardened', got {mode!r}")

    if approval_store is None:
        approval_store = _default_approval_store

    # --- Hardened mode: require and validate signing config FIRST ---
    if mode == "hardened":
        if private_key_bytes is None or not signing_key_id:
            return _blocked_receipt(
                contract,
                policy_profile,
                policy,
                start,
                "hardened mode requires signing configuration (private_key_bytes and signing_key_id)",
                mode=mode,
            )
        try:
            from csc_runner.signing import _load_private_key

            _load_private_key(private_key_bytes)
        except Exception as exc:
            return _blocked_receipt(
                contract,
                policy_profile,
                policy,
                start,
                f"invalid signing key: {exc}",
                mode=mode,
            )

    # --- Pre-execution: approval required but absent ---
    if approval_required and approval is None:
        return _finalize_receipt(
            _blocked_receipt(
                contract,
                policy_profile,
                policy,
                start,
                "approval is required but none was provided",
                mode=mode,
            ),
            mode=mode,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
        )

    # --- Pre-execution: validate approval (but don't consume yet) ---
    if approval is not None:
        from csc_runner.approval import ApprovalError, validate_approval

        contract_sha256 = hash_contract(contract)
        try:
            validate_approval(approval, contract_sha256)
        except ApprovalError as exc:
            return _finalize_receipt(
                _blocked_receipt(contract, policy_profile, policy, start, str(exc), mode=mode),
                mode=mode,
                private_key_bytes=private_key_bytes,
                signing_key_id=signing_key_id,
            )

        aid = approval.get("approval_id", "")
        if approval.get("scope") == "single_execution" and approval_store.is_consumed(aid):
            return _finalize_receipt(
                _blocked_receipt(
                    contract,
                    policy_profile,
                    policy,
                    start,
                    f"approval {aid!r} has already been consumed (single_execution)",
                    mode=mode,
                ),
                mode=mode,
                private_key_bytes=private_key_bytes,
                signing_key_id=signing_key_id,
            )

    # --- Pre-execution: hardened mode sandbox verification ---
    if mode == "hardened":
        from csc_runner.sandbox import SandboxError, verify_hardened_runtime

        if sandbox_config is None:
            return _finalize_receipt(
                _blocked_receipt(
                    contract,
                    policy_profile,
                    policy,
                    start,
                    "hardened mode requires sandbox_config",
                    mode=mode,
                ),
                mode=mode,
                private_key_bytes=private_key_bytes,
                signing_key_id=signing_key_id,
            )
        try:
            verify_hardened_runtime(sandbox_config)
        except SandboxError as exc:
            return _finalize_receipt(
                _blocked_receipt(contract, policy_profile, policy, start, str(exc), mode=mode),
                mode=mode,
                private_key_bytes=private_key_bytes,
                signing_key_id=signing_key_id,
            )

    # --- Pre-execution: resource limits ---
    violations = validate_contract_limits(contract)
    if violations:
        return _finalize_receipt(
            _blocked_receipt(
                contract,
                policy_profile,
                policy,
                start,
                "; ".join(violations),
                mode=mode,
            ),
            mode=mode,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
        )

    rc: int | None = None
    last_stdout = _empty_capture()
    last_stderr = _empty_capture()
    completed_command_ids: list[str] = []
    failed_command_id: str | None = None
    approval_consumed = False

    try:
        for command in contract.commands:
            allowed_cwd = policy.get("allowed_cwd_prefixes", [])
            allowed_read = policy.get("allowed_read_prefixes", [])
            allowed_write = policy.get("allowed_write_prefixes", [])

            try:
                resolved_cwd = resolve_and_check_cwd(command.cwd, allowed_cwd)
            except PathEscapeError as exc:
                return _finalize_receipt(
                    _blocked_receipt(
                        contract,
                        policy_profile,
                        policy,
                        start,
                        str(exc),
                        exit_code=126,
                        completed_ids=completed_command_ids,
                        failed_cmd_id=command.id,
                        mode=mode,
                    ),
                    mode=mode,
                    private_key_bytes=private_key_bytes,
                    signing_key_id=signing_key_id,
                )

            try:
                check_cwd_exists(resolved_cwd)
            except CwdNotFoundError as exc:
                return _finalize_receipt(
                    _failed_receipt(
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
                        mode=mode,
                    ),
                    mode=mode,
                    private_key_bytes=private_key_bytes,
                    signing_key_id=signing_key_id,
                )

            for path in command.read_paths:
                try:
                    normalize_and_check_scope(path, allowed_read, label="read_paths")
                except PathEscapeError as exc:
                    return _finalize_receipt(
                        _blocked_receipt(
                            contract,
                            policy_profile,
                            policy,
                            start,
                            str(exc),
                            exit_code=126,
                            completed_ids=completed_command_ids,
                            failed_cmd_id=command.id,
                            mode=mode,
                        ),
                        mode=mode,
                        private_key_bytes=private_key_bytes,
                        signing_key_id=signing_key_id,
                    )

            for path in command.write_paths:
                try:
                    normalize_and_check_scope(path, allowed_write, label="write_paths")
                except PathEscapeError as exc:
                    return _finalize_receipt(
                        _blocked_receipt(
                            contract,
                            policy_profile,
                            policy,
                            start,
                            str(exc),
                            exit_code=126,
                            completed_ids=completed_command_ids,
                            failed_cmd_id=command.id,
                            mode=mode,
                        ),
                        mode=mode,
                        private_key_bytes=private_key_bytes,
                        signing_key_id=signing_key_id,
                    )

            env = _build_env(command.env_allow)

            if command.exec is not None:
                user_argv = command.exec.argv
            else:
                if mode == "hardened":
                    return _finalize_receipt(
                        _blocked_receipt(
                            contract,
                            policy_profile,
                            policy,
                            start,
                            "pipelines are not supported in hardened mode",
                            completed_ids=completed_command_ids,
                            failed_cmd_id=command.id,
                            mode=mode,
                        ),
                        mode=mode,
                        private_key_bytes=private_key_bytes,
                        signing_key_id=signing_key_id,
                    )

                if not approval_consumed and approval is not None:
                    _consume_approval(approval, approval_store)
                    approval_consumed = True

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
                continue

            if mode == "hardened":
                from csc_runner.sandbox import (
                    SandboxError,
                    build_hardened_command,
                    check_command_allowed,
                )

                try:
                    check_command_allowed(user_argv, sandbox_config)
                except SandboxError as exc:
                    return _finalize_receipt(
                        _blocked_receipt(
                            contract,
                            policy_profile,
                            policy,
                            start,
                            str(exc),
                            completed_ids=completed_command_ids,
                            failed_cmd_id=command.id,
                            mode=mode,
                        ),
                        mode=mode,
                        private_key_bytes=private_key_bytes,
                        signing_key_id=signing_key_id,
                    )

                read_bind = [_extract_literal_prefix(p) for p in command.read_paths if _extract_literal_prefix(p)]
                write_bind = [_extract_literal_prefix(p) for p in command.write_paths if _extract_literal_prefix(p)]

                try:
                    exec_argv = build_hardened_command(
                        user_argv,
                        cwd=resolved_cwd,
                        read_bind_prefixes=read_bind,
                        write_bind_prefixes=write_bind,
                        config=sandbox_config,
                    )
                except SandboxError as exc:
                    return _finalize_receipt(
                        _blocked_receipt(
                            contract,
                            policy_profile,
                            policy,
                            start,
                            str(exc),
                            completed_ids=completed_command_ids,
                            failed_cmd_id=command.id,
                            mode=mode,
                        ),
                        mode=mode,
                        private_key_bytes=private_key_bytes,
                        signing_key_id=signing_key_id,
                    )
            else:
                exec_argv = user_argv

            if not approval_consumed and approval is not None:
                _consume_approval(approval, approval_store)
                approval_consumed = True

            rc, last_stdout, last_stderr = _run_exec(
                exec_argv,
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
        return _finalize_receipt(
            _failed_receipt(
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
                mode=mode,
            ),
            mode=mode,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
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
        return _finalize_receipt(
            _failed_receipt(
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
                mode=mode,
            ),
            mode=mode,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
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
        return _finalize_receipt(
            _failed_receipt(
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
                mode=mode,
            ),
            mode=mode,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
        )

    except Exception as exc:
        failed_command_id = failed_command_id or (
            contract.commands[len(completed_command_ids)].id
            if len(completed_command_ids) < len(contract.commands)
            else None
        )
        return _finalize_receipt(
            _failed_receipt(
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
                mode=mode,
            ),
            mode=mode,
            private_key_bytes=private_key_bytes,
            signing_key_id=signing_key_id,
        )

    end = _iso_now()
    exit_code = rc if rc is not None else 1
    status = "success" if exit_code == 0 else "failed"

    receipt = _base_receipt(contract, policy_profile, policy, start, mode=mode)
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

    return _finalize_receipt(
        receipt,
        mode=mode,
        private_key_bytes=private_key_bytes,
        signing_key_id=signing_key_id,
    )
