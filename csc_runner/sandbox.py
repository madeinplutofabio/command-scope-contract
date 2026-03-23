"""Linux sandbox backend — kernel-enforced process isolation.

Builds a hardened launcher argv using Linux-native tools:
- bubblewrap (bwrap): mount/pid/network namespace isolation
- setpriv: --no-new-privs always; privilege drop when configured
- prlimit: resource limits (CPU, address space, processes, file size)

No Python preexec_fn. The security boundary is the kernel, not
Python child hooks.

Integration contract:
    1. Call verify_hardened_runtime(config) ONCE at startup.
    2. Call check_command_allowed(argv, config) for EACH command (advisory).
    3. Call build_hardened_command(...) with normalized literal bind prefixes
       (no glob metacharacters, absolute paths only). The caller is
       responsible for extracting literal prefixes from declared scopes
       before passing them here.
    4. Pass launcher argv to Popen(preexec_fn=None, shell=False).
    Skipping step 1 means platform/tool/network checks are not enforced.

Writable bind model:
    Writable roots come only from write_bind_prefixes. cwd is always
    visible but read-only unless it is under an approved writable root.
    Non-existing write prefixes that are under an already-writable
    ancestor are skipped (the command can create them at runtime).
    Non-existing write prefixes with no writable ancestor are rejected.
    Read-only binds are skipped for paths already under a writable root.
    Redundant nested roots are collapsed to the outermost ancestor.

Command blocking (check_command_allowed) is advisory product policy,
not a security boundary. The sandbox contains even if a blocked command
runs — restricted filesystem view, dropped privileges, no privilege
gain, isolated namespaces.

Network enforcement: the production boundary is bwrap --unshare-net
(network namespace isolation). verify_network_disabled() is a preflight
sanity check on the host/container environment — it checks that the
runner's own environment has no non-loopback interfaces, which is
expected when the container is started with --network=none. The sandbox
additionally creates its own network namespace via bwrap.

Hardened pilot is tied to the shipped container image layout. The
visible filesystem and available binaries are image-dependent.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
from dataclasses import dataclass, field

_GLOB_META = frozenset("*?[")


class SandboxError(Exception):
    """Raised when sandbox constraints are violated or cannot be enforced."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"sandbox error: {reason}")


# ---------------------------------------------------------------------------
# Advisory command denylist (product policy, not security boundary)
# ---------------------------------------------------------------------------

_BLOCKED_SHELLS: frozenset[str] = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "csh",
        "tcsh",
        "dash",
        "ksh",
        "powershell",
        "pwsh",
        "cmd",
        "cmd.exe",
    }
)

_BLOCKED_INTERPRETER_NAMES: frozenset[str] = frozenset(
    {
        "perl",
        "ruby",
        "node",
        "php",
    }
)

_BLOCKED_INTERPRETER_PREFIXES: tuple[str, ...] = (
    "python",
    "pypy",
)

_BLOCKED_WRAPPERS: frozenset[str] = frozenset(
    {
        "env",
        "busybox",
        "toybox",
        "xargs",
        "nohup",
        "strace",
        "ltrace",
        "sudo",
        "su",
        "doas",
        "chroot",
        "unshare",
        "nsenter",
        "firejail",
    }
)

_BLOCKED_EXACT: frozenset[str] = _BLOCKED_SHELLS | _BLOCKED_INTERPRETER_NAMES | _BLOCKED_WRAPPERS


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxConfig:
    """Resource limits and isolation parameters for hardened mode.

    Container-level isolation (mount/pid/network namespaces) is enforced
    by bubblewrap. Resource limits by prlimit. Privilege drop by setpriv.
    --no-new-privs is always applied in hardened mode.
    """

    # Resource limits (prlimit)
    cpu_time_sec: int = 300
    memory_bytes: int = 1_073_741_824  # 1 GiB
    max_processes: int = 100
    max_file_size_bytes: int = 104_857_600  # 100 MiB

    # Privilege drop (setpriv). Either both set or neither.
    # --no-new-privs is always applied regardless of these.
    run_as_uid: int | None = None
    run_as_gid: int | None = None

    # Filesystem: read-only system paths visible inside the sandbox.
    readonly_bind_paths: tuple[str, ...] = (
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/etc",
    )

    # Additional command basenames to block (advisory).
    blocked_commands: frozenset[str] = field(default_factory=frozenset)

    # Whether to enforce network-disabled sanity check on host.
    require_network_disabled: bool = True


def default_hardened_config() -> SandboxConfig:
    """Return the default hardened mode sandbox configuration."""
    return SandboxConfig()


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def validate_config(config: SandboxConfig) -> None:
    """Validate sandbox config values before use.

    Raises SandboxError on any invalid value.
    """
    if config.cpu_time_sec <= 0:
        raise SandboxError(f"cpu_time_sec must be positive, got {config.cpu_time_sec}")
    if config.memory_bytes <= 0:
        raise SandboxError(f"memory_bytes must be positive, got {config.memory_bytes}")
    if config.max_processes <= 0:
        raise SandboxError(f"max_processes must be positive, got {config.max_processes}")
    if config.max_file_size_bytes <= 0:
        raise SandboxError(f"max_file_size_bytes must be positive, got {config.max_file_size_bytes}")
    if config.run_as_uid is not None and config.run_as_uid < 0:
        raise SandboxError(f"run_as_uid must be non-negative, got {config.run_as_uid}")
    if config.run_as_gid is not None and config.run_as_gid < 0:
        raise SandboxError(f"run_as_gid must be non-negative, got {config.run_as_gid}")
    uid_set = config.run_as_uid is not None
    gid_set = config.run_as_gid is not None
    if uid_set != gid_set:
        raise SandboxError(
            "run_as_uid and run_as_gid must both be set or both be None; "
            f"got uid={config.run_as_uid}, gid={config.run_as_gid}"
        )


# ---------------------------------------------------------------------------
# Path comparison helper
# ---------------------------------------------------------------------------


def _cmp_path(path: str) -> str:
    """Normalize a path for internal comparison.

    Normalizes separators to forward slash so cross-platform tests pass.
    Does NOT case-fold — this module targets Linux (case-sensitive).
    """
    norm = os.path.normpath(path).replace("\\", "/")
    if norm != "/":
        norm = norm.rstrip("/")
    return norm


# ---------------------------------------------------------------------------
# Bind prefix validation and path helpers
# ---------------------------------------------------------------------------


def _validate_bind_prefix(path: str, label: str) -> None:
    """Reject invalid bind prefixes.

    Bind prefixes must be:
    - Non-empty
    - Absolute paths
    - Free of glob metacharacters (*, ?, [)

    Raises SandboxError on any violation.
    """
    if not path:
        raise SandboxError(f"{label}: bind prefix must not be empty")

    if not os.path.isabs(path):
        raise SandboxError(f"{label}: bind prefix must be absolute: {path!r}")

    if any(ch in _GLOB_META for ch in path):
        raise SandboxError(f"{label}: bind prefix must not contain glob metacharacters: {path!r}")


def _is_under_any(path: str, ancestors: set[str]) -> bool:
    """Check if path is equal to or under any ancestor in the set."""
    norm = _cmp_path(path)
    for ancestor in ancestors:
        ancestor_norm = _cmp_path(ancestor)
        if norm == ancestor_norm or norm.startswith(ancestor_norm + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Writable path resolution
# ---------------------------------------------------------------------------


def _resolve_writable_roots(write_bind_prefixes: list[str]) -> list[str]:
    """Determine which writable paths to bind-mount.

    Rules:
    - Write prefixes that exist are included as writable roots.
    - Write prefixes that don't exist but are under an already-writable
      root are skipped — the command can create them at runtime.
    - Write prefixes that don't exist and have no writable ancestor
      are rejected with SandboxError.
    - Redundant nested roots are collapsed: if both /workspace and
      /workspace/out exist, only /workspace is bound.

    cwd is NOT included here. cwd visibility is handled separately.

    Returns sorted list of existing, non-redundant writable root paths.
    """
    writable: set[str] = set()

    # First pass: add existing prefixes.
    for prefix in write_bind_prefixes:
        if os.path.exists(prefix):
            writable.add(prefix)

    # Second pass: check non-existing prefixes have a writable ancestor.
    for prefix in write_bind_prefixes:
        if not os.path.exists(prefix):
            if not _is_under_any(prefix, writable):
                raise SandboxError(
                    f"write_bind_prefixes: {prefix!r} does not exist and is not under any writable ancestor"
                )

    # Third pass: collapse nested roots to outermost ancestors.
    collapsed: set[str] = set()
    for path in sorted(writable):
        if not _is_under_any(path, collapsed):
            collapsed.add(path)

    return sorted(collapsed)


# ---------------------------------------------------------------------------
# Pre-flight verification
# ---------------------------------------------------------------------------

_REQUIRED_TOOLS: tuple[str, ...] = ("bwrap", "setpriv", "prlimit")


def verify_platform() -> None:
    """Verify the platform is Linux. Raises SandboxError otherwise."""
    if platform.system() != "Linux":
        raise SandboxError(f"hardened mode requires Linux, current platform is {platform.system()}")


def verify_tools() -> None:
    """Verify required binaries are on PATH.

    Always checks for bwrap, setpriv, and prlimit (setpriv is required
    even without privilege drop because --no-new-privs is always applied).

    Raises SandboxError if any tool is missing.
    """
    missing = [tool for tool in _REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        raise SandboxError(f"required tools not found on PATH: {', '.join(missing)}")


def verify_network_disabled() -> None:
    """Sanity check: no non-loopback network interfaces on the host.

    This is a preflight heuristic on the runner's own environment,
    not the security boundary. The production enforcement is
    bwrap --unshare-net (network namespace isolation inside the sandbox).

    Expected to pass when the container is started with --network=none.
    The sandbox additionally creates its own network namespace.

    Raises SandboxError if non-loopback interfaces are detected.
    """
    try:
        interfaces = socket.if_nameindex()
    except OSError as exc:
        raise SandboxError(f"cannot enumerate network interfaces: {exc}") from exc

    non_loopback = [name for _idx, name in interfaces if name != "lo"]

    if non_loopback:
        raise SandboxError(f"network not disabled: found non-loopback interfaces: {', '.join(non_loopback)}")


def verify_hardened_runtime(config: SandboxConfig) -> None:
    """Run all pre-flight checks for hardened mode.

    Checks:
    1. Config values are valid.
    2. Platform is Linux.
    3. Required tools are on PATH (bwrap, setpriv, prlimit).
    4. Network sanity check (if config.require_network_disabled).

    Call once at startup before spawning any sandbox subprocess.
    Raises SandboxError on any failure.
    """
    validate_config(config)
    verify_platform()
    verify_tools()

    if config.require_network_disabled:
        verify_network_disabled()


# ---------------------------------------------------------------------------
# Advisory command blocking
# ---------------------------------------------------------------------------


def check_command_allowed(argv: list[str], config: SandboxConfig) -> None:
    """Advisory check: is this command allowed by product policy?

    NOT a security boundary. The sandbox contains even if a blocked
    command runs. This is product-policy lint for operator UX.

    Blocked categories (basename, lowercased):
    - Shell interpreters (exact match)
    - Scripting interpreters (exact + prefix: python*, pypy*)
    - Wrapper commands (exact match)
    - Custom blocked_commands (exact match)

    Raises SandboxError if the command is blocked.
    """
    if not argv:
        raise SandboxError("empty argv")

    command = os.path.basename(argv[0]).lower()

    if command in (_BLOCKED_EXACT | config.blocked_commands):
        raise SandboxError(f"command {argv[0]!r} is blocked in hardened mode")

    if command.startswith(_BLOCKED_INTERPRETER_PREFIXES):
        raise SandboxError(f"command {argv[0]!r} is blocked in hardened mode")


# ---------------------------------------------------------------------------
# Launcher construction
# ---------------------------------------------------------------------------


def build_hardened_command(
    user_argv: list[str],
    *,
    cwd: str,
    read_bind_prefixes: list[str],
    write_bind_prefixes: list[str],
    config: SandboxConfig,
) -> list[str]:
    """Build a hardened launcher argv for Popen.

    Constructs the chain:
        bwrap <namespace/fs args> --
        setpriv --no-new-privs [--reuid/--regid/--clear-groups] --
        prlimit <limit args> --
        <user command>

    Writable bind model:
        Writable roots come only from write_bind_prefixes. cwd is
        always visible but read-only unless it is under an approved
        writable root. Non-existing write prefixes under an existing
        writable ancestor are skipped. Redundant nested roots are
        collapsed to the outermost ancestor. Read-only binds are
        skipped for paths already under a writable root.

    Args:
        user_argv: The user's command to execute.
        cwd: Working directory (absolute, literal, must exist).
        read_bind_prefixes: Normalized literal read scope paths
            (no glob metacharacters, absolute). Bind-mounted read-only
            unless already under a writable root.
        write_bind_prefixes: Normalized literal write scope paths
            (no glob metacharacters, absolute). Bind-mounted writable
            if they exist; skipped if under a writable ancestor.
        config: Sandbox configuration.

    Returns:
        Complete argv list for Popen.

    Raises:
        SandboxError: If argv is empty, config is invalid, bind
            prefixes are malformed, cwd doesn't exist, or writable
            paths cannot be resolved.
    """
    if not user_argv:
        raise SandboxError("empty user argv")

    validate_config(config)

    # Validate all bind prefixes: absolute, no globs, non-empty.
    _validate_bind_prefix(cwd, "cwd")
    for prefix in read_bind_prefixes:
        _validate_bind_prefix(prefix, "read_bind_prefixes")
    for prefix in write_bind_prefixes:
        _validate_bind_prefix(prefix, "write_bind_prefixes")

    if not os.path.isdir(cwd):
        raise SandboxError(f"cwd does not exist or is not a directory: {cwd!r}")

    # Resolve writable roots from write_bind_prefixes only.
    writable_paths = _resolve_writable_roots(write_bind_prefixes)
    writable_set = set(writable_paths)

    argv: list[str] = []

    # --- bubblewrap ---
    argv.append("bwrap")

    # Read-only system paths
    for path in config.readonly_bind_paths:
        if os.path.exists(path):
            argv.extend(["--ro-bind", path, path])

    # Writable roots (from write_bind_prefixes only)
    for path in writable_paths:
        argv.extend(["--bind", path, path])

    # cwd: read-only unless already under a writable root
    if not _is_under_any(cwd, writable_set):
        argv.extend(["--ro-bind", cwd, cwd])

    # Read-only declared paths: skip if under a writable root or nonexistent
    for prefix in read_bind_prefixes:
        if _is_under_any(prefix, writable_set):
            continue
        if not os.path.exists(prefix):
            continue
        # Also skip if it's the same as cwd (already bound above)
        if _cmp_path(prefix) == _cmp_path(cwd):
            continue
        argv.extend(["--ro-bind", prefix, prefix])

    # Virtual filesystems
    argv.extend(["--tmpfs", "/tmp"])
    argv.extend(["--proc", "/proc"])
    argv.extend(["--dev", "/dev"])

    # Namespace isolation
    argv.append("--unshare-net")
    argv.append("--unshare-pid")
    argv.append("--new-session")
    argv.append("--die-with-parent")

    # Working directory inside sandbox
    argv.extend(["--chdir", cwd])

    argv.append("--")

    # --- setpriv (always present for --no-new-privs) ---
    argv.append("setpriv")
    argv.append("--no-new-privs")

    if config.run_as_uid is not None:
        argv.append(f"--reuid={config.run_as_uid}")
        argv.append(f"--regid={config.run_as_gid}")
        argv.append("--clear-groups")

    argv.append("--")

    # --- prlimit ---
    argv.append("prlimit")
    argv.append(f"--cpu={config.cpu_time_sec}")
    argv.append(f"--as={config.memory_bytes}")
    argv.append(f"--nproc={config.max_processes}")
    argv.append(f"--fsize={config.max_file_size_bytes}")
    argv.append("--")

    # --- user command ---
    argv.extend(user_argv)

    return argv
