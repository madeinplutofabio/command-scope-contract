"""Real-path resolution and filesystem boundary enforcement.

This module provides executor-side path checking that uses the real
filesystem (os.path.realpath, os.path.isdir) rather than pure path
objects.  Policy-level path checking (flavour-aware normalization,
prefix matching on declared scopes) remains in policy.py.

pathutil is for runtime enforcement:
- Resolve cwd to its real path (following symlinks)
- Reject symlink escapes and .. traversal after resolution
- Verify cwd exists as a directory
- Normalize declared read/write scope paths and check against allowed
  prefixes (extracting literal prefix before glob metacharacters)
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath, PureWindowsPath


class PathEscapeError(Exception):
    """Raised when a resolved path escapes its allowed scope."""

    def __init__(self, declared_path: str, resolved_path: str, reason: str) -> None:
        self.declared_path = declared_path
        self.resolved_path = resolved_path
        self.reason = reason
        super().__init__(f"{reason}: declared={declared_path!r}, resolved={resolved_path!r}")


class CwdNotFoundError(Exception):
    """Raised when a declared cwd does not exist or is not a directory."""

    def __init__(self, cwd: str) -> None:
        self.cwd = cwd
        super().__init__(f"cwd does not exist or is not a directory: {cwd!r}")


# ---------------------------------------------------------------------------
# Path flavour detection and normalization (shared with policy.py)
# ---------------------------------------------------------------------------


def detect_path_flavour(path: str) -> str:
    """Detect whether a path is Windows-style or POSIX-style."""
    if path.startswith(("\\\\", "//")):
        return "windows"
    if len(path) >= 3 and path[1] == ":" and path[2] in ("\\", "/"):
        return "windows"
    return "posix"


def normalize_path(path: str) -> tuple[str, str]:
    """Return (flavour, normalized comparison form).

    Raises PathEscapeError if the path is not absolute.
    Windows paths are lowercased for case-insensitive comparison.
    POSIX paths preserve case.
    """
    flavour = detect_path_flavour(path)
    if flavour == "windows":
        p = PureWindowsPath(path)
        if not p.is_absolute():
            raise PathEscapeError(path, path, "path must be absolute")
        return (flavour, p.as_posix().lower())
    else:
        p = PurePosixPath(path)
        if not p.is_absolute():
            raise PathEscapeError(path, path, "path must be absolute")
        return (flavour, str(p))


def path_within_prefixes(path: str, prefixes: list[str]) -> bool:
    """Check if a path falls within any of the given prefixes.

    Only same-flavour comparisons are performed. Mixed-flavour
    comparisons fail closed (deny).
    """
    path_flavour, norm_path = normalize_path(path)
    for prefix in prefixes:
        prefix_flavour, norm_prefix = normalize_path(prefix)
        if prefix_flavour != path_flavour:
            continue

        if norm_prefix == "/":
            if path_flavour == "posix":
                return True
            continue

        if norm_prefix.endswith("/"):
            norm_prefix = norm_prefix.rstrip("/")

        if norm_path == norm_prefix or norm_path.startswith(norm_prefix + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Glob literal prefix extraction
# ---------------------------------------------------------------------------

_GLOB_META = frozenset("*?[")


def _glob_literal_prefix(path: str) -> str:
    """Extract the literal directory prefix before the first glob metacharacter.

    For example:
        /workspace/out/**  -> /workspace/out
        /workspace/out/*.log -> /workspace/out
        /workspace/out -> /workspace/out  (no glob)

    Returns the longest directory prefix that contains no metacharacters.
    """
    for i, ch in enumerate(path):
        if ch in _GLOB_META:
            # Find the last separator before the metacharacter
            prefix = path[:i]
            sep_idx = max(prefix.rfind("/"), prefix.rfind("\\"))
            if sep_idx >= 0:
                return path[:sep_idx]
            return ""
    return path


# ---------------------------------------------------------------------------
# Runtime enforcement
# ---------------------------------------------------------------------------


def resolve_and_check_cwd(declared_cwd: str, allowed_prefixes: list[str]) -> str:
    """Resolve cwd to its real filesystem path and check scope.

    1. Validates the declared path syntactically (absolute, correct flavour).
    2. Calls os.path.realpath() to resolve symlinks and .. components.
    3. Checks the resolved path against allowed prefixes.
    4. Returns the resolved path on success.

    Raises PathEscapeError if the declared path is not absolute or if
    the resolved path escapes allowed scope.
    """
    # Syntactic validation before touching the filesystem.
    normalize_path(declared_cwd)

    resolved = os.path.realpath(declared_cwd)

    if not path_within_prefixes(resolved, allowed_prefixes):
        raise PathEscapeError(
            declared_cwd,
            resolved,
            "cwd resolves outside allowed scope",
        )

    return resolved


def check_cwd_exists(cwd: str) -> None:
    """Verify that cwd exists and is a directory.

    Should be called with the resolved (real) path from
    resolve_and_check_cwd().

    Raises CwdNotFoundError if the path does not exist or is not a
    directory.
    """
    if not os.path.isdir(cwd):
        raise CwdNotFoundError(cwd)


def normalize_and_check_scope(
    declared_path: str,
    allowed_prefixes: list[str],
    label: str = "path",
) -> None:
    """Normalize a declared scope path and check against allowed prefixes.

    For declared read/write scopes that may contain glob patterns.
    Does NOT call realpath() — these paths may not exist yet (they
    declare intent, not existing files).

    Strategy:
    1. Reject paths containing '..' in the literal portion (before any
       glob metacharacter).
    2. Extract the literal directory prefix before the first glob
       metacharacter.
    3. Check that literal prefix against allowed prefixes using
       flavour-aware normalization.

    Raises PathEscapeError on any violation.
    """
    literal = _glob_literal_prefix(declared_path)

    if not literal:
        raise PathEscapeError(
            declared_path,
            declared_path,
            f"{label}: no literal prefix before glob metacharacter",
        )

    # Reject .. in the literal portion
    parts = literal.replace("\\", "/").split("/")
    if ".." in parts:
        raise PathEscapeError(
            declared_path,
            declared_path,
            f"{label}: '..' not allowed in declared scope",
        )

    if not path_within_prefixes(literal, allowed_prefixes):
        raise PathEscapeError(
            declared_path,
            declared_path,
            f"{label}: scope outside allowed prefixes",
        )
