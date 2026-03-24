"""Resource exhaustion constants and budget-checking utilities.

Single source of truth for all runner-side limits that Pydantic schema
validation cannot express (e.g. pipeline depth, argv element size, total
contract/policy file size).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from csc_runner.models import CommandContract

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_COMMANDS_PER_CONTRACT: int = 20
"""Cross-check with Pydantic max_length on CommandContract.commands."""

MAX_PIPELINE_SEGMENTS: int = 10
"""Maximum number of segments in a single pipeline."""

MAX_ARGV_LENGTH: int = 200
"""Maximum number of elements in a single argv array."""

MAX_ARGV_ELEMENT_BYTES: int = 131_072  # 128 KiB
"""Maximum byte length of any single argv element (UTF-8 encoded)."""

MAX_CONTRACT_SIZE_BYTES: int = 1_048_576  # 1 MiB
"""Maximum raw JSON file size for a contract before parsing."""

MAX_POLICY_SIZE_BYTES: int = 524_288  # 512 KiB
"""Maximum raw YAML file size for a policy before parsing."""

MAX_JUSTIFICATION_LENGTH: int = 4_000
"""Maximum character length of the justification field."""

MAX_RECEIPT_ERROR_LENGTH: int = 4_000
"""Maximum character length of the error field in a receipt."""

MAX_STDOUT_CAPTURE_BYTES: int = 10_485_760  # 10 MiB
"""Maximum bytes captured from stdout during command execution."""

MAX_STDERR_CAPTURE_BYTES: int = 1_048_576  # 1 MiB
"""Maximum bytes captured from stderr during command execution."""


# ---------------------------------------------------------------------------
# Budget checking
# ---------------------------------------------------------------------------


def validate_contract_limits(contract: CommandContract) -> list[str]:
    """Check a parsed contract against runner resource budgets.

    Returns a list of human-readable violation descriptions.
    Empty list means the contract is within all budgets.

    Primarily checks limits that Pydantic alone should not be relied on
    to enforce at runtime (e.g. pipeline depth, argv element size).
    """
    violations: list[str] = []

    # Command count (cross-check with Pydantic max_length)
    if len(contract.commands) > MAX_COMMANDS_PER_CONTRACT:
        violations.append(f"contract has {len(contract.commands)} commands (max {MAX_COMMANDS_PER_CONTRACT})")

    for cmd in contract.commands:
        # Pipeline depth
        if cmd.pipeline is not None:
            n_segments = len(cmd.pipeline.segments)
            if n_segments > MAX_PIPELINE_SEGMENTS:
                violations.append(
                    f"command {cmd.id!r}: pipeline has {n_segments} segments (max {MAX_PIPELINE_SEGMENTS})"
                )

        # Argv length and element size (check both exec and pipeline)
        argvs: list[tuple[str, list[str]]] = []
        if cmd.exec is not None:
            argvs.append((f"command {cmd.id!r} exec", cmd.exec.argv))
        if cmd.pipeline is not None:
            for i, seg in enumerate(cmd.pipeline.segments):
                argvs.append((f"command {cmd.id!r} pipeline segment {i}", seg.argv))

        for label, argv in argvs:
            if len(argv) > MAX_ARGV_LENGTH:
                violations.append(f"{label}: argv has {len(argv)} elements (max {MAX_ARGV_LENGTH})")
            for j, elem in enumerate(argv):
                elem_bytes = len(elem.encode("utf-8"))
                if elem_bytes > MAX_ARGV_ELEMENT_BYTES:
                    violations.append(f"{label}: argv[{j}] is {elem_bytes} bytes (max {MAX_ARGV_ELEMENT_BYTES})")

    # Justification length
    if len(contract.justification) > MAX_JUSTIFICATION_LENGTH:
        violations.append(f"justification is {len(contract.justification)} chars (max {MAX_JUSTIFICATION_LENGTH})")

    return violations


def truncate_error(text: str, max_len: int = MAX_RECEIPT_ERROR_LENGTH) -> str:
    """Truncate an error message for inclusion in a receipt."""
    if len(text) <= max_len:
        return text
    suffix = "... [truncated]"
    if max_len <= len(suffix):
        return text[:max_len]
    return text[: max_len - len(suffix)] + suffix
