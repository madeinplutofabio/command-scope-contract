"""Approval artifact model — validates and enforces approval semantics.

An approval artifact authorizes execution of a specific contract
(bound by contract_sha256). The runner validates the approval before
spawning any sandbox or executing any command.

Validation rules:
- Schema validation via JSON Schema (csc.approval.v0.1)
- Hash binding: approval.contract_sha256 must match the contract being executed
- Temporal: expires_at must be after approved_at
- Expiry: approval must not be expired at validation time
- Scope: single_execution approvals may be consumed once (tracked by caller)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "csc.approval.v0.1.schema.json"
_APPROVAL_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(
    _APPROVAL_SCHEMA,
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


class ApprovalError(Exception):
    """Raised when an approval artifact is invalid or does not match the contract."""

    def __init__(self, approval_id: str | None, reason: str) -> None:
        self.approval_id = approval_id
        self.reason = reason
        super().__init__(f"approval rejected: {reason}" + (f" (approval_id={approval_id!r})" if approval_id else ""))


def _parse_dt(value: str, field_name: str, approval_id: str | None) -> datetime:
    """Parse an ISO 8601 date-time string into a timezone-aware datetime.

    Raises ApprovalError on any parse failure.
    """
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ApprovalError(
            approval_id,
            f"{field_name} is not a valid ISO 8601 date-time: {value!r}",
        ) from exc

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def load_approval(path: str) -> dict:
    """Load and schema-validate an approval artifact from a JSON file.

    Returns the parsed approval dict on success.
    Raises ApprovalError on schema validation failure or file errors.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
        approval = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ApprovalError(None, f"cannot load approval file: {exc}") from exc

    errors = list(_VALIDATOR.iter_errors(approval))
    if errors:
        messages = "; ".join(e.message for e in errors[:5])
        aid = approval.get("approval_id") if isinstance(approval, dict) else None
        raise ApprovalError(aid, f"schema validation failed: {messages}")

    return approval


def validate_approval(
    approval: dict,
    contract_sha256: str,
    *,
    now: datetime | None = None,
) -> None:
    """Validate an approval artifact against a specific contract.

    Checks:
    1. Hash binding — approval.contract_sha256 must match contract_sha256
    2. Temporal ordering — expires_at must be strictly after approved_at
    3. Expiry — approval must not be expired at validation time

    Raises ApprovalError on any violation.

    The ``now`` parameter exists for deterministic testing. Production
    callers should omit it (defaults to UTC now).
    """
    aid = approval.get("approval_id")

    # 1. Hash binding
    if approval["contract_sha256"] != contract_sha256:
        raise ApprovalError(
            aid,
            f"contract_sha256 mismatch: approval covers "
            f"{approval['contract_sha256']!r}, contract is {contract_sha256!r}",
        )

    # 2. Temporal ordering
    approved_at = _parse_dt(approval["approved_at"], "approved_at", aid)
    expires_at = _parse_dt(approval["expires_at"], "expires_at", aid)

    if expires_at <= approved_at:
        raise ApprovalError(
            aid,
            f"expires_at ({approval['expires_at']}) must be strictly after approved_at ({approval['approved_at']})",
        )

    # 3. Expiry
    if now is None:
        now = datetime.now(UTC)

    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    if now >= expires_at:
        raise ApprovalError(
            aid,
            f"approval expired at {approval['expires_at']}",
        )
