"""Tests for csc_runner.approval — approval artifact validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from csc_runner.approval import ApprovalError, load_approval, validate_approval

_VALID_SHA256 = "a" * 64
_OTHER_SHA256 = "b" * 64

_NOW = datetime(2026, 3, 23, 12, 0, 0, tzinfo=UTC)


def _make_approval(**overrides) -> dict:
    defaults = {
        "approval_version": "csc.approval.v0.1",
        "approval_id": "approval-001",
        "contract_sha256": _VALID_SHA256,
        "approver": {
            "identity": "fabio@example.com",
            "method": "manual",
        },
        "approved_at": "2026-03-23T11:00:00Z",
        "expires_at": "2026-03-23T13:00:00Z",
        "scope": "single_execution",
    }
    defaults.update(overrides)
    return defaults


def _write_approval(tmp_path, approval: dict) -> str:
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(approval), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# load_approval — file I/O and schema validation
# ---------------------------------------------------------------------------


class TestLoadApproval:
    def test_valid_minimal(self, tmp_path):
        approval = _make_approval()
        path = _write_approval(tmp_path, approval)
        result = load_approval(path)
        assert result["approval_id"] == "approval-001"
        assert result["contract_sha256"] == _VALID_SHA256

    def test_valid_with_optional_fields(self, tmp_path):
        approval = _make_approval(
            ticket_id="JIRA-1234",
            reason="Emergency hotfix approved by on-call lead",
        )
        path = _write_approval(tmp_path, approval)
        result = load_approval(path)
        assert result["ticket_id"] == "JIRA-1234"
        assert result["reason"].startswith("Emergency")

    def test_missing_file_raises(self):
        with pytest.raises(ApprovalError, match="cannot load"):
            load_approval("/nonexistent/path/approval.json")

    def test_invalid_json_raises(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ApprovalError, match="cannot load"):
            load_approval(str(path))

    def test_missing_required_field_raises(self, tmp_path):
        approval = _make_approval()
        del approval["contract_sha256"]
        path = _write_approval(tmp_path, approval)
        with pytest.raises(ApprovalError, match="schema validation failed"):
            load_approval(str(path))

    def test_wrong_version_raises(self, tmp_path):
        approval = _make_approval(approval_version="csc.approval.v999")
        path = _write_approval(tmp_path, approval)
        with pytest.raises(ApprovalError, match="schema validation failed"):
            load_approval(str(path))

    def test_bad_sha256_format_raises(self, tmp_path):
        approval = _make_approval(contract_sha256="not-a-hex-hash")
        path = _write_approval(tmp_path, approval)
        with pytest.raises(ApprovalError, match="schema validation failed"):
            load_approval(str(path))

    def test_unknown_method_raises(self, tmp_path):
        approval = _make_approval()
        approval["approver"]["method"] = "telepathy"
        path = _write_approval(tmp_path, approval)
        with pytest.raises(ApprovalError, match="schema validation failed"):
            load_approval(str(path))

    def test_unknown_scope_raises(self, tmp_path):
        approval = _make_approval(scope="forever")
        path = _write_approval(tmp_path, approval)
        with pytest.raises(ApprovalError, match="schema validation failed"):
            load_approval(str(path))

    def test_additional_properties_rejected(self, tmp_path):
        approval = _make_approval(extra_field="should not be here")
        path = _write_approval(tmp_path, approval)
        with pytest.raises(ApprovalError, match="schema validation failed"):
            load_approval(str(path))


# ---------------------------------------------------------------------------
# validate_approval — semantic checks
# ---------------------------------------------------------------------------


class TestValidateApproval:
    def test_valid_approval_passes(self):
        approval = _make_approval()
        validate_approval(approval, _VALID_SHA256, now=_NOW)

    def test_hash_mismatch_raises(self):
        approval = _make_approval()
        with pytest.raises(ApprovalError, match="contract_sha256 mismatch"):
            validate_approval(approval, _OTHER_SHA256, now=_NOW)

    def test_expired_approval_raises(self):
        approval = _make_approval()
        future = datetime(2026, 3, 24, 0, 0, 0, tzinfo=UTC)
        with pytest.raises(ApprovalError, match="expired"):
            validate_approval(approval, _VALID_SHA256, now=future)

    def test_expires_at_equals_approved_at_raises(self):
        approval = _make_approval(
            approved_at="2026-03-23T12:00:00Z",
            expires_at="2026-03-23T12:00:00Z",
        )
        with pytest.raises(ApprovalError, match="strictly after"):
            validate_approval(approval, _VALID_SHA256, now=_NOW)

    def test_expires_at_before_approved_at_raises(self):
        approval = _make_approval(
            approved_at="2026-03-23T12:00:00Z",
            expires_at="2026-03-23T11:00:00Z",
        )
        with pytest.raises(ApprovalError, match="strictly after"):
            validate_approval(approval, _VALID_SHA256, now=_NOW)

    def test_exactly_at_expiry_raises(self):
        approval = _make_approval(
            approved_at="2026-03-23T11:00:00Z",
            expires_at="2026-03-23T12:00:00Z",
        )
        at_expiry = datetime(2026, 3, 23, 12, 0, 0, tzinfo=UTC)
        with pytest.raises(ApprovalError, match="expired"):
            validate_approval(approval, _VALID_SHA256, now=at_expiry)

    def test_one_second_before_expiry_passes(self):
        approval = _make_approval(
            approved_at="2026-03-23T11:00:00Z",
            expires_at="2026-03-23T12:00:00Z",
        )
        just_before = datetime(2026, 3, 23, 11, 59, 59, tzinfo=UTC)
        validate_approval(approval, _VALID_SHA256, now=just_before)

    def test_time_window_scope_passes(self):
        approval = _make_approval(scope="time_window")
        validate_approval(approval, _VALID_SHA256, now=_NOW)

    def test_malformed_timestamp_raises(self):
        approval = _make_approval(approved_at="garbage")
        with pytest.raises(ApprovalError, match="not a valid ISO 8601"):
            validate_approval(approval, _VALID_SHA256, now=_NOW)

    def test_none_timestamp_raises(self):
        approval = _make_approval(approved_at=None)
        with pytest.raises(ApprovalError, match="not a valid ISO 8601"):
            validate_approval(approval, _VALID_SHA256, now=_NOW)

    def test_approval_id_in_error(self):
        approval = _make_approval(approval_id="my-special-id")
        try:
            validate_approval(approval, _OTHER_SHA256, now=_NOW)
            pytest.fail("should have raised")
        except ApprovalError as exc:
            assert exc.approval_id == "my-special-id"
            assert "my-special-id" in str(exc)

    def test_naive_now_treated_as_utc(self):
        approval = _make_approval()
        naive_now = datetime(2026, 3, 23, 12, 0, 0)  # no tzinfo
        validate_approval(approval, _VALID_SHA256, now=naive_now)
