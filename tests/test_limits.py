"""Tests for csc_runner.limits — resource exhaustion budget checks."""

from __future__ import annotations

from csc_runner.limits import (
    MAX_ARGV_ELEMENT_BYTES,
    MAX_ARGV_LENGTH,
    MAX_JUSTIFICATION_LENGTH,
    MAX_PIPELINE_SEGMENTS,
    MAX_RECEIPT_ERROR_LENGTH,
    truncate_error,
    validate_contract_limits,
)
from csc_runner.models import (
    Actor,
    Command,
    CommandContract,
    ExecSpec,
    PipelineSegment,
    PipelineSpec,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTOR = Actor(
    agent_id="a-1",
    session_id="s-1",
    initiating_user="u-1",
    delegation_scope="test",
)


def _make_exec_command(cmd_id: str = "cmd_1", argv: list[str] | None = None) -> Command:
    return Command(
        id=cmd_id,
        exec=ExecSpec(argv=argv or ["echo", "hi"]),
        cwd="/workspace",
        read_paths=["/workspace/**"],
        write_paths=[],
        network="deny",
        env_allow=[],
        secret_refs=[],
        timeout_sec=10,
        proposed_effect_type="observe",
    )


def _make_pipeline_command(cmd_id: str = "cmd_1", n_segments: int = 2) -> Command:
    segments = [PipelineSegment(argv=["seg", str(i)]) for i in range(n_segments)]
    return Command(
        id=cmd_id,
        pipeline=PipelineSpec(segments=segments),
        cwd="/workspace",
        read_paths=["/workspace/**"],
        write_paths=[],
        network="deny",
        env_allow=[],
        secret_refs=[],
        timeout_sec=10,
        proposed_effect_type="observe",
    )


def _make_contract(
    commands: list[Command] | None = None,
    justification: str = "test",
) -> CommandContract:
    return CommandContract(
        version="csc.v0.1",
        contract_id="limits-test-001",
        intent="test",
        actor=_ACTOR,
        commands=commands or [_make_exec_command()],
        risk_class="low",
        approval_mode="policy_only",
        justification=justification,
    )


# ---------------------------------------------------------------------------
# validate_contract_limits
# ---------------------------------------------------------------------------


class TestValidateContractLimits:
    def test_valid_contract_passes(self):
        assert validate_contract_limits(_make_contract()) == []

    def test_too_many_commands(self):
        contract = CommandContract.model_construct(
            version="csc.v0.1",
            contract_id="limits-test-001",
            intent="test",
            actor=_ACTOR,
            commands=[_make_exec_command(cmd_id=f"cmd_{i}") for i in range(21)],
            risk_class="low",
            approval_mode="policy_only",
            justification="test",
        )
        violations = validate_contract_limits(contract)
        assert len(violations) == 1
        assert "commands" in violations[0]

    def test_command_count_at_limit_passes(self):
        commands = [_make_exec_command(cmd_id=f"cmd_{i}") for i in range(20)]
        contract = _make_contract(commands=commands)
        assert validate_contract_limits(contract) == []

    def test_pipeline_too_deep(self):
        cmd = _make_pipeline_command(n_segments=MAX_PIPELINE_SEGMENTS + 1)
        contract = _make_contract(commands=[cmd])
        violations = validate_contract_limits(contract)
        assert len(violations) == 1
        assert "pipeline" in violations[0]
        assert str(MAX_PIPELINE_SEGMENTS) in violations[0]

    def test_pipeline_at_limit_passes(self):
        cmd = _make_pipeline_command(n_segments=MAX_PIPELINE_SEGMENTS)
        contract = _make_contract(commands=[cmd])
        assert validate_contract_limits(contract) == []

    def test_argv_too_long(self):
        argv = ["echo"] + ["x"] * MAX_ARGV_LENGTH
        cmd = _make_exec_command(argv=argv)
        contract = _make_contract(commands=[cmd])
        violations = validate_contract_limits(contract)
        assert len(violations) == 1
        assert "argv" in violations[0]
        assert str(MAX_ARGV_LENGTH) in violations[0]

    def test_argv_at_limit_passes(self):
        argv = ["echo"] + ["x"] * (MAX_ARGV_LENGTH - 1)
        cmd = _make_exec_command(argv=argv)
        contract = _make_contract(commands=[cmd])
        assert validate_contract_limits(contract) == []

    def test_argv_element_too_large(self):
        big_elem = "x" * (MAX_ARGV_ELEMENT_BYTES + 1)
        cmd = _make_exec_command(argv=["echo", big_elem])
        contract = _make_contract(commands=[cmd])
        violations = validate_contract_limits(contract)
        assert len(violations) == 1
        assert "argv[1]" in violations[0]

    def test_argv_element_at_limit_passes(self):
        elem = "x" * MAX_ARGV_ELEMENT_BYTES
        cmd = _make_exec_command(argv=["echo", elem])
        contract = _make_contract(commands=[cmd])
        assert validate_contract_limits(contract) == []

    def test_argv_element_multibyte_utf8(self):
        # Each CJK character is 3 bytes in UTF-8
        n_chars = (MAX_ARGV_ELEMENT_BYTES // 3) + 1
        big_elem = "\u4e00" * n_chars
        assert len(big_elem.encode("utf-8")) > MAX_ARGV_ELEMENT_BYTES
        cmd = _make_exec_command(argv=["echo", big_elem])
        contract = _make_contract(commands=[cmd])
        violations = validate_contract_limits(contract)
        assert len(violations) == 1
        assert "bytes" in violations[0]

    def test_argv_element_multibyte_at_limit_passes(self):
        # Each CJK character is 3 bytes — stay within limit
        n_chars = MAX_ARGV_ELEMENT_BYTES // 3
        elem = "\u4e00" * n_chars
        assert len(elem.encode("utf-8")) <= MAX_ARGV_ELEMENT_BYTES
        cmd = _make_exec_command(argv=["echo", elem])
        contract = _make_contract(commands=[cmd])
        assert validate_contract_limits(contract) == []

    def test_justification_too_long(self):
        contract = _make_contract(justification="x" * (MAX_JUSTIFICATION_LENGTH + 1))
        violations = validate_contract_limits(contract)
        assert len(violations) == 1
        assert "justification" in violations[0]

    def test_justification_at_limit_passes(self):
        contract = _make_contract(justification="x" * MAX_JUSTIFICATION_LENGTH)
        assert validate_contract_limits(contract) == []

    def test_multiple_violations(self):
        big_elem = "x" * (MAX_ARGV_ELEMENT_BYTES + 1)
        cmd = _make_pipeline_command(n_segments=MAX_PIPELINE_SEGMENTS + 1)
        cmd2 = _make_exec_command(cmd_id="cmd_2", argv=["echo", big_elem])
        contract = _make_contract(
            commands=[cmd, cmd2],
            justification="x" * (MAX_JUSTIFICATION_LENGTH + 1),
        )
        violations = validate_contract_limits(contract)
        assert len(violations) >= 3


# ---------------------------------------------------------------------------
# truncate_error
# ---------------------------------------------------------------------------


class TestTruncateError:
    def test_short_text_unchanged(self):
        assert truncate_error("hello", max_len=100) == "hello"

    def test_exact_length_unchanged(self):
        text = "x" * 100
        assert truncate_error(text, max_len=100) == text

    def test_truncated_with_marker(self):
        text = "x" * 200
        result = truncate_error(text, max_len=50)
        assert len(result) == 50
        assert result.endswith("... [truncated]")

    def test_very_small_max_len(self):
        text = "x" * 200
        result = truncate_error(text, max_len=5)
        assert len(result) == 5
        assert result == "xxxxx"

    def test_max_len_equals_suffix_length(self):
        text = "x" * 200
        suffix = "... [truncated]"
        result = truncate_error(text, max_len=len(suffix))
        assert len(result) == len(suffix)

    def test_default_max_len(self):
        text = "x" * 5000
        result = truncate_error(text)
        assert len(result) == MAX_RECEIPT_ERROR_LENGTH
        assert result.endswith("... [truncated]")
