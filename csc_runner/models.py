from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


NetworkMode = Literal["deny", "allowlisted", "full"]
EffectType = Literal[
    "observe",
    "transform_local",
    "fetch_external",
    "mutate_repo",
    "deploy",
    "touch_secrets",
]
RiskClass = Literal["low", "medium", "high", "critical"]
ApprovalMode = Literal["policy_only", "human_required", "dual_control_required"]


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Actor(StrictBaseModel):
    agent_id: str
    session_id: str
    initiating_user: str
    delegation_scope: str


class ExecSpec(StrictBaseModel):
    argv: list[str] = Field(min_length=1)


class PipelineSegment(StrictBaseModel):
    argv: list[str] = Field(min_length=1)


class PipelineSpec(StrictBaseModel):
    segments: list[PipelineSegment] = Field(min_length=2)


class Command(StrictBaseModel):
    id: str
    exec: ExecSpec | None = None
    pipeline: PipelineSpec | None = None
    cwd: str
    read_paths: list[str]
    write_paths: list[str]
    network: NetworkMode
    env_allow: list[str]
    secret_refs: list[str]
    timeout_sec: int = Field(ge=1, le=86400)
    proposed_effect_type: EffectType

    @model_validator(mode="after")
    def validate_shape(self) -> "Command":
        if (self.exec is None) == (self.pipeline is None):
            raise ValueError("exactly one of exec or pipeline must be set")
        return self


class CommandContract(StrictBaseModel):
    version: Literal["csc.v0.1"]
    contract_id: str
    intent: str
    actor: Actor
    commands: list[Command] = Field(min_length=1, max_length=20)
    risk_class: RiskClass
    approval_mode: ApprovalMode
    expected_outputs: list[str] = Field(default_factory=list)
    justification: str
