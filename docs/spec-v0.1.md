# CSC v0.1 Specification

> **Status: FROZEN**
> This specification and its companion schemas are locked as of v0.1.0 (2026-03-20).
> Normative changes require an RFC accepted through the process defined in `rfcs/RFC_PROCESS.md`.
> The normative source of truth for CSC v0.1 is: this spec, the three protocol JSON Schemas (`csc.contract.v0.1.schema.json`, `csc.policy-decision.v0.1.schema.json`, `csc.execution-receipt.v0.1.schema.json`), and the conformance test suite.
> Everything else — including the reference runner — is implementation behavior unless explicitly promoted into the spec via RFC.

## 1. Overview

CSC (Command Scope Contract) is a lightweight protocol for bounded shell and CLI execution by AI agents.

CSC is designed as a **standalone execution protocol** with clear conceptual lineage from PIC:

- **PIC** provides the higher-level contract, governance, and provenance thesis.
- **CSC** applies that pattern specifically to shell and CLI execution.

CSC defines three core object types:

1. CommandContract
2. PolicyDecision
3. ExecutionReceipt

The protocol is designed to reduce ambient authority by forcing every execution request to explicitly declare scope and intended effects before execution.

## 2. Terminology

- **Agent**: an automated system proposing one or more commands.
- **Contract**: a structured request describing intended execution.
- **Policy Engine**: trusted component that validates syntax, classifies effects, and decides whether a contract is allowed.
- **Executor**: trusted component that executes an allowed contract in a constrained environment.
- **Receipt**: immutable record of execution outcome.
- **Pipeline**: a structured ordered sequence of commands where stdout from each segment is connected to stdin of the next without invoking a shell metainterpreter.

## 3. Protocol flow

1. Agent emits a `CommandContract`.
2. Policy engine validates syntax and evaluates declared scope.
3. Policy engine independently classifies or overrides effect types using trusted rules.
4. Policy engine emits `PolicyDecision`.
5. Executor runs allowed commands under bounded constraints.
6. Executor emits `ExecutionReceipt` bound to the executed contract.

## 4. Trust boundaries

CSC assumes that the following components are trusted relative to the agent:

- policy engine
- executor
- sandbox or runtime boundary
- secret injection mechanism
- receipt writer

The agent is **not** trusted to self-certify the meaning or safety of its own actions.

## 5. CommandContract

### 5.1 Required top-level fields

Required fields:

- `version`
- `contract_id`
- `intent`
- `actor`
- `commands`
- `risk_class`
- `approval_mode`
- `justification`

Recommended fields:

- `expected_outputs`

A contract is a bounded execution batch, not a general workflow graph.
Implementations SHOULD impose a maximum command count.
CSC v0.1 RECOMMENDS a limit of **20 commands per contract**.

### 5.2 Actor object

Required fields:

- `agent_id`
- `session_id`
- `initiating_user`
- `delegation_scope`

### 5.3 Command object

A command entry MUST contain exactly one of:
- `exec`
- `pipeline`

Each command object also includes shared command-level fields:
- `id`
- `cwd`
- `read_paths`
- `write_paths`
- `network`
- `env_allow`
- `secret_refs`
- `timeout_sec`
- `proposed_effect_type`

#### 5.3.1 `exec`

An `exec` command represents a single executable invocation.

The `exec` object MUST contain:
- `argv`

#### 5.3.2 `pipeline`

A `pipeline` command represents a structured sequence of executable invocations where stdout from one segment becomes stdin of the next.

The `pipeline` object MUST contain:
- `segments`

Each segment MUST contain:
- `argv`

A pipeline is treated as **one scoped operation**. Scope is declared once at the pipeline level and applies to the whole pipeline.

If different pipeline segments require materially different permission scopes, they SHOULD be expressed as separate commands or separate contracts with explicit artifact handoff.

### 5.4 Constraints

#### argv
- MUST be an array of strings.
- MUST NOT be a raw shell string.
- Implementations SHOULD reject shell metainterpreters by default.

#### pipeline segments
- MUST each use argv arrays.
- MUST NOT invoke shell metainterpreters by default.
- MUST inherit scope from the enclosing pipeline.

#### cwd
- MUST be an absolute path.

#### read_paths / write_paths
- MUST be arrays of path globs or exact paths.
- Omitted access MUST be treated as denied.

#### network

Allowed values:

- `deny`
- `allowlisted`
- `full`

Implementations SHOULD treat `full` as high risk.

#### proposed_effect_type

Initial core values:

- `observe`
- `transform_local`
- `fetch_external`
- `mutate_repo`
- `deploy`
- `touch_secrets`

Domain-specific effect types such as payments or healthcare actions SHOULD be defined by extension profiles or policy packs rather than the core v0.1 spec.

### 5.5 Risk classes

Allowed values:

- `low`
- `medium`
- `high`
- `critical`

### 5.6 Approval modes

Allowed values:

- `policy_only`
- `human_required`
- `dual_control_required`

## 6. Policy classification and override

The agent MAY propose an effect type.

The policy engine MUST independently classify the actual effect type using trusted rules derived from facts such as:
- executable name
- argv shape
- destination host or service
- touched paths
- secret class requested
- execution profile
- organizational policy context

The policy engine MAY accept the proposed effect type, narrow it, or override it entirely.

Effect typing MUST NOT rely solely on agent self-declaration.

- Core contracts use core `proposed_effect_type` values only.
- Policy engines MAY classify commands into richer internal or extension-defined effect types for decisioning and reporting.
- Those extension-classified values MAY appear in `PolicyDecision.classified_effects` even when they are not valid core agent-proposed values.

## 7. Default deny behavior

Implementations MUST deny any capability that is not explicitly declared and allowed by policy.

## 8. Command execution semantics

Commands execute **sequentially** in the order listed in the contract.

- If a command succeeds, execution proceeds to the next command.
- If a command fails, remaining commands MUST NOT execute.
- The receipt MUST reflect partial completion when some commands ran before failure.

CSC v0.1 does not define dynamic templating of later commands from earlier stdout.

If an agent must inspect prior output and choose a next step, that SHOULD be expressed as a new contract rather than implicit intra-contract planning.

## 9. PolicyDecision

Required fields:

- `contract_id`
- `decision`
- `policy_profile`
- `reasons`
- `reason_codes`
- `expires_at`

Recommended fields:

- `contract_sha256`
- `classified_effects`

Allowed `decision` values:

- `allow`
- `deny`
- `needs_approval`

### 9.1 Reason codes

`reason_codes` is an array of machine-readable strings drawn from the reason-code registry (see `docs/reason-codes.md`).

Reason codes are **stable API surface**: new codes may be added in future versions; existing codes MUST NOT be renamed or removed without a spec version bump.

`reasons` (free text) is retained for human readability but is non-normative. Automation, dashboards, and audit systems SHOULD rely on `reason_codes`, not `reasons`.

## 10. ExecutionReceipt

Required fields:

- `receipt_version`
- `contract_id`
- `execution_id`
- `contract_sha256`
- `status`
- `started_at`
- `ended_at`
- `policy_profile`

Recommended fields:

- `exit_code`
- `stdout_hash`
- `stderr_hash`
- `artifacts`
- `effect_summary`
- `completed_command_ids`
- `failed_command_id`
- `error`
- `policy_schema_version`
- `policy_sha256`
- `runner_version`
- `execution_mode`
- `sandbox_profile_id`
- `signing_key_id`

Allowed `status` values:

- `success`
- `failed`
- `blocked`
- `expired`

Receipts MUST bind to the exact contract body that was evaluated and executed.

### 10.1 Receipt versioning

`receipt_version` is a required field that identifies the receipt schema version used to produce this receipt. Parsers MUST use this field to select the correct schema for validation and interpretation.

## 11. Justification handling

`justification` exists for human audit and display.

Policy engines and executors MUST treat `justification` as untrusted agent-supplied text.

Implementations MUST NOT make authorization or classification decisions based on `justification` text.

## 12. Secret handling

`secret_refs` identify secrets requested by the contract.

CSC v0.1 requires the following baseline semantics:

- secrets MUST NOT appear directly in the contract body
- secrets MUST NOT be passed in argv
- secrets SHOULD be injected by the executor only after policy approval
- injected secrets SHOULD be exposed through tightly scoped environment variables or mounted files
- executors SHOULD avoid inheriting ambient host secrets

## 13. Tool-output trust model

Stdout and stderr returned by executed commands are untrusted tool output.

If these outputs are returned to an agent for subsequent reasoning, they MUST be treated as untrusted input and MUST NOT be given implicit authority.

## 14. Security requirements

Implementations SHOULD:

- run commands as a low-privilege user
- isolate workspaces
- sanitize inherited environment variables
- use short-lived credentials only
- log policy decisions and receipts
- disable shell metainterpreters by default
- constrain network access externally, not only logically
- canonicalize paths before policy evaluation
- bind approvals to contract hash when approval layers exist

## 15. Non-goals

CSC does not itself provide:

- sandboxing
- cryptographic signing
- identity federation
- secret issuance
- semantic verification of user intent
- a general workflow language

## 16. Future extensions

Possible extensions include:

- signed contracts
- signed receipts
- extension effect types
- approval attestations
- short-lived secret claims
- reproducibility bundles
- richer pipeline artifact controls

## 17. Versioning policy

### 17.1 Spec and schema versioning

The `version` field in a CommandContract identifies the spec version it was authored against. Runners MUST support an explicit set of versions and MUST reject contracts with unrecognized versions with a clear version error. There is no implicit negotiation in v0.x.

### 17.2 Receipt version stability

Receipts are immutable audit artifacts. A receipt emitted under any version MUST remain valid and parseable by all future runner versions. No future spec or schema change may retroactively invalidate an existing receipt. Receipt schema changes that would break existing receipts MUST be introduced as a new receipt version, never as a modification of an existing version.

### 17.3 Changelog discipline

All normative changes to this spec, the schemas, or the conformance suite MUST go through the RFC process defined in `rfcs/RFC_PROCESS.md` and MUST be recorded in `CHANGELOG.md`.
