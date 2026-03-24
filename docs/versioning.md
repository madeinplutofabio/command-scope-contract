# CSC Versioning and Migration Policy

## Scope

This document defines the versioning rules for all CSC protocol artifacts: contracts, receipts, policy schemas, and the spec itself.

## Version namespaces

CSC uses multiple version namespaces that serve different purposes:

- **Project/spec release version** — for example, `0.1.0`, managed in releases and `CHANGELOG.md`
- **Contract protocol version** — for example, `csc.v0.1`, carried in `CommandContract.version`
- **Receipt schema version** — for example, `csc.receipt.v0.1`, carried in `ExecutionReceipt.receipt_version`
- **Policy schema version** — for example, `csc.policy.v0.1`, carried in `policy_schema_version`

These version namespaces are related but not identical. A patch release of the project/spec does not necessarily imply a change to the contract, receipt, or policy version identifiers.

## Contract versioning

### Contract protocol identifiers

The `version` field in a `CommandContract` is a protocol identifier such as `csc.v0.1`.

Patch releases of the project/spec (for example, `0.1.1`) do not by themselves change the contract protocol identifier. The contract protocol identifier changes only when the protocol surface for contracts changes in a way that requires a new contract version.

### Runner behavior

- A runner MUST support an explicit, enumerated set of contract protocol identifiers.
- A runner MUST reject a contract whose `version` is not in its supported set, with a clear error indicating the unsupported version and the versions the runner accepts.
- There is **no implicit negotiation** in v0.x.

## Receipt versioning

### Receipt schema identifiers

The `receipt_version` field in an `ExecutionReceipt` is a schema identifier such as `csc.receipt.v0.1`.

The receipt schema identifier changes only when the receipt schema changes in a way that affects validation or interpretation.

### Stability guarantee

Receipts are immutable audit artifacts. A receipt emitted under any version MUST remain valid and parseable by all future runner versions, tooling, and audit systems. This is a permanent guarantee.

### Migration rules

- No future spec or schema change may retroactively invalidate an existing receipt.
- Receipt schema changes that would break existing receipts MUST be introduced as a new receipt schema identifier, never as a modification of an existing version.
- Runners MAY emit receipts under newer schema identifiers, but MUST NOT refuse to parse receipts from older identifiers.
- Parsers MUST use `receipt_version` to select the correct schema for validation and interpretation.

## Policy schema versioning

### Policy schema identifiers

Policy files carry a `policy_schema_version` field with a schema identifier such as `csc.policy.v0.1`.

The policy schema identifier changes only when the policy schema changes in a way that affects validation or loading behavior.

### Runner behavior

- A runner MUST validate policy files against the declared `policy_schema_version`.
- A runner MUST reject a policy file whose `policy_schema_version` is not in its supported set.

### Policy provenance in receipts

Receipts SHOULD include `policy_sha256` and `policy_schema_version` so that auditors can determine exactly which policy artifact produced a given decision.

## Spec versioning

### Release version format

The project/spec release version uses semantic versioning: `MAJOR.MINOR.PATCH`.

- **MAJOR**: breaking changes to protocol semantics or required fields.
- **MINOR**: new optional fields, new recommended fields, new conformance requirements.
- **PATCH**: clarifications, typo fixes, non-normative editorial changes.

Protocol identifiers (`csc.v0.1`, `csc.receipt.v0.1`, `csc.policy.v0.1`) are not semver strings. They change only when the protocol surface they govern requires a new version.

### Freeze and change process

The spec and protocol identifiers are frozen at each minor version. All normative changes MUST go through the RFC process defined in `rfcs/RFC_PROCESS.md` and MUST be recorded in `CHANGELOG.md`.

## Compatibility matrix

The file `docs/compatibility-matrix.md` records which runner versions support which contract protocol identifiers, emit which receipt schema identifiers, and accept which policy schema identifiers. This matrix MUST be kept current with every release.

## Canonicalization coordination

CSC contract hashing follows the canonicalization rules defined in `docs/canonicalization.md`. The current reference runner implements those rules using deterministic JSON serialization. Changes to canonicalization rules require a spec version bump.
