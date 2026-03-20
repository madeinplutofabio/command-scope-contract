# CSC Compatibility Matrix

## Purpose

This document records which runner versions support which protocol identifiers. It MUST be kept current with every release, as required by `docs/versioning.md`.

## Current matrix

| Runner version | Accepted contract protocol identifiers | Emitted receipt schema identifiers | Accepted policy schema identifiers |
|---|---|---|---|
| `0.1.0` | `csc.v0.1` | `csc.receipt.v0.1` | `csc.policy.v0.1` |

## Reading this matrix

- **Accepted contract protocol identifiers** — the set of `CommandContract.version` values the runner accepts.
- **Emitted receipt schema identifiers** — the `ExecutionReceipt.receipt_version` values the runner emits by default.
- **Accepted policy schema identifiers** — the set of `policy_schema_version` values the runner accepts when loading policy files.

A runner MUST reject any protocol identifier not listed in its supported set. There is no implicit negotiation.

Runners MAY parse older receipt schema identifiers even when they emit a newer one, in accordance with the receipt stability rules defined in `docs/versioning.md`.

## Update rules

- A new row MUST be added for every release that changes any supported protocol identifier.
- A new row SHOULD be added for every minor or major release even if protocol identifiers are unchanged, to confirm continued support.
- Removal of a previously supported identifier is a breaking change and MUST be documented in `CHANGELOG.md`.
