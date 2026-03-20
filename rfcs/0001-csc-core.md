# RFC-0001: CSC Core Protocol

- **Status**: draft
- **Authors**:
  - Fabio Marcello Salvadori
- **Created**: 2026-03-19

## Summary

This RFC defines the core CSC (Command Scope Contract) protocol: a lightweight protocol for bounded shell and CLI execution by AI agents. It specifies the three core object types (`CommandContract`, `PolicyDecision`, `ExecutionReceipt`), the protocol flow, trust boundaries, and execution semantics.

## Motivation

AI agents increasingly need to execute shell commands. Raw shell access carries ambient authority that is difficult to audit, scope, or govern. CSC removes that ambient authority by requiring every execution request to declare intent, scope, and expected effects before anything runs.

## Design

The full protocol design is specified in [docs/spec-v0.1.md](../docs/spec-v0.1.md). This RFC serves as the formal proposal record for adopting that specification as the CSC v0.1 baseline.

Key design decisions covered by this RFC:

- argv arrays only, no raw shell strings
- default deny on omitted capabilities
- sequential command execution with fail-fast
- policy engine independently classifies effects rather than trusting agent self-declaration
- receipts bind to the exact contract body via SHA-256
- justification is untrusted text and is never used for authorization

## Security considerations

CSC is intended to reduce ambient authority, not eliminate the need for runtime hardening. The protocol defines declared constraints and provenance expectations, but enforcement still depends on the executor, runtime boundary, and surrounding policy controls.

## Compatibility

CSC is designed to be complementary to MCP and compatible with PIC-style provenance and governance patterns. It does not attempt to replace workflow engines, IAM systems, or sandboxing layers.

## Alternatives considered

- **Raw shell with post-hoc logging.** Insufficient: no pre-execution policy gate.
- **Full workflow engine.** Over-scoped for the execution-boundary problem.
- **Extending MCP.** MCP solves tool access, not execution boundary. CSC is complementary.

## Open questions

- Glob matching discipline for path enforcement (prefix-based in v0.1, may need normalization hardening)
- Network enforcement beyond logical declaration (requires container/firewall integration in later versions)
- Signed contracts and receipts (deferred to v0.2)
