---
rfc: "0002"
title: PIC Alignment and Mapping
status: draft
authors:
  - Fabio
created: 2026-03-20
---

# RFC-0002: PIC Alignment and Mapping

## Summary

This RFC defines the relationship between CSC (Command Scope Contract) and PIC (Provenance & Intent Contracts, v0.7.1). CSC is normatively independent of PIC. CSC is structurally aligned with PIC. This document specifies which PIC implementation surfaces CSC may import, which it aligns with conceptually, and which remain CSC-native.

## Motivation

CSC and PIC share the same author and the same core thesis: AI agents should not have ambient authority. Both enforce declared intent, bounded action, and evidence of outcome. Without an explicit alignment document, the relationship between CSC and PIC will become folklore — inconsistent, assumed differently by different consumers, and impossible to verify.

## Background

### PIC status (v0.7.1)

PIC is a local-first action-gating protocol with a more mature implementation and ecosystem than CSC as of v0.7.1.

**Shipped:**
- Core verifier + JSON Schema (PIC/1.0)
- Evidence verification: SHA-256 hash artifacts + Ed25519 signatures
- Trusted keyring management with expiry and revocation (`KeyResolver` protocol)
- Impact taxonomy: 7 classes (read, write, external, compute, money, privacy, irreversible)
- Causal taint semantics: untrusted data cannot trigger high-impact actions without trusted evidence
- Policy system: impact-by-tool mapping
- Shared verification pipeline with DoS hardening
- Python SDK with CLI
- 4 integrations: LangGraph, MCP, OpenClaw, Cordum
- 9 structured error codes
- Defensive-publication RFC (RFC-0001)

**Planned (Phase 1+):**
- PIC Canonical JSON v1 (highest priority — blocks cross-language interop)
- Conformance suite with cross-implementation vectors
- Normative semantics document
- TypeScript local verifier (second independent implementation)

### CSC status (v0.1.0)

CSC is a lightweight protocol for bounded shell and CLI execution by AI agents.

**Shipped:**
- Spec, three protocol JSON Schemas (contract, policy decision, execution receipt)
- Policy schema with schema validation on load and duplicate-key rejection
- Reference Python runner with CLI
- Reason-code registry (stable API surface)
- Canonicalization spec for deterministic hashing
- Security targets and claims matrix

**Planned (Stage 1b–3):**
- Hardened executor with real path resolution
- Process isolation and sandbox mode
- Approval artifacts (hash-bound)
- Receipt signing
- Network enforcement

## Architectural relationship

CSC is a **standalone execution protocol** with clear conceptual lineage from PIC.

- **PIC** provides the higher-level contract, governance, and provenance thesis for AI agent actions.
- **CSC** applies that pattern specifically to shell and CLI execution, adding execution-boundary enforcement, pipeline semantics, and execution receipts.

Shell execution is a specialized action class within PIC's broader provenance/governance thesis. CSC is the execution-boundary specialization.

Long-term, the ecosystem architecture is:
- PIC core (action-level provenance gating)
- CSC profile (shell/CLI execution boundary)
- Future profiles (API calls, database operations, deployment actions)

## Normative independence

CSC does **not** depend on PIC at the protocol level. A CSC implementation does not need to import, reference, or be aware of PIC to be conformant.

This is intentional:
- CSC must be adoptable by teams that have no PIC deployment
- CSC's shell execution semantics are domain-specific and not generalizable into PIC's action model without loss
- CSC's spec and schemas are self-contained

## Structural alignment

Despite normative independence, CSC and PIC are structurally aligned:

### Concept mapping

| CSC concept | PIC concept | Notes |
|---|---|---|
| `CommandContract` | PIC action proposal | CSC adds: shell-specific fields (argv, cwd, paths, pipeline), execution batch semantics |
| `CommandContract.intent` | PIC proposal intent field | Same purpose: plain-text declared intent |
| `CommandContract.risk_class` | No direct PIC equivalent | CSC `risk_class` is an ordinal risk label (`low`/`medium`/`high`/`critical`), while PIC impact is a categorical action class. They inform policy differently and should not be treated as direct equivalents. |
| `proposed_effect_type` | PIC impact (classified) | CSC's 6 core effect types map loosely to PIC's 7 impact classes; see effect mapping below |
| `PolicyDecision` | Verifier result + policy gating | CSC adds: reason codes, classified effects, expiry |
| `ExecutionReceipt` | No PIC equivalent yet | CSC may provide a useful model for execution-evidence artifacts in the broader PIC ecosystem |
| `contract_sha256` | PIC SHA-256 evidence model | Same algorithm, same purpose: bind decisions to exact input |
| `approval_mode` | PIC trusted bridge pattern | CSC's `human_required` maps to PIC's requirement for trusted provenance on high-impact actions |
| Policy profiles | PIC policy (impact-by-tool mapping) | Different schemas, same purpose: operator-configured gating rules |

### Effect type mapping

| CSC `proposed_effect_type` | Closest PIC impact class | Alignment notes |
|---|---|---|
| `observe` | `read` | Direct mapping |
| `transform_local` | `write` | Direct mapping |
| `fetch_external` | `external` | Direct mapping |
| `mutate_repo` | `write` | CSC distinguishes repo mutation from general write; PIC does not |
| `deploy` | `irreversible` | Deployment is typically irreversible; mapping is approximate |
| `touch_secrets` | `privacy` | Secrets access maps to privacy impact |

These mappings are informational, not normative. CSC effect types and PIC impact classes serve different evaluation contexts and should not be mechanically translated.

## Import boundary

This section defines what CSC may import from PIC at the implementation level.

### May import directly

- **Evidence signing and verification**: SHA-256 hash verification and Ed25519 signature verification. CSC receipt signing should use the same cryptographic primitives rather than reimplementing them.
- **Keyring and key resolver**: Trusted keyring management, key resolver protocol, key lifecycle (expiry, revocation, key status). CSC's receipt signing trust roots should use the same model.

These imports are optional. A CSC implementation that does not sign receipts does not need PIC as a dependency.

### May align conceptually but not import

- **Impact taxonomy**: CSC's effect types are domain-specific to shell execution. They should not import PIC's 7-class taxonomy directly, but the classification philosophy (trusted rules, not agent self-declaration) is shared.
- **Causal taint semantics**: PIC's formal taint model (untrusted data cannot trigger high-impact actions without trusted bridge) informs CSC's approval model, but CSC does not implement taint tracking.
- **DoS hardening patterns**: PIC's size/time/count budgets inform CSC's resource exhaustion controls, but CSC defines its own limits.

### Must remain CSC-native

- **Shell execution schema**: argv, cwd, read_paths, write_paths, pipeline segments, env_allow, secret_refs, timeout_sec. These are CSC domain concepts with no PIC equivalent.
- **Pipeline semantics**: Structured multi-segment execution with stdin/stdout chaining. PIC actions are single tool calls.
- **Runtime enforcement**: Executor, sandbox, real-path resolution, filesystem boundary enforcement. PIC is a pre-execution gate; CSC also enforces during execution.
- **Receipt semantics**: Structure, fields, versioning, and stability guarantees.
- **Reason codes**: CSC's machine-readable denial/approval codes are specific to shell policy evaluation.

## Canonicalization coordination

CSC's canonicalization spec (`docs/canonicalization.md`) and PIC's planned Canonical JSON v1 share the same design goals: deterministic, reproducible, cross-language hashing of protocol artifacts. Both use SHA-256 and lexicographic key ordering.

Until PIC Canonical JSON v1 ships, CSC's canonicalization rules are self-contained and authoritative for CSC artifacts. Future alignment may reduce divergence between the two specs.

## Decision gate

Before CSC imports any PIC module at runtime:

1. The import must be optional (CSC works without PIC installed)
2. The imported PIC surface must be wrapped behind an optional adapter boundary, pinned to a tested version range, and covered by CSC tests with and without PIC installed
3. The import must be documented in `docs/pic-mapping.md`
4. The CSC test suite must pass with and without PIC installed

## Future work

- CSC as a formal PIC execution-boundary profile (post PIC normative spec)
- Shared conformance vectors for evidence verification
- Cross-protocol evidence chains
- Joint canonicalization alignment if PIC Canonical JSON v1 converges closely enough

## References

- PIC Standard repository
- PIC RFC-0001
- CSC Spec v0.1 (`docs/spec-v0.1.md`)
- CSC Canonicalization (`docs/canonicalization.md`)
- CSC Versioning (`docs/versioning.md`)
