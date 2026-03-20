# CSC–PIC Mapping

## Purpose

This document is the normative mapping artifact produced by RFC-0002. It records the concrete field-level and artifact-level correspondences between CSC and PIC, and documents the import boundary decisions for the CSC reference runner.

This document is maintained alongside the CSC spec. Changes require an RFC update or a new RFC.

## Protocol artifact mapping

| CSC artifact | PIC artifact | Relationship |
|---|---|---|
| `CommandContract` | PIC action proposal | CSC is shell-execution-specific; PIC is action-general. Not interchangeable. |
| `PolicyDecision` | PIC verifier result + policy gating | CSC adds reason codes, classified effects, and expiry. PIC adds causal taint evaluation. |
| `ExecutionReceipt` | No PIC equivalent (audit logs planned) | CSC-native. May inform future PIC execution-evidence design. |
| Policy profile (YAML) | `pic_policy.json` | Different schemas, same purpose: operator-configured gating rules. |
| Policy schema (`csc.policy.v0.1`) | No PIC equivalent | CSC validates policy files against a JSON Schema on load; PIC uses a simpler config format. |

## Field-level mapping

### Contract → Proposal

| CSC field | PIC field | Notes |
|---|---|---|
| `version` | `protocol` | CSC: `csc.v0.1`; PIC: `PIC/1.0`. Both are protocol identifiers, not semver. |
| `contract_id` | (no equivalent) | PIC proposals do not carry an explicit ID. |
| `intent` | `intent` | Same semantics: plain-text declared intent. |
| `actor` | `provenance` | Structural analogy, not field equivalence. CSC actor is a single object with agent_id, session_id, initiating_user, and delegation_scope. PIC provenance is an array of source objects, each with required id and trust level, and optional source metadata. Both identify who/what is behind the action, but the data models are different. |
| `risk_class` | (no direct equivalent) | CSC uses ordinal risk labels (low/medium/high/critical). PIC uses categorical impact classes. They serve different policy evaluation roles. |
| `proposed_effect_type` | `impact` | Closest conceptual match. CSC has 6 core types; PIC has 7 impact classes. See effect mapping below. |
| `approval_mode` | (implicit in PIC) | CSC makes approval requirements explicit. PIC expresses this through the trusted-bridge requirement on high-impact actions. |
| `justification` | (no equivalent) | CSC-specific. Untrusted agent-supplied text for human audit. |
| `commands` | `action` | CSC supports batched commands (up to 20) with per-command scope. PIC proposals contain a single action. |
| `commands[].exec.argv` | `action.args` | CSC uses structured argv arrays. PIC uses a tool name + args object. |
| `commands[].cwd` | (no equivalent) | CSC-native: working directory for shell execution. |
| `commands[].read_paths` | (no equivalent) | CSC-native: declared filesystem read scope. |
| `commands[].write_paths` | (no equivalent) | CSC-native: declared filesystem write scope. |
| `commands[].pipeline` | (no equivalent) | CSC-native: structured multi-segment stdin/stdout chaining. |
| `commands[].network` | (no equivalent) | CSC-native: declared network access mode. |
| `commands[].secret_refs` | (no equivalent) | CSC-native: declared secret references. |
| `expected_outputs` | (no equivalent) | CSC-native: declared expected output artifacts. |

### PIC-only fields with no CSC equivalent

| PIC field | CSC equivalent | Notes |
|---|---|---|
| `claims` | (no equivalent) | PIC claims are assertions backed by provenance references. CSC does not model claims; policy evaluation is rule-based, not claim-based. |
| `evidence` | (no equivalent) | PIC evidence is cryptographic proof (SHA-256 hashes, Ed25519 signatures) attached to proposals to upgrade provenance trust. CSC does not attach pre-execution evidence to contracts; receipt signing (planned) is post-execution. |

These are central to PIC's causal taint model. CSC intentionally does not cover this surface.

### Effect type → Impact class

| CSC `proposed_effect_type` | Closest PIC impact class | Notes |
|---|---|---|
| `observe` | `read` | Direct correspondence. |
| `transform_local` | `write` | Direct correspondence. |
| `fetch_external` | `external` | Direct correspondence. |
| `mutate_repo` | `write` | CSC distinguishes repo mutation; PIC does not. |
| `deploy` | `irreversible` | Approximate. Deployment is typically irreversible. |
| `touch_secrets` | `privacy` | Approximate. Secrets access maps to privacy impact. |

These mappings are informational. They should not be used for mechanical translation between protocols.

### Receipt → (no PIC equivalent)

CSC `ExecutionReceipt` fields have no current PIC counterpart. The following fields are CSC-native:

- `receipt_version`, `contract_id`, `execution_id`, `contract_sha256`
- `status`, `started_at`, `ended_at`, `exit_code`
- `stdout_hash`, `stderr_hash`, `artifacts`
- `policy_profile`, `policy_schema_version`, `policy_sha256`
- `runner_version`, `execution_mode`, `sandbox_profile_id`, `signing_key_id`
- `effect_summary`, `completed_command_ids`, `failed_command_id`, `error`

### Hashing and evidence

| CSC mechanism | PIC mechanism | Notes |
|---|---|---|
| `contract_sha256` (SHA-256 over canonical JSON) | SHA-256 hash evidence over file bytes | Same algorithm. CSC hashes structured protocol objects; PIC hashes file artifacts. |
| Receipt signing (planned, Ed25519) | Ed25519 signature evidence | Same algorithm planned. CSC will sign receipts; PIC signs evidence payloads. |
| Canonicalization (`docs/canonicalization.md`) | PIC Canonical JSON v1 (planned) | CSC spec is self-contained. Future alignment possible when PIC spec ships. |

### Reason codes → PIC error codes

| CSC concept | PIC concept | Notes |
|---|---|---|
| `reason_codes` (array in PolicyDecision) | PIC error codes (9 structured codes) | Different registries, same pattern: machine-readable codes for automation. CSC codes are policy-evaluation-specific. PIC codes span schema, verifier, evidence, and policy layers. |

## Import boundary status

As of CSC v0.1.0, no PIC modules are imported at runtime. All PIC alignment is conceptual.

### Planned imports (Stage 2, subject to decision gate)

| PIC surface | CSC use case | Adapter needed |
|---|---|---|
| Evidence verification (SHA-256 + Ed25519) | Receipt signing and verification | Yes — optional adapter behind CSC signing interface |
| Keyring management (key resolver, expiry, revocation) | Receipt signing trust roots | Yes — optional adapter behind CSC key management interface |

### Decision gate checklist (per RFC-0002)

Before any PIC import is added:

- [ ] Import is optional (CSC works without PIC installed)
- [ ] Imported surface is wrapped behind an adapter boundary
- [ ] Import is pinned to a tested PIC version range
- [ ] CSC tests pass with and without PIC installed
- [ ] Import is documented in this file

## Version history

| Date | Change |
|---|---|
| 2026-03-20 | Initial mapping based on PIC v0.7.1 and CSC v0.1.0 |
