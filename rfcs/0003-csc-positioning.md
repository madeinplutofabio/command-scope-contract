# RFC-0003: CSC Positioning, Contribution, and Boundaries

- **Status:** Accepted
- **Authors:** Fabio Marcello Salvadori
- **Created:** 2026-03-25
- **Related:**
  - `docs/spec-v0.1.md`
  - `docs/pic-mapping.md`
  - `docs/deployment-modes.md`
  - `docs/threat-model.md`
  - `docs/production-readiness-gate.md`
  - `rfcs/0002-pic-alignment.md`

## 1. Summary

This RFC defines what CSC contributes, what it reuses, and what claims it does not make.

CSC does **not** claim to invent sandboxing, policy engines, approval workflows, or digital signatures.

CSC's contribution is to formalize **bounded shell and CLI execution for AI agents** as a protocol with:

- structured command contracts
- explicit execution scope
- policy-gated evaluation
- approval-aware execution
- mode-specific trust claims
- signed execution receipts
- a clear separation between protocol semantics and runtime enforcement

The purpose of this RFC is to make CSC's novelty, boundaries, and positioning explicit so the project can be evaluated honestly and adopted without inflated claims.

## 2. Motivation

AI agents increasingly invoke shell commands, local tools, CI workflows, and developer environments.

The common failure mode is not that shell tools are inherently wrong. The failure mode is that agent execution often inherits **ambient authority**:

- raw shell access
- unclear scope
- no structured policy decision
- no approval artifact
- no verifiable execution evidence
- unclear trust boundary between "what was intended" and "what actually ran"

Existing building blocks solve parts of this problem:

- operating-system isolation primitives constrain execution
- policy engines decide allow/deny
- cryptographic signatures protect integrity
- workflow tools coordinate tasks
- MCP standardizes tool interfaces

CSC exists because those pieces, by themselves, do not define a **single protocol for bounded shell execution with receipts**.

## 3. Non-Goals of This RFC

This RFC does not claim that CSC:

- invented sandboxing
- invented namespace isolation
- invented approval systems
- invented Ed25519 signing
- invented policy evaluation
- replaces MCP
- replaces containers, IAM, workflow engines, or OS security models
- provides general-purpose sandboxing on all platforms
- solves every agent-security problem

This RFC is not a patent-style novelty claim over generic security techniques.

## 4. What CSC Reuses

CSC intentionally builds on existing primitives and practices.

### 4.1 Runtime isolation

CSC hardened mode reuses Linux-native enforcement mechanisms such as:

- `bubblewrap`
- `setpriv`
- `prlimit`

These are implementation choices, not protocol inventions.

### 4.2 Policy evaluation

CSC reuses familiar policy-engine ideas:

- allow/deny decisions
- explicit risk classes
- explicit effect types
- scope checking
- reason codes

### 4.3 Cryptographic integrity

CSC reuses standard integrity primitives:

- SHA-256 hashing
- Ed25519 signatures
- key identifiers
- verification against trusted public keys

### 4.4 Human approval patterns

CSC reuses familiar approval workflow concepts:

- explicit approval artifacts
- expiry
- contract binding
- replay considerations

### 4.5 Tool and agent ecosystems

CSC is designed to coexist with:

- MCP-style tool interfaces
- agent frameworks
- CI systems
- containerized execution environments

## 5. What CSC Contributes

CSC's contribution is the **formal combination and constraint model**, not a single primitive.

### 5.1 CommandContract as a bounded execution intent

CSC defines a structured artifact for shell/CLI execution that captures:

- executable intent
- argv form
- cwd
- read scope
- write scope
- network mode
- secret references
- timeout
- proposed effect type
- risk class
- approval mode

This is more specific than "tool call" and narrower than general workflow orchestration.

### 5.2 Policy-gated shell execution as a protocol

CSC treats shell execution as a protocolized event:

1. contract is authored
2. policy evaluates it
3. approval may be required
4. constrained execution occurs
5. a receipt is emitted

That sequence is part of CSC's contribution.

### 5.3 Signed execution receipts as a first-class artifact

CSC makes the execution receipt central.

A receipt binds together:

- contract hash
- policy provenance
- execution mode
- outcome
- stdout/stderr hashes
- optional signing metadata and signature

This turns shell execution from an opaque side effect into an auditable artifact.

### 5.4 Mode-specific trust claims

CSC makes an explicit distinction between:

- **local mode**
- **hardened mode**

Local mode is not described as a sandbox. Hardened mode is.

This mode-specific claim discipline is a meaningful part of CSC's design and helps prevent overstatement.

### 5.5 Separation between protocol and backend

CSC separates:

- protocol semantics
- policy semantics
- receipt semantics
- implementation backend

The current hardened backend is Linux-specific, but the protocol is not defined as "bubblewrap only forever."

That separation is deliberate.

## 6. Why CSC Is Distinct

CSC is distinct not because each ingredient is new, but because the project makes a specific execution model explicit.

### 6.1 CSC is not raw shell access

Raw shell access says:

- here is a shell
- do what you want

CSC says:

- here is a contract
- here is the intended scope
- here is the policy result
- here is the receipt of what happened

### 6.2 CSC is not just "run it in Docker"

A container alone does not define:

- the intended command contract
- policy reason codes
- approval semantics
- signed receipts
- mode-specific trust claims

CSC can use containers or sandbox tools, but it is not reducible to them.

### 6.3 CSC is not MCP

MCP standardizes tool communication. CSC standardizes bounded shell/CLI execution semantics and receipts.

The projects are complementary.

### 6.4 CSC is not a general workflow engine

CSC is narrow by design. It focuses on:

- bounded command execution
- policy control
- execution evidence

That narrowness is a feature, not a weakness.

## 7. Trust and Claim Boundaries

CSC should be evaluated using the following claim boundaries.

### 7.1 Claims CSC can make

CSC can credibly claim to provide, within documented deployment constraints:

- structured command contracts
- policy-gated execution
- approval-aware execution flow
- signed receipt generation
- auditable execution evidence
- bounded hardened execution on supported Linux runtimes

### 7.2 Claims CSC does not make

CSC does not claim:

- host-compromise resistance
- universal Linux runtime compatibility
- cross-platform hardened mode today
- complete runtime attestation from receipt signing alone
- durable replay prevention in the current in-memory approval store
- independent third-party assurance unless that review actually exists

## 8. Relationship to PIC

CSC is normatively independent from PIC but structurally aligned with it.

PIC is broader in scope around provenance and intent.
CSC is narrower and execution-focused.

CSC contributes a concrete pattern for:

- command intent
- bounded action scope
- post-execution evidence
- signed execution receipts

In that sense, CSC can be read as an execution-boundary profile within the broader provenance/governance direction that PIC addresses.

For details, see [RFC-0002](0002-pic-alignment.md) and [docs/pic-mapping.md](../docs/pic-mapping.md).

## 9. Production Positioning

CSC should be positioned as:

> a bounded execution layer for AI agents: structured command contracts, policy-gated shell execution, hardened runtime enforcement on supported Linux systems, and signed receipts for auditability.

CSC should **not** be positioned as:

- a universal sandbox
- a replacement for MCP
- a replacement for containers
- a full agent security platform
- a guarantee across all host environments

## 10. Novelty and Credit

CSC should take credit for:

- formalizing bounded shell/CLI execution as a protocol
- making signed execution receipts central
- combining policy, approval, scope, and evidence into a coherent model
- making mode-specific trust claims explicit
- separating protocol semantics from backend implementation

CSC should **not** take credit for inventing:

- sandboxing
- namespaces
- approval workflows
- signatures
- policy engines
- tool invocation as a concept

The right claim is not:

- "CSC invented secure agent execution"

The right claim is:

- "CSC formalizes bounded shell execution for agents as a protocol with policy, approvals, and signed receipts."

## 11. Implications for Future Work

This RFC implies the following development direction:

- keep the protocol narrow and legible
- preserve honest mode-specific claims
- improve backend compatibility without redefining the protocol around one runtime
- strengthen the approval model
- strengthen hardened runtime diagnostics
- pursue independent review
- add integrations without collapsing CSC into a framework-specific design

It also leaves open future work such as:

- alternate hardened backends
- seccomp as a second defense layer
- durable approval replay prevention
- cryptographic approval authentication
- receipt consumers and verification tooling
- cross-platform hardened backends where feasible

## 12. Alternatives Considered

### 12.1 Present CSC as a new sandbox

Rejected.

CSC is not best understood as inventing a new sandbox. Its value is the protocolized execution model around existing enforcement primitives.

### 12.2 Present CSC as only an implementation detail of PIC

Rejected.

CSC is aligned with PIC but solves a specific problem cleanly enough to stand on its own.

### 12.3 Make broad claims of novelty over all agent-security mechanisms

Rejected.

This would reduce credibility and overstate what CSC actually contributes.

## 13. Adoption Guidance

Users and adopters should understand CSC as:

- a protocol for bounded shell execution
- a reference runner with a Linux hardened backend
- a system that produces signed receipts
- a bounded-production tool under documented constraints

Adopters should not assume:

- all Linux hosts are equally compatible
- local mode is a sandbox
- signed receipts prove every runtime property automatically
- current approval replay handling is durable across restarts

## 14. Final Position

CSC is valuable not because it invents every primitive it uses, but because it makes a previously loose execution pattern explicit, bounded, and auditable.

That is enough.

The project should be judged on:

- clarity of scope
- honesty of claims
- correctness of execution semantics
- quality of evidence artifacts
- rigor of runtime and policy boundaries

Not on whether it invented namespaces, signatures, or policy engines from scratch.

## 15. Decision

Accepted.

CSC will present itself as:

- a bounded shell/CLI execution protocol for AI agents
- complementary to MCP
- aligned with PIC but normatively independent
- distinct because of its contract → policy → approval → execution → signed receipt model
- production-ready only for the documented bounded deployment shape
