<p align="center">
  <img src="https://raw.githubusercontent.com/madeinplutofabio/command-scope-contract/main/docs/assets/logo.png" alt="CSC — Command Scope Contract" width="140">
</p>

<h1 align="center">CSC — Command Scope Contract</h1>

<p align="center">
  Bounded shell and CLI execution for AI agents.<br>
  Structured contracts. Policy-gated execution. Signed receipts.
</p>

<p align="center">
  <a href="https://github.com/madeinplutofabio/command-scope-contract/actions/workflows/ci.yml"><img src="https://github.com/madeinplutofabio/command-scope-contract/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/madeinplutofabio/command-scope-contract/actions/workflows/hardened-tests.yml"><img src="https://github.com/madeinplutofabio/command-scope-contract/actions/workflows/hardened-tests.yml/badge.svg" alt="Hardened Tests"></a>
  <a href="https://pypi.org/project/csc-runner/"><img src="https://img.shields.io/pypi/v/csc-runner.svg" alt="PyPI"></a>
  <a href="https://pypi.org/project/csc-runner/"><img src="https://img.shields.io/pypi/dm/csc-runner.svg" alt="Downloads"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="License"></a>
</p>

---

CSC is a protocol for bounded shell and CLI execution by AI agents.

CSC is complementary to MCP, not a replacement for it.

It exists to remove **ambient authority** from agentic execution.

Instead of giving an agent raw shell access, CSC requires the agent to submit a structured command contract that declares:

- what it wants to run
- why it wants to run it
- where it wants to run it
- what it needs to read
- what it may write
- whether it needs network access
- whether it needs secrets
- what kind of effect it may cause
- how long it may run

A trusted policy layer evaluates the contract. If allowed, a constrained executor runs it and emits a verifiable, signed receipt.

## Why CSC exists

Shell is useful because it is universal, composable, and token-efficient.

Shell is dangerous because it often carries too much implicit power.

CSC keeps the flexibility of shell while making scope, policy, and execution evidence explicit.

## Execution model

```text
agent -> command contract -> policy gate -> constrained executor -> execution receipt
```

## Status

**v0.5.1 — bounded production-ready**

The reference runner implements the full CSC v0.1 protocol:

- **Stage 1a** — Protocol complete: spec frozen, conformance suite, policy schema with structured reason codes, receipt field semantics
- **Stage 1b** — Hardened defaults: fail-closed executor, path enforcement, resource limits, capped output capture, adversarial test suite
- **Stage 2** — First hardened mode: Linux sandbox (bubblewrap + setpriv + prlimit), Ed25519 receipt signing, approval artifacts with replay prevention, end-to-end integration tests
- **Stage 3** — Production candidate: release infrastructure, CI gates, security process, pilot validation, internal red-team review

### Bounded production claim

> CSC hardened mode is safe enough for bounded production use in Linux-based, filesystem-bounded local/CI execution workflows without network access, under the documented trust assumptions and deployment constraints.

See [docs/deployment-modes.md](docs/deployment-modes.md) for security claims by mode and [docs/production-readiness-gate.md](docs/production-readiness-gate.md) for the formal release gate.

## Deployment modes

| Mode | Platform | Security boundary | Receipt signing |
|---|---|---|---|
| **Local** | Any | Pre-launch validation only | Optional |
| **Hardened** | Linux only | Kernel-enforced (bwrap namespaces) | Mandatory |

Local mode is for development, testing, and demos. Hardened mode is for CI/CD pipelines and production-like workflows where execution integrity matters.

See [docs/deployment-modes.md](docs/deployment-modes.md) for full details.

## Design goals

- Keep shell composability.
- Remove raw arbitrary shell by default.
- Make intent and scope explicit before execution.
- Let trusted policy decide.
- Emit signed receipts for audit and provenance.
- Enforce boundaries with the kernel, not just Python.
- Stay small enough to implement and adopt quickly.

## Non-goals

CSC does not attempt to replace:

- container isolation (CSC uses it as the enforcement layer)
- IAM
- workflow engines
- semantic validation of task correctness
- prompt injection defenses at every layer

CSC is an execution-boundary protocol. For a full statement of what CSC contributes and what it reuses, see [RFC-0003](rfcs/0003-csc-positioning.md).

## Core objects

- **CommandContract** — what the agent wants to run
- **PolicyDecision** — whether it may run (with structured reason codes)
- **ExecutionReceipt** — what actually happened (signed in hardened mode)
- **ApprovalArtifact** — human authorization for sensitive operations

## v0.1 rules

- argv arrays only
- no raw shell strings
- no `bash -lc`, `sh -c`, `eval`, `python -c`, `node -e` by default
- explicit read/write/network/env/secret scope
- default deny on omitted capabilities
- bounded runtime
- signed receipts in hardened mode

## Quickstart

```bash
# Install from PyPI
pip install csc-runner

# Or install from source with dev dependencies
pip install -e ".[dev]"

# Check a contract against a policy (no execution)
csc check examples/contracts/git-status.json examples/policies/dev-readonly.yaml

# Run a contract (local mode)
csc run examples/contracts/git-status.json examples/policies/dev-readonly.yaml

# Run in hardened mode (Linux, requires bwrap/setpriv/prlimit)
csc run contract.json policy.yaml \
  --mode hardened \
  --sign --signing-key key.pem --key-id prod-01

# Verify a signed receipt
csc verify-receipt receipt.json --public-key pub.pem --key-id prod-01
```

## Documentation

- [Spec v0.1](docs/spec-v0.1.md) — protocol specification
- [Deployment Modes](docs/deployment-modes.md) — local vs hardened, security claims
- [Key Management](docs/key-management.md) — signing key lifecycle
- [Threat Model](docs/threat-model.md) — threat classes and mitigations
- [Security Targets](docs/security-targets.md) — claims matrix by mode
- [Production Readiness Gate](docs/production-readiness-gate.md) — formal release checklist
- [Policy Packs](docs/policy-packs.md) — organizational policy conventions
- [Reason Codes](docs/reason-codes.md) — structured decision reason registry
- [Security Policy](SECURITY.md) — vulnerability reporting
- [Internal Red-Team Review](docs/internal-red-team-review.md) — adversarial review findings
- [Pilot Retrospective](docs/pilot-retrospective.md) — pilot execution and lessons learned

## RFCs

- [RFC-0001](rfcs/0001-csc-core.md) — CSC core protocol
- [RFC-0002](rfcs/0002-pic-alignment.md) — PIC alignment and mapping
- [RFC-0003](rfcs/0003-csc-positioning.md) — CSC positioning, contribution, and boundaries

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and start with `docs/spec-v0.1.md` and `schemas/`.

## License

Apache-2.0
