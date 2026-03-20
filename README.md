[![CI](https://github.com/madeinplutofabio/command-scope-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/madeinplutofabio/command-scope-contract/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

# CSC — Command Scope Contract

CSC is a lightweight protocol for bounded shell and CLI execution by AI agents.

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

A trusted policy layer evaluates the contract. If allowed, a constrained executor runs it and emits a verifiable receipt.

## Why CSC exists

Shell is useful because it is universal, composable, and token-efficient.

Shell is dangerous because it often carries too much implicit power.

CSC keeps the flexibility of shell while making scope, policy, and execution evidence explicit.

## Execution model

```text
agent -> command contract -> policy gate -> constrained executor -> execution receipt
```

## Status

**Draft / v0.1 bootstrap**

Not production-ready. The current runner is a minimal reference implementation intended to validate the protocol shape.

## Design goals

- Keep shell composability.
- Remove raw arbitrary shell by default.
- Make intent and scope explicit before execution.
- Let trusted policy decide.
- Emit receipts for audit and provenance.
- Stay small enough to implement and adopt quickly.

## Non-goals

CSC does not attempt to replace:

- container isolation
- IAM
- workflow engines
- semantic validation of task correctness
- prompt injection defenses at every layer

CSC is an execution-boundary protocol.

## Core objects

- **CommandContract** — what the agent wants to run
- **PolicyDecision** — whether it may run
- **ExecutionReceipt** — what actually happened

## v0.1 rules

- argv arrays only
- no raw shell strings
- no `bash -lc`, `sh -c`, `eval`, `python -c`, `node -e` by default
- explicit read/write/network/env/secret scope
- default deny on omitted capabilities
- bounded runtime
- receipts required

## Quickstart

```bash
pip install -e ".[dev]"
csc check examples/contracts/git-status.json examples/policies/dev-readonly.yaml
csc run examples/contracts/git-status.json examples/policies/dev-readonly.yaml
```

## Roadmap

See [docs/roadmap.md](docs/roadmap.md).

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and start with `docs/spec-v0.1.md` and `schemas/`.

## License

Apache-2.0
