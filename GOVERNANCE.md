# Governance

## Overview

CSC is an open-source project maintained by its maintainers. This document describes how decisions are made, how contributions are accepted, and how the project evolves.

## Roles

### Maintainers

Maintainers have write access to the repository and are responsible for:

- Reviewing and merging pull requests
- Managing releases and versioning
- Deciding on RFC acceptance
- Enforcing the code of conduct

### Contributors

Anyone who submits a pull request, files an issue, or participates in discussions is a contributor. Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and [Contributing Guide](CONTRIBUTING.md).

## Decision-making

- **Code changes**: reviewed and merged by at least one maintainer.
- **Protocol changes**: require an RFC (see `rfcs/RFC_PROCESS.md`). RFCs must be reviewed by at least two maintainers before acceptance.
- **Breaking changes**: require explicit discussion and a documented migration path.

## Versioning

- The project follows [Semantic Versioning](https://semver.org/).
- Protocol versions (for example, `csc.v0.1`) are independent of the runner package version.
- Schema changes that break backward compatibility require a new protocol version.

## Extensions

- Extension effect types and policy rules may be defined outside the core spec.
- Extensions should be documented and should not conflict with core semantics.
- The `rfcs/` process is the recommended path for proposing extensions to core behavior.

## Release process

- Releases are tagged from `main`.
- Each release updates `CHANGELOG.md`.
- Relevant accepted or final RFC artifacts may be hashed and recorded in `rfcs/index.yaml` in accordance with `rfcs/RFC_PROCESS.md`.

## Dispute resolution

If contributors cannot reach agreement, maintainers make the final decision. Maintainer decisions can be revisited through the RFC process.
