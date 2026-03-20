# Contributing to CSC

Thank you for your interest in contributing to the Command Scope Contract project.

## Getting started

1. Fork the repository
2. Clone your fork
3. Install dev dependencies: `pip install -e ".[dev]"`
4. Create a feature branch: `git checkout -b my-feature`
5. Make your changes
6. Run checks: `make check`
7. Submit a pull request

## Where to start

- Read the spec: `docs/spec-v0.1.md`
- Review the schemas: `schemas/`
- Look at example contracts: `examples/contracts/`

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

- `make lint` — check for issues
- `make fmt` — auto-format

## Tests

Run the test suite with:

```bash
make test
```

All pull requests must pass CI before merging.

## RFCs

For changes to the protocol or significant design decisions, follow the RFC process described in `rfcs/RFC_PROCESS.md`.

## Code of conduct

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).
