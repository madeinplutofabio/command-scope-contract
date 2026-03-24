# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-03-24

### Added — Stage 1a (Protocol Complete)

- Conformance test suite with golden fixtures (contracts, decisions, receipts)
- Policy schema validation on load (`policy_schema_version` field)
- Structured reason codes in PolicyDecision (ALLOW, COMMAND_NOT_ALLOWED, ARGV_PREFIX_DENIED, etc.)
- Receipt field semantics: policy provenance, runner provenance, blocked vs failed distinction
- Conditional receipt schema: success/failed require exit_code, stdout_hash, stderr_hash
- Security targets, support matrix, compatibility matrix, canonicalization spec
- PIC alignment RFC-0002 and mapping document
- Reason-code registry (`docs/reason-codes.md`)

### Added — Stage 1b (Hardened Defaults)

- Resource exhaustion controls (`csc_runner/limits.py`): command count, argv size, pipeline depth, justification length, output capture caps
- Filesystem path enforcement (`csc_runner/pathutil.py`): realpath resolution, symlink rejection, mixed-flavour fail-closed, glob prefix extraction
- Popen-based executor with capped output capture, OS-pipe pipelines, ownership-based cleanup
- Receipt integrity: hash-bound to contract, deterministic structure, truncation flags (stdout_truncated, stderr_truncated)
- Adversarial test suite: shell escapes, path tricks, env leakage, timeout abuse, Unicode edge cases
- Emergency deny-all policy mode
- Policy provenance in receipts (policy_sha256, policy_schema_version)

### Added — Stage 2 (First Hardened Mode)

- Approval artifacts (`csc_runner/approval.py`): hash-bound to contract_sha256, expiry enforcement, temporal ordering, schema validation
- Ed25519 receipt signing (`csc_runner/signing.py`): standalone `cryptography` library, CSC-native PublicKeyResolver protocol, authenticated signing metadata
- Linux sandbox backend (`csc_runner/sandbox.py`): bubblewrap + setpriv + prlimit launcher, kernel-enforced namespace isolation, advisory command blocking
- Hardened CLI: `--mode hardened`, `--sign`, `--signing-key`, `--key-id`, `--approval`, `--sandbox-debug`
- `verify-receipt` CLI command
- Executor integration: approval before sandbox, signing after execution, fail-closed on signing failure in hardened mode
- In-memory approval consumption store with replay prevention (single-execution scope)
- Dockerfile for hardened mode container image
- End-to-end hardened integration tests (19 tests): filesystem boundaries, network isolation, no_new_privs, signed receipt verification
- `docs/deployment-modes.md`: local vs hardened, security claims per mode
- `docs/key-management.md`: rotation, revocation, CSC/PIC dependency boundary
- `docs/policy-packs.md`: organizational conventions, not engine features
- `cryptography` added as runtime dependency

### Added — Stage 3 (Production Candidate)

- Production readiness gate (`docs/production-readiness-gate.md`): formal checklist for bounded production claim
- CI workflow for hardened integration tests (`.github/workflows/hardened-tests.yml`): Docker build + `--network=none`
- Release workflow (`.github/workflows/release.yml`): sigstore signing, SBOM generation, PyPI trusted publishing
- Security policy (`SECURITY.md`): severity rubric, SLA targets, disclosure process
- Security advisory template (`.github/SECURITY_ADVISORY_TEMPLATE.md`)
- Security release notes template (`.github/SECURITY_RELEASE_TEMPLATE.md`)
- Dependabot configuration (`.github/dependabot.yml`): pip, GitHub Actions, Docker
- Threat model (`docs/threat-model.md`): trust boundaries, 7 threat classes, known unsafe conditions
- README updated to reflect hardened mode availability and bounded production claim
- Branch protection on main: required status checks, PR review, no force push
- Dependabot alerts, security updates, and private vulnerability reporting enabled

### Changed

- Version bumped from 0.1.0 to 0.5.0 to reflect protocol maturity
- Receipt schema: conditional rules require exit_code/stdout_hash/stderr_hash for success/failed status
- Executor signature: `run_contract()` accepts mode, approval, signing, and sandbox config
- CLI: `run` command accepts hardened mode flags; `check` command unchanged

## [0.1.0] - 2026-03-20

### Added

- Initial project scaffold
- CSC v0.1 specification draft
- JSON Schemas for CommandContract, PolicyDecision, ExecutionReceipt
- Reference Python runner (`csc-runner`)
- YAML policy profiles: dev-readonly, dev-test-no-network, regulated-restricted
- Example contracts and receipts
- RFC process with artifact integrity rules
