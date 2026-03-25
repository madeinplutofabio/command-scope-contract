# CSC Production Readiness Gate

## Purpose

This is the formal checklist for the CSC bounded production claim. No "production-ready" assertion is made until every required item passes.

## Scope

Passing this gate permits only the bounded production claim:

> CSC hardened mode is safe enough for bounded production use in Linux-based, filesystem-bounded local/CI execution workflows without network access, under the documented trust assumptions and deployment constraints.

This does not imply general-purpose production readiness outside those constraints.

## Stage Completion

| Stage | Status | Commit | Notes |
|---|---|---|---|
| 1a — Protocol Complete | PASS | `800dc8b` | Spec frozen, conformance suite, policy schema, reason codes |
| 1b — Hardened Defaults | PASS | `f1b699f` | Fail-closed executor, path enforcement, resource limits, adversarial tests |
| 2 — First Hardened Mode | IMPLEMENTATION COMPLETE | `3e8d751` | Approval, signing, sandbox (bwrap), integration tests, docs. Bounded pilot claim pending Linux CI confirmation. |
| 3 — Production Candidate | PENDING | — | Release infrastructure, CI gates, security process, pilot |

## Required Gate Items

### Engineering

- [ ] **Hardened integration tests pass on Linux in CI.** `.github/workflows/hardened-tests.yml` builds Docker image, runs `tests/test_integration_hardened.py` in a privileged container. Network isolation is tested by bwrap `--unshare-net` inside the sandbox. Must be green on every push/PR.
- [ ] **Standard test suite passes on the supported platform matrix.** All local-mode tests pass across supported Python versions and operating systems.
- [ ] **Adversarial test suite passes.** `tests/test_adversarial.py` covers shell escapes, path tricks, env leakage, timeout abuse, resource exhaustion, Unicode edge cases.
- [ ] **No open high/critical security issues** for the supported bounded deployment shape (Linux hardened mode, filesystem-bounded, no network).

### Release Integrity

- [ ] **Signed releases.** Tags and release artifacts are signed (GPG or sigstore).
- [ ] **Provenance attestations.** SLSA provenance discipline (start level, not full SLSA 3).
- [ ] **SBOM generated** for each release.
- [ ] **Dependencies scanned.** `pip-audit` or equivalent runs in CI.
- [ ] **CI action versions pinned.**
- [ ] **PyPI trusted publishing configured** for the release workflow.
- [ ] **Signed wheel/sdist release process in place.**

### Security Process

- [ ] **`SECURITY.md` published** with vulnerability disclosure process.
- [ ] **Security advisory template** (`.github/SECURITY_ADVISORY_TEMPLATE.md`) exists.
- [ ] **Security release notes template** (`.github/SECURITY_RELEASE_TEMPLATE.md`) exists.
- [ ] **Severity rubric documented** with fix/SLA targets.
- [ ] **Security advisories enabled** on the GitHub repository.

### Documentation

- [ ] **`docs/threat-model.md` populated** with real content: threat classes, mitigations, residual risks. Not a placeholder.
- [ ] **`docs/deployment-modes.md` current.** Accurately describes local vs hardened mode, security claims, limitations.
- [ ] **`docs/security-targets.md` current.** Claims matrix reflects actual implementation state.
- [ ] **`docs/support-matrix.md` current.** Supported platforms, Python versions, deployment modes.
- [ ] **`docs/canonicalization.md` current.** Policy-hash rules unchanged or explicitly versioned.
- [ ] **`README.md` aligned with production status.** No longer presents CSC as bootstrap/minimal. Reflects hardened-mode availability and bounded production claim.

### Ecosystem Hygiene

- [ ] **Branch protection configured.** Main branch requires PR review and CI pass.
- [ ] **Required CI checks for PRs.** Hardened tests + standard tests + lint.
- [ ] **Dependabot enabled** (`.github/dependabot.yml`).
- [ ] **Dependency graph + alerts enabled** on the repository.

### Review and Pilot

- [ ] **At least one structured review completed.** Independent external or peer review preferred; documented internal red-team acceptable for Stage 3.
- [ ] **Review findings closed** or explicitly accepted with rationale.
- [ ] **At least one pilot completed** with a real user in a production-like workflow.
- [ ] **Pilot retrospective written** and published.
- [ ] **Known limitations section published** honestly.

### Severity Policy

- **High/critical security issues** block the production claim.
- **Medium issues** require an explicit acceptance note with rationale.
- **Low issues** may remain open with documented rationale.

## What This Gate Does NOT Cover

- Windows or macOS hardened mode
- Network allowlisting / egress control (Stage 2 enforces "no network"; allowlisting is Stage 3 optional)
- Secrets management
- Syscall filtering (seccomp)
- Multi-tenant isolation
- Durable approval replay prevention (process-local only in Stage 2)

These are documented limitations, not failures. The bounded claim is scoped to exclude them.

## How to Use This Document

1. Work through Stage 3 steps (A through G, and H only if the pilot demands egress control), plus required repository settings.
2. Check off each item as it is completed.
3. When all required items pass, the bounded production claim is valid.
4. If any required item regresses, the claim is suspended until fixed.
