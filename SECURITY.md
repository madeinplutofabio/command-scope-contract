# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (current) | ✅ Security fixes on best-effort basis |

CSC is pre-1.0. Security fixes are applied to the latest release on the default branch. Older versions are not backported unless a critical issue affects a deployed pilot.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use this repository's GitHub Security Advisories page to report vulnerabilities privately.

### What to include

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected component (executor, sandbox, signing, approval, policy, CLI)
- Affected mode (local, hardened, or both)
- Severity assessment (your estimate)
- Any suggested fix

### Response timeline

| Action | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Initial triage and severity assessment | 5 business days |
| Fix developed and tested | Depends on severity (see below) |
| Security advisory published | With the fix release |

## Severity Rubric

| Severity | Description | Fix Target |
|---|---|---|
| Critical | Remote code execution, sandbox escape, signing key compromise | 48 hours |
| High | Privilege escalation, path traversal bypass, unsigned receipt accepted as signed | 7 days |
| Medium | Information disclosure, denial of service, approval replay in narrow conditions | 30 days |
| Low | Minor information leak, cosmetic security UI issue, documentation gap | Next release |

### Severity and the production claim

- **High/critical issues** block the bounded production claim until resolved.
- **Medium issues** require an explicit acceptance note with rationale if the claim is maintained.
- **Low issues** may remain open with documented rationale.

## Scope

### In scope

- `csc_runner/` — all runner modules (executor, sandbox, signing, approval, policy, pathutil, limits)
- `csc_runner/cli.py` — CLI entry points
- `schemas/` — JSON Schema definitions
- `Dockerfile` — hardened mode container image
- Receipt integrity and signing
- Approval artifact validation and replay prevention
- Sandbox boundary enforcement (bubblewrap launcher construction)
- Third-party dependency vulnerabilities affecting CSC (triage and remediation; upstream disclosure may also be appropriate)

### Out of scope

- The host/container runtime configuration (we document requirements but don't control the runtime)
- PIC ecosystem components (report to PIC directly)
- Attacks requiring host root access (documented as a known limitation)

## Disclosure Policy

- We follow coordinated disclosure.
- We aim to publish a security advisory simultaneously with the fix release.
- Credit is given to reporters unless they request otherwise.
- We do not pay bug bounties at this time.

## Security Release Process

When a security fix is ready:

1. Fix is developed and tested in the private security advisory workflow (or equivalent non-public fix branch).
2. Security advisory is drafted in GitHub Security Advisories.
3. Fix is merged, tagged, and released.
4. Advisory is published with the release.
5. Release notes reference the advisory (see `.github/SECURITY_RELEASE_TEMPLATE.md`).
6. A regression test for the vulnerability is added to the appropriate test suite (adversarial, unit, or integration).

## Known Limitations

These are documented design boundaries, not vulnerabilities:

- **Command blocking is advisory, not enforcement.** The sandbox namespace is the real boundary.
- **Approval replay prevention is process-local.** Consumed approvals are lost on restart.
- **Receipt signing proves integrity, not sandbox configuration.** A signed receipt does not prove the sandbox was correctly set up.
- **No syscall filtering (seccomp).** Deferred to post-pilot.
- **No Windows/macOS hardened mode.**
- **No network allowlisting.** Stage 2 enforces "no network" only.

See `docs/deployment-modes.md` for the full security posture by mode.
