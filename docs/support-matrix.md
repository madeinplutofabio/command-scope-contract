# CSC Support Matrix

## Purpose

This document defines which platforms, runtimes, and deployment modes are supported by the CSC reference runner, and at what level. It exists to set clear expectations and prevent assumptions about untested configurations.

## Python versions

| Python version | Support level |
|---|---|
| 3.11, 3.12 | Fully supported, tested in CI |
| 3.10 and earlier | Unsupported |
| 3.13+ | Best-effort, not tested in CI until explicitly added |

## Operating systems

| OS | Local/dev mode | Hardened mode |
|---|---|---|
| Linux (x86_64) | Fully supported, tested in CI | Target platform for first bounded production claim |
| Linux (arm64) | Best-effort, not tested in CI | Best-effort, not tested in CI |
| macOS (Apple Silicon) | Fully supported for development | Not a hardened mode target |
| macOS (Intel) | Expected to work, not tested in CI | Not a hardened mode target |
| Windows | Supported for local/dev workflows with cross-platform path handling | Not a hardened mode target |

## Path flavours

| Path flavour | Schema validation | Policy evaluation | Executor enforcement |
|---|---|---|---|
| POSIX absolute (`/workspace/app`) | Supported | Supported, case-sensitive | Supported |
| Windows absolute (`C:\Work\App`) | Supported | Supported, case-insensitive | Local/dev only |
| UNC (`\\server\share`) | Supported in schema | Allowed only if policy explicitly permits | Local/dev only |
| Mixed-flavour comparison | N/A | Fails closed (deny) | Fails closed (deny) |
| Relative paths | Rejected by schema | Rejected by policy | Rejected by executor |

## Deployment modes

| Mode | Status | Security guarantees |
|---|---|---|
| Local/dev | Available in v0.1.0 | Policy-based only; no OS-level enforcement of filesystem or network boundaries |
| Hardened (Linux) | Target for Stage 2 | OS/runtime-enforced filesystem boundaries, process isolation, optional receipt signing |
| Hardened (macOS) | Not planned | — |
| Hardened (Windows) | Not planned | — |

## Feature support by mode

Hardened mode entries below describe the Stage 2 target state, not current v0.1.0 availability.

| Feature | Local/dev | Hardened (target) |
|---|---|---|
| Contract validation | Yes | Targeted |
| Policy evaluation | Yes | Targeted |
| Reason codes | Yes | Targeted |
| Command execution | Yes | Targeted, sandboxed |
| Receipt generation | Yes | Targeted, optionally signed |
| Filesystem enforcement (resolved paths) | No | Targeted |
| Network enforcement (OS-level) | No | Targeted (when enabled) |
| Process isolation | No | Targeted |
| Approval artifacts | No | Targeted |
| Secret brokering | No | Targeted (if pilot requires) |

## Experimental and unsupported

### Experimental

- Windows path handling in policy evaluation (cross-platform normalization is implemented but has limited real-world testing)
- UNC path support (schema accepts them; policy and executor support is minimal)

### Unsupported

- Shell metainterpreters in argv (denied by default; no supported path to enable)
- Floating-point values in protocol artifacts
- Dynamic templating between commands within a contract
- Implicit version negotiation between runner and contract

## First bounded production claim

The first bounded production claim applies to:

> **Linux hardened mode only, filesystem-bounded local/CI execution, no network.**

All other configurations are suitable for development, testing, and evaluation but are not covered by the production readiness gate defined in `docs/production-readiness-gate.md`.
