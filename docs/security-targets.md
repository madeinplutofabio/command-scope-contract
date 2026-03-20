# CSC Security Targets

## Purpose

This document states explicitly what CSC is designed to mitigate, what it does not mitigate, in which mode, and under which deployment constraints. It exists to prevent people from projecting their own assumptions onto CSC.

## Deployment modes

CSC defines two deployment modes with different security properties:

- **Local/dev mode** — easy to run, limited enforcement, suitable for learning, demos, and development workflows.
- **Hardened mode** — containerized, process-isolated, path-enforced, low-privilege, with optional approval service and receipt signing. Suitable for bounded production use under documented constraints.

Security claims in this document are **mode-specific**. A property marked as enforced in hardened mode is not necessarily enforced in local/dev mode.

## Claims matrix

| Threat | Local/dev mode | Hardened mode | Hardened + approvals | Hardened + signed receipts |
|---|---|---|---|---|
| Shell metainterpreter execution | Policy denies by default; not OS-enforced | Policy denies by default; hardened mode adds OS/runtime isolation that reduces bypass avenues | Same as hardened | Same as hardened |
| Path breakout (read/write outside declared scope) | Policy checks declared paths; no hardened runtime enforcement in local/dev mode | Policy checks + executor resolves real paths + OS-level workspace boundary | Same as hardened | Same as hardened |
| Symlink escape | Not enforced in local/dev | Executor resolves symlinks before scope check; rejects escapes | Same as hardened | Same as hardened |
| `..` traversal | Policy normalizes paths; no runtime resolution in local/dev | Policy normalizes + executor resolves real paths; rejects traversal | Same as hardened | Same as hardened |
| Environment variable leakage | Executor filters inherited environment to a minimal allowlist required for execution | Executor filters inherited environment to a minimal allowlist + sandbox inherits minimal env | Same as hardened | Same as hardened |
| Network egress *(see note 1)* | Policy declares network mode; no OS-level enforcement | Sandbox enforces egress policy at OS/container level (when network enforcement is enabled) | Same as hardened | Same as hardened |
| Receipt tampering | Receipts are hash-bound to contract; no integrity protection on receipt itself | Receipts are hash-bound to contract; no integrity protection on receipt itself | Same as hardened | Receipts are signed (Ed25519); tampering is detectable if trust roots and signing keys are managed correctly |
| Stale approval replay | Not applicable (no approval system) | Not applicable (no approval system) | Approvals are hash-bound to `contract_sha256`; stale approvals rejected if contract changes | Same as hardened + approvals |
| Malicious stdout content | Stdout is treated as untrusted tool output per spec; no sanitization | Same as local/dev; stdout remains untrusted | Same as hardened | Same as hardened |
| Insider with host root access | **Not protected.** Host root can modify runner, policy, sandbox, and receipts. | **Not protected.** Host root can modify runner, policy, sandbox, and receipts. | **Not protected.** Host root can forge approvals. | **Not protected.** Host root can access signing keys. |
| Compromised container runtime | Not applicable (no container) | **Not protected.** A compromised runtime can violate all sandbox guarantees. | Same as hardened | Same as hardened |
| Oversized or malformed contracts | Schema validation rejects malformed contracts; runner enforces resource limits | Same as local/dev + sandbox resource caps (CPU, memory, process count) | Same as hardened | Same as hardened |
| Policy confusion (malformed policy) | Policy schema validation rejects malformed policies | Same as local/dev | Same as hardened | Same as hardened |

**Note 1:** Network enforcement is outside the first bounded production claim (Linux hardened mode, filesystem-bounded local/CI, no network) unless a later pilot validates it.

## Known unsafe if...

CSC does **not** provide meaningful security guarantees under any of the following conditions:

- **Host root is compromised.** An attacker with root access on the host can modify the runner binary, policy files, sandbox configuration, signing keys, and receipts. CSC cannot protect against a compromised host.

- **Sandbox is disabled.** Without OS-level process isolation, filesystem enforcement and network controls rely solely on policy declarations. A malicious or buggy command can bypass declared constraints.

- **Policies are mutable without review.** If an attacker or misconfigured system can modify policy files at runtime without detection, all policy-based guarantees are void.

- **Signing keys are unmanaged.** If receipt signing keys are stored without access controls, rotation, or revocation, signed receipts provide integrity evidence but not trust. An attacker with key access can forge receipts.

- **Hardened mode is not actually used.** Local/dev mode is designed for convenience, not security. Claims about enforcement, isolation, and integrity apply only to hardened mode unless explicitly stated otherwise.

- **Network enforcement is not enabled.** If the sandbox does not enforce egress policy at the OS/container level, the `network` field in contracts is a declaration only, not a control.

- **The runner itself is compromised.** CSC's trust model assumes the runner, policy engine, executor, and receipt writer are trusted components. If any of these are compromised, all downstream guarantees fail.

## Interpreting this document

- "Policy denies by default" means the policy engine will return a deny decision, but the OS does not independently prevent the action.
- "Executor resolves" means the executor performs runtime path resolution before scope checking.
- "Sandbox enforces" means an OS-level or container-level mechanism independently prevents the action regardless of policy.
- "Not protected" means CSC provides no meaningful defense against this threat in any mode.

## Scope of bounded production claim

The first bounded production claim applies to:

> **Linux hardened mode only, filesystem-bounded local/CI execution, no network.**

This claim is valid only under the trust assumptions documented above and the deployment constraints documented in `docs/deployment-modes.md`. It does not imply general-purpose production readiness outside those constraints.
