# CSC Deployment Modes

## Overview

CSC supports two execution modes with distinct security properties. The mode determines which enforcement mechanisms are active and what claims can be made about execution integrity.

**Rule: security claims are mode-specific.** A receipt produced in local mode does not carry the same trust guarantees as one produced in hardened mode. Operators must not treat them as equivalent.

## Local Mode

**Purpose:** Development, testing, demos, and learning.

### Usage

```bash
csc run contract.json policy.yaml
csc run contract.json policy.yaml --mode local
```

### What It Provides

- Policy evaluation (allow/deny/needs_approval)
- Contract schema validation
- Resource limit checking (command count, argv size, justification length)
- Pre-launch path validation (cwd resolution, symlink rejection, scope prefix checks) — this is contract-level validation before execution, not runtime containment
- Capped output capture with deterministic hashing
- Structured receipts for every outcome (success, failed, blocked)
- Optional receipt signing (`--sign --signing-key PATH --key-id ID`)

### What It Does NOT Provide

- Process isolation (no namespace separation)
- Runtime filesystem containment — a subprocess can access anything the runner process can, regardless of declared scopes
- Network restriction
- Privilege drop or `no_new_privs`
- Mandatory receipt signing

### Security Posture

Local mode trusts the host environment. Policy evaluation and path checks are pre-launch validation — they reject obviously wrong contracts but cannot prevent a running subprocess from exceeding declared scope. Local mode is not a sandbox.

### When to Use

Development workflows, policy authoring, CI dry runs, integration testing on non-Linux platforms.

## Hardened Mode

**Purpose:** Bounded production execution with kernel-enforced isolation.

### Usage

```bash
csc run contract.json policy.yaml \
  --mode hardened \
  --sign --signing-key /keys/key.pem --key-id prod-01
```

### Requirements

- Linux only (rejects other platforms at startup)
- `bwrap`, `setpriv`, `prlimit` must be on PATH
- Receipt signing is mandatory (`--sign --signing-key --key-id`)
- Container should be started with `--network=none` for host-level isolation

### What It Provides

Everything in local mode, plus:

- **Namespace isolation** via bubblewrap:
  - Mount namespace: explicit filesystem view (only declared paths visible)
  - Network namespace: `--unshare-net` (no external connectivity)
  - PID namespace: `--unshare-pid` (process isolation)
  - New session: `--new-session`
  - Parent-linked lifecycle: `--die-with-parent`
- **Privilege controls** via setpriv:
  - `--no-new-privs` always applied (prevents privilege escalation)
  - Optional UID/GID drop with `--clear-groups` (requires root container)
- **Resource limits** via prlimit:
  - CPU time, address space, process count, file size
- **Mandatory receipt signing** (Ed25519)
- **Advisory command blocking** (shells, interpreters, wrappers denied by default)

### Filesystem Model

- Writable paths come only from declared write scopes
- cwd is read-only unless under an approved writable root
- System paths (`/usr`, `/lib`, `/bin`, `/etc`) are read-only
- `/tmp` is a private tmpfs (not shared with host)
- `/proc` and `/dev` are sandbox-local
- Paths not explicitly bound are invisible inside the sandbox

### Network Model

- Primary enforcement: `bwrap --unshare-net` (kernel namespace)
- Secondary check: `verify_network_disabled()` confirms no non-loopback interfaces on the host (expects `--network=none` container)
- No DNS, no egress, no ingress inside the sandbox
- Full allowlist/egress engine deferred to Stage 3

### What It Does NOT Provide

- Syscall filtering (seccomp — deferred to post-pilot)
- Arbitrary UID/GID switching in default non-root container image
- Protection against compromised container runtime
- Protection against host root compromise
- Guarantee that command-name blocking is a security boundary (it is advisory)

### Security Posture

Hardened mode uses kernel-enforced boundaries. Even if a subprocess attempts to escape declared scope, the namespace isolation restricts what it can see and do. The security boundary is bubblewrap + setpriv + prlimit, not Python-side checks.

### When to Use

CI/CD pipelines, automated agent execution, any context where execution integrity matters and the environment is Linux-based.

## Comparison

| Property | Local | Hardened |
|---|---|---|
| Platform | Any | Linux only |
| Namespace isolation | No | Yes (mount, net, pid) |
| Filesystem boundary | Pre-launch validation only | Kernel-enforced (bwrap) |
| Network | Unrestricted | Disabled (namespace) |
| `no_new_privs` | No | Always |
| Resource limits | Schema/runner checks | prlimit enforced |
| Receipt signing | Optional | Mandatory |
| Command blocking | Advisory | Advisory |
| Receipts | Produced for all runtime outcomes | Signed for all runtime outcomes |
| Approval artifacts | Supported | Supported |

**Note on receipts:** In both modes, CLI/configuration errors (e.g. missing signing key, invalid mode string, unparseable contract file) may fail before receipt generation. The "produced/signed for all outcomes" claim applies to runtime outcomes after successful CLI setup — not to pre-parse or pre-config failures.

## Known Limitations

### Hardened mode is not a general-purpose sandbox

The pilot claim is bounded: **Linux, filesystem-bounded local/CI execution, no network.** Hardened mode does not currently support:

- Windows or macOS
- Network allowlisting (full egress control is Stage 3)
- Secrets management (deferred)
- Syscall filtering (seccomp deferred to post-pilot)
- Multi-tenant isolation (single-runner, single-contract model)

### Command blocking is advisory

`check_command_allowed()` blocks known shells, interpreters, and wrappers by basename. This is a product-policy layer, not a security enforcement mechanism. A renamed binary bypasses it. The real containment is the sandbox namespace.

### Container runtime dependency

bubblewrap requires the host/container runtime to support the namespace features it uses. Restrictive seccomp profiles or disabled user namespaces can prevent bwrap from functioning. The hardened pilot is tested against the shipped container image only.

### Approval replay prevention is process-local

The `InMemoryApprovalStore` tracks consumed single-execution approvals in memory. Consumed approvals are lost on process restart. For durable replay prevention across restarts, a persistent backend is needed (deferred).

### Receipt signing does not prove sandbox configuration

A signed receipt proves integrity and signer identity. It does not by itself prove that the sandbox was correctly configured or that isolation was enforced. Receipt trust and runtime trust are separate concepts.

## Bounded Production Claim

> CSC hardened mode is safe enough for bounded production use in Linux-based, filesystem-bounded local/CI execution workflows without network access, under the documented trust assumptions and deployment constraints.

This claim applies only to the tested container image running in hardened mode with `--network=none`. It does not extend to arbitrary Linux hosts, other operating systems, or deployment configurations not covered by the integration test suite.
