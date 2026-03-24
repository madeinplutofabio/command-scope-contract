# CSC Threat Model

## Scope

This threat model covers CSC's bounded production deployment shape: **Linux hardened mode, filesystem-bounded local/CI execution, no network.** It does not cover local mode (which makes no security claims beyond pre-launch validation) or deployment shapes outside the pilot boundary.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│ Operator Environment                                │
│  ┌───────────────┐  ┌────────────┐  ┌───────────┐  │
│  │ Contract JSON  │  │ Policy YAML│  │ Approval  │  │
│  └───────┬───────┘  └─────┬──────┘  └─────┬─────┘  │
│          │                │              │          │
│  ════════╪════════════════╪══════════════╪══════════│══ TB1: Input validation
│          ▼                ▼              ▼          │
│  ┌─────────────────────────────────────────────┐   │
│  │ CSC Runner (Python process)                 │   │
│  │  ┌──────────┐ ┌────────┐ ┌───────────────┐ │   │
│  │  │ Policy   │ │Approval│ │ Executor      │ │   │
│  │  │ Engine   │ │Validate│ │               │ │   │
│  │  └──────────┘ └────────┘ │ ┌───────────┐ │ │   │
│  │                          │ │ Sandbox   │ │ │   │
│  │  ════════════════════════│═│═══════════│═│═│═══│══ TB2: Sandbox boundary
│  │                          │ │ bwrap     │ │ │   │
│  │                          │ │ setpriv   │ │ │   │
│  │                          │ │ prlimit   │ │ │   │
│  │                          │ │           │ │ │   │
│  │                          │ │ ┌───────┐ │ │ │   │
│  │                          │ │ │User   │ │ │ │   │
│  │                          │ │ │Command│ │ │ │   │
│  │                          │ │ └───────┘ │ │ │   │
│  │                          │ └───────────┘ │ │   │
│  │                          └───────────────┘ │   │
│  │  ┌──────────┐                              │   │
│  │  │ Signing  │ ◄── Ed25519 private key      │   │
│  │  └──────────┘                              │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │ Receipt JSON (signed)                       │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

**TB1 — Input validation boundary:** Contracts, policies, and approvals enter the runner as untrusted input. Schema validation, semantic checks, and hash binding happen here.

**TB2 — Sandbox boundary:** The user command executes inside a bubblewrap namespace with restricted filesystem, no network, isolated PID space, `no_new_privs`, and resource limits. This is the primary security enforcement point.

## Threat Classes

### 1. Malicious Contract

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Oversized contract (DoS) | `MAX_CONTRACT_SIZE_BYTES` check before parsing | None for the bounded claim |
| Excessive commands/args | `validate_contract_limits()` checks count, argv length, element size | None for the bounded claim |
| Malformed JSON | Pydantic schema validation rejects before execution | None |
| Path traversal in cwd | `resolve_and_check_cwd()` resolves realpath, rejects symlink escapes and `..` | None for declared paths; runtime file access within sandbox is bounded by bwrap |
| Mixed-flavour path tricks | `normalize_path()` detects flavour, rejects mixed comparisons | None |
| Shell metacharacters in argv | `shell=False` in Popen — argv elements are literal | None |

### 2. Malicious Command

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Command reads outside workspace | bwrap mount namespace — only declared paths are visible | None for paths not bound |
| Command writes outside workspace | bwrap writable binds only for declared write scopes; cwd is read-only unless under writable root | None for paths not bound |
| Command accesses network | bwrap `--unshare-net` — loopback only inside the sandbox namespace | None |
| Command escalates privileges | setpriv `--no-new-privs` — always applied | None |
| Command forks excessively | prlimit `--nproc` limit | Process count bounded |
| Command exhausts memory | prlimit `--as` limit | Address space bounded |
| Command exhausts CPU | prlimit `--cpu` limit + executor wall-clock timeout | Bounded |
| Command exhausts disk | prlimit `--fsize` limit | Single-file size bounded; total disk usage not capped by prlimit |
| Command renamed to bypass denylist | Advisory denylist is product policy, not enforcement. Sandbox namespace is the real boundary. | Renamed binary still runs inside sandbox with all restrictions |

### 3. Malicious Policy

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Policy grants excessive scope | Policy is operator-provided — CSC trusts the policy source. `policy_sha256` in receipts provides auditability. | If operator deploys wrong policy, CSC executes according to it |
| Policy file tampered | `policy_sha256` in receipt proves which policy content was used. Source authentication is external (deployment pipeline, access controls). | No in-protocol policy authentication |
| Oversized policy (DoS) | `MAX_POLICY_SIZE_BYTES` check before YAML parsing | None for the bounded claim |
| Malformed YAML | `load_policy()` validates schema on load, rejects duplicate keys | None |

### 4. Approval Manipulation

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Wrong-contract approval | `contract_sha256` binding — approval is rejected if hash doesn't match | None |
| Expired approval | Expiry check at validation time | Clock skew between approver and runner |
| Replayed single-execution approval | `InMemoryApprovalStore` tracks consumed `approval_id` | Process-local only — lost on restart |
| Forged approval | Contract hash binding, expiry, and temporal checks prevent some misuse, but Stage 2 does not authenticate approval origin cryptographically | An attacker with filesystem write access (or equivalent control over approval input) can forge a valid-looking approval artifact |

### 5. Receipt Tampering

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Receipt content modified | Ed25519 signature over canonical JSON payload (includes signing metadata) | None if verifier has correct public key |
| Signature metadata forged | `algorithm`, `key_id`, `signed_at` are included in the signed payload | None |
| Signing key compromised | Key rotation procedure documented. Old receipts remain verifiable with old public key. | Receipts signed during compromise window are untrustworthy |
| Unsigned receipt accepted as signed | Verifier checks for `signature` object presence and validity | None if verifier is correctly implemented |

### 6. Sandbox Escape

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Kernel vulnerability in namespace implementation | Outside CSC's control. Container runtime and host kernel are trusted. | Real but external |
| bwrap misconfiguration | Launcher argv is constructed programmatically with fixed structure. `--sandbox-debug` allows inspection. | Configuration bugs are possible |
| Container runtime allows namespace bypass | `verify_hardened_runtime()` checks tools are present. Runtime correctness is not verified. | Restrictive seccomp profiles or disabled user namespaces can break bwrap |

### 7. Environment and Infrastructure

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Host root compromise | Out of scope. Documented as "known unsafe if." | Full compromise — no mitigation possible |
| Signing key stolen from runner environment | Key should be in secrets manager/HSM. Never in source control or container image. | Operational control, not CSC enforcement |
| Runner process compromise before sandbox | Python process runs as non-root in container. Sandbox spawn is the enforcement boundary. | If runner process is compromised before spawning sandbox, attacker controls execution |

## Known Unsafe Conditions

CSC hardened mode is **not safe** if any of the following are true:

- Host root is compromised
- Container runtime is compromised or misconfigured
- Sandbox (bubblewrap) is disabled or not functioning
- Policies are mutable without review (attacker can deploy permissive policy)
- Signing keys are unmanaged or stored in plaintext on the host
- Hardened mode is not actually used (local mode makes no security claims)
- The deployment does not match the tested containerized pilot shape (including outer-container network disablement where required by the documented deployment mode)

These are explicit trust assumptions, not weaknesses to be fixed. Users must not deploy CSC outside these assumptions and expect the bounded production claim to hold.

## Maturity Path

| Stage | Trust Level |
|---|---|
| Stage 1b | Structural integrity — deterministic receipts, hash-bound, fail-closed |
| Stage 2 | Signed receipts + kernel-enforced sandbox |
| Stage 3 (current) | Release integrity, security process, pilot validation |
| Future | Syscall filtering (seccomp), durable approval replay prevention, optional PIC adapter |
