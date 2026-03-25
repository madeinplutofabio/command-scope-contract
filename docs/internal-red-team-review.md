# CSC Internal Red-Team Review

## Purpose

This document records a structured internal adversarial review of CSC hardened mode.

This is **not an independent external audit**. It is a maintainer-led review intended to stress the hardened boundary, identify realistic failure modes, and document what was tested, what failed, what was fixed, and what residual risks remain.

Its purpose is to increase project rigor before broader external review.

Independent review is still preferred. For this stage, CSC completed a structured internal red-team review plus a real pilot retrospective, with findings documented and either fixed or explicitly accepted.

## Review Scope

### In scope

- Hardened mode execution path
- `csc_runner/sandbox.py`
- `csc_runner/executor.py`
- `csc_runner/signing.py`
- `csc_runner/approval.py`
- `csc_runner/policy.py`
- CLI hardened-mode path
- Receipt signing and verification
- Approval validation and replay handling
- Filesystem boundary enforcement
- Resource limit enforcement
- CI/runtime compatibility issues affecting hardened mode

### Out of scope

- Local mode beyond sanity checks and claim boundaries
- Third-party infrastructure outside CSC control
- Host-root compromise
- Full kernel exploit research
- Formal cryptographic audit
- Independent third-party validation
- Concurrent approval consumption race (documented as TOCTOU, accepted for Stage 2)
- Timing side-channels in signing/verification

## Review Metadata

- **Reviewer:** Fabio Marcello Salvadori
- **Review type:** Internal red-team / adversarial review
- **Date(s):** 2026-03-24
- **Code baseline:** `12771f1` (main, v0.5.0)
- **CSC version:** v0.5.0
- **Related docs:**
  - `docs/threat-model.md`
  - `docs/deployment-modes.md`
  - `docs/production-readiness-gate.md`
  - `docs/pilot-retrospective.md`
  - `SECURITY.md`

## Review Method

The review attempted to break CSC hardened mode through realistic attacker behaviors and configuration stress cases.

The goal was not to "prove security," but to answer:

- Does the hardened boundary fail closed?
- Are claims mode-specific and honest?
- Can policy, approval, receipt, or sandbox assumptions be bypassed?
- Are failures explainable and auditable?
- Are unsupported environments detected clearly enough?

Some findings below were identified and fixed during the Stage 2–3 hardening cycle and are included here because they were discovered through adversarial review, even if they are not present in the current baseline. Fresh adversarial testing during the review itself produced additional findings (RT-013 through RT-018).

## Test Environment

- **Primary environment:** WSL2 Ubuntu 24.04 on Windows 10 Pro, GitHub Actions ubuntu-latest
- **Container/runtime:** Docker 28.2.2
- **Sandbox backend:** bubblewrap + setpriv + prlimit
- **Execution mode:** hardened
- **Receipt signing:** Ed25519 (standalone `cryptography` library)
- **Policy shape:** bounded filesystem, no network, no writes unless explicitly allowed

## Findings Summary

| ID | Severity | Area | Result | Status |
|---|---|---|---|---|
| RT-001 | High | Runtime | AppArmor blocks bwrap namespace creation in default Docker profile | Fixed (CI) + documented |
| RT-002 | Medium | Runtime | bwrap loopback fails when Docker --network=none combined with --unshare-net | Fixed (CI config) + documented |
| RT-003 | Medium | Sandbox | cwd was automatically mounted writable, overgranting write access | Fixed in code |
| RT-004 | Medium | Executor | preexec_fn unsafe with threads — wrong foundation for hardened mode | Fixed (architecture redesign) |
| RT-005 | Medium | Approval | No cryptographic authentication of approval origin | Accepted for Stage 2 |
| RT-006 | Medium | Approval | Replay prevention is process-local only | Accepted for Stage 2 |
| RT-007 | Low | Sandbox | Command blocking is basename-only, bypassable by renamed binary | Accepted (advisory, not boundary) |
| RT-008 | Low | Signing | Empty signing_key_id passed hardened preflight | Fixed in code |
| RT-009 | Low | Executor | Blocked receipts lost completed command IDs | Fixed in code |
| RT-010 | Info | Sandbox | Interpreter denylist was too enumerated (missed python3.9, pypy) | Fixed (prefix matching) |
| RT-011 | Info | Pipeline | Pipeline stderr from early segments was lost | Fixed (shared capture) |
| RT-012 | Info | Pipeline | Pipeline used Python-mediated stdin, blocking before timeout | Fixed (OS pipes) |
| RT-013 | Low | Schema | Schema allows logically inconsistent receipts (success with exit_code=1) | Accepted (schema is structural) |
| RT-014 | Info | Schema | Schema allows stdout_hash on blocked receipts | Accepted (not enforced as absent) |
| RT-015 | Medium | Sandbox | Null byte in command name bypassed advisory denylist | Fixed in code |
| RT-016 | Info | Pathutil | Unicode homoglyphs pass prefix checks (not exploitable — bwrap fails on nonexistent path) | Accepted |
| RT-017 | Info | Signing | Pre-signed receipt re-signing works correctly — old signature replaced, tampering detected | No issue found |
| RT-018 | Medium | Policy | load_policy() did not enforce MAX_POLICY_SIZE_BYTES | Fixed in code |

## Detailed Findings

### RT-001 — AppArmor blocks bwrap namespace creation

- **Severity:** High
- **Area:** Runtime / deployment compatibility
- **Attack attempted:** Run hardened mode inside a standard Docker container on Ubuntu 24.04 (GitHub Actions)
- **Expected attacker goal:** N/A — this is a compatibility issue, not an attack
- **Observed result:** `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. Default Docker AppArmor profile prevents bwrap from configuring loopback in its network namespace.
- **Impact:** Hardened mode completely non-functional on default Ubuntu Docker without configuration changes.
- **Disposition:** Fixed (CI configuration) + documented
- **Fix / follow-up:** CI uses `--privileged --security-opt apparmor=unconfined`. Added bwrap capability smoke test (`_verify_bwrap_capabilities()`) that fails early with actionable error message. Runtime prerequisites documented in `docs/deployment-modes.md`.
- **Regression coverage:** `tests/test_sandbox.py::TestBwrapSmoke*`

### RT-002 — Docker --network=none conflicts with bwrap --unshare-net

- **Severity:** Medium
- **Area:** Runtime / deployment compatibility
- **Attack attempted:** Run hardened mode with both outer Docker `--network=none` and inner bwrap `--unshare-net`
- **Expected attacker goal:** N/A — compatibility issue
- **Observed result:** bwrap cannot configure loopback when Docker has already stripped network namespace capabilities.
- **Impact:** The "double isolation" configuration (Docker + bwrap) fails. Only one network isolation layer works at a time in some environments.
- **Disposition:** Fixed (CI uses bwrap as primary boundary, outer --network=none is deployment recommendation)
- **Fix / follow-up:** CI workflow does not use `--network=none`. Documentation clarifies bwrap `--unshare-net` is the primary enforcement boundary. Pilot retrospective documents this explicitly.
- **Regression coverage:** CI workflow green without `--network=none`

### RT-003 — cwd mounted writable by default

- **Severity:** Medium
- **Area:** Sandbox / filesystem
- **Attack attempted:** Review sandbox filesystem model — is cwd automatically writable?
- **Expected attacker goal:** Write to any file under cwd even if write_bind_prefixes is restricted
- **Observed result:** Original implementation included cwd in writable roots automatically. A contract with `cwd=/workspace` and `write_bind_prefixes=["/workspace/out"]` would still allow writes anywhere under `/workspace`.
- **Impact:** Filesystem boundary claim was weaker than documented.
- **Disposition:** Fixed
- **Fix / follow-up:** cwd is now read-only unless it falls under an approved writable root. Writable roots come only from `write_bind_prefixes`. Read-only binds skip anything under a writable root.
- **Regression coverage:** `tests/test_sandbox.py::TestBuildHardenedCommand::test_cwd_readonly_when_not_under_writable`

### RT-004 — preexec_fn unsafe with threads

- **Severity:** Medium
- **Area:** Executor / sandbox architecture
- **Attack attempted:** Review whether Python's `preexec_fn` is safe for hardened-mode enforcement
- **Expected attacker goal:** Deadlock or undefined behavior in forked child process
- **Observed result:** Python docs explicitly warn `preexec_fn` can deadlock in multi-threaded parents. CSC's executor uses threads for output capture.
- **Impact:** The entire hardened enforcement layer was built on an unsafe foundation.
- **Disposition:** Fixed (architecture redesign)
- **Fix / follow-up:** Replaced `preexec_fn` with external launcher chain: `bwrap` → `setpriv` → `prlimit` → user command. No Python code runs in the child process. `Popen(preexec_fn=None)`.
- **Regression coverage:** All hardened integration tests use the launcher architecture

### RT-005 — No cryptographic approval authentication

- **Severity:** Medium
- **Area:** Approval
- **Attack attempted:** Forge a structurally valid approval artifact with correct contract_sha256
- **Expected attacker goal:** Execute a contract that requires approval without legitimate authorization
- **Observed result:** A forged approval with valid structure, correct hash, and future expiry passes validation. Stage 2 does not authenticate approval origin cryptographically.
- **Impact:** An attacker with filesystem write access (or control over approval input) can forge approvals.
- **Disposition:** Accepted for Stage 2
- **Fix / follow-up:** Documented in threat model. Future: cryptographic approval signing (HMAC or Ed25519 over approval artifact).
- **Regression coverage:** `tests/test_approval.py` covers hash binding, expiry, and temporal ordering

### RT-006 — Approval replay prevention is process-local

- **Severity:** Medium
- **Area:** Approval
- **Attack attempted:** Restart runner process and reuse a consumed single-execution approval
- **Expected attacker goal:** Execute same contract twice with one approval
- **Observed result:** `InMemoryApprovalStore` is cleared on process restart. The same approval_id can be reused.
- **Impact:** Single-execution scope is not durable across restarts.
- **Disposition:** Accepted for Stage 2 (narrow pilot, single runner)
- **Fix / follow-up:** Documented in `InMemoryApprovalStore` docstring and threat model. Future: persistent backend with atomic `consume_if_unused()`.
- **Regression coverage:** `tests/test_executor.py` covers single-execution consumption within a process

### RT-007 — Command blocking bypassable by renamed binary

- **Severity:** Low
- **Area:** Sandbox
- **Attack attempted:** Rename a blocked interpreter (e.g. copy `python3` to `my_tool`) and execute it
- **Expected attacker goal:** Run an interpreter inside the sandbox despite the denylist
- **Observed result:** The renamed binary would pass `check_command_allowed()` but still run inside the sandbox with all namespace/filesystem/privilege restrictions.
- **Impact:** None beyond what the sandbox already contains. Command blocking is advisory product policy, not a security boundary.
- **Disposition:** Accepted (by design)
- **Fix / follow-up:** Documented explicitly in `docs/deployment-modes.md` and `docs/threat-model.md` as advisory, not enforcement.
- **Regression coverage:** `tests/test_adversarial.py` documents shell=False literal argv behavior

### RT-008 — Empty signing_key_id passed hardened preflight

- **Severity:** Low
- **Area:** Signing / executor
- **Attack attempted:** Call `run_contract()` in hardened mode with `signing_key_id=""`
- **Expected attacker goal:** Execute in hardened mode without proper signing config
- **Observed result:** Original code checked `signing_key_id is None` but not empty string. Execution proceeded, signing failed later.
- **Impact:** "Fail before execution, not after" goal was not fully achieved.
- **Disposition:** Fixed
- **Fix / follow-up:** Changed to `not signing_key_id` (catches both None and empty). Also fixed in `_finalize_receipt()` and CLI signing validation.
- **Regression coverage:** `tests/test_integration_hardened.py::TestSigningEnforcement::test_hardened_with_empty_key_id_blocked`

### RT-009 — Blocked receipts lost completed command IDs

- **Severity:** Low
- **Area:** Executor
- **Attack attempted:** Multi-command contract where command 1 succeeds and command 2 is blocked by path enforcement
- **Expected attacker goal:** N/A — correctness issue
- **Observed result:** `_blocked_receipt()` always emitted `completed_command_ids: []`, erasing real execution history.
- **Impact:** Audit trail was incomplete for partially-executed contracts.
- **Disposition:** Fixed
- **Fix / follow-up:** `_blocked_receipt()` now accepts `completed_ids` and `failed_cmd_id` parameters.
- **Regression coverage:** `tests/test_executor.py::test_blocked_preserves_completed_ids`

### RT-010 — Interpreter denylist was too enumerated

- **Severity:** Info
- **Area:** Sandbox
- **Attack attempted:** Use `python3.9` or `pypy3` which were not in the explicit denylist
- **Expected attacker goal:** Run an interpreter that bypasses the exact-name denylist
- **Observed result:** Only `python`, `python3`, and specific version numbers were blocked. Unlisted versions passed.
- **Impact:** Advisory denylist was incomplete (though sandbox containment is unaffected).
- **Disposition:** Fixed
- **Fix / follow-up:** Changed to prefix matching: `command.startswith(("python", "pypy"))`. Catches all variants.
- **Regression coverage:** `tests/test_sandbox.py::TestCheckCommandAllowed::test_python3_12_blocked`, `test_pypy_blocked`

### RT-011 — Pipeline stderr from early segments lost

- **Severity:** Info
- **Area:** Pipeline / executor
- **Attack attempted:** Run a pipeline where an early segment produces diagnostic stderr
- **Expected attacker goal:** N/A — correctness issue
- **Observed result:** Only the last/failing segment's stderr was captured. Earlier segments' stderr was discarded.
- **Impact:** Diagnostic information lost in receipt.
- **Disposition:** Fixed
- **Fix / follow-up:** Single shared `_CappedCapture` for all pipeline stderr. Thread-safe with `threading.Lock`.
- **Regression coverage:** Pipeline tests verify stderr aggregation

### RT-012 — Pipeline used Python-mediated stdin

- **Severity:** Info
- **Area:** Pipeline / executor
- **Attack attempted:** Review pipeline implementation for correctness
- **Expected attacker goal:** N/A — design review
- **Observed result:** Original pipeline ran segments sequentially, passing `last_stdout.data` as stdin to the next. This meant capped capture limits changed execution behavior (later segments saw truncated input). Also, `proc.stdin.write()` could block before timeout enforcement.
- **Impact:** Receipt capture limits affected execution semantics. Timeout protection was incomplete.
- **Disposition:** Fixed (architecture redesign)
- **Fix / follow-up:** Real OS pipes between segments: `Popen(stdin=prev_proc.stdout)`. Intermediate data flows through kernel pipe buffers. Only final stdout and all stderr captured. Ownership-based cleanup prevents FD races.
- **Regression coverage:** `tests/test_executor.py::test_pipeline_execution`

### RT-013 — Schema allows logically inconsistent receipts

- **Severity:** Low
- **Area:** Schema
- **Attack attempted:** Construct a receipt with `status: "success"` and `exit_code: 1`
- **Expected attacker goal:** Confuse auditors with contradictory receipt fields
- **Observed result:** The receipt passes JSON Schema validation. The schema enforces structural presence of fields (`exit_code` required for success/failed) but not logical consistency between `status` and `exit_code`.
- **Impact:** A malicious or buggy runner could emit a receipt that is schema-valid but logically wrong. Consumers relying only on schema validation would not detect this.
- **Disposition:** Accepted (schema is structural validation, not semantic)
- **Fix / follow-up:** Documented. The executor always produces consistent receipts. Schema consumers should validate semantic consistency independently.
- **Regression coverage:** N/A (schema design decision, not a code bug)

### RT-014 — Schema allows stdout_hash on blocked receipts

- **Severity:** Info
- **Area:** Schema
- **Attack attempted:** Construct a blocked receipt with `stdout_hash` and `stderr_hash` present
- **Expected attacker goal:** N/A — schema strictness exploration
- **Observed result:** Schema does not enforce that blocked receipts must NOT have stdout_hash/stderr_hash. The conditional rule only requires them for success/failed, but does not forbid them for blocked.
- **Impact:** None practical — the executor correctly omits them for blocked receipts. A schema-only consumer would accept them if present.
- **Disposition:** Accepted
- **Fix / follow-up:** Could add a `then: { not: { required: ["stdout_hash"] } }` conditional for blocked, but this adds schema complexity for marginal benefit.
- **Regression coverage:** `tests/test_receipt_integrity.py::test_limits_blocked_has_no_exit_code` verifies executor omits them

### RT-015 — Null byte in command name bypassed advisory denylist

- **Severity:** Medium
- **Area:** Sandbox
- **Attack attempted:** Pass `bash\x00ignored` as a command name
- **Expected attacker goal:** Bypass advisory command blocking by confusing `os.path.basename()`
- **Observed result:** `os.path.basename("bash\x00ignored")` returns `"bash\x00ignored"` (not `"bash"`), which does not match the `"bash"` denylist entry. The command passes the advisory check.
- **Impact:** Advisory denylist was bypassable via null byte injection. The sandbox namespace still contains the command, but the advisory layer failed to flag it.
- **Disposition:** Fixed
- **Fix / follow-up:** Added null byte check for all argv elements before basename extraction: `if any("\x00" in arg for arg in argv): raise SandboxError(...)`.
- **Regression coverage:** `tests/test_sandbox.py::TestCheckCommandAllowed::test_null_byte_in_command_rejected`, `test_null_byte_in_later_argv_rejected`

### RT-016 — Unicode homoglyphs pass prefix checks

- **Severity:** Info
- **Area:** Pathutil
- **Attack attempted:** Use Cyrillic `а` (U+0430) in a path like `/workspace/dаta` to mimic `/workspace/data`
- **Expected attacker goal:** Confuse path matching to access a different directory than intended
- **Observed result:** The homoglyph path passes `path_within_prefixes("/workspace")` because it is genuinely under `/workspace/`. However, it does not match `/workspace/data` because the strings are different.
- **Impact:** Not exploitable. The path would need to exist on the filesystem for bwrap to bind it. A nonexistent homoglyph path would cause bwrap to fail at mount time. No confusion between the real path and the homoglyph.
- **Disposition:** Accepted
- **Fix / follow-up:** Unicode normalization could be added as defense-in-depth but is not needed for the current threat model.
- **Regression coverage:** N/A (not exploitable)

### RT-017 — Pre-signed receipt re-signing behavior

- **Severity:** Info
- **Area:** Signing
- **Attack attempted:** Pass a receipt that already has a `signature` field to `sign_receipt()`, then tamper with `key_id` after signing
- **Expected attacker goal:** Confuse signature verification by mixing old and new signing metadata
- **Observed result:** `sign_receipt()` correctly replaces the old signature metadata with fresh values. After signing, tampering `key_id` from `"real-key"` to `"attacker-key"` correctly invalidates the signature (because `key_id` is in the signed payload).
- **Impact:** No issue found. The signing design (metadata in payload) correctly prevents this class of attack.
- **Disposition:** No issue
- **Regression coverage:** `tests/test_signing.py::TestTamperDetection::test_tampered_key_id_fails`

### RT-018 — load_policy() did not enforce MAX_POLICY_SIZE_BYTES

- **Severity:** Medium
- **Area:** Policy
- **Attack attempted:** Provide an extremely large YAML file as a policy
- **Expected attacker goal:** DoS the runner via unbounded YAML parsing (memory/CPU exhaustion)
- **Observed result:** `MAX_POLICY_SIZE_BYTES` was defined in `csc_runner/limits.py` (524,288 bytes) but never checked in `load_policy()`. Any size file was parsed.
- **Impact:** An attacker with control over the policy file path could cause resource exhaustion by providing a multi-gigabyte YAML file.
- **Disposition:** Fixed
- **Fix / follow-up:** `load_policy()` now reads raw bytes first and checks `len(raw) > MAX_POLICY_SIZE_BYTES` before YAML parsing. Same pattern as contract size enforcement in the CLI.
- **Regression coverage:** `tests/test_policy_loading.py::test_oversized_policy_rejected`

## Attempt Log

### Sandbox / Filesystem

- [x] Attempted read outside declared roots — blocked by bwrap mount namespace
- [x] Attempted write outside declared writable roots — blocked, verified file does not exist
- [x] Attempted cwd traversal / symlink escape — blocked by `resolve_and_check_cwd()`
- [x] Attempted write through nested path tricks — cwd now read-only unless under writable root
- [x] Attempted renamed blocked command — passes advisory check but contained by sandbox
- [x] Attempted null byte in command name — now rejected before basename check

### Approval Handling

- [x] Wrong-contract approval rejected — hash binding check
- [x] Expired approval rejected — temporal validation
- [x] Missing approval rejected when required — `approval_required=True` enforcement
- [x] Replay of consumed approval rejected — `InMemoryApprovalStore` (within process)
- [x] Forged approval artifact assessed — accepted risk (no cryptographic auth in Stage 2)

### Receipt Integrity

- [x] Signed receipt verifies successfully — Ed25519 round-trip
- [x] Tampered receipt rejected — any field change invalidates signature
- [x] Wrong key rejected — different keypair fails verification
- [x] Unsigned receipt not accepted as signed — `VerificationError("missing signature")`
- [x] Signature metadata tampering rejected — `signed_at` and `key_id` are in signed payload
- [x] Pre-signed receipt re-signing — old metadata correctly replaced, tampering detected

### Schema Consistency

- [x] Success with wrong exit_code — schema-valid but logically inconsistent (accepted)
- [x] Blocked with stdout_hash — schema allows it (accepted)

### Path / Unicode

- [x] Path traversal in command name — basename extraction handles `../` correctly
- [x] Unicode homoglyph in path — passes prefix check but not exploitable (nonexistent path fails at mount)

### Resource Exhaustion

- [x] Oversized contract rejected — `MAX_CONTRACT_SIZE_BYTES` check
- [x] Excessive command count rejected — `validate_contract_limits()`
- [x] Long argv elements rejected — byte-count check including multi-byte UTF-8
- [x] Timeout enforced — wall-clock deadline with terminate/kill escalation
- [x] Large stdout capped — `_CappedCapture` with byte limit, hash covers prefix only
- [x] Oversized policy rejected — `MAX_POLICY_SIZE_BYTES` check before YAML parsing

### Runtime / Environment

- [x] Unsupported runtime fails clearly — bwrap smoke test with actionable error
- [x] AppArmor-restricted runtime behavior documented — `docs/deployment-modes.md`
- [x] Host/container network preflight behavior understood — defense-in-depth, not primary boundary
- [x] Hardened preflight catches incompatible environment early — `_verify_bwrap_capabilities()`

## What Held Up Well

- **Filesystem boundary held under all attempted breakout scenarios.** bwrap mount namespace correctly restricts visibility and writability.
- **Receipt tampering was detected correctly in all cases.** Ed25519 signature covers all receipt fields plus signing metadata.
- **Approval hash binding prevented wrong-contract misuse.** SHA-256 binding is checked before any execution.
- **Shell metacharacters are literal.** `shell=False` in all Popen calls. Semicolons, backticks, `$()`, pipes are all passed as literal argv elements.
- **Environment is aggressively filtered.** Only PATH and minimal system vars are passed. Secrets like AWS_SECRET_ACCESS_KEY are confirmed absent.
- **Fail-closed behavior on signing config errors.** Hardened mode rejects missing or invalid signing config before any execution.
- **Signing metadata is authenticated.** Tampering key_id or signed_at after signing invalidates the signature.

## Weaknesses Identified

- **Approval forgery is possible** with filesystem write access (no cryptographic approval authentication)
- **Approval replay prevention is process-local** (not durable across restarts)
- **Command blocking is advisory** (renamed binaries bypass it; sandbox is the real boundary)
- **No syscall filtering** (seccomp not implemented)
- **Receipt signing does not prove sandbox configuration** (integrity only, not runtime attestation)
- **CLI lacks `--skip-network-check` flag** (operators must use Python API for non-standard network environments)
- **Some Linux runtimes require explicit AppArmor/container configuration** for bwrap to function
- **Schema does not enforce semantic consistency** between status and exit_code

## Fixes Made During or After Review

- `csc_runner/sandbox.py`: cwd read-only by default, prefix-matched interpreter blocking, bwrap smoke test, writable root collapse, **null byte rejection in all argv elements**
- `csc_runner/executor.py`: OS-pipe pipelines, ownership-based cleanup, shared stderr capture, approval consumption timing, signing config validation (empty key_id), blocked receipt preserves completed IDs, `_finalize_receipt()` for all paths
- `csc_runner/signing.py`: canonicalization error wrapping, empty key_id rejection at sign time
- `csc_runner/approval.py`: `AttributeError` catch in `_parse_dt`, format checker on schema validator
- `csc_runner/policy.py`: **MAX_POLICY_SIZE_BYTES enforcement before YAML parsing**
- `.github/workflows/hardened-tests.yml`: `--privileged --security-opt apparmor=unconfined`
- `docs/deployment-modes.md`: runtime prerequisites, AppArmor compatibility notes

## Residual Risks

These issues remain after the internal review and are either accepted for the bounded claim or explicitly deferred:

- Durable approval replay prevention is not implemented
- Seccomp is not implemented
- Hardened mode remains Linux-only
- Some Linux runtimes may require AppArmor/container configuration for bwrap
- Advisory command blocking is not a security boundary
- Receipt signing proves integrity, not correct runtime configuration
- Approval origin is not cryptographically authenticated
- Schema allows logically inconsistent receipts (structural validation only)

## Claim Impact

### Does this review invalidate the bounded production claim?

**No**, provided CSC is deployed only within the documented bounded shape and runtime prerequisites.

### What does this review support?

This review supports the narrower claim that:

> CSC hardened mode is safe enough for bounded production use in Linux-based, filesystem-bounded local/CI execution workflows without network access, under the documented trust assumptions and deployment constraints.

### What does this review not support?

- General-purpose sandboxing claims
- Cross-platform hardened-mode claims
- Independent third-party assurance
- Host-compromise resistance
- Multi-tenant isolation claims

## Recommended Next Steps

1. Obtain at least one independent external or peer review
2. Add durable approval replay prevention
3. Evaluate seccomp as a second defense layer
4. Add CLI `--skip-network-check` flag for non-standard environments
5. Improve runtime compatibility diagnostics
6. Keep the support matrix and deployment prerequisites explicit

## Conclusion

This internal red-team review did not replace independent review, but it did materially improve confidence in CSC hardened mode by forcing adversarial testing of the actual execution boundary, receipt integrity model, approval handling, and deployment assumptions.

The review produced 18 findings: 10 fixed in code or architecture (including 2 found during fresh adversarial testing), 5 accepted as documented design decisions or known limitations, and 3 informational with no action needed.

The review should be read together with:

- `docs/threat-model.md`
- `docs/pilot-retrospective.md`
- `docs/production-readiness-gate.md`
- `SECURITY.md`
