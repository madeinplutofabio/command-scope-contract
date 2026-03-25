# Current Task: bwrap runtime capability smoke test

## Context

CI revealed bwrap fails on AppArmor-restricted Ubuntu with `RTM_NEWADDR: Operation not permitted`. Error surfaces as generic command failure — no actionable guidance for operators.

## Change

Add `_verify_bwrap_capabilities()` to `csc_runner/sandbox.py`. Verifies runtime supports the hardened namespace boundary, not just binary presence.

### `csc_runner/sandbox.py`

- Add `import subprocess` at top
- New function `_verify_bwrap_capabilities()`:
  - Runs representative probe: `bwrap --unshare-net --proc /proc --dev /dev --ro-bind /usr /usr --ro-bind /bin /bin -- /bin/true`
  - Timeout: 5 seconds
  - On failure: raises `SandboxError` with diagnostic message:
    - "hardened mode runtime check failed: bubblewrap could not create the required namespace sandbox"
    - Common causes: AppArmor-restricted Ubuntu, container runtime confinement, disabled user namespaces, restrictive seccomp
    - Points to `docs/deployment-modes.md`
    - Includes bwrap stderr for debugging
- Called from `verify_hardened_runtime()` after `verify_tools()`, before network check
- Order: config → platform → tools → bwrap capability → optional network

### `tests/test_sandbox.py`

- `test_bwrap_smoke_success` — monkeypatch `csc_runner.sandbox.subprocess.run` to return rc=0, verify no error
- `test_bwrap_smoke_failure_gives_clear_error` — monkeypatch to return rc=1 with stderr, assert SandboxError contains "runtime check failed" and "deployment-modes"
- Not brittle on exact argv — test the error behavior, not the probe command

### Verification

- `python -m pytest tests/test_sandbox.py -v`
- `ruff check csc_runner/sandbox.py tests/test_sandbox.py`

---

# Stage 3 — Implementation Sequence

## Context

Stage 1a (Protocol Complete), Stage 1b (Hardened Defaults), and Stage 2 (First Hardened Mode) are committed. The runner now has: conformance suite, policy schema with reason codes, resource limits, path enforcement, capped capture, OS-pipe pipelines, adversarial tests, receipt integrity, Ed25519 receipt signing, approval artifacts with replay prevention, Linux sandbox backend (bubblewrap + setpriv + prlimit), hardened CLI with `--mode hardened --sign --sandbox-debug`, Dockerfile, and end-to-end hardened integration tests.

Stage 3 goal: **production candidate** — release infrastructure, security process hardening, CI automation, and at least one real pilot with retrospective.

## Guiding Principles

1. **Do not regress the Stage 2 security boundary.** Kernel-enforced sandbox, signed receipts, approval hash-binding — these are non-negotiable.
2. **Keep mode-specific claims honest.** Local mode is not hardened. Hardened mode has documented limitations.
3. **Keep CSC core standalone while preserving PIC-shape compatibility.** No PIC hard dependency. Optional adapter only.
4. **Stage 3 is both engineering hardening and release/security-process hardening.** Not just more code — also CI gates, vulnerability management, release signing, and external review.

## Execution Order

### Step A: `docs/production-readiness-gate.md` (NEW)
- The coordinating artifact for Stage 3 — created first, not last
- Formal checklist: every item must pass before the bounded production claim
- References all other gate items (threat model, CI, review, pilot retrospective)
- Living document updated as items are completed

### Step B: `.github/workflows/hardened-tests.yml` (NEW)
- CI workflow for hardened integration tests — before release automation
- Builds Docker image, runs tests on Linux (`docker run --network=none`)
- Required gate: hardened tests must pass for production claim
- Standard test suite also runs (non-Docker) on the same runner
- Windows/macOS: standard tests only (hardened tests skip automatically)
- Must be green before any release workflow is meaningful

### Step C: Release integrity + supply chain
- Signed releases/tags (GPG or sigstore)
- Provenance attestations (SLSA — start with provenance discipline, not full SLSA 3)
- SBOM generation for releases (`cyclonedx-bom` or `syft`)
- Dependency scanning in CI (`pip-audit` or equivalent)
- Pinned CI action versions
- PyPI trusted publishing
- Signed wheel/sdist release process
- `.github/workflows/release.yml`

### Step D: Vulnerability management + security process
- `SECURITY.md` — full vulnerability management process
- `.github/SECURITY_ADVISORY_TEMPLATE.md` — advisory template
- `.github/SECURITY_RELEASE_TEMPLATE.md` — security release notes template
- Severity rubric documented
- Fix/SLA targets documented
- Regression tests for every security bug

### Step E: Repo settings + ecosystem hygiene
- **Files/workflows in git:**
  - Dependabot configuration (`.github/dependabot.yml`)
  - CI workflow updates (required check names)
- **GitHub repo configuration (outside git):**
  - Branch protection rules
  - Required CI checks for PRs
  - Security advisories enabled on the repository
  - Dependency graph + alerts enabled
- OpenSSF Best Practices / OSPS baseline passing

### Step F: Documentation alignment
- `docs/threat-model.md` — populate (exists as placeholder, needs real content: threat classes, mitigations, residual risks)
- `docs/deployment-modes.md` — update only if Step H ships
- `README.md` — align with production status (currently bootstrap/minimal; needs to reflect hardened-mode availability and bounded production claim after pilot)
- Update `docs/production-readiness-gate.md` with final status

### Step G: External review + pilot retrospective
- At least one independent review: external security review preferred, internal red-team acceptable if documented and credible
- Findings tracked in issues, fixed or explicitly accepted with rationale
- At least one real user ran it in a production-like workflow
- Publish limitations honestly
- Pilot retrospective written

### Step H: Network enforcement — ONLY IF PILOT DEMANDS IT
- `csc_runner/network.py` — egress control beyond `--unshare-net`
- `tests/test_network.py`
- **Do not add this just because it is "Stage 3."** The strongest current claim is "no network." That is much easier to defend than "network, but allowlisted."
- **If this ships, define the enforcement boundary tightly first:**
  - Whether literal IPs are allowed
  - How DNS is resolved (stub resolver? system resolver? none?)
  - Whether redirects are followed
  - Whether the control point is the sandbox, a proxy, or both
  - What exactly is logged as a violation
- Without those answers, the feature becomes broader and weaker than intended.

## CI Fix: bwrap loopback failure

### Problem
bwrap 0.8.0 `--unshare-net` fails inside Docker containers (even `--privileged`) with:
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`
bwrap tries to configure loopback in its new network namespace, which requires capabilities that don't propagate into nested namespaces on GH Actions runners.

### Fix
1. `csc_runner/sandbox.py`: Add `unshare_net: bool = True` to `SandboxConfig`. When `False`, skip `--unshare-net` in bwrap argv. Default `True` (production unchanged).
2. `tests/test_integration_hardened.py`: Use `SandboxConfig(require_network_disabled=False, unshare_net=False)`. Network isolation in CI provided by outer Docker container.
3. `.github/workflows/hardened-tests.yml`: Restore `--network=none` on Docker run (outer container enforces). Keep `--privileged`. Remove debug steps.
4. `tests/test_sandbox.py`: Add test for `unshare_net=False` argv.
5. Network test: verify outer container has no connectivity when `unshare_net=False`.

### Files
- `csc_runner/sandbox.py`
- `tests/test_integration_hardened.py`
- `tests/test_sandbox.py`
- `.github/workflows/hardened-tests.yml`

## Stage 3 Exit Criteria

- [ ] `docs/production-readiness-gate.md` exists and all items pass
- [ ] CI workflow for hardened integration tests (required gate, green)
- [ ] Signed releases with provenance and SBOM
- [ ] Security advisory process active
- [ ] `docs/threat-model.md` populated with real content
- [ ] `README.md` aligned with production status
- [ ] Adversarial suite passes
- [ ] At least one pilot completed with retrospective
- [ ] At least one independent review completed (external preferred, internal red-team acceptable if credible)
- [ ] No open high/critical security issues for the supported bounded deployment shape
- [ ] Bounded production claim: "safe enough for bounded production use under documented constraints" — Linux hardened mode, filesystem-bounded local/CI, no network

## Files Summary

| File | Action |
|---|---|
| `docs/production-readiness-gate.md` | New — formal release gate checklist (FIRST) |
| `.github/workflows/hardened-tests.yml` | New — CI for hardened integration tests |
| `.github/workflows/release.yml` | New — signed release workflow with provenance + SBOM |
| `SECURITY.md` | Update with full vulnerability management process |
| `.github/SECURITY_ADVISORY_TEMPLATE.md` | New — advisory template |
| `.github/SECURITY_RELEASE_TEMPLATE.md` | New — security release notes template |
| `.github/dependabot.yml` | New — dependency update automation |
| `docs/threat-model.md` | Populate — threat classes, mitigations, residual risks |
| `docs/deployment-modes.md` | Update only if Step H ships |
| `README.md` | Update — align with production status |
| `csc_runner/network.py` | New — ONLY if pilot demands egress control |
| `tests/test_network.py` | New — ONLY if Step H ships |

---

# Stage 2 — Implementation Sequence

## Context

Stage 1a (Protocol Complete) and Stage 1b (Hardened Defaults) are committed. 245 tests pass, lint clean. The reference runner now has: conformance suite, policy schema with reason codes, resource limits, path enforcement, capped capture with OS-pipe pipelines, ownership-based cleanup, adversarial tests, and receipt integrity verification.

Stage 2 goal: pick one pilot use case, build only what it needs. The official target is **filesystem-bounded local/CI execution, no network, Linux only**.

## Design Decisions

1. **Network disabled in hardened mode (Stage 2, not Stage 3).** The pilot claim is "no network." The production enforcement is `bwrap --unshare-net` (network namespace isolation). Python-side interface checks (`verify_network_disabled`) are a preflight sanity check only, not the security boundary. Integration tests must prove network absence from inside the sandbox. Full allowlist/egress engine deferred to Stage 3.

2. **Standalone CSC signing, PIC-compatible interfaces.** Step 4 uses `cryptography` directly for Ed25519. CSC-native resolver protocol (`PublicKeyResolver`). Optional PIC adapter deferred to extras. No hard PIC dependency in CSC core.

3. **Approval before sandbox spawn.** Integration order in Step 7: load contract → load policy → evaluate policy → validate approval → spawn sandbox → execute → sign receipt. Replay checks are cheap; sandbox startup is not.

4. **Secrets explicitly deferred.** Step 8 stays in plan but is skipped for the first pilot. Stage 2 exits cleanly without secrets if approval + hardened mode + signing + integration tests are solid.

5. **Security boundary = kernel-enforced sandbox, not Python child hooks.** Python's `preexec_fn` is unsafe with threads and is the wrong foundation for hardened-mode claims. Enforcement uses Linux-native tools: bubblewrap (namespace/filesystem isolation), setpriv (privilege drop, `--no-new-privs`, `--clear-groups`), prlimit (resource limits). Python-side command denylisting is advisory product policy only, not part of the security boundary.

6. **Command blocking is advisory, not enforcement.** `check_command_allowed()` is a product-policy lint layer. The real containment is the sandbox: restricted filesystem view, dropped privileges, no privilege gain, isolated namespaces. A renamed binary bypasses basename checks but cannot escape the sandbox.

7. **Hardened pilot is tied to the shipped container image layout.** The visible filesystem, available runtime binaries, and `bwrap`/`setpriv`/`prlimit` versions are image-dependent. The pilot claim applies to the tested container image only — not arbitrary Linux host compatibility. This is acceptable for Stage 2; broader host support can follow.

## Execution Order

Code-first, docs interleaved. Least-risk path to Stage 2 exit.

### Step 1: `schemas/csc.approval.v0.1.schema.json` (NEW)
- Approval artifact schema
- Fields: approver identity, timestamp, scope, expiry, contract_sha256 binding, optional ticket/change-request ID
- Zero code dependencies — pure schema

### Step 3: `csc_runner/approval.py` (NEW) + `tests/test_approval.py` (NEW)
- Approval artifact model — schema validation, semantic checks
- Hash-bound to contract_sha256 (prevents wrong-contract replay)
- Expiry enforcement (expires_at > approved_at, not expired at validation time)
- Temporal ordering validation
- Required for human_required and policy-classified sensitive effects
- Single-approver only (dual control deferred)
- **Note:** single-execution replay prevention (consuming `approval_id` so it cannot be reused on the same contract) belongs in Step 7 integration, not here. This module validates the artifact; the executor tracks consumption.
- ~22 tests: valid approval, expired, wrong hash, missing fields, schema validation, temporal edge cases

Depends on: Step 1 (schema)

### Step 4: `csc_runner/signing.py` (NEW) + `tests/test_signing.py` (NEW)
- Standalone `cryptography` implementation — Ed25519 sign/verify
- CSC-native `PublicKeyResolver` protocol (PIC-compatible shape, no PIC dependency)
- `StaticKeyResolver` for testing and single-key deployments
- Optional PIC adapter deferred to `csc-runner[pic]` extras
- Signing metadata (algorithm, key_id, signed_at) authenticated in the signed payload
- ~27 tests: sign/verify round-trip, tamper detection (including signed_at/key_id tampering), wrong key, malformed signatures, error wrapping

Depends on: nothing (standalone, `cryptography` library only)

### Step 6: `csc_runner/sandbox.py` (REWRITE) + `tests/test_sandbox.py` (NEW)

Linux sandbox backend — kernel-enforced boundaries, no Python child hooks.

**What this file does:**
- Verify hardened prerequisites once at startup:
  - Linux only
  - Required binaries present: `bwrap`, `setpriv`, `prlimit`
- Build a hardened launcher argv (not a Python preexec_fn)
- Advisory command-name blocking (product policy, not security enforcement)

**Public surface:**
- `SandboxConfig` — resource limits, UID/GID, filesystem binds, blocked commands
- `verify_hardened_runtime(config) -> None` — pre-flight: Linux, tools, network
- `check_command_allowed(argv, config) -> None` — advisory basename denylist
- `build_hardened_command(user_argv, *, cwd, read_prefixes, write_prefixes, config) -> list[str]`

**Launcher chain:**
```
bwrap \
  --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin --ro-bind /etc /etc \
  --bind <workspace> <workspace> \
  --tmpfs /tmp --proc /proc --dev /dev \
  --unshare-net --unshare-pid --new-session \
  -- \
setpriv --reuid=<uid> --regid=<gid> --clear-groups --no-new-privs -- \
prlimit --cpu=<sec> --as=<bytes> --nproc=<count> --fsize=<bytes> -- \
<user command argv...>
```

- `bwrap`: mount namespace with explicit visible filesystem, writable only in workspace, network namespace isolated, pid namespace isolated
- `setpriv`: privilege drop, supplementary groups cleared, `--no-new-privs`
- `prlimit`: resource limits (CPU, address space, processes, file size)
- If no privilege drop configured, omit `setpriv` segment
- Command blocking is advisory basename check only — documented as product policy, not security claim

**Tests (~15-18):**
- Launcher argv construction (with/without privilege drop)
- Prerequisite verification (missing tools, non-Linux, network present)
- Config validation (zero limits, UID without GID, etc.)
- Command blocking (shells, interpreters, wrappers, prefix-matched python variants)
- Filesystem bind construction (read-only vs writable paths)

Depends on: nothing (standalone, Linux-specific)

### Step 6b: seccomp profile (OPTIONAL, can defer to post-pilot)

- Conservative syscall allowlist for the pilot use case
- `sandbox/seccomp-default.json` or similar
- Applied via `bwrap --seccomp` or standalone `seccomp-bpf` loader
- Tests that prove syscall denials fail cleanly
- Second defense layer, not primary boundary

### Step 7: `csc_runner/executor.py` (MODIFY) + `csc_runner/cli.py` (MODIFY)

**Executor changes:**
- Local mode: current execution path unchanged
- Hardened mode integration order:
  1. Validate mode string — reject anything except `"local"` and `"hardened"`
  2. If `approval_required=True` and `approval is None` → fail closed (blocked receipt)
  3. Validate approval artifact (if provided) — hash binding, expiry, temporal ordering
  4. Check consumed-approval registry: reject `scope=single_execution` approvals already consumed. Mark consumed only right before first subprocess spawn.
  5. Reject hardened mode without signing config (private_key_bytes + signing_key_id)
  6. Verify sandbox runtime once (`verify_hardened_runtime`)
  7. Check resource limits
  8. For each command: path checks → `check_command_allowed` (advisory) → `build_hardened_command`
  9. Consume approval right before first subprocess spawn
  10. `Popen(hardened_argv, preexec_fn=None, shell=False, ...)`
  11. Finalize receipt through `_finalize_receipt()` — signs if configured, fail-closed in hardened mode on signing failure
- All receipts go through `_finalize_receipt()` — blocked, failed, and success
- `approval_required: bool = False` parameter added to `run_contract()`
- `_consume_approval()` helper defined in this file

**CLI changes:**
- `--mode local|hardened` flag
- `--approval PATH` artifact input
- `--sign` / `--signing-key PATH` options
- `--sandbox-debug` for printing composed launcher argv (dev/test only). Mirrors real hardened path: runs `verify_hardened_runtime()` first, rejects pipelines as BLOCKED (not SKIP), uses same path/scope checks as executor.
- Update existing tests for new flags

Depends on: Steps 3, 4, 6

### Step 10: `Dockerfile` (NEW) + `tests/test_integration_hardened.py` (NEW)

**Dockerfile installs:**
- bubblewrap
- util-linux (provides `setpriv`, `prlimit`)
- CSC runner + dependencies

**End-to-end tests prove:**
- Writable access only inside approved workspace
- Writes outside workspace fail
- Network unavailable inside hardened sandbox (namespace, not just interface check)
- Receipt signed and verifiable
- Approval mismatch rejected
- Expired approval rejected
- Denial paths are deterministic and auditable
- `no_new_privs` is set before user command exec

Depends on: Steps 6, 7

### Docs (interleaved alongside implementation)
- `docs/deployment-modes.md` — local vs hardened, security claims per mode, sandbox architecture, network-disabled requirement
- `docs/key-management.md` — rotation cadence, compromise runbook, CSC signing independence
- `docs/policy-packs.md` — pack lifecycle, versioning, compatibility, signing, deprecation

### Step 8: `csc_runner/secrets.py` — DEFERRED
- Explicitly skipped for first pilot
- Stays in plan for future pilots that require runtime secrets
- Stage 2 exits cleanly without this

### Step 11: Pilot success criteria verification
- Process runs in a private filesystem view (bubblewrap mount namespace)
- Writable paths bounded to approved workspace
- Privilege escalation blocked with `no_new_privs`
- Network absent by namespace enforcement, not only interface inspection
- Resource limits applied by `prlimit`
- Receipt signing works and verifies
- Approval is hash-bound and replay-safe
- Command-name blocking documented as advisory policy, not enforcement
- All denials explainable
- No silent crashes
- Acceptable performance bounds
- Retrospective written

## Stage 2 Exit Criteria

- [ ] Hardened mode exists for one use case (Linux, filesystem-bounded, no network)
- [ ] Filesystem view explicitly constructed by bubblewrap (mount namespace)
- [ ] Writable paths bounded to approved workspace
- [ ] Privilege escalation blocked (`no_new_privs`, `setpriv`)
- [ ] Network absent by namespace enforcement
- [ ] Resource limits enforced by `prlimit`
- [ ] Approvals are hash-bound and non-replayable
- [ ] Receipts are signed in hardened mode
- [ ] Command blocking is documented as advisory policy only
- [ ] Policy-pack lifecycle documented
- [ ] End-to-end hardened-mode integration tests pass in CI
- [ ] Pilot success criteria met
- [ ] Secret access (if needed) is brokered and redacted

## Working Rules (same as 1a/1b)

- File-by-file approval: show full drop-in, wait for "APPROVED"
- User commits manually
- One file at a time until approved

---

# CSC Production Readiness Plan (reference)

## Context

CSC v0.1.0 is scaffolded and passing CI. The goal is to define and execute a production-readiness path that is SSDF-aligned, OpenSSF/OSPS-hygienic, SLSA-provenance-aware, and structurally aligned with PIC (Provenance & Intent Contracts, v0.7.1 at /c/projects/pic-standard).

PIC is the more mature sibling project — shipping Python SDK, 4 integrations (LangGraph, MCP, OpenClaw, Cordum), Ed25519 evidence verification, 7-class impact taxonomy, causal taint semantics, and a defensive-publication RFC. CSC should build on PIC's existing foundations where possible, not reinvent them.

"Production-ready" is defined by a formal gate: `docs/production-readiness-gate.md`. No claim is made until every item passes.

## Stage 1a — Protocol Complete

**Goal:** CSC becomes a real protocol, not just a repo with code.

### 1. Freeze spec + schemas
- Lock `docs/spec-v0.1.md` and all three schemas
- Changelog rule: spec changes require an RFC
- Define normative source of truth: spec + schemas + conformance tests
- Everything else is reference implementation behavior unless promoted

### 2. Conformance suite
- Valid/invalid contract fixtures
- Policy decision fixtures
- Receipt fixtures
- Cross-platform path fixtures (POSIX, Windows, UNC, mixed-flavour denial)
- Exec vs pipeline edge cases
- Approval-mode cases
- **Exit:** every normative rule maps to ≥1 conformance test; a second implementation could prove compatibility

### 3. Policy schema + decision reason codes
- JSON Schema or YAML schema for policy files
- Validate policies on load — malformed policy cannot load
- Require: name, allowed commands, allowed effect types, risk classes, path prefixes
- Add `policy_schema_version` field
- Structured reason codes in PolicyDecision — not just free text:
  - `RISK_CLASS_NOT_ALLOWED`, `COMMAND_NOT_ALLOWED`, `ARGV_PREFIX_DENIED`
  - `NETWORK_EXCEEDS_POLICY`, `WRITE_SCOPE_DENIED`, `READ_SCOPE_DENIED`
  - `APPROVAL_REQUIRED`, `EFFECT_TYPE_NOT_ALLOWED`, `PATH_NOT_ABSOLUTE`
  - `CWD_NOT_ALLOWED`, `TIMEOUT_EXCEEDS_POLICY`, `SECRET_REF_NOT_ALLOWED`
- Free text reasons kept for humans (non-normative); `reason_codes` list for automation, dashboards, stable audit analysis, cross-version compatibility
- Reason codes are stable API surface: new codes may be added; existing codes are never renamed without a spec version bump
- Reason-code registry: `docs/reason-codes.md` — for each code: name, meaning, when emitted, deny/approval/failure orientation, backward-compatibility note
- Engine stays structural (evaluation, reason codes, fail-closed, versioned semantics)
- Domain-specific classification lives in profiles/packs, not the engine

### 4. Versioning and migration
- Contracts carry explicit version
- Receipts carry explicit `receipt_version` field — not convention, a real field for parsers and future migrations
- Runner supports an explicit set of versions
- No negotiation in v0.x — accept or reject with clear version error
- Receipt version stability rule: a v0.1 receipt remains valid and parseable forever, even when contract format evolves — receipts are immutable audit artifacts
- Patch-level compatibility documented but dispatcher is explicit
- Coordinate with PIC Canonical JSON v1 when it ships — CSC's `hash_contract()` (`sort_keys=True, separators=(",",":")`) is already a canonicalization decision

### 5. PIC alignment (RFC-0002 + mapping doc)
- RFC-0002: PIC Alignment and Mapping — answers:
  - CSC is normatively independent of PIC
  - CSC is structurally aligned with PIC
  - Shared fields/artifacts mapped explicitly
- PIC import boundary (explicit policy):
  - May import directly: evidence signing/verification, keyring/resolver
  - May align conceptually but not import: impact taxonomy, causal taint semantics
  - Must remain CSC-native: shell execution schema, pipeline semantics, runtime enforcement, receipt semantics
- The mapping doc (`docs/pic-mapping.md`) is the normative artifact the RFC produces:
  - `CommandContract.intent` → PIC proposal intent
  - CSC `effect_type` → PIC impact class (7 classes: read/write/external/compute/money/privacy/irreversible) — document differences
  - `ExecutionReceipt` → no PIC equivalent yet (PIC audit logs planned Phase 2) — CSC can contribute this concept back
  - `contract_sha256` → PIC SHA-256 evidence model
  - CSC approval artifacts → PIC trusted bridge pattern
  - CSC receipt signing → PIC `evidence.py` (SHA-256 + Ed25519)
  - CSC trust roots → PIC `keyring.py` (expiry, revocation, KeyResolver)
  - Long-term: CSC as a PIC execution-boundary profile for shell/CLI

### 6. Receipt field semantics
- Define every receipt field's meaning normatively
- Distinguish "blocked before execution" vs "failed during execution"
- Classified effect metadata, wall-clock timing, timeout cause
- Policy provenance in receipts: `policy_schema_version`, `policy_profile`, `policy_sha256` — so auditors can answer "which exact policy version made this decision?"
- Runner provenance in receipts: `runner_version`, `execution_mode` (local/hardened), `sandbox_profile_id` (when applicable), `signing_key_id` (when signed) — makes receipts operationally useful

### 7. Security target / claims matrix + "known unsafe if…"
- Explicit artifact stating what CSC protects against, what it doesn't, in which mode, for which deployment shape
- Dimensions: local/dev mode, hardened mode, no-network pilot, with approvals, with signed receipts
- Rows: shell metainterpreters, path breakout, symlink escape, env leakage, egress, receipt tampering, stale approval replay, malicious stdout, insider with host root, compromised container runtime
- "Known unsafe if…" section — explicitly document invalid assumptions:
  - Unsafe if host root is compromised
  - Unsafe if sandbox is disabled
  - Unsafe if policies are mutable without review
  - Unsafe if signing keys are unmanaged
  - Unsafe if hardened mode is not actually used
  - Without these, people project their own assumptions onto CSC

### 8. Support matrix
- `docs/support-matrix.md`
- Supported OSes, Python versions, path flavours, deployment modes
- Which features are experimental, which combinations are unsupported
- First bounded production claim applies to Linux hardened mode only — stated explicitly here and in deployment-modes and production-readiness-gate

### 8b. Protocol/runner compatibility matrix
- `docs/compatibility-matrix.md`
- Which runner versions support which contract versions
- Which runner versions emit which receipt versions
- Which policy schema versions are accepted by which runner versions

### 9. Canonicalization spec
- `docs/canonicalization.md` — standalone artifact, not just code behavior
- Contract hashing rules, receipt hashing/signing rules, policy hashing rules
- Policy hash source explicitly defined: hash over normalized parsed representation (not raw YAML bytes) — specify exact canonical form so policy provenance is deterministic across implementations
- Unicode normalization stance, line ending stance, ordering rules, null/omitted-field rules
- Aligned with PIC Canonical JSON v1 direction

**Stage 1a exit criteria:**
- ✅ Spec and schemas frozen
- ✅ Conformance suite exists with golden fixtures
- ✅ Policy schema validated on load (with version field)
- ✅ Versioning rules documented (including receipt stability)
- ✅ Compatibility matrix published (runner↔contract↔receipt↔policy versions)
- ✅ Reason-code registry published
- ✅ RFC-0002 accepted, PIC mapping doc published (with dependency decision gate)
- ✅ Receipt semantics normatively defined (including policy provenance + runner provenance)
- ✅ Security target matrix published
- ✅ Support matrix published
- ✅ Canonicalization spec written (including policy-hash source rules)

## Stage 1b — Hardened Defaults

**Goal:** the reference runner fails closed and enforces boundaries.

### 10. Failure-mode normalization
- Every failure mode produces a valid receipt:
  - timeout, file not found, bad cwd, permission denied, sandbox violation, policy violation
- Fail closed on enforcement uncertainty
- No silent crashes — malicious or malformed contract always yields a receipt

### 11. Filesystem / path enforcement (absorbs former "path handling" item)
- Contract/schema path syntax (already done: `$defs/absolutePath`)
- Flavour-aware normalization (already done in `policy.py`)
- New: executor-side real path resolution for cwd before execution
- Reject symlink escapes and `..` traversal in cwd after resolution
- Normalize and fail-close declared read/write scopes (prefix check against literal portion before glob metacharacters; no syscall-level runtime file-access enforcement — that belongs to Stage 2 hardened mode)
- Path semantics in spec: POSIX case-sensitive, Windows case-insensitive, mixed-flavour fail-closed, UNC only if policy allows
- Tests: `C:\Work\App` vs `c:\work\app`, `/workspace` vs `/workspace-evil`, symlink breakout, `..` traversal, UNC, globs with absolute prefixes

### 12. Resource exhaustion controls + DoS/performance budgets
- Runner-side enforcement independent of schema:
  - Max command count, max pipeline depth, max argv length
  - Max total contract size in bytes, max justification length
  - Max receipt/error payload length
  - Time budget (already partially done with deadline-based pipeline timeout)
- Explicit measurable budgets for:
  - Max contract size, max policy size, max receipt size
  - Max classification time, max validation time
  - Max signing/verifying time (when added)
  - Max sandbox startup time (when added)
- Test every budget

### 13. Receipt integrity baseline
- Deterministic receipt structure
- Hash-bound to contract (`contract_sha256` already present)
- Distinguish "receipt signed" from "receipt trusted":
  - Signing proves integrity and signer identity
  - Does not by itself prove sandbox was correctly configured
  - Document separately: receipt integrity vs runtime trust assumptions
- Maturity path: Stage 1b structural integrity → Stage 2 signed/HMAC → Stage 3 verifiable attestation

### 14. Rollback / emergency-disable
- Emergency policy disable path (deny-all mode)
- Runner kill switch
- Revocation process for receipt signing keys (when added)
- Rollback guidance for hardened mode deployments (when added)

### 15. Adversarial tests
- Shell escape attempts, policy confusion
- Malformed / mixed-flavour path tricks, symlink escapes
- Env leakage, stdout prompt-injection content
- command-not-found and cwd failures, timeout abuse
- Oversized contracts (resource exhaustion), Unicode and case edge cases
- Suspicious curl / package-manager patterns
- Every bug found → regression test in CI

**Stage 1b exit criteria:**
- ✅ All failure modes produce receipts
- ✅ Executor resolves real paths and enforces filesystem boundaries
- ✅ Resource exhaustion controls enforced with measurable budgets
- ✅ Receipts are hash-bound and deterministic
- ✅ Emergency-disable path exists
- ✅ Adversarial test suite passes in CI

## Stage 2 — First Hardened Mode (one use case)

**Goal:** pick one pilot, build only what it needs.

Official production-candidate target: **filesystem-bounded local/CI execution, no network, Linux only**. Network enforcement, secrets, and Windows hardened mode can truly wait unless a real pilot demands them. This keeps hardened mode simpler to reason about and matches container/sandbox reality.

### 16. Process isolation
- Run as low-privilege user
- Bounded env (aggressive filtering already started)
- CPU / memory / process / time limits
- Disable shell metainterpreters by default
- Deterministic failure receipts for sandbox violations

### 17. Single-approver approval artifact
- Approval object bound to `contract_sha256` (prevents wrong-contract use)
- Fields: approver identity, timestamp, scope, expiry, optional ticket/change-request ID
- Schema validation + semantic checks (hash binding, expiry, temporal ordering)
- Single-execution replay prevention (consumed-approval registry) belongs in executor integration, not the artifact model
- Required for `human_required` and policy-classified sensitive effects
- Dual control deferred — ship single-approver first, learn from pilot

### 18. Secret model (only if pilot needs it)
- Secret provider interface
- Short-lived fetch at execution time, after policy approval
- Env or file injection with explicit lifecycle
- Redaction in logs and receipts
- Zero secret values in contracts, receipts, or plaintext logs
- Depends on: approval artifacts + runtime isolation being stable

### 19. Receipt signing + key management
- CSC-native Ed25519 signing with standalone `cryptography` library
- CSC-native `PublicKeyResolver` protocol (PIC-compatible interface shape, no PIC dependency)
- Optional PIC adapter deferred to `csc-runner[pic]` extras
- Signed receipts in hardened mode deployments
- Key management operational rules (`docs/key-management.md` or `docs/runbooks/key-compromise.md`):
  - Key rotation cadence defined
  - Compromise response procedure: how to revoke, how to rotate, how to publish revocation
  - Treatment of previously signed receipts after key rotation (do old receipts remain valid?)
  - Trusted key distribution and update process

### 20. Policy-pack lifecycle
- Policy packs versioned independently
- Compatibility rules between engine and pack versions
- Signing or hashing for policy packs
- Deprecation policy
- Test fixture requirements for each pack
- Keeps engine clean while preventing ecosystem mess

### 21. Hardened-mode integration tests
- End-to-end integration tests for hardened mode container (not just unit tests around sandbox helpers)
- Required in CI for core path; nightly for heavier scenarios if runtime cost is too high
- Test the full path: contract → policy → sandbox → execution → signed receipt
- Verify isolation boundaries hold under real subprocess execution

### 22. Pilot success criteria (defined in advance)
- No critical security escapes
- All denials explainable
- All approvals replay-safe
- Operator feedback acceptable
- Receipt audit trail sufficient
- No silent crashes
- Acceptable performance bounds
- Retrospective written

**Stage 2 exit criteria:**
- [ ] Hardened mode exists for one use case
- [ ] Process isolation enforced by OS/runtime
- [ ] Approvals are hash-bound and non-replayable
- [ ] Receipts are signed in hardened mode
- [ ] Policy-pack lifecycle documented
- [ ] End-to-end hardened-mode integration tests pass in CI
- [ ] Pilot success criteria met
- [ ] Secret access (if needed) is brokered and redacted

## Stage 3 — Production Candidate

**For implementation, the Step A–H execution order at the top of this document is authoritative.**

### 23. Network enforcement (if needed for next pilot)
- deny/allowlisted/full becomes real egress control
- DNS/IP allowlisting
- Sandbox/container boundary
- Log attempted violations

### 24. Release integrity + supply chain
- Signed releases/tags
- Provenance attestations (SLSA target: provenance discipline first, higher integrity over time)
- Source-to-artifact chain documented
- SBOM generation for releases
- Dependency scanning
- Pinned CI action versions
- PyPI trusted publishing
- Signed wheel/sdist release process

### 24b. CI workflows for hardened integration tests
- `.github/workflows/hardened-tests.yml` — builds Docker image, runs integration tests on Linux
- Runs on every push/PR to verify hardened-mode claims in CI
- `docker build -t csc-hardened .` → `docker run --network=none` → `pytest tests/test_integration_hardened.py`
- Required gate: hardened tests must pass for Stage 3 production claim
- Also runs standard test suite (`pytest` without Docker) on the same runner
- Windows/macOS: standard tests only (hardened tests skip automatically)

### 25. OSS security maturity
- OpenSSF Best Practices / OSPS baseline passing
- Branch protection, required CI, dependency updates
- Security advisories enabled

### 26. Vulnerability management
- GitHub repository security advisories (private triage)
- Severity rubric, fix/SLA targets
- Security release notes template
- Regression tests for every security bug

### 27. Documentation alignment
- `docs/production-readiness-gate.md` — formal release gate checklist (referenced by plan and other docs, does not yet exist)
- `docs/threat-model.md` — populate (exists as placeholder, needs real content)
- `docs/deployment-modes.md` — update only if Step 23 ships
- `SECURITY.md` — update with full vulnerability management process
- `README.md` — align with production status (currently bootstrap/minimal; needs to reflect hardened-mode availability and bounded production claim after pilot)

### 28. External review + pilot evidence
- At least one independent review: external security review preferred, internal red-team acceptable if documented and credible
- Findings tracked in issues, fixed or explicitly accepted with rationale
- At least one real user ran it in a production-like workflow
- Publish limitations honestly

**Stage 3 exit criteria:**
- [ ] `docs/production-readiness-gate.md` exists and all items pass
- [ ] CI workflow for hardened integration tests (required gate, green)
- [ ] Signed releases with provenance and SBOM
- [ ] Security advisory process active
- [ ] `docs/threat-model.md` populated with real content
- [ ] `README.md` aligned with production status
- [ ] Adversarial suite passes
- [ ] At least one pilot completed with retrospective
- [ ] At least one independent review completed (external preferred, internal red-team acceptable if credible)
- [ ] No open high/critical security issues for the supported bounded deployment shape
- [ ] Bounded production claim: "safe enough for bounded production use under documented constraints" — Linux hardened mode, filesystem-bounded local/CI, no network

## Production Readiness Gate

`docs/production-readiness-gate.md` — formal checklist. No "production-ready" claim until all pass.

**Scope statement:** Passing this gate permits only the bounded production claim documented in `docs/security-targets.md` and `docs/deployment-modes.md`. It does not imply general-purpose production readiness outside those constraints.

**Bounded claim text (draft):** "CSC hardened mode is safe enough for bounded production use in Linux-based, filesystem-bounded local/CI execution workflows without network access, under the documented trust assumptions and deployment constraints."

- ✅ Stage 1a exit complete (committed: `800dc8b`)
- ✅ Stage 1b exit complete (committed: `f1b699f`)
- ✅ Stage 2 implementation complete (committed: `3e8d751`) — bounded pilot claim pending Linux CI confirmation
- [ ] Stage 3 exit complete
- [ ] Pilot retrospective written
- [ ] Threat model populated
- [ ] Known limitations section published
- [ ] Release-blocking severity policy enforced:
  - High/critical security issues block production claim
  - Medium issues require explicit acceptance note with rationale
  - Low issues may remain open with documented rationale
- [ ] External review findings closed or explicitly accepted with rationale
- [ ] Security target / claims matrix current
- [ ] Support matrix current
- [ ] Deployment modes documentation current
- [ ] Canonicalization spec current and policy-hash rules unchanged or explicitly versioned
- [ ] Bounded production claim: "safe enough for bounded production use under documented constraints" — Linux hardened mode, filesystem-bounded local/CI, no network

## PIC Ecosystem Architecture (long-term)

- CSC = standalone protocol for adoption + PIC-aligned execution profile
- Shell execution is a specialized action class within PIC's broader provenance/governance thesis
- Future: PIC core + CSC profile (shell/CLI) + other profiles (API/database/deploy)
- CSC receipts as the execution-evidence artifact PIC currently lacks
- Canonicalization coordination: CSC's contract hashing aligns with PIC Canonical JSON v1
- PIC language for high-impact actions: declared intent + bounded action + evidence

## Files to create/modify

### Stage 1a — Protocol Complete

| File | Action |
|------|--------|
| `docs/spec-v0.1.md` | Add freeze notice, versioning rules, receipt version stability rule, path semantics |
| `docs/versioning.md` | New — versioning/migration policy |
| `docs/pic-mapping.md` | New — PIC field/artifact mapping |
| `docs/security-targets.md` | New — security target / claims matrix |
| `docs/support-matrix.md` | New — supported OSes, Python versions, path flavours, deployment modes |
| `docs/compatibility-matrix.md` | New — runner↔contract↔receipt↔policy version compatibility |
| `docs/reason-codes.md` | New — reason-code registry |
| `docs/canonicalization.md` | New — hashing rules, policy hash source, Unicode/ordering/null-field stances |
| `schemas/csc.policy.v0.1.schema.json` | New — policy file schema with `policy_schema_version` |
| `schemas/csc.execution-receipt.v0.1.schema.json` | Update — add `receipt_version`, policy provenance fields, runner provenance fields |
| `schemas/csc.policy-decision.v0.1.schema.json` | Update — add `reason_codes` array field |
| `csc_runner/models.py` | Update — add `receipt_version`, `reason_codes`, policy/runner provenance fields |
| `rfcs/0002-pic-alignment.md` | New — PIC alignment RFC |
| `rfcs/index.yaml` | Update with RFC-0002 |
| `csc_runner/policy.py` | Add policy schema validation on load |
| `tests/conformance/contracts/` | New — valid/invalid contract fixtures |
| `tests/conformance/decisions/` | New — policy decision fixtures |
| `tests/conformance/receipts/` | New — receipt fixtures |
| `tests/conformance/paths/` | New — cross-platform path fixtures |
| `tests/conformance/README.md` | New — fixture format docs |

### Stage 1b — Hardened Defaults

| File | Action |
|------|--------|
| `csc_runner/limits.py` | New — resource exhaustion constants + budget-checking utility |
| `csc_runner/pathutil.py` | New — real-path resolution, symlink/traversal enforcement |
| `csc_runner/policy.py` | Import path functions from pathutil, add emergency deny-all + limits check |
| `csc_runner/executor.py` | Popen + threaded capture, pre-execution path checks, new failure-mode receipts |
| `csc_runner/cli.py` | Pass policy to run_contract, contract size check, needs_approval receipt |
| `schemas/csc.policy.v0.1.schema.json` | Add optional `emergency_deny_all` boolean |
| `schemas/csc.execution-receipt.v0.1.schema.json` | Add optional `stdout_truncated`, `stderr_truncated` booleans |
| `docs/spec-v0.1.md` | Document hash-of-captured-window semantics, truncation flags |
| `docs/reason-codes.md` | Add `EMERGENCY_DENY_ALL`, `CONTRACT_LIMITS_EXCEEDED` |
| `tests/test_limits.py` | New — resource exhaustion + DoS budget tests |
| `tests/test_pathutil.py` | New — symlink escape, traversal, case sensitivity, mixed-flavour |
| `tests/test_executor.py` | Update for new `run_contract` signature + new failure-mode tests |
| `tests/test_cli.py` | Update for needs_approval receipt + oversized contract test |
| `tests/test_receipt_integrity.py` | New — deterministic structure, hash binding, truncation fidelity |
| `tests/test_adversarial.py` | New — shell escapes, env leakage, Unicode, prompt-injection, path tricks |

### Stage 2 — First Hardened Mode

| File | Action |
|------|--------|
| `csc_runner/sandbox.py` | New — Linux sandbox backend (bubblewrap + setpriv + prlimit launcher) |
| `csc_runner/approval.py` | New — approval artifact model |
| `csc_runner/secrets.py` | New (if pilot needs) — secret provider interface |
| `csc_runner/signing.py` | New — CSC-native Ed25519 receipt signing (standalone `cryptography`) |
| `csc_runner/executor.py` | Integrate sandbox launcher, approval checks, optional signing |
| `csc_runner/cli.py` | Add `--mode local|hardened`, `--approval`, `--sign`, `--signing-key`, `--sandbox-debug` |
| `schemas/csc.approval.v0.1.schema.json` | New — approval artifact schema |
| `docs/deployment-modes.md` | New — local vs hardened, security claims per mode, sandbox architecture |
| `docs/policy-packs.md` | New — pack lifecycle |
| `docs/key-management.md` | New — rotation cadence, compromise runbook |
| `tests/test_sandbox.py` | New — isolation boundary tests |
| `tests/test_approval.py` | New — hash binding, expiry, temporal validation, schema validation |
| `tests/test_signing.py` | New — receipt signature verification |
| `Dockerfile` | New — hardened mode container image |
| `tests/test_integration_hardened.py` | New — end-to-end hardened mode integration tests |

### Stage 3 — Production Candidate

| File | Action |
|------|--------|
| `docs/production-readiness-gate.md` | New — formal release gate checklist (FIRST) |
| `.github/workflows/hardened-tests.yml` | New — CI for hardened integration tests |
| `.github/workflows/release.yml` | New — signed release workflow with provenance + SBOM |
| `SECURITY.md` | Update with full vulnerability management process |
| `.github/SECURITY_ADVISORY_TEMPLATE.md` | New — advisory template |
| `.github/SECURITY_RELEASE_TEMPLATE.md` | New — security release notes template |
| `.github/dependabot.yml` | New — dependency update automation |
| `docs/threat-model.md` | Populate — real content (exists as placeholder) |
| `README.md` | Update — align with production status |
| `docs/deployment-modes.md` | Update only if Step H ships |
| `csc_runner/network.py` | New — ONLY if pilot demands egress control |
| `tests/test_network.py` | New — ONLY if Step H ships |

## Stage 1a — COMPLETE (committed)

115 tests, 56 conformance fixtures, all docs, lint clean. Committed on scaffold branch.

**Freeze status:** pre-release internal baseline. Spec, schemas, reason codes, and receipt fields may still evolve during Stage 1b/2/3 before the first public release. The freeze becomes a real external contract only when a public release/tag is cut. Until then, Stage 1a is the protocol baseline that later stages build on, not an immutable artifact.

## Stage 1b — COMPLETE (committed)

245 tests, lint clean. All failure modes produce receipts. Executor resolves real paths and enforces filesystem boundaries. Resource exhaustion controls enforced. Receipts are hash-bound and deterministic. Adversarial test suite passes.

## Stage 2 — COMPLETE (committed)

Commit: `3e8d751 Stage 2: First Hardened Mode — approval, signing, sandbox, integration tests, docs`

### Progress
- [x] Step 1: `schemas/csc.approval.v0.1.schema.json` ✅
- [x] Step 3: `csc_runner/approval.py` + `tests/test_approval.py` ✅ (22 tests)
- [x] Step 4: `csc_runner/signing.py` + `tests/test_signing.py` ✅ (27 tests, standalone `cryptography`)
- [x] Step 6: `csc_runner/sandbox.py` + `tests/test_sandbox.py` ✅ (bubblewrap + setpriv + prlimit launcher)
- [x] Step 6b: seccomp profile — DEFERRED to post-pilot
- [x] Step 7: `csc_runner/executor.py` + `csc_runner/cli.py` ✅ (approval→hardened launcher→execute→sign)
- [x] Step 10: `Dockerfile` + `tests/test_integration_hardened.py` ✅ (19 integration tests)
- [x] Docs: `deployment-modes.md` ✅, `key-management.md` ✅, `policy-packs.md` ✅
- [x] Step 8: `csc_runner/secrets.py` — DEFERRED (not needed for pilot)
- [ ] Step 11: Pilot success criteria verification — pending CI validation on Linux

### Working Rules
- File-by-file approval: show full drop-in, wait for "APPROVED"
- User commits manually
- One file at a time until approved
