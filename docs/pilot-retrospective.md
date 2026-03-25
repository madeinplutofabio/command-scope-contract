# CSC Pilot Retrospective

## Date

2026-03-24

## Pilot Configuration

- **Workload:** `/bin/ls -la /workspace` (list workspace contents)
- **Mode:** Hardened (bubblewrap + setpriv + prlimit)
- **Platform:** WSL2 Ubuntu 24.04 on Windows 10 Pro, Docker 28.2.2
- **Container:** `csc-hardened` (Python 3.11-slim-bookworm + bubblewrap + util-linux)
- **Signing:** Ed25519, 32-byte raw key, key ID `pilot-001`
- **Policy:** `pilot-readonly` — allow `/bin/ls`, observe-only, no network, no writes

## What Worked

1. **Full hardened execution path completed successfully.** Contract → policy evaluation → sandbox spawn → command execution → signed receipt → independent signature verification. All steps completed without error.

2. **Receipt signing and verification are correct.** Ed25519 signature produced by `sign_receipt()` was independently verified by `verify_receipt_signature()` using a separate public key. Signing metadata (algorithm, key_id, signed_at) is authenticated in the payload.

3. **Sandbox enforcement is real.** The bubblewrap launcher constructed the correct namespace isolation chain: `bwrap --unshare-net --unshare-pid --new-session --die-with-parent` → `setpriv --no-new-privs` → `prlimit` → user command.

4. **CI integration tests pass.** 17 hardened integration tests pass in GitHub Actions, providing additional evidence for filesystem boundaries, network isolation (loopback only), `no_new_privs`, approval enforcement, and signing enforcement.

5. **Policy evaluation works correctly.** The `pilot-readonly` policy correctly allowed `/bin/ls` with `observe` effect type and `low` risk class.

6. **Receipt structure is complete.** The receipt includes: `receipt_version`, `contract_sha256`, `policy_sha256`, `policy_schema_version`, `execution_mode: hardened`, `stdout_hash`, `stderr_hash`, signed `signature` object with authenticated metadata.

## What Didn't Work (and How We Fixed It)

### 1. AppArmor blocks bubblewrap in CI

**Problem:** `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` on GitHub Actions Ubuntu runners. The default Docker AppArmor profile restricts namespace operations that bubblewrap needs.

**Fix:** Added `--privileged --security-opt apparmor=unconfined` to the CI Docker run command. This is a CI-specific accommodation, not a product requirement.

**Lesson:** AppArmor compatibility is a real deployment consideration. Documented in `docs/deployment-modes.md` under Runtime Prerequisites.

### 2. Docker networking in WSL2

**Problem:** Docker's `dockerd` failed to start with default settings because the WSL2 kernel lacked iptables/nf_tables support. Then `--network=none` combined with bwrap's `--unshare-net` caused loopback setup failures.

**Fix:** Started Docker with `--iptables=false` and used `--network=host` for the build step. For the pilot run, used `--privileged --security-opt apparmor=unconfined` without `--network=none`. Network isolation is enforced by bwrap's `--unshare-net` inside the sandbox, not by Docker's network flag.

**Lesson:** The primary network isolation boundary is bwrap, not Docker. This is correctly documented but the pilot confirmed it operationally.

### 3. Host network interface preflight check

**Problem:** `verify_network_disabled()` detected non-loopback interfaces (`tunl0`, `sit0`, `eth0`) inside the Docker container and blocked execution.

**Fix:** Set `SandboxConfig(require_network_disabled=False)` for the pilot. The preflight check is a defense-in-depth sanity check, not the primary boundary. The primary boundary (`bwrap --unshare-net`) was tested and supported by CI integration tests.

**Lesson:** The CLI should expose a flag to disable the network preflight check for environments where the outer container has network interfaces but bwrap handles isolation. This is a usability improvement, not a security gap.

**Network claim scope:** The pilot validated sandbox-level network denial via `bwrap --unshare-net`. The outer-container `--network=none` deployment recommendation was not part of this pilot run. Therefore the pilot validates the primary boundary, while the outer-container defense-in-depth recommendation remains an operational deployment choice.

### 4. Receipt write permissions

**Problem:** The container runs as `csc-runner` (non-root) but the mounted volume was root-owned, causing `PermissionError` when writing the receipt.

**Workaround used in pilot:** Made the mounted output directory writable by the container user.

**Recommended production approach:** Use correct ownership/UID mapping or a dedicated writable output directory for the container user. Documentation should note that mounted output directories must be writable by the container user (UID 1000 by default).

### 5. PyPI sdist upload failure

**Problem:** First release workflow run failed on SBOM generation (wrong `cyclonedx-py` CLI flags) and sigstore action version. After fixing, the sdist upload failed because PyPI already had the version from a partial first upload.

**Fix:** Updated `cyclonedx-py` flags (`--output-file` instead of `--output`) and sigstore action version (`v3.2.0`). The wheel was already published successfully. PyPI does not allow re-uploading the same version.

**Lesson:** Test the release workflow on a pre-release tag first (e.g. `v0.5.0rc1`) before the real release. Pin action versions explicitly.

## What's Missing

1. **CLI `--skip-network-check` flag.** The CLI does not expose `SandboxConfig.require_network_disabled`. Operators in environments where bwrap handles network isolation but the outer container has interfaces must use the Python API directly.

2. **Durable approval replay prevention.** `InMemoryApprovalStore` is process-local. Consumed approvals are lost on restart. Acceptable for the pilot but not for multi-runner or persistent deployments.

3. **Syscall filtering (seccomp).** Not implemented. The sandbox relies on namespace isolation and `no_new_privs` only. Seccomp would be a second defense layer.

4. **sdist on PyPI.** Only the wheel was published for v0.5.0. The sdist failed due to version conflict from partial first upload.

5. **Full platform matrix CI.** Hardened tests run on Linux only (by design). Standard tests currently run on Linux only in the hardened-tests workflow. A separate `ci.yml` should cover Windows and macOS for local-mode tests.

## Observations

- **The protocol works end-to-end.** From contract authoring through signed receipt verification, the flow is coherent and auditable.
- **The sandbox boundary is the kernel, not Python.** This was a correct architectural decision. Every Python-side check (path enforcement, command blocking, network preflight) is defense-in-depth. The real containment is bubblewrap.
- **WSL2 is a viable local development path** for hardened-mode testing, with some Docker configuration work. Not as clean as native Linux or GitHub Actions, but functional.
- **The receipt is the central trust artifact.** It carries: contract hash, policy hash, execution mode, signing metadata, stdout/stderr hashes. An auditor can reconstruct what happened, under what policy, with what approval, and verify the signature independently.

## Verdict

The pilot demonstrates that CSC hardened mode works as designed for the bounded production claim: **Linux, filesystem-bounded, no network, signed receipts.** The remaining items (CLI usability, durable replay prevention, seccomp, full CI matrix) are documented improvements, not blockers for the bounded claim.

## Pilot Artifacts

Pilot artifacts (contract, policy, receipt, disposable signing keys) were created as temporary files during the pilot run and are not committed to the repository. The contract and policy structures used are documented in `examples/` and `docs/deployment-modes.md`.
