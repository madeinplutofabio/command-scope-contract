# Security Advisory Template

## Summary

<!-- One-sentence description of the vulnerability -->

## Affected Versions

<!-- Which versions are affected? -->

- 0.x.y and earlier

## Affected Components

<!-- Check all that apply -->

- [ ] Executor (`csc_runner/executor.py`)
- [ ] Sandbox (`csc_runner/sandbox.py`)
- [ ] Signing (`csc_runner/signing.py`)
- [ ] Approval (`csc_runner/approval.py`)
- [ ] Policy (`csc_runner/policy.py`)
- [ ] Path enforcement (`csc_runner/pathutil.py`)
- [ ] Resource limits (`csc_runner/limits.py`)
- [ ] CLI (`csc_runner/cli.py`)
- [ ] Schemas
- [ ] Dockerfile / container image

## Affected Modes

- [ ] Local mode
- [ ] Hardened mode
- [ ] Both

## Severity

<!-- Critical / High / Medium / Low — see SECURITY.md for rubric -->

## Bounded Production Claim Impact

<!-- Does this issue block or weaken the bounded production claim?
     High/critical issues block the claim until resolved.
     Medium issues require an explicit acceptance note. -->

- [ ] Blocks bounded production claim
- [ ] Weakens claim (requires acceptance note)
- [ ] No impact on claim

## Description

<!-- Detailed description of the vulnerability, including root cause -->

## Impact

<!-- What can an attacker do? What is the blast radius? -->

## Reproduction

<!-- Steps to reproduce, proof of concept, or test case -->

## Fix

<!-- Description of the fix, PR reference -->

## Mitigation

<!-- Workarounds available before applying the fix -->

## Regression Test

<!-- Reference to the regression test added for this vulnerability.
     Required before closing the advisory. -->

- Test file: <!-- e.g. tests/test_adversarial.py, tests/test_executor.py -->
- Test name: <!-- e.g. test_vuln_123_path_traversal_regression -->
- [ ] Regression test merged

## Credit

<!-- Reporter attribution (unless they request anonymity) -->
