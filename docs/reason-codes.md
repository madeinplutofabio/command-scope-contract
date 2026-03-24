# CSC Reason Code Registry

## Purpose

This document is the authoritative registry of machine-readable reason codes used in `PolicyDecision.reason_codes`.

Reason codes are **stable API surface**. New codes may be added in future spec versions. Existing codes MUST NOT be renamed or removed without a spec version bump.

## Usage

- `reason_codes` is an array of strings in every `PolicyDecision`.
- Each string MUST be drawn from this registry.
- Multiple codes may apply to a single decision.
- `reasons` (free text) is retained for human readability but is non-normative. Automation, dashboards, and audit systems SHOULD rely on `reason_codes`.

## Registry

### Deny-oriented codes

| Code | Meaning | Emitted when |
|---|---|---|
| `RISK_CLASS_NOT_ALLOWED` | The contract's `risk_class` is not permitted by the active policy. | Policy restricts `allowed_risk_classes` and the contract's value is not in the set. |
| `COMMAND_NOT_ALLOWED` | The executable is not in the policy's command allowlist. | The first element of `argv` is not in `allow_commands`. |
| `ARGV_PREFIX_DENIED` | A denied argv prefix pattern matched. | An entry in `deny_argv_prefixes` matched the command's argv. |
| `NETWORK_EXCEEDS_POLICY` | The command's declared network access exceeds the policy maximum. | The command's `network` rank is higher than the policy's allowed maximum network mode. |
| `WRITE_SCOPE_DENIED` | A declared write path is outside the policy's allowed write prefixes. | A `write_paths` entry does not fall under any `allowed_write_prefixes`. |
| `READ_SCOPE_DENIED` | A declared read path is outside the policy's allowed read prefixes. | A `read_paths` entry does not fall under any `allowed_read_prefixes`. |
| `CWD_NOT_ALLOWED` | The command's working directory is outside allowed prefixes. | `cwd` does not fall under any `allowed_cwd_prefixes`. |
| `EFFECT_TYPE_NOT_ALLOWED` | The proposed effect type is not permitted by policy. | `proposed_effect_type` is not in `allowed_effect_types`. |
| `TIMEOUT_EXCEEDS_POLICY` | The command's timeout exceeds the policy maximum. | `timeout_sec` is greater than `max_timeout_sec`. |
| `SECRET_REF_NOT_ALLOWED` | Secret references are not permitted by policy. | The command declares non-empty `secret_refs` and the policy does not allow secret refs. |
| `PATH_NOT_ABSOLUTE` | A declared path is not absolute. | A `cwd`, `read_paths`, or `write_paths` value fails absolute path validation during validation or policy preflight. |
| `WRITE_PATHS_NOT_EMPTY` | Write paths are declared but policy requires them to be empty. | Policy has `require_write_paths_empty: true` and the command declares non-empty `write_paths`. |

### Approval-oriented codes

| Code | Meaning | Emitted when |
|---|---|---|
| `APPROVAL_REQUIRED` | The contract requires approval before execution. | `approval_mode` is `human_required` or `dual_control_required`, or policy classification requires approval. |

### Informational codes

| Code | Meaning | Emitted when |
|---|---|---|
| `ALLOW` | The contract satisfied policy checks and may proceed without approval. | The policy engine determines the contract is allowed. |
| `EFFECT_RECLASSIFIED` | The policy engine overrode the agent's proposed effect type. | `classified_effects` differs materially from the proposed effect type. |

## Backward compatibility

- Codes in this registry are permanent once published in a frozen spec version.
- New codes may be introduced in new spec versions.
- Consumers MUST tolerate unknown codes gracefully (for example, log and continue rather than crash).
- Removal or renaming of an existing code requires a spec version bump and corresponding schema update where applicable.
