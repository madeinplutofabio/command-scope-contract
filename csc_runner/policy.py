from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError

from csc_runner.limits import MAX_POLICY_SIZE_BYTES
from csc_runner.models import CommandContract
from csc_runner.utils import hash_contract

NETWORK_RANK = {"deny": 0, "allowlisted": 1, "full": 2}


class _UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate keys at parse time."""

    pass


def _check_duplicate_key(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _check_duplicate_key,
)


@dataclass
class PolicyResult:
    decision: str
    reasons: list[str]
    reason_codes: list[str]
    policy_profile: str
    contract_sha256: str
    classified_effects: list[dict] = field(default_factory=list)


class PolicyError(Exception):
    pass


def _matches_prefix(argv: list[str], denied_prefixes: list[list[str]]) -> bool:
    for prefix in denied_prefixes:
        if argv[: len(prefix)] == prefix:
            return True
    return False


def _detect_path_flavour(path: str) -> str:
    """Detect whether a path is Windows-style or POSIX-style."""
    if path.startswith(("\\\\", "//")):
        return "windows"
    if len(path) >= 3 and path[1] == ":" and path[2] in ("\\", "/"):
        return "windows"
    return "posix"


def _normalize_path(path: str) -> tuple[str, str]:
    """Return (flavour, normalized comparison form) for consistent comparison.

    Raises PolicyError if the path is not absolute.
    Windows paths are lowercased for case-insensitive comparison.
    POSIX paths preserve case.
    """
    flavour = _detect_path_flavour(path)
    if flavour == "windows":
        p = PureWindowsPath(path)
        if not p.is_absolute():
            raise PolicyError(f"path must be absolute: {path}")
        return (flavour, p.as_posix().lower())
    else:
        p = PurePosixPath(path)
        if not p.is_absolute():
            raise PolicyError(f"path must be absolute: {path}")
        return (flavour, str(p))


def _path_allowed(path: str, prefixes: list[str]) -> bool:
    """Check if a path is allowed by any of the given prefixes.

    Only same-flavour comparisons are performed. Mixed-flavour
    comparisons fail closed (deny).
    """
    path_flavour, norm_path = _normalize_path(path)
    for prefix in prefixes:
        prefix_flavour, norm_prefix = _normalize_path(prefix)
        if prefix_flavour != path_flavour:
            continue
        norm_prefix = norm_prefix.rstrip("/")
        if norm_path == norm_prefix or norm_path.startswith(norm_prefix + "/"):
            return True
    return False


def _iter_argv_vectors(command) -> list[list[str]]:
    if command.exec is not None:
        return [command.exec.argv]
    return [segment.argv for segment in command.pipeline.segments]


def load_policy(path: str) -> dict:
    """Load and validate a policy file against the policy schema.

    Raises PolicyError if the file is oversized, cannot be read, contains
    invalid YAML, has duplicate keys, is not a mapping, or does not conform
    to the policy schema.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise PolicyError(f"failed to read policy file: {exc}") from exc

    if len(raw) > MAX_POLICY_SIZE_BYTES:
        raise PolicyError(
            f"policy file is {len(raw)} bytes (max {MAX_POLICY_SIZE_BYTES})"
        )

    try:
        data = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyError("policy file must contain a YAML mapping")

    try:
        schema_path = Path(__file__).resolve().parent.parent / "schemas" / "csc.policy.v0.1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"failed to load policy schema: {exc}") from exc

    try:
        validator = Draft202012Validator(schema)
        validator.validate(data)
    except JsonSchemaValidationError as exc:
        raise PolicyError(f"policy schema validation failed: {exc.message}") from exc

    return data


def classify_effect(command, policy: dict) -> str:
    """Starter heuristic for v0.1 effect classification.

    This is not a complete semantic classifier. It does basic pattern
    matching (e.g. curl + stripe -> financial_action) and falls back
    to the agent's proposed effect type.
    """
    argv_vectors = _iter_argv_vectors(command)
    first_argv = argv_vectors[0]
    executable = first_argv[0]

    if executable == "curl":
        joined = " ".join(first_argv)
        for host in policy.get("allowed_egress_hosts", []):
            if host in joined and "stripe" in host:
                return "financial_action"
        return "fetch_external"

    return command.proposed_effect_type


def _deny(reason: str, code: str, profile: str, sha256: str, effects: list[dict]) -> PolicyResult:
    return PolicyResult("deny", [reason], [code], profile, sha256, effects)


def _needs_approval(reason: str, code: str, profile: str, sha256: str, effects: list[dict]) -> PolicyResult:
    return PolicyResult("needs_approval", [reason], [code], profile, sha256, effects)


def _check_path_allowed(
    path: str, prefixes: list[str], deny_reason: str, deny_code: str, profile: str, sha256: str, effects: list[dict]
) -> PolicyResult | None:
    """Check a path against prefixes, returning a deny PolicyResult or None.

    Returns PATH_NOT_ABSOLUTE deny if any path is not absolute.
    Returns the provided deny_code if the path is outside allowed prefixes.
    Returns None if the path is allowed.
    """
    try:
        allowed = _path_allowed(path, prefixes)
    except PolicyError as exc:
        return _deny(
            str(exc),
            "PATH_NOT_ABSOLUTE",
            profile,
            sha256,
            effects,
        )
    if not allowed:
        return _deny(deny_reason, deny_code, profile, sha256, effects)
    return None


def evaluate_contract(contract: CommandContract, policy: dict) -> PolicyResult:
    contract_sha256 = hash_contract(contract)
    classified_effects: list[dict] = []
    profile = policy["name"]

    if contract.risk_class not in policy.get("allowed_risk_classes", []):
        return _deny(
            f"risk class not allowed: {contract.risk_class}",
            "RISK_CLASS_NOT_ALLOWED",
            profile,
            contract_sha256,
            classified_effects,
        )

    max_network = policy.get("network", "deny")

    for command in contract.commands:
        argv_vectors = _iter_argv_vectors(command)

        for argv in argv_vectors:
            executable = argv[0]

            if executable not in policy.get("allow_commands", []):
                return _deny(
                    f"command not allowed: {executable}",
                    "COMMAND_NOT_ALLOWED",
                    profile,
                    contract_sha256,
                    classified_effects,
                )

            if _matches_prefix(argv, policy.get("deny_argv_prefixes", [])):
                return _deny(
                    f"argv prefix denied: {argv}",
                    "ARGV_PREFIX_DENIED",
                    profile,
                    contract_sha256,
                    classified_effects,
                )

        classified_effect = classify_effect(command, policy)
        classified_effects.append({"command_id": command.id, "effect_type": classified_effect})

        if command.proposed_effect_type not in policy.get("allowed_effect_types", []):
            return _deny(
                f"proposed effect type not allowed: {command.proposed_effect_type}",
                "EFFECT_TYPE_NOT_ALLOWED",
                profile,
                contract_sha256,
                classified_effects,
            )

        if classified_effect in policy.get("manual_approval_for_classified_effect_types", []):
            return _needs_approval(
                f"classified effect type requires approval: {classified_effect}",
                "APPROVAL_REQUIRED",
                profile,
                contract_sha256,
                classified_effects,
            )

        if command.timeout_sec > policy.get("max_timeout_sec", 60):
            return _deny(
                f"timeout too large: {command.timeout_sec}",
                "TIMEOUT_EXCEEDS_POLICY",
                profile,
                contract_sha256,
                classified_effects,
            )

        if NETWORK_RANK.get(command.network, 999) > NETWORK_RANK.get(max_network, -1):
            return _deny(
                f"network mode exceeds policy maximum: {command.network}",
                "NETWORK_EXCEEDS_POLICY",
                profile,
                contract_sha256,
                classified_effects,
            )

        if command.secret_refs and not policy.get("allow_secret_refs", False):
            return _deny(
                "secret refs not allowed",
                "SECRET_REF_NOT_ALLOWED",
                profile,
                contract_sha256,
                classified_effects,
            )

        result = _check_path_allowed(
            command.cwd,
            policy.get("allowed_cwd_prefixes", []),
            f"cwd not allowed: {command.cwd}",
            "CWD_NOT_ALLOWED",
            profile,
            contract_sha256,
            classified_effects,
        )
        if result is not None:
            return result

        for path in command.read_paths:
            result = _check_path_allowed(
                path,
                policy.get("allowed_read_prefixes", []),
                f"read path not allowed: {path}",
                "READ_SCOPE_DENIED",
                profile,
                contract_sha256,
                classified_effects,
            )
            if result is not None:
                return result

        # Enforce read-only profiles before validating write path scopes
        if policy.get("require_write_paths_empty", False) and command.write_paths:
            return _deny(
                "writes not allowed in this profile",
                "WRITE_PATHS_NOT_EMPTY",
                profile,
                contract_sha256,
                classified_effects,
            )

        for path in command.write_paths:
            result = _check_path_allowed(
                path,
                policy.get("allowed_write_prefixes", []),
                f"write path not allowed: {path}",
                "WRITE_SCOPE_DENIED",
                profile,
                contract_sha256,
                classified_effects,
            )
            if result is not None:
                return result

    if contract.approval_mode in {"human_required", "dual_control_required"}:
        return _needs_approval(
            f"contract approval mode requires approval: {contract.approval_mode}",
            "APPROVAL_REQUIRED",
            profile,
            contract_sha256,
            classified_effects,
        )

    return PolicyResult(
        "allow",
        ["contract satisfies v0.1 policy checks"],
        ["ALLOW"],
        profile,
        contract_sha256,
        classified_effects,
    )
