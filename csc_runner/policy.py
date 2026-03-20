from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath

import yaml

from csc_runner.models import CommandContract
from csc_runner.utils import hash_contract


NETWORK_RANK = {"deny": 0, "allowlisted": 1, "full": 2}


@dataclass
class PolicyResult:
    decision: str
    reasons: list[str]
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
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise PolicyError("policy file must contain a YAML mapping")
    if "name" not in data:
        raise PolicyError("policy file missing required field: name")

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


def evaluate_contract(contract: CommandContract, policy: dict) -> PolicyResult:
    reasons: list[str] = []
    contract_sha256 = hash_contract(contract)
    classified_effects: list[dict] = []
    profile = policy["name"]

    if contract.risk_class not in policy.get("allowed_risk_classes", []):
        return PolicyResult(
            "deny",
            [f"risk class not allowed: {contract.risk_class}"],
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
                return PolicyResult(
                    "deny",
                    [f"command not allowed: {executable}"],
                    profile,
                    contract_sha256,
                    classified_effects,
                )

            if _matches_prefix(argv, policy.get("deny_argv_prefixes", [])):
                return PolicyResult(
                    "deny",
                    [f"argv prefix denied: {argv}"],
                    profile,
                    contract_sha256,
                    classified_effects,
                )

        classified_effect = classify_effect(command, policy)
        classified_effects.append({"command_id": command.id, "effect_type": classified_effect})

        if command.proposed_effect_type not in policy.get("allowed_effect_types", []):
            return PolicyResult(
                "deny",
                [f"proposed effect type not allowed: {command.proposed_effect_type}"],
                profile,
                contract_sha256,
                classified_effects,
            )

        if classified_effect in policy.get("manual_approval_for_classified_effect_types", []):
            return PolicyResult(
                "needs_approval",
                [f"classified effect type requires approval: {classified_effect}"],
                profile,
                contract_sha256,
                classified_effects,
            )

        if command.timeout_sec > policy.get("max_timeout_sec", 60):
            return PolicyResult(
                "deny",
                [f"timeout too large: {command.timeout_sec}"],
                profile,
                contract_sha256,
                classified_effects,
            )

        if NETWORK_RANK.get(command.network, 999) > NETWORK_RANK.get(max_network, -1):
            return PolicyResult(
                "deny",
                [f"network mode exceeds policy maximum: {command.network}"],
                profile,
                contract_sha256,
                classified_effects,
            )

        if command.secret_refs and not policy.get("allow_secret_refs", False):
            return PolicyResult(
                "deny",
                ["secret refs not allowed"],
                profile,
                contract_sha256,
                classified_effects,
            )

        if not _path_allowed(command.cwd, policy.get("allowed_cwd_prefixes", [])):
            return PolicyResult(
                "deny",
                [f"cwd not allowed: {command.cwd}"],
                profile,
                contract_sha256,
                classified_effects,
            )

        for path in command.read_paths:
            if not _path_allowed(path, policy.get("allowed_read_prefixes", [])):
                return PolicyResult(
                    "deny",
                    [f"read path not allowed: {path}"],
                    profile,
                    contract_sha256,
                    classified_effects,
                )

        # Enforce read-only profiles before validating write path scopes
        if policy.get("require_write_paths_empty", False) and command.write_paths:
            return PolicyResult(
                "deny",
                ["writes not allowed in this profile"],
                profile,
                contract_sha256,
                classified_effects,
            )

        for path in command.write_paths:
            if not _path_allowed(path, policy.get("allowed_write_prefixes", [])):
                return PolicyResult(
                    "deny",
                    [f"write path not allowed: {path}"],
                    profile,
                    contract_sha256,
                    classified_effects,
                )

    if contract.approval_mode in {"human_required", "dual_control_required"}:
        return PolicyResult(
            "needs_approval",
            [f"contract approval mode requires approval: {contract.approval_mode}"],
            profile,
            contract_sha256,
            classified_effects,
        )

    reasons.append("contract satisfies v0.1 policy checks")
    return PolicyResult("allow", reasons, profile, contract_sha256, classified_effects)
