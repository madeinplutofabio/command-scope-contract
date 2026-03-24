# CSC Policy Packs

## Overview

A policy pack is an organizational convention for grouping, versioning, and distributing CSC policy files. Packs allow organizations to standardize policy configurations across teams and environments without embedding domain logic in the engine itself.

**Important:** The CSC engine does not read pack metadata. The engine loads and evaluates a single policy YAML file per invocation. Pack structure, naming, and versioning are organizational conventions — the engine is not aware of them.

The CSC engine evaluates policies structurally (commands, scopes, risk classes, effect types). Domain-specific classification — what constitutes "sensitive," which tools are appropriate for which workflows, how risk classes map to organizational controls — lives in policy packs, not the engine.

## Design Principles

1. **Engine stays structural.** The policy engine evaluates declared contracts against declared policy rules. It does not embed domain knowledge about specific tools, services, or organizational workflows.

2. **Packs are versioned independently.** A pack version is not tied to the engine version. Packs can evolve faster or slower than the engine, as long as the individual policy files conform to the `policy_schema_version` they declare.

3. **Packs are not code.** A policy pack is a collection of YAML policy files, optional documentation, and optional test fixtures. It does not contain executable code, hooks, or plugins.

4. **The runner evaluates one policy file per invocation.** Pack selection, distribution, and environment-to-policy mapping are external operational concerns, not engine features.

## Pack Structure

A minimal policy pack:

```
my-org-policies/
├── pack.yaml              # Pack metadata (organizational, not read by engine)
├── policies/
│   ├── dev-readonly.yaml  # Development policy
│   ├── ci-standard.yaml   # CI/CD policy
│   └── prod-hardened.yaml # Production policy
├── tests/                 # Optional decision fixtures
│   ├── dev-allow.json
│   └── prod-deny.json
└── README.md              # Usage documentation
```

### pack.yaml

This file is for organizational use only — the engine does not read it.

```yaml
pack_name: my-org-policies
pack_version: "1.2.0"
policy_schema_version: "csc.policy.v0.1"
description: "Organization-standard CSC policies"
maintainer: "security-team@example.com"
```

## Compatibility

### Engine ↔ Policy Compatibility

The compatibility contract is the `policy_schema_version` field in each policy file:

- Each policy file declares its `policy_schema_version`
- The engine validates policies against the schema version they declare
- A policy file is compatible with any engine version that supports the declared schema version

### Version Rules

- **Policy schema versions** follow the CSC spec versioning rules
- **Pack versions** are independent — use semantic versioning or any scheme that fits your organization
- **Breaking changes** in the policy schema require a schema version bump; policy files must update accordingly

## Integrity

### What `policy_sha256` Proves

Every receipt includes `policy_sha256` — the SHA-256 hash of the canonical JSON form of the parsed policy that produced the decision:

- The hash is over the canonical parsed representation, not raw YAML bytes
- YAML comments, formatting, and key ordering do not affect the hash
- Auditors can verify which exact policy content was used for any execution

### What `policy_sha256` Does Not Prove

- It does not authenticate the source of the policy (who authored or deployed it)
- It does not prove the policy was the correct or intended one for the environment
- Source authentication depends on receipt trust, signing, and operational controls (deployment pipelines, access controls, change review)

Receipts record `policy_sha256` and `policy_profile`, not pack name or pack version. The connection between a receipt and a specific pack version is an organizational mapping, not an engine guarantee.

### Future

- Policy pack signing (hash or signature over the pack manifest)
- Pack provenance attestation
- Automated compatibility checking between pack versions and engine versions

## Distribution

Stage 2 does not prescribe a distribution mechanism. Policy files are loaded from local filesystem paths via the CLI.

Common distribution approaches:

- **Git repository:** Version-controlled policy files, reviewed via pull requests
- **Artifact registry:** Publish versioned pack tarballs
- **Configuration management:** Deploy via Ansible, Puppet, Chef, etc.
- **Container image:** Bake policies into the runner container image

## Deprecation

When retiring a policy or pack version:

1. **Announce** the deprecation with a timeline
2. **Add** a successor policy/pack version
3. **Keep** the deprecated version available for the announced period
4. **Remove** the deprecated version after the period expires
5. **Document** which receipts were produced under the deprecated policy

Receipts produced under a deprecated policy remain valid — they reference the policy by hash, not by name or version.

## Testing

Each policy pack should include test fixtures that verify expected decisions:

- Allow cases: contracts that should be permitted
- Deny cases: contracts that should be rejected
- Approval cases: contracts that require human approval

Test fixtures can follow the conformance fixture format used by the CSC test suite.

```bash
# Illustrative example — not a CSC convention.
# Organize and run pack tests however fits your workflow.
python -m pytest tests/ -k "policy_pack"
```

## Relationship to Engine

| Concern | Engine | Policy Pack |
|---|---|---|
| Evaluation logic | Yes | No |
| Reason codes | Defined by engine | Referenced by pack docs |
| Command allowlists | Enforced by engine | Declared in pack policies |
| Risk class mapping | Structural evaluation | Domain-specific classification |
| Effect type rules | Structural evaluation | Domain-specific classification |
| Path scope rules | Enforced by engine | Declared in pack policies |
| Versioning | Engine release cycle | Independent pack cycle |
| Pack metadata | Not read by engine | Organizational convention |
