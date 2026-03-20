# CSC v0.1 Conformance Fixtures

Machine-readable test fixtures for verifying protocol compliance.
A conforming CSC v0.1 implementation MUST pass all fixtures in this suite.

## Structure

```
conformance/
  contracts/valid.json        — valid CommandContract instances
  contracts/invalid.json      — invalid CommandContract instances
  policies/schema.json        — valid and invalid policy objects (JSON Schema validation)
  policies/loader.json        — raw YAML text for loader-level behaviour (duplicate keys, parse errors)
  decisions/decisions.json    — contract + policy → expected PolicyDecision
  receipts/valid.json         — valid ExecutionReceipt instances
  receipts/invalid.json       — invalid ExecutionReceipt instances
```

## Fixture Formats

### Schema validation fixtures (contracts, policies/schema, receipts)

```json
{
  "id": "contract-valid-minimal-001",
  "description": "minimal valid exec contract",
  "spec_refs": ["spec:5.1", "schema:csc.contract.v0.1"],
  "input": { "...": "..." },
  "valid": true
}
```

- `id`: stable unique identifier, never reused
- `description`: human-readable purpose
- `spec_refs`: normative references (spec section or schema identifier)
- `input`: the JSON object to validate against the target schema
- `valid`: whether the input conforms to the target schema

### Loader fixtures (policies/loader)

```json
{
  "id": "policy-loader-duplicate-key-001",
  "description": "duplicate YAML key rejected before schema validation",
  "spec_refs": ["docs:canonicalization", "schema:csc.policy.v0.1"],
  "raw_text": "name: dup\nname: dup-again\n...",
  "format": "yaml",
  "valid": false,
  "expected_error_contains": "duplicate key"
}
```

- `raw_text`: the raw file content to feed to the policy loader
- `source`: alternative to `raw_text`; `"missing_file"` means the test runner should pass a path that does not exist
- `format`: always `"yaml"` in v0.1
- `expected_error_contains`: substring the error message MUST contain

Loader fixtures test behaviour that cannot be represented as parsed JSON objects
(e.g. duplicate YAML keys, malformed YAML syntax, non-mapping documents).

### Decision fixtures

```json
{
  "id": "decision-allow-git-status-001",
  "description": "simple git status allowed under dev-readonly",
  "spec_refs": ["spec:6", "spec:7"],
  "contract": { "...": "..." },
  "policy": { "...": "..." },
  "expected_decision": "allow",
  "expected_reason_codes": ["ALLOW"],
  "expected_classified_effects": []
}
```

- `contract`: a valid CommandContract object (MUST pass `csc.contract.v0.1` schema validation)
- `policy`: a valid policy profile object (MUST pass `csc.policy.v0.1` schema validation; inline, not a file path)
- `expected_decision`: one of `allow`, `deny`, `needs_approval`
- `expected_reason_codes`: exact array (order matters)
- `expected_classified_effects`: optional; array of `{"command_id", "effect_type"}`; compared as sets

## Target Schemas

| Fixture directory | Schema |
|---|---|
| `contracts/` | `csc.contract.v0.1.schema.json` |
| `policies/schema.json` | `csc.policy.v0.1.schema.json` |
| `receipts/` | `csc.execution-receipt.v0.1.schema.json` |
| `policies/loader.json` | loader behaviour (no single schema; tests `load_policy()` or equivalent) |
| `decisions/` | policy engine behaviour (validates contract + policy inputs, then checks decision output) |

## Runner Behaviour

- **Schema fixtures** validate `input` against the target JSON Schema directly. No file I/O, no `load_policy()`.
- **Loader fixtures** write `raw_text` to a temporary file and pass it to `load_policy()` or equivalent. They test parser-level behaviour that cannot be captured in parsed JSON. Fixtures with `"source": "missing_file"` instead of `raw_text` instruct the test runner to pass a path that does not exist.
- **Decision fixtures** pass `contract` and `policy` as in-memory objects to the policy engine. They bypass `load_policy()` file loading and YAML parsing — those are tested separately in loader fixtures and unit tests.
- **Conformance is OS-independent.** Path fixtures use POSIX paths. Windows-specific path behaviour is documented in `docs/support-matrix.md` but is not part of the portable conformance suite.
- **`expected_reason_codes`**: exact ordered match. In v0.1, each decision produces exactly one reason code.
- **`expected_classified_effects`**: compared as sets (order does not matter).
