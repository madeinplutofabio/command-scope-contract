# CSC Canonicalization Spec

## Purpose

This document defines the canonical serialization rules for CSC protocol artifacts. Canonicalization ensures that hashes and signatures are deterministic and reproducible across implementations, platforms, and languages.

## Scope

These rules apply to:

- **Contract hashing** — producing `contract_sha256`
- **Policy hashing** — producing `policy_sha256`
- **Receipt hashing/signing** — when receipt integrity or signing is applied

## Canonical JSON rules

CSC uses the deterministic JSON canonicalization rules defined in this document.

### 1. Key ordering

Object keys MUST be sorted lexicographically by Unicode code point (equivalent to byte-order sorting of UTF-8 encoded keys).

### 2. Whitespace

- No whitespace between tokens.
- No trailing newline.
- Separators are `,` between elements and `:` between key-value pairs, with no surrounding spaces.

### 3. Unicode

- Output MUST be encoded as UTF-8.
- Non-ASCII characters MUST be preserved as literal UTF-8, not escaped to `\uXXXX` sequences.
- No Unicode normalization (NFC, NFD, etc.) is applied. The byte sequence of the original string value is preserved.

### 4. Null and omitted fields

- Fields with a value of `null` MUST be omitted from the canonical form.
- Fields that are absent from the source object are naturally omitted.
- The canonicalization rule is `exclude_none`: any field whose value is `null` / `None` is dropped before serialization.
- Stored artifacts MAY still contain explicit `null` values outside the canonicalized hashing/signing form, but canonical hashing/signing always operates on the normalized form with nulls omitted.

### 5. Numbers

- Integer values MUST be serialized without a decimal point or exponent (for example, `42`, not `42.0` or `4.2e1`).
- Floating-point values are outside the CSC v0.1 protocol surface and SHOULD NOT appear in canonicalized protocol artifacts.
- If floating-point values are introduced in a future version, that version MUST define precise canonical serialization rules for them.

### 6. Booleans

- `true` and `false` in lowercase, per JSON.

### 7. Arrays

- Array element order is preserved. Arrays are not sorted.

### 8. Line endings

- Line endings within string values are preserved as-is. Canonicalization does not normalize `\r\n` to `\n` or vice versa within string content.
- The canonical output itself contains no line endings (no trailing newline, no pretty-printing).

## Hash algorithm

CSC uses SHA-256 for all protocol hashing. Hash values are represented as lowercase hexadecimal strings, prefixed where noted:

- `contract_sha256`: bare hex (e.g., `a1b2c3...`)
- `stdout_hash` / `stderr_hash`: prefixed (e.g., `sha256:a1b2c3...`)
- `policy_sha256`: bare hex

## Contract hashing

To produce `contract_sha256`:

1. Take the contract body as a structured object.
2. Normalize the structured object by omitting null fields, then serialize using the canonical JSON rules defined above.
3. Compute SHA-256 over the resulting UTF-8 byte sequence.
4. Encode as lowercase hexadecimal.

## Policy hashing

To produce `policy_sha256`:

1. Parse the policy file (YAML or JSON) into a structured object.
2. Reject the policy file if it contains duplicate keys. Duplicate keys are invalid and MUST be rejected before hashing.
3. Serialize the parsed object using the canonical JSON rules defined above.
4. Compute SHA-256 over the resulting UTF-8 byte sequence.
5. Encode as lowercase hexadecimal.

The hash is over the **normalized parsed representation**, not the raw file bytes. This ensures that semantically equivalent policy files (for example, differing only in YAML formatting or comment content) produce the same hash.

## Receipt hashing

When receipt integrity or signing is applied, the same canonical JSON rules apply to the receipt body. The exact fields included in the hash are defined by the receipt signing specification (see Stage 2 roadmap).

## Stability

Canonicalization rules are part of the protocol surface. Changes to these rules require a spec version bump and affect all artifacts that depend on deterministic hashing. The canonicalization rules defined here MUST remain stable within a protocol version.

## PIC alignment

These rules are designed to be compatible with PIC Canonical JSON v1 when that specification is published. Both projects share the same author and the same design intent: deterministic, reproducible, cross-language hashing of protocol artifacts.
