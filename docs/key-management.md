# CSC Key Management

## Overview

CSC uses Ed25519 for receipt signing. This document covers key lifecycle, rotation, compromise response, and the dependency boundary between CSC's signing layer and external key infrastructure.

In hardened mode, signing configuration is mandatory for execution; in local mode, signing remains optional.

## Architecture

CSC's signing layer is standalone:

- **`csc_runner/signing.py`** — Ed25519 sign/verify using the `cryptography` library directly
- **`PublicKeyResolver` protocol** — CSC-native interface for resolving public keys by `key_id`
- **`StaticKeyResolver`** — simple in-memory resolver for single-key deployments and testing
- **No hard dependency on PIC or any external key management system**

The `PublicKeyResolver` interface is intentionally compatible with PIC's key-resolution shape. A future `csc-runner[pic]` extras package can provide an adapter from PIC's `TrustedKeyRing` / `StaticKeyRingResolver` into CSC's protocol, without coupling CSC core to PIC.

Stage 2 CLI verification is single-key (`--public-key` + `--key-id`); multi-key trust stores and custom resolvers are library-level integration points.

## Key Types

### Signing Key (Private)

- Ed25519 private key (32-byte seed, 64-byte keypair, or PEM-encoded)
- Used by the runner to sign receipts
- Must be available to the runner process at execution time
- Loaded via `--signing-key PATH` CLI flag

### Verification Key (Public)

- Ed25519 public key
- Used by auditors/verifiers to check receipt signatures
- In Stage 2 CLI usage, this is typically supplied as a public-key file alongside the expected `key_id`
- Distributed separately from the signing key
- Referenced by `key_id` in the receipt's `signature` object

### Key ID

- Stable string identifier for a key pair (e.g. `key-prod-2026-03`)
- Included in every signed receipt's `signature.key_id` field
- Used by `PublicKeyResolver` to look up the corresponding public key
- Must be unique within the trust domain

## Key Lifecycle

### Generation

```bash
# Generate a new Ed25519 keypair
python -c "
from csc_runner.signing import generate_test_keypair
priv, pub = generate_test_keypair()
open('signing-key.bin', 'wb').write(priv)
open('verification-key.bin', 'wb').write(pub)
print(f'Private: {len(priv)} bytes, Public: {len(pub)} bytes')
"
```

For production, use a dedicated key generation tool or HSM. The above is for development/testing only.

### Storage

- **Private keys:** Store in a secrets manager, HSM, or encrypted volume. Never commit to source control. Never embed in container images.
- **Public keys:** Distribute to all parties that need to verify receipts. Can be committed to a trust store repository.
- **Key IDs:** Document in a key registry alongside the public key and validity period.

### Rotation

**Recommended cadence:** Rotate signing keys at least every 90 days for production deployments, or immediately after any suspected compromise.

**Rotation procedure:**

1. Generate a new keypair with a new `key_id` (e.g. `key-prod-2026-06`)
2. Deploy the new private key to the runner environment
3. Add the new public key to all verification trust stores
4. Update the runner's `--key-id` to the new ID
5. Keep the old public key in trust stores for verifying historical receipts
6. After the retention period, remove the old private key from active storage

**Important:** Old receipts signed with the previous key remain valid and verifiable as long as the old public key is retained in the trust store. Rotation does not invalidate previously signed receipts.

### Revocation

If a signing key is compromised:

1. **Immediately** remove the private key from all runner environments
2. **Immediately** stop all runners using the compromised key
3. Generate and deploy a new keypair
4. Mark the compromised key as revoked in the key registry
5. Assess which receipts were signed during the compromise window
6. Document the incident and affected receipt time range

**Treatment of receipts signed with a revoked key:** Receipts signed before the compromise window remain trustworthy. Receipts signed during or after the compromise window should be treated as untrustworthy — their signatures are technically valid but the signer identity is no longer reliable.

CSC core verifies cryptographic validity only against the verifier's current trust material. Revocation semantics and compromise-window policy are external operational controls.

## Signed Receipt Structure

The signature is embedded in the receipt as a `signature` object:

```json
{
  "receipt_version": "csc.receipt.v0.1",
  "contract_id": "...",
  "...": "...",
  "signature": {
    "algorithm": "ed25519",
    "key_id": "key-prod-2026-03",
    "signed_at": "2026-03-23T12:34:56+00:00",
    "signature": "<base64-encoded Ed25519 signature>"
  }
}
```

**Authenticated fields:** `algorithm`, `key_id`, and `signed_at` are included in the signing payload. Tampering with any of these fields invalidates the signature.

**Signing payload:** The canonical JSON of the receipt with only the nested `signature.signature` value removed. All other receipt fields and signature metadata are signed.

## Verification

```bash
csc verify-receipt receipt.json \
  --public-key verification-key.bin \
  --key-id key-prod-2026-03
```

Verification checks:

1. `signature` object is present and well-formed
2. `algorithm` is `ed25519`
3. `key_id` resolves to a known public key
4. The Ed25519 signature is valid over the canonical signing payload

## CSC ↔ PIC Dependency Boundary

CSC's signing layer is normatively independent of PIC:

| Concern | CSC | PIC |
|---|---|---|
| Signing primitive | Ed25519 via `cryptography` | Ed25519 via `evidence.py` |
| Key resolution | `PublicKeyResolver` protocol | `KeyResolver` / `TrustedKeyRing` |
| Receipt payload | CSC-native JSON | N/A |
| Trust store | `StaticKeyResolver` (Stage 2) | `StaticKeyRingResolver` |

**What CSC imports from PIC:** Nothing (Stage 2). The interface shapes are compatible by design, not by import.

**Future adapter:** A `csc-runner[pic]` extras package could provide:

```python
class PicResolverAdapter:
    def __init__(self, pic_resolver) -> None:
        self._pic = pic_resolver

    def resolve_public_key(self, key_id: str) -> bytes | None:
        key = self._pic.resolve(key_id)
        return key.public_key_bytes if key else None
```

This keeps CSC independent by default and interoperable when wanted.
