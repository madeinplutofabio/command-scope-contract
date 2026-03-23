"""Receipt signing and verification — Ed25519 over canonical JSON.

CSC-native signing layer. Uses the ``cryptography`` library directly
for Ed25519 primitives. Does not depend on PIC; the resolver protocol
is intentionally compatible with PIC's key-resolution shape for future
adapter interop.

Canonicalization rule (aligned with hash_contract / _hash_policy):
    json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

Signing payload = canonical JSON of the receipt with only the nested
``signature.signature`` value removed. The signing metadata fields
(algorithm, key_id, signed_at) are included in the signed payload
so they are authenticated and tamper-evident.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


class SigningError(Exception):
    """Raised when receipt signing fails."""


class VerificationError(Exception):
    """Raised when receipt signature verification fails."""


@runtime_checkable
class PublicKeyResolver(Protocol):
    """Resolve Ed25519 public keys by key_id.

    Intentionally compatible with PIC's key-resolution shape.
    A future ``csc_runner.pic_adapter`` module can bridge PIC's
    TrustedKeyRing / StaticKeyRingResolver into this protocol.
    """

    def resolve_public_key(self, key_id: str) -> bytes | None:
        """Return 32-byte Ed25519 public key bytes, or None if unknown."""
        ...


@dataclass(frozen=True)
class StaticKeyResolver:
    """Simple in-memory resolver for testing and single-key deployments."""

    keys: dict[str, bytes]

    def resolve_public_key(self, key_id: str) -> bytes | None:
        return self.keys.get(key_id)


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def canonicalize_receipt(receipt: dict[str, Any]) -> bytes:
    """Canonical JSON bytes of the receipt as-is."""
    return json.dumps(
        receipt,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def receipt_signing_payload(receipt: dict[str, Any]) -> bytes:
    """Canonical JSON bytes of the receipt with only the signature value removed.

    If ``signature`` is a dict, removes only the nested ``signature``
    value (the base64 string) while preserving ``algorithm``, ``key_id``,
    and ``signed_at`` in the signed payload. This makes signing metadata
    authenticated and tamper-evident.

    If ``signature`` is not a dict (or absent), removes it entirely.
    """
    payload = copy.deepcopy(receipt)
    sig = payload.get("signature")
    if isinstance(sig, dict):
        sig.pop("signature", None)
    else:
        payload.pop("signature", None)
    return canonicalize_receipt(payload)


def hash_receipt_payload(receipt: dict[str, Any]) -> str:
    """Raw SHA-256 hex of the signing payload."""
    return hashlib.sha256(receipt_signing_payload(receipt)).hexdigest()


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def sign_receipt(
    receipt: dict[str, Any],
    *,
    private_key_bytes: bytes,
    key_id: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Sign a receipt and return a new dict with signature attached.

    Does NOT mutate the input dict.

    Flow:
    1. Attach signature metadata (algorithm, key_id, signed_at) without
       the signature value.
    2. Canonicalize the payload (includes metadata, excludes signature value).
    3. Ed25519 sign the canonical bytes.
    4. Fill in the base64 signature value.

    Args:
        receipt: The receipt dict to sign.
        private_key_bytes: 32-byte Ed25519 private key seed, or 64-byte
            keypair, or PEM-encoded private key bytes.
        key_id: Identifier for the signing key (included in the signature
            bundle for resolver lookup during verification).
        signed_at: Optional ISO 8601 timestamp. Defaults to UTC now.

    Returns:
        A new receipt dict with a ``signature`` field.

    Raises:
        SigningError: If key_id is empty, the private key is invalid,
            canonicalization fails, or signing fails.
    """
    if not key_id:
        raise SigningError("key_id must be non-empty")

    try:
        private_key = _load_private_key(private_key_bytes)
    except Exception as exc:
        raise SigningError(f"invalid private key: {exc}") from exc

    if signed_at is None:
        signed_at = datetime.now(UTC).isoformat()

    # 1. Attach metadata without signature value
    signed = copy.deepcopy(receipt)
    signed["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "signed_at": signed_at,
    }

    # 2. Canonicalize (includes metadata, no signature value)
    try:
        payload = receipt_signing_payload(signed)
    except Exception as exc:
        raise SigningError(f"cannot canonicalize receipt payload: {exc}") from exc

    # 3. Sign
    try:
        raw_signature = private_key.sign(payload)
    except Exception as exc:
        raise SigningError(f"signing failed: {exc}") from exc

    # 4. Fill in signature value
    signed["signature"]["signature"] = base64.b64encode(raw_signature).decode("ascii")
    return signed


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_receipt_signature(
    receipt: dict[str, Any],
    *,
    resolver: PublicKeyResolver,
) -> bool:
    """Verify a signed receipt's Ed25519 signature.

    Args:
        receipt: The signed receipt dict (must contain ``signature``).
        resolver: Resolves key_id to 32-byte Ed25519 public key bytes.

    Returns:
        True if the signature is valid.

    Raises:
        VerificationError: With a specific reason on any failure:
            missing signature, unsupported algorithm, unknown key_id,
            malformed signature encoding, invalid signature, invalid
            public key material, canonicalization failure.
    """
    sig_obj = receipt.get("signature")
    if sig_obj is None:
        raise VerificationError("missing signature")

    if not isinstance(sig_obj, dict):
        raise VerificationError("malformed signature object")

    algorithm = sig_obj.get("algorithm")
    if algorithm != "ed25519":
        raise VerificationError(f"unsupported algorithm: {algorithm!r}")

    key_id = sig_obj.get("key_id")
    if not key_id:
        raise VerificationError("missing key_id in signature")

    sig_b64 = sig_obj.get("signature")
    if not sig_b64:
        raise VerificationError("missing signature value")

    # Decode signature
    try:
        raw_signature = base64.b64decode(sig_b64, validate=True)
    except Exception as exc:
        raise VerificationError(f"malformed signature encoding: {exc}") from exc

    # Resolve public key
    public_key_bytes = resolver.resolve_public_key(key_id)
    if public_key_bytes is None:
        raise VerificationError(f"unknown key_id: {key_id!r}")

    # Load public key
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception as exc:
        raise VerificationError(f"invalid public key material for {key_id!r}: {exc}") from exc

    # Reconstruct signing payload (includes metadata, excludes signature value)
    try:
        payload = receipt_signing_payload(receipt)
    except Exception as exc:
        raise VerificationError(f"cannot canonicalize receipt payload: {exc}") from exc

    # Verify
    try:
        public_key.verify(raw_signature, payload)
    except InvalidSignature:
        raise VerificationError("invalid signature")
    except Exception as exc:
        raise VerificationError(f"verification failed: {exc}") from exc

    return True


# ---------------------------------------------------------------------------
# Key loading helpers
# ---------------------------------------------------------------------------


def _load_private_key(key_bytes: bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from raw seed, keypair, or PEM bytes.

    - 32 bytes: treated as Ed25519 private key seed.
    - 64 bytes: treated as seed + public key; first 32 bytes used as seed.
    - Any other length: treated as PEM-encoded private key. Must be
      Ed25519; raises TypeError if the PEM contains a different key type.
    """
    if len(key_bytes) == 32:
        return Ed25519PrivateKey.from_private_bytes(key_bytes)

    if len(key_bytes) == 64:
        # Some formats store seed + public as 64 bytes.
        return Ed25519PrivateKey.from_private_bytes(key_bytes[:32])

    key = load_pem_private_key(key_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("PEM does not contain an Ed25519 private key")
    return key


def generate_test_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair for testing.

    Returns (private_key_seed_32bytes, public_key_32bytes).
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return private_bytes, public_bytes
