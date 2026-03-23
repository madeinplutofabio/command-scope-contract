"""Tests for csc_runner.signing — Ed25519 receipt signing and verification."""

from __future__ import annotations

import copy

import pytest

from csc_runner.signing import (
    SigningError,
    StaticKeyResolver,
    VerificationError,
    canonicalize_receipt,
    generate_test_keypair,
    hash_receipt_payload,
    receipt_signing_payload,
    sign_receipt,
    verify_receipt_signature,
)

_KEY_ID = "test-key-001"


@pytest.fixture()
def keypair():
    priv, pub = generate_test_keypair()
    return priv, pub


@pytest.fixture()
def sample_receipt():
    return {
        "receipt_version": "csc.receipt.v0.1",
        "contract_id": "signing-test-001",
        "execution_id": "exec-001",
        "contract_sha256": "a" * 64,
        "status": "success",
        "started_at": "2026-03-23T12:00:00Z",
        "ended_at": "2026-03-23T12:00:05Z",
        "exit_code": 0,
        "stdout_hash": "sha256:" + "b" * 64,
        "stderr_hash": "sha256:" + "c" * 64,
        "policy_profile": "test-policy",
    }


def _resolver(pub: bytes) -> StaticKeyResolver:
    return StaticKeyResolver(keys={_KEY_ID: pub})


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


class TestCanonicalization:
    def test_deterministic(self, sample_receipt):
        a = canonicalize_receipt(sample_receipt)
        b = canonicalize_receipt(sample_receipt)
        assert a == b

    def test_key_order_independent(self):
        r1 = {"b": 2, "a": 1}
        r2 = {"a": 1, "b": 2}
        assert canonicalize_receipt(r1) == canonicalize_receipt(r2)

    def test_signing_payload_excludes_signature_value(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
            signed_at="2026-03-23T12:00:06Z",
        )
        payload = receipt_signing_payload(signed)
        # The nested signature value must not be in the payload
        assert signed["signature"]["signature"].encode() not in payload

    def test_signing_payload_includes_metadata(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
            signed_at="2026-03-23T12:00:06Z",
        )
        payload = receipt_signing_payload(signed)
        assert b'"algorithm":"ed25519"' in payload
        assert b'"key_id":"test-key-001"' in payload
        assert b'"signed_at":"2026-03-23T12:00:06Z"' in payload

    def test_hash_receipt_payload_is_hex(self, sample_receipt):
        h = hash_receipt_payload(sample_receipt)
        assert len(h) == 64
        int(h, 16)  # must be valid hex


# ---------------------------------------------------------------------------
# Sign / verify round trip
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_round_trip(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        assert verify_receipt_signature(signed, resolver=_resolver(pub)) is True

    def test_signature_fields_present(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
            signed_at="2026-03-23T12:00:06Z",
        )
        sig = signed["signature"]
        assert sig["algorithm"] == "ed25519"
        assert sig["key_id"] == _KEY_ID
        assert sig["signed_at"] == "2026-03-23T12:00:06Z"
        assert isinstance(sig["signature"], str)
        assert len(sig["signature"]) > 0

    def test_sign_does_not_mutate_input(self, keypair, sample_receipt):
        priv, _ = keypair
        original = copy.deepcopy(sample_receipt)
        sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        assert sample_receipt == original

    def test_signed_at_defaults_to_now(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        assert signed["signature"]["signed_at"] is not None

    def test_whitespace_order_independent_verification(self, keypair, sample_receipt):
        """Sign, serialize with different formatting, reload, verify."""
        import json

        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        # Re-serialize with indentation and different key order
        ugly = json.dumps(signed, indent=4, sort_keys=False)
        reloaded = json.loads(ugly)
        assert verify_receipt_signature(reloaded, resolver=_resolver(pub)) is True


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_tampered_field_fails(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        signed["status"] = "failed"
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=_resolver(pub))

    def test_tampered_contract_sha256_fails(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        signed["contract_sha256"] = "f" * 64
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=_resolver(pub))

    def test_tampered_signed_at_fails(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
            signed_at="2026-03-23T12:00:06Z",
        )
        signed["signature"]["signed_at"] = "2026-01-01T00:00:00Z"
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=_resolver(pub))

    def test_tampered_key_id_fails(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        # Change key_id but keep the same resolver mapping
        signed["signature"]["key_id"] = "forged-key"
        resolver = StaticKeyResolver(keys={_KEY_ID: pub, "forged-key": pub})
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=resolver)

    def test_added_field_fails(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        signed["injected"] = "malicious"
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=_resolver(pub))

    def test_removed_field_fails(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(
            sample_receipt,
            private_key_bytes=priv,
            key_id=_KEY_ID,
        )
        del signed["exit_code"]
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=_resolver(pub))


# ---------------------------------------------------------------------------
# Verification error cases
# ---------------------------------------------------------------------------


class TestVerificationErrors:
    def test_missing_signature(self, sample_receipt):
        with pytest.raises(VerificationError, match="missing signature"):
            verify_receipt_signature(sample_receipt, resolver=StaticKeyResolver(keys={}))

    def test_malformed_signature_object(self, sample_receipt):
        sample_receipt["signature"] = "not a dict"
        with pytest.raises(VerificationError, match="malformed signature"):
            verify_receipt_signature(sample_receipt, resolver=StaticKeyResolver(keys={}))

    def test_unsupported_algorithm(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        signed["signature"]["algorithm"] = "rsa-sha256"
        with pytest.raises(VerificationError, match="unsupported algorithm"):
            verify_receipt_signature(signed, resolver=_resolver(pub))

    def test_unknown_key_id(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        empty_resolver = StaticKeyResolver(keys={})
        with pytest.raises(VerificationError, match="unknown key_id"):
            verify_receipt_signature(signed, resolver=empty_resolver)

    def test_malformed_base64_signature(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        signed["signature"]["signature"] = "not!valid!base64!!!"
        with pytest.raises(VerificationError, match="malformed signature encoding"):
            verify_receipt_signature(signed, resolver=_resolver(pub))

    def test_wrong_key_fails(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        _, other_pub = generate_test_keypair()
        wrong_resolver = StaticKeyResolver(keys={_KEY_ID: other_pub})
        with pytest.raises(VerificationError, match="invalid signature"):
            verify_receipt_signature(signed, resolver=wrong_resolver)

    def test_invalid_public_key_material(self, keypair, sample_receipt):
        priv, _ = keypair
        signed = sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        bad_resolver = StaticKeyResolver(keys={_KEY_ID: b"tooshort"})
        with pytest.raises(VerificationError, match="invalid public key material"):
            verify_receipt_signature(signed, resolver=bad_resolver)

    def test_missing_key_id_in_signature(self, keypair, sample_receipt):
        priv, pub = keypair
        signed = sign_receipt(sample_receipt, private_key_bytes=priv, key_id=_KEY_ID)
        signed["signature"]["key_id"] = ""
        with pytest.raises(VerificationError, match="missing key_id"):
            verify_receipt_signature(signed, resolver=_resolver(pub))


# ---------------------------------------------------------------------------
# Signing error cases
# ---------------------------------------------------------------------------


class TestSigningErrors:
    def test_empty_key_id_rejected(self, keypair, sample_receipt):
        priv, _ = keypair
        with pytest.raises(SigningError, match="key_id must be non-empty"):
            sign_receipt(sample_receipt, private_key_bytes=priv, key_id="")

    def test_invalid_private_key(self, sample_receipt):
        with pytest.raises(SigningError, match="invalid private key"):
            sign_receipt(
                sample_receipt,
                private_key_bytes=b"garbage",
                key_id=_KEY_ID,
            )

    def test_wrong_length_raw_key(self, sample_receipt):
        with pytest.raises(SigningError, match="invalid private key"):
            sign_receipt(
                sample_receipt,
                private_key_bytes=b"x" * 48,
                key_id=_KEY_ID,
            )
