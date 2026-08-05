from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
from typing import Any

import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.multisig_bundle import (
    MultisignatureBundle,
    MultisignatureProof,
    draft_identity_bundle,
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.encoding import is_canonical_cbor
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.signed_envelope import decode_multisignature_envelope


OWNER_NAME = b"owner-name"
OBJECT_HASH = hashlib.sha256(b"object-bytes").hexdigest()
PROVIDER_URL = "https://example.com/object.bin"


def _keypairs(count: int = 4) -> list[Any]:
    return [create_new_key_pair() for _ in range(count)]


def _signer_set(keypairs: list[Any]) -> list[dict[int, Any]]:
    return [
        {1: chr(ord("a") + index), 2: keypair.public_key.to_bytes()}
        for index, keypair in enumerate(keypairs)
    ]


def _draft_identity(keypairs: list[Any]) -> MultisignatureBundle:
    return draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )


def test_identity_draft_is_canonical_and_has_no_proofs_or_private_key_material():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)

    assert isinstance(bundle, MultisignatureBundle)
    assert bundle.proofs == ()
    assert bundle.threshold == 2
    assert bundle.signer_ids == ("a", "b", "c")
    wire = bundle.to_cbor()
    assert is_canonical_cbor(wire)
    assert keypairs[0].private_key.to_bytes() not in wire
    assert decode_multisignature_envelope(wire).proofs == ()


def test_bundle_objects_are_immutable():
    bundle = _draft_identity(_keypairs())

    with pytest.raises(FrozenInstanceError):
        setattr(bundle, "proofs", ())



def test_provider_draft_contains_the_complete_provider_payload():
    keypairs = _keypairs()
    bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url=PROVIDER_URL,
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )

    assert bundle.record_kind == 2
    assert bundle.signed_update[2] == build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=OBJECT_HASH,
        provider_url=PROVIDER_URL,
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
    )


def test_provider_bundle_supports_sign_merge_finalize_and_round_trip():
    keypairs = _keypairs()
    bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url=PROVIDER_URL,
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )

    complete = merge_proof(
        merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key)),
        sign_bundle(bundle, keypairs[1].private_key),
    )
    envelope = finalize_bundle(complete)
    restored = MultisignatureBundle.from_cbor(envelope)

    assert restored.signed_update_bytes == bundle.signed_update_bytes
    assert [proof.signer_id for proof in restored.proofs] == ["a", "b"]
    assert is_canonical_cbor(envelope)


def test_sign_accepts_one_member_private_key_and_merge_adds_detached_proof():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)

    proof_a = sign_bundle(bundle, keypairs[0].private_key)
    signed_bundle = merge_proof(bundle, proof_a)

    assert proof_a.signed_update_bytes == bundle.signed_update_bytes
    assert proof_a.signer_id == "a"
    assert len(signed_bundle.proofs) == 1
    assert signed_bundle.proofs[0].signer_id == "a"


def test_sign_rejects_private_key_not_in_bundle_signer_set():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)

    with pytest.raises(ValueError, match="Signer Set"):
        sign_bundle(bundle, keypairs[3].private_key)


def test_merge_rejects_proof_from_another_bundle():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)
    other_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
    )

    with pytest.raises(ValueError, match="exact bundle"):
        merge_proof(bundle, sign_bundle(other_bundle, keypairs[0].private_key))


def test_merge_rejects_duplicate_nonmember_and_invalid_proofs():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)
    proof_a = sign_bundle(bundle, keypairs[0].private_key)
    signed_bundle = merge_proof(bundle, proof_a)

    with pytest.raises(ValueError, match="duplicate"):
        merge_proof(signed_bundle, proof_a)

    with pytest.raises(ValueError, match="Signer Set"):
        merge_proof(bundle, sign_bundle(bundle, keypairs[3].private_key))

    malformed_length = MultisignatureProof(
        signed_update_bytes=bundle.signed_update_bytes,
        signer_id="a",
        signature=b"\x00" * 63,
    )
    with pytest.raises(ValueError, match="malformed"):
        merge_proof(bundle, malformed_length)

    invalid_signature = MultisignatureProof(
        signed_update_bytes=bundle.signed_update_bytes,
        signer_id="a",
        signature=b"\x00" * 64,
    )
    with pytest.raises(ValueError, match="signature"):
        merge_proof(bundle, invalid_signature)


def test_finalize_rejects_partial_bundle_and_returns_threshold_valid_envelope():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)
    partial = merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key))

    with pytest.raises(ValueError, match="threshold"):
        finalize_bundle(partial)

    complete = merge_proof(partial, sign_bundle(bundle, keypairs[1].private_key))
    envelope = finalize_bundle(complete)
    assert is_canonical_cbor(envelope)
    decoded = decode_multisignature_envelope(envelope)

    assert decoded.signed_update_bytes == bundle.signed_update_bytes
    assert [proof[1] for proof in decoded.proofs] == ["a", "b"]


def test_finalize_rejects_duplicate_proofs_even_for_direct_bundle_construction():
    keypairs = _keypairs()
    bundle = _draft_identity(keypairs)
    proof_a = sign_bundle(bundle, keypairs[0].private_key)
    malformed_bundle = MultisignatureBundle(
        signed_update_bytes=bundle.signed_update_bytes,
        proofs=(proof_a, proof_a),
    )

    with pytest.raises(ValueError, match="duplicate"):
        finalize_bundle(malformed_bundle)


def test_bundle_round_trip_preserves_exact_signed_bytes_and_proofs():
    keypairs = _keypairs()
    draft = _draft_identity(keypairs)
    bundle = merge_proof(
        merge_proof(draft, sign_bundle(draft, keypairs[0].private_key)),
        sign_bundle(draft, keypairs[1].private_key),
    )

    restored = MultisignatureBundle.from_cbor(bundle.to_cbor())
    assert restored.signed_update_bytes == bundle.signed_update_bytes
    assert restored.proofs == bundle.proofs
