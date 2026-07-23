from __future__ import annotations

import hashlib

import cbor2
import pytest
from typing import Any

from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.verification import (
    SeqStateEntry,
    make_signed_update_signature,
    validate_identity_update,
    validate_provider_update,
    validate_signed_update_overwrite,
)


PROVIDER_URL = "https://example.com/object.bin"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _keypair():
    kp = create_new_key_pair()
    return kp.private_key, kp.public_key


def _identity_update(*, owner_name: bytes, owner_pubkey: bytes, seq: int) -> bytes:
    record_fields = {1: owner_name, 2: owner_pubkey}
    payload: dict[int, Any] = {}
    return encode_signed_update(
        record_fields=record_fields,
        payload=payload,
        seq=seq,
    )


def _provider_update(
    *,
    owner_pubkey: bytes,
    object_hash_hex: str,
    payload_dict: dict[int, Any],
    seq: int,
) -> bytes:
    record_fields = {1: owner_pubkey}
    payload: dict[int, Any] = payload_dict
    return encode_signed_update(
        record_fields=record_fields,
        payload=payload,
        seq=seq,
    )


def test_valid_identity_overwrite_updates_seq_state():
    owner_priv, owner_pub = _keypair()
    owner_name = b"owner-name"

    seq_state: dict[bytes, SeqStateEntry] = {}

    signed_update_bytes = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=1,
    )

    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=owner_priv,
    )

    record_key = _sha256(owner_name)

    decoded = validate_identity_update(
        record_key=record_key,
        signed_update_bytes_canonical=signed_update_bytes,
        signature=signature,
        seq_state=seq_state,
    )

    assert 1 in decoded and 2 in decoded and 3 in decoded
    assert record_key in seq_state
    assert seq_state[record_key].seq == 1
    assert seq_state[record_key].owner_public_key == owner_pub.to_bytes()


def test_old_seq_rejected_identity():
    owner_priv, owner_pub = _keypair()
    owner_name = b"owner-name"
    record_key = _sha256(owner_name)

    seq_state: dict[bytes, SeqStateEntry] = {}

    su1 = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=1,
    )
    sig1 = make_signed_update_signature(
        signed_update_bytes_canonical=su1,
        owner_private_key=owner_priv,
    )

    validate_identity_update(
        record_key=record_key,
        signed_update_bytes_canonical=su1,
        signature=sig1,
        seq_state=seq_state,
    )

    su2 = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=1,
    )
    sig2 = make_signed_update_signature(
        signed_update_bytes_canonical=su2,
        owner_private_key=owner_priv,
    )

    with pytest.raises(ValueError, match="strictly increasing"):
        validate_identity_update(
            record_key=record_key,
            signed_update_bytes_canonical=su2,
            signature=sig2,
            seq_state=seq_state,
        )


def test_owner_collision_rejected_identity():
    owner1_priv, owner1_pub = _keypair()
    owner2_priv, owner2_pub = _keypair()
    owner_name = b"owner-name"
    record_key = _sha256(owner_name)

    seq_state: dict[bytes, SeqStateEntry] = {}

    su1 = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner1_pub.to_bytes(),
        seq=1,
    )
    sig1 = make_signed_update_signature(
        signed_update_bytes_canonical=su1,
        owner_private_key=owner1_priv,
    )

    validate_identity_update(
        record_key=record_key,
        signed_update_bytes_canonical=su1,
        signature=sig1,
        seq_state=seq_state,
    )

    su2 = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner2_pub.to_bytes(),
        seq=2,
    )
    sig2 = make_signed_update_signature(
        signed_update_bytes_canonical=su2,
        owner_private_key=owner2_priv,
    )

    with pytest.raises(ValueError, match="owner collision"):
        validate_identity_update(
            record_key=record_key,
            signed_update_bytes_canonical=su2,
            signature=sig2,
            seq_state=seq_state,
        )


def test_wrong_signature_rejected_identity():
    owner_priv, owner_pub = _keypair()
    other_priv, _other_pub = _keypair()

    owner_name = b"owner-name"
    record_key = _sha256(owner_name)

    seq_state: dict[bytes, SeqStateEntry] = {}

    signed_update_bytes = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=1,
    )

    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=other_priv,
    )

    with pytest.raises(ValueError, match="wrong signature"):
        validate_identity_update(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state=seq_state,
        )


def test_lookup_key_mismatch_rejected_identity():
    owner_priv, owner_pub = _keypair()
    owner_name = b"owner-name"
    correct_record_key = _sha256(owner_name)
    wrong_record_key = _sha256(b"different")

    seq_state: dict[bytes, SeqStateEntry] = {}

    signed_update_bytes = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=1,
    )

    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=owner_priv,
    )

    with pytest.raises(ValueError, match="lookup-key mismatch"):
        validate_identity_update(
            record_key=wrong_record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state=seq_state,
        )


def test_non_canonical_signed_update_rejected_identity():
    owner_priv, owner_pub = _keypair()
    owner_name = b"owner-name"
    record_key = _sha256(owner_name)

    # Build a logically-equivalent SignedUpdate but encoded non-canonically.
    record_fields_noncanonical = {2: owner_pub.to_bytes(), 1: owner_name}
    payload_noncanonical: dict[int, Any] = {}
    signed_update_map_noncanonical = {1: record_fields_noncanonical, 2: payload_noncanonical, 3: 1}
    signed_update_bytes_noncanonical = cbor2.dumps(signed_update_map_noncanonical, canonical=False)

    signature = b"\x00" * 64
    seq_state: dict[bytes, SeqStateEntry] = {}

    with pytest.raises(ValueError, match="non-canonical"):
        validate_identity_update(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes_noncanonical,
            signature=signature,
            seq_state=seq_state,
        )


def test_valid_provider_overwrite():
    owner_priv, owner_pub = _keypair()
    obj_content = b"object-bytes"
    object_hash_hex = hashlib.sha256(obj_content).hexdigest()  # 64 hex chars
    record_key = bytes.fromhex(object_hash_hex)

    endpoints = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash_hex,
        provider_url=PROVIDER_URL,
        endpoints=endpoints,
    )

    seq_state: dict[bytes, SeqStateEntry] = {}

    signed_update_bytes = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )

    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=owner_priv,
    )

    decoded = validate_provider_update(
        record_key=record_key,
        signed_update_bytes_canonical=signed_update_bytes,
        signature=signature,
        seq_state=seq_state,
    )

    assert 1 in decoded and 2 in decoded and 3 in decoded
    assert seq_state[record_key].seq == 1
    assert seq_state[record_key].owner_public_key == owner_pub.to_bytes()


@pytest.mark.parametrize("kind", ["identity", "provider"])
def test_validate_signed_update_overwrite_delegates(kind: str):
    owner_priv, owner_pub = _keypair()

    seq_state: dict[bytes, SeqStateEntry] = {}

    if kind == "identity":
        owner_name = b"owner-name"
        record_key = _sha256(owner_name)
        signed_update_bytes = _identity_update(
            owner_name=owner_name,
            owner_pubkey=owner_pub.to_bytes(),
            seq=1,
        )
    else:
        obj_content = b"object-bytes"
        object_hash_hex = hashlib.sha256(obj_content).hexdigest()
        record_key = bytes.fromhex(object_hash_hex)
        endpoints = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
        payload_dict = build_provider_payload_dict(
            alg="Ed25519",
            version=1,
            object_hash=object_hash_hex,
            provider_url=PROVIDER_URL,
            endpoints=endpoints,
        )
        signed_update_bytes = _provider_update(
            owner_pubkey=owner_pub.to_bytes(),
            object_hash_hex=object_hash_hex,
            payload_dict=payload_dict,
            seq=1,
        )

    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=owner_priv,
    )

    decoded = validate_signed_update_overwrite(
        record_key=record_key,
        signed_update_bytes_canonical=signed_update_bytes,
        signature=signature,
        seq_state=seq_state,
    )

    assert 1 in decoded and 2 in decoded and 3 in decoded
    assert record_key in seq_state
    assert seq_state[record_key].seq == 1
    assert seq_state[record_key].owner_public_key == owner_pub.to_bytes()
