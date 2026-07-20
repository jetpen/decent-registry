from __future__ import annotations

import hashlib

import cbor2
import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.record_validator import RecordValidator
from decent_registry.signed_envelope import encode_signed_envelope
from decent_registry.verification import (
    make_signed_update_signature,
)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _keypair():
    kp = create_new_key_pair()
    return kp.private_key, kp.public_key


def _identity_update(*, owner_name: bytes, owner_pubkey: bytes, seq: int) -> bytes:
    record_fields = {1: owner_name, 2: owner_pubkey}
    payload = {}
    return encode_signed_update(
        record_fields=record_fields,
        payload=payload,
        seq=seq,
    )


def _provider_update(
    *,
    owner_pubkey: bytes,
    object_hash_hex: str,
    payload_dict: dict,
    seq: int,
) -> bytes:
    record_fields = {1: owner_pubkey}
    payload = payload_dict
    return encode_signed_update(
        record_fields=record_fields,
        payload=payload,
        seq=seq,
    )


def _envelope(*, signed_update_bytes: bytes, signature: bytes) -> bytes:
    return encode_signed_envelope(
        signed_update_bytes=signed_update_bytes,
        signature=signature,
    )


def test_validate_provider_overwrite_with_prev_seq_allows_increase():
    owner_priv, owner_pub = _keypair()
    obj_content = b"object-bytes"
    object_hash_hex = hashlib.sha256(obj_content).hexdigest()  # 64 hex chars
    record_key = bytes.fromhex(object_hash_hex)

    endpoints = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash_hex,
        provider_id="02" * 32,
        endpoints=endpoints,
    )

    su1 = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )
    sig1 = make_signed_update_signature(
        signed_update_bytes_canonical=su1,
        owner_private_key=owner_priv,
    )
    env1 = _envelope(signed_update_bytes=su1, signature=sig1)

    su2 = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=2,
    )
    sig2 = make_signed_update_signature(
        signed_update_bytes_canonical=su2,
        owner_private_key=owner_priv,
    )
    env2 = _envelope(signed_update_bytes=su2, signature=sig2)

    v = RecordValidator()
    res = v.validate_provider_overwrite(
        record_key=record_key,
        envelope_cbor=env2,
        existing_envelope_cbor=env1,
    )

    assert res.object_hash_hex == object_hash_hex
    assert res.owner_public_key == owner_pub.to_bytes()
    assert res.seq == 2


def test_validate_provider_overwrite_rejects_old_seq():
    owner_priv, owner_pub = _keypair()
    obj_content = b"object-bytes"
    object_hash_hex = hashlib.sha256(obj_content).hexdigest()
    record_key = bytes.fromhex(object_hash_hex)

    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash_hex,
        provider_id="02" * 32,
        endpoints=["/ip4/1/tcp/1"],
    )

    su1 = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )
    sig1 = make_signed_update_signature(
        signed_update_bytes_canonical=su1,
        owner_private_key=owner_priv,
    )
    env1 = _envelope(signed_update_bytes=su1, signature=sig1)

    # Attempt overwrite at the same seq.
    su_same = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )
    sig_same = make_signed_update_signature(
        signed_update_bytes_canonical=su_same,
        owner_private_key=owner_priv,
    )
    env_same = _envelope(signed_update_bytes=su_same, signature=sig_same)

    v = RecordValidator()
    with pytest.raises(ValueError, match="strictly increasing"):
        v.validate_provider_overwrite(
            record_key=record_key,
            envelope_cbor=env_same,
            existing_envelope_cbor=env1,
        )


def test_validate_identity_overwrite_with_prev_seq_allows_increase():
    owner_priv, owner_pub = _keypair()
    owner_name = b"owner-name"
    object_key_hex = _sha256(owner_name).hex()
    record_key = bytes.fromhex(object_key_hex)

    su1 = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=1,
    )
    sig1 = make_signed_update_signature(
        signed_update_bytes_canonical=su1,
        owner_private_key=owner_priv,
    )
    env1 = _envelope(signed_update_bytes=su1, signature=sig1)

    su2 = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=2,
    )
    sig2 = make_signed_update_signature(
        signed_update_bytes_canonical=su2,
        owner_private_key=owner_priv,
    )
    env2 = _envelope(signed_update_bytes=su2, signature=sig2)

    v = RecordValidator()
    res = v.validate_identity_overwrite(
        record_key=record_key,
        envelope_cbor=env2,
        existing_envelope_cbor=env1,
    )

    assert res.object_key_hex == object_key_hex
    assert res.owner_public_key == owner_pub.to_bytes()
    assert res.owner_name_hex == owner_name.hex()
    assert res.seq == 2


def test_validate_identity_get_returns_decoded_fields():
    owner_priv, owner_pub = _keypair()
    owner_name = b"owner-name"
    object_key_hex = _sha256(owner_name).hex()
    record_key = bytes.fromhex(object_key_hex)

    su = _identity_update(
        owner_name=owner_name,
        owner_pubkey=owner_pub.to_bytes(),
        seq=3,
    )
    sig = make_signed_update_signature(
        signed_update_bytes_canonical=su,
        owner_private_key=owner_priv,
    )
    env = _envelope(signed_update_bytes=su, signature=sig)

    v = RecordValidator()
    res = v.validate_identity_get(record_key=record_key, envelope_cbor=env)

    assert res.object_key_hex == object_key_hex
    assert res.owner_public_key == owner_pub.to_bytes()
    assert res.owner_name_hex == owner_name.hex()
    assert res.seq == 3


def test_validate_provider_get_returns_decoded_provider_payload():
    owner_priv, owner_pub = _keypair()
    obj_content = b"object-bytes"
    object_hash_hex = hashlib.sha256(obj_content).hexdigest()
    record_key = bytes.fromhex(object_hash_hex)

    endpoints = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash_hex,
        provider_id="02" * 32,
        endpoints=endpoints,
    )

    su = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )
    sig = make_signed_update_signature(
        signed_update_bytes_canonical=su,
        owner_private_key=owner_priv,
    )
    env = _envelope(signed_update_bytes=su, signature=sig)

    v = RecordValidator()
    payload = v.validate_provider_get(record_key=record_key, envelope_cbor=env)

    assert payload.object_hash == object_hash_hex
    assert payload.provider_id == "02" * 32
    # Provider schema normalizes/sorts endpoints.
    assert payload.endpoints == sorted(endpoints)


def test_validate_provider_overwrite_rejects_lookup_key_mismatch():
    owner_priv, owner_pub = _keypair()
    obj_content = b"object-bytes"
    object_hash_hex = hashlib.sha256(obj_content).hexdigest()
    correct_record_key = bytes.fromhex(object_hash_hex)
    wrong_record_key = bytes.fromhex(hashlib.sha256(b"different").hexdigest())

    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash_hex,
        provider_id="02" * 32,
        endpoints=["/ip4/1/tcp/1"],
    )

    su = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )
    sig = make_signed_update_signature(
        signed_update_bytes_canonical=su,
        owner_private_key=owner_priv,
    )
    env = _envelope(signed_update_bytes=su, signature=sig)

    v = RecordValidator()
    with pytest.raises(ValueError, match="lookup-key mismatch"):
        v.validate_provider_overwrite(
            record_key=wrong_record_key,
            envelope_cbor=env,
            existing_envelope_cbor=None,
        )


def test_validate_provider_get_rejects_noncanonical_envelope():
    owner_priv, owner_pub = _keypair()
    obj_content = b"object-bytes"
    object_hash_hex = hashlib.sha256(obj_content).hexdigest()
    record_key = bytes.fromhex(object_hash_hex)

    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash_hex,
        provider_id="02" * 32,
        endpoints=["/ip4/1/tcp/1"],
    )

    su = _provider_update(
        owner_pubkey=owner_pub.to_bytes(),
        object_hash_hex=object_hash_hex,
        payload_dict=payload_dict,
        seq=1,
    )
    sig = make_signed_update_signature(
        signed_update_bytes_canonical=su,
        owner_private_key=owner_priv,
    )

    # Force non-canonical CBOR for the envelope by reversing the CBOR map key
    # insertion order (RFC 7049 requires canonical ordering).
    env_noncanonical = cbor2.dumps({2: sig, 1: su}, canonical=False)

    v = RecordValidator()
    with pytest.raises(ValueError, match="non-canonical"):
        v.validate_provider_get(record_key=record_key, envelope_cbor=env_noncanonical)
