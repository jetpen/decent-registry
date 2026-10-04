from __future__ import annotations

import hashlib
from typing import Any

import cbor2
import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import (
    OPERATION_GENESIS,
    OPERATION_ORDINARY_UPDATE,
    canonical_cbor,
)
from decent_registry.envelope_builder import build_provider_envelope
from decent_registry.multisig_bundle import (
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.provider_schema import (
    ProviderPayloadV1,
    ProviderWithdrawnPayloadV2,
    build_provider_payload_dict,
    build_provider_withdrawal_payload_dict,
    decode_provider_payload_dict,
)
from decent_registry.record_validator import (
    ProviderWithdrawnResult,
    RecordValidator,
)
from decent_registry.signed_envelope import (
    decode_multisignature_envelope,
    decode_signed_envelope,
    encode_multisignature_envelope,
    encode_signed_envelope,
)
from decent_registry.verification import make_signed_update_signature


OBJECT_HASH = hashlib.sha256(b"provider withdrawal object").hexdigest()
REPLACEMENT_HASH = hashlib.sha256(b"replacement object").hexdigest()
PROVIDER_URL = "https://example.com/object.bin"
ENDPOINT = "/ip4/127.0.0.1/tcp/9000"


def _legacy_envelope(private_key: Any, *, seq: int, payload: dict[int, Any] | None = None) -> bytes:
    owner_public_key = private_key.get_public_key().to_bytes()
    if payload is None:
        payload = build_provider_payload_dict(
            alg="Ed25519",
            version=1,
            object_hash=OBJECT_HASH,
            provider_url=PROVIDER_URL,
            endpoints=[ENDPOINT],
        )
    from decent_registry.encoding import encode_signed_update

    signed_update = encode_signed_update(
        record_fields={1: owner_public_key}, payload=payload, seq=seq
    )
    return encode_signed_envelope(
        signed_update_bytes=signed_update,
        signature=make_signed_update_signature(
            signed_update_bytes_canonical=signed_update,
            owner_private_key=private_key,
        ),
    )


def _multisig_provider(
    keypairs: list[Any], *, seq: int, operation: int = OPERATION_GENESIS,
    predecessor: bytes = bytes(32), url: str = PROVIDER_URL,
):
    signer_set = [
        {1: chr(ord("a") + i), 2: keypairs[i].public_key.to_bytes()}
        for i in range(3)
    ]
    bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url=url,
        endpoints=[ENDPOINT],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=seq,
        signer_set=signer_set,
        operation=operation,
        predecessor_state_hash=predecessor,
    )
    bundle = merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key))
    bundle = merge_proof(bundle, sign_bundle(bundle, keypairs[1].private_key))
    return bundle, finalize_bundle(bundle)


def _withdrawn_multisig(keypairs: list[Any], *, seq: int, predecessor: bytes, replacement: str | None = None):
    signer_set = [
        {1: chr(ord("a") + i), 2: keypairs[i].public_key.to_bytes()}
        for i in range(3)
    ]
    from decent_registry.multisig_bundle import draft_bundle
    from decent_registry.encoding import RECORD_KIND_PROVIDER

    payload = build_provider_withdrawal_payload_dict(
        alg="Ed25519", object_hash=OBJECT_HASH, replacement_object_hash=replacement
    )
    bundle = draft_bundle(
        record_kind=RECORD_KIND_PROVIDER,
        record_fields={1: keypairs[0].public_key.to_bytes()},
        payload=payload,
        seq=seq,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=predecessor,
    )
    bundle = merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key))
    bundle = merge_proof(bundle, sign_bundle(bundle, keypairs[1].private_key))
    return bundle, finalize_bundle(bundle)


def test_withdrawn_provider_payload_has_strict_v2_wire_shape():
    payload = build_provider_withdrawal_payload_dict(
        alg="Ed25519", object_hash=OBJECT_HASH, replacement_object_hash=REPLACEMENT_HASH
    )

    assert payload == {
        1: "Ed25519",
        2: 2,
        3: OBJECT_HASH,
        4: "withdrawn",
        5: REPLACEMENT_HASH,
    }
    assert isinstance(decode_provider_payload_dict(payload), ProviderWithdrawnPayloadV2)
    assert 4 in payload and 5 not in build_provider_withdrawal_payload_dict(
        alg="Ed25519", object_hash=OBJECT_HASH
    )


@pytest.mark.parametrize("payload", [
    {1: "Ed25519", 2: 2, 3: OBJECT_HASH, 4: "withdrawn", 5: "z" * 64},
    {1: "Ed25519", 2: 2, 3: OBJECT_HASH, 4: "withdrawn", 5: OBJECT_HASH},
    {1: "Ed25519", 2: 3, 3: OBJECT_HASH, 4: "withdrawn"},
    {1: "Ed25519", 2: 2, 3: "not-an-object-hash", 4: "withdrawn"},
    {1: "Ed25519", 2: 2, 3: OBJECT_HASH, 4: "active"},
    {1: "Ed25519", 2: 2, 3: OBJECT_HASH, 4: "withdrawn", 6: "extra"},
])
def test_withdrawn_provider_payload_rejects_invalid_shapes(payload):
    with pytest.raises((TypeError, ValueError)):
        decode_provider_payload_dict(payload)


def test_existing_provider_v1_payload_remains_unchanged():
    payload = build_provider_payload_dict(
        alg="Ed25519", version=1, object_hash=OBJECT_HASH,
        provider_url=PROVIDER_URL, endpoints=[ENDPOINT],
    )

    assert cbor2.loads(canonical_cbor(payload)) == {
        1: "Ed25519", 2: 1, 3: OBJECT_HASH,
        4: PROVIDER_URL, 5: [ENDPOINT],
    }
    assert isinstance(decode_provider_payload_dict(payload), ProviderPayloadV1)


def test_legacy_owner_can_withdraw_and_lookup_is_explicit():
    owner = create_new_key_pair()
    active = _legacy_envelope(owner.private_key, seq=4)
    tombstone_payload = build_provider_withdrawal_payload_dict(
        alg="Ed25519", object_hash=OBJECT_HASH, replacement_object_hash=REPLACEMENT_HASH
    )
    candidate = _legacy_envelope(owner.private_key, seq=5, payload=tombstone_payload)
    validator = RecordValidator()

    accepted = validator.validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH),
        envelope_cbor=candidate,
        existing_envelope_cbor=active,
    )
    result = validator.validate_provider_get(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=candidate,
        existing_envelope_cbor=active,
    )

    assert accepted.seq == 5
    assert isinstance(result, ProviderWithdrawnResult)
    assert result.to_dict() == {
        "status": "withdrawn", "object_key": OBJECT_HASH,
        "seq": 5, "replacement_object_key": REPLACEMENT_HASH,
    }


def test_withdrawal_rejects_wrong_owner_stale_seq_and_repeated_withdrawal():
    owner = create_new_key_pair()
    other = create_new_key_pair()
    active = _legacy_envelope(owner.private_key, seq=4)
    payload = build_provider_withdrawal_payload_dict(alg="Ed25519", object_hash=OBJECT_HASH)
    validator = RecordValidator()

    with pytest.raises(ValueError):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH),
            envelope_cbor=_legacy_envelope(other.private_key, seq=5, payload=payload),
            existing_envelope_cbor=active,
        )
    with pytest.raises(ValueError, match="strictly increasing"):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH),
            envelope_cbor=_legacy_envelope(owner.private_key, seq=4, payload=payload),
            existing_envelope_cbor=active,
        )

    tombstone = _legacy_envelope(owner.private_key, seq=5, payload=payload)
    validator.validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH),
        envelope_cbor=tombstone,
        existing_envelope_cbor=active,
    )
    with pytest.raises(Exception, match="already withdrawn"):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH),
            envelope_cbor=_legacy_envelope(owner.private_key, seq=6, payload=payload),
            existing_envelope_cbor=tombstone,
        )


def test_multisignature_withdrawal_rejects_wrong_predecessor_owner_and_stale_sequence():
    keypairs = [create_new_key_pair() for _ in range(4)]
    _active_bundle, active = _multisig_provider(keypairs[:3], seq=4)
    active_result = RecordValidator().validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=active
    )
    assert not isinstance(active_result, ProviderWithdrawnResult)
    active_state = active_result.state
    assert active_state is not None
    validator = RecordValidator()

    wrong_previous = _withdrawn_multisig(
        keypairs[:3], seq=5, predecessor=bytes(32)
    )[1]
    with pytest.raises(ValueError, match="predecessor"):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=wrong_previous,
            existing_envelope_cbor=active,
        )

    stale = _withdrawn_multisig(
        keypairs[:3], seq=4, predecessor=active_state.state_hash
    )[1]
    with pytest.raises(ValueError, match="strictly increasing"):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=stale,
            existing_envelope_cbor=active,
        )

    wrong_owner = _withdrawn_multisig(
        [keypairs[3], *keypairs[1:3]], seq=5,
        predecessor=active_state.state_hash,
    )[1]
    with pytest.raises(ValueError):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=wrong_owner,
            existing_envelope_cbor=active,
        )


def test_multisignature_withdrawal_binds_current_predecessor_and_rejects_replay():
    keypairs = [create_new_key_pair() for _ in range(3)]
    active_bundle, active = _multisig_provider(keypairs, seq=1)
    active_state = RecordValidator().validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=active
    ).state
    assert active_state is not None
    tombstone_bundle, tombstone = _withdrawn_multisig(
        keypairs, seq=2, predecessor=active_state.state_hash, replacement=REPLACEMENT_HASH
    )
    validator = RecordValidator()

    accepted = validator.validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH),
        envelope_cbor=tombstone,
        existing_envelope_cbor=active,
    )
    result = validator.validate_provider_get(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=tombstone,
        existing_envelope_cbor=active,
    )

    assert accepted.seq == 2
    assert isinstance(result, ProviderWithdrawnResult)
    assert result.authorization is not None and result.authorization.threshold == 2
    wrong_predecessor_bundle, wrong_predecessor = _withdrawn_multisig(
        keypairs, seq=3, predecessor=bytes(32)
    )
    with pytest.raises(ValueError, match="predecessor"):
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH),
            envelope_cbor=wrong_predecessor,
            existing_envelope_cbor=active,
        )
    with pytest.raises(Exception, match="already withdrawn"):
        _ = (tombstone_bundle, wrong_predecessor_bundle)
        validator.validate_provider_overwrite(
            record_key=bytes.fromhex(OBJECT_HASH),
            envelope_cbor=_withdrawn_multisig(
                keypairs, seq=3,
                predecessor=hashlib.sha256(
                    decode_multisignature_envelope(tombstone).signed_update_bytes
                ).digest(),
            )[1],
            existing_envelope_cbor=tombstone,
        )


def test_active_v1_update_reactivates_tombstone_and_can_be_withdrawn_again():
    owner = create_new_key_pair()
    active = _legacy_envelope(owner.private_key, seq=1)
    tombstone = _legacy_envelope(
        owner.private_key, seq=2,
        payload=build_provider_withdrawal_payload_dict(alg="Ed25519", object_hash=OBJECT_HASH),
    )
    reactivated = _legacy_envelope(owner.private_key, seq=3)
    validator = RecordValidator()

    validator.validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=tombstone,
        existing_envelope_cbor=active,
    )
    validator.validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=reactivated,
        existing_envelope_cbor=tombstone,
    )
    assert isinstance(
        validator.validate_provider_get(
            record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=reactivated
        ), ProviderPayloadV1
    )
    again = _legacy_envelope(
        owner.private_key, seq=4,
        payload=build_provider_withdrawal_payload_dict(alg="Ed25519", object_hash=OBJECT_HASH),
    )
    assert validator.validate_provider_overwrite(
        record_key=bytes.fromhex(OBJECT_HASH), envelope_cbor=again,
        existing_envelope_cbor=reactivated,
    ).seq == 4


def test_replacement_hash_must_be_valid_non_self_hash():
    with pytest.raises(ValueError):
        build_provider_withdrawal_payload_dict(
            alg="Ed25519", object_hash=OBJECT_HASH, replacement_object_hash=OBJECT_HASH
        )
    with pytest.raises(ValueError):
        build_provider_withdrawal_payload_dict(
            alg="Ed25519", object_hash=OBJECT_HASH, replacement_object_hash="x" * 64
        )
