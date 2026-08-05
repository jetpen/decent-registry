from __future__ import annotations

import hashlib
from typing import Any

import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import (
    OPERATION_GENESIS,
    OPERATION_ORDINARY_UPDATE,
    OPERATION_UPGRADE,
    encode_signed_update,
)
from decent_registry.multisig_bundle import (
    MultisignatureBundle,
    draft_identity_bundle,
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.record_validator import RecordValidator
from decent_registry.signed_envelope import (
    decode_signed_envelope,
    encode_multisignature_envelope,
    encode_signed_envelope,
)
from decent_registry.verification import make_signed_update_signature


OWNER_NAME = b"integration-owner"
OBJECT_HASH = hashlib.sha256(b"integration-object").hexdigest()
PROVIDER_URL = "https://example.com/integration.bin"


def _keypairs(count: int = 4) -> list[Any]:
    return [create_new_key_pair() for _ in range(count)]


def _signer_set(keypairs: list[Any]) -> list[dict[int, Any]]:
    return [
        {1: chr(ord("a") + index), 2: keypair.public_key.to_bytes()}
        for index, keypair in enumerate(keypairs)
    ]


def _complete(bundle: MultisignatureBundle, keypairs: list[Any]) -> bytes:
    partial = merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key))
    complete = merge_proof(partial, sign_bundle(bundle, keypairs[1].private_key))
    return finalize_bundle(complete)


def _legacy_identity_envelope(*, private_key: Any, owner_name: bytes, seq: int) -> bytes:
    owner_public_key = private_key.get_public_key().to_bytes()
    signed_update = encode_signed_update(
        record_fields={1: owner_name, 2: owner_public_key},
        payload={},
        seq=seq,
    )
    return encode_signed_envelope(
        signed_update_bytes=signed_update,
        signature=make_signed_update_signature(
            signed_update_bytes_canonical=signed_update,
            owner_private_key=private_key,
        ),
    )


def test_identity_put_and_get_validate_multisig_state_and_metadata():
    keypairs = _keypairs()
    record_key = hashlib.sha256(OWNER_NAME).digest()
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _complete(genesis_bundle, keypairs)

    validator = RecordValidator()
    genesis_result = validator.validate_identity_overwrite(
        record_key=record_key,
        envelope_cbor=genesis,
    )
    assert genesis_result.seq == 1
    assert genesis_result.authorization is not None
    assert genesis_result.authorization.operation == OPERATION_GENESIS
    assert genesis_result.authorization.threshold == 2

    ordinary_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_result.authorization.state_hash,
    )
    ordinary = _complete(ordinary_bundle, keypairs)
    ordinary_result = validator.validate_identity_overwrite(
        record_key=record_key,
        envelope_cbor=ordinary,
        existing_envelope_cbor=genesis,
    )
    assert ordinary_result.seq == 2
    assert ordinary_result.authorization is not None
    assert ordinary_result.authorization.operation == OPERATION_ORDINARY_UPDATE

    resolved = validator.validate_identity_get(
        record_key=record_key,
        envelope_cbor=ordinary,
    )
    assert resolved.owner_name_hex == OWNER_NAME.hex()
    assert resolved.authorization is not None
    assert resolved.authorization.state_hash == ordinary_result.authorization.state_hash


def test_provider_put_and_get_validate_multisig_payload_and_metadata():
    keypairs = _keypairs()
    record_key = bytes.fromhex(OBJECT_HASH)
    bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url=PROVIDER_URL,
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    envelope = _complete(bundle, keypairs)

    validator = RecordValidator()
    result = validator.validate_provider_overwrite(
        record_key=record_key,
        envelope_cbor=envelope,
    )
    assert result.object_hash_hex == OBJECT_HASH
    assert result.authorization is not None
    assert result.authorization.operation == OPERATION_GENESIS

    resolved = validator.validate_provider_get(
        record_key=record_key,
        envelope_cbor=envelope,
    )
    assert resolved.payload.object_hash == OBJECT_HASH
    assert resolved.payload.provider_url == PROVIDER_URL
    assert resolved.authorization is not None
    assert resolved.authorization.threshold == 2


def test_legacy_identity_upgrade_is_accepted_but_legacy_downgrade_is_rejected():
    keypairs = _keypairs()
    legacy = _legacy_identity_envelope(
        private_key=keypairs[0].private_key,
        owner_name=OWNER_NAME,
        seq=1,
    )
    legacy_signed_update, _legacy_signature = decode_signed_envelope(legacy)
    record_key = hashlib.sha256(OWNER_NAME).digest()
    signer_set = _signer_set(keypairs[:3])
    upgrade_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_UPGRADE,
        predecessor_state_hash=hashlib.sha256(legacy_signed_update).digest(),
    )
    upgrade_signed_update = upgrade_bundle.signed_update_bytes
    legacy_owner_proof = {
        1: "a",
        2: make_signed_update_signature(
            signed_update_bytes_canonical=upgrade_signed_update,
            owner_private_key=keypairs[0].private_key,
        ),
    }
    upgrade = encode_multisignature_envelope(
        signed_update_bytes=upgrade_signed_update,
        proofs=[legacy_owner_proof],
    )

    validator = RecordValidator()
    result = validator.validate_identity_overwrite(
        record_key=record_key,
        envelope_cbor=upgrade,
        existing_envelope_cbor=legacy,
    )
    assert result.authorization is not None
    assert result.authorization.operation == OPERATION_UPGRADE

    legacy_after_upgrade = _legacy_identity_envelope(
        private_key=keypairs[0].private_key,
        owner_name=OWNER_NAME,
        seq=3,
    )
    with pytest.raises(ValueError, match="legacy|downgrade|multisignature"):
        validator.validate_identity_overwrite(
            record_key=record_key,
            envelope_cbor=legacy_after_upgrade,
            existing_envelope_cbor=upgrade,
        )
