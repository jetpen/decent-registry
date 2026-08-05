from __future__ import annotations

import hashlib
from typing import Any

import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import (
    OPERATION_GENESIS,
    OPERATION_ORDINARY_UPDATE,
    OPERATION_REPLACE_SIGNERS,
    OPERATION_UPGRADE,
    RECORD_KIND_IDENTITY,
    RECORD_KIND_PROVIDER,
    encode_multisignature_signed_update,
    encode_signed_update,
)
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.signed_envelope import (
    encode_multisignature_envelope,
    encode_signed_envelope,
)
from decent_registry.verification import (
    MultisignatureState,
    make_signed_update_signature,
    validate_multisignature_update,
)


PROVIDER_URL = "https://example.com/object.bin"
OWNER_NAME = b"owner-name"


def _keypairs(count: int = 4) -> list[Any]:
    return [create_new_key_pair() for _ in range(count)]


def _signer_set(
    keypairs: list[Any], *, prefix: str = ""
) -> list[dict[int, Any]]:
    return [
        {1: f"{prefix}{chr(ord('a') + index)}", 2: keypair.public_key.to_bytes()}
        for index, keypair in enumerate(keypairs)
    ]


def _authorization(
    *,
    record_kind: int,
    operation: int,
    epoch: int,
    predecessor_state_hash: bytes,
    signer_set: list[dict[int, Any]],
    threshold: int = 2,
) -> dict[int, Any]:
    return {
        1: 1,
        2: record_kind,
        3: operation,
        4: epoch,
        5: threshold,
        6: signer_set,
        7: predecessor_state_hash,
    }


def _identity_update(
    *,
    owner_public_key: bytes,
    seq: int,
    authorization: dict[int, Any],
) -> bytes:
    return encode_multisignature_signed_update(
        record_fields={1: OWNER_NAME, 2: owner_public_key},
        payload={},
        seq=seq,
        authorization=authorization,
    )


def _provider_payload() -> dict[int, Any]:
    object_hash = hashlib.sha256(b"object-bytes").hexdigest()
    return build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=object_hash,
        provider_url=PROVIDER_URL,
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
    )


def _provider_update(
    *,
    owner_public_key: bytes,
    seq: int,
    authorization: dict[int, Any],
) -> bytes:
    return encode_multisignature_signed_update(
        record_fields={1: owner_public_key},
        payload=_provider_payload(),
        seq=seq,
        authorization=authorization,
    )


def _proof(signer_id: str, keypair: Any, signed_update: bytes) -> dict[int, Any]:
    return {
        1: signer_id,
        2: make_signed_update_signature(
            signed_update_bytes_canonical=signed_update,
            owner_private_key=keypair.private_key,
        ),
    }


def _envelope(signed_update: bytes, proofs: list[dict[int, Any]]) -> bytes:
    return encode_multisignature_envelope(
        signed_update_bytes=signed_update,
        proofs=proofs,
    )


def _identity_genesis(keypairs: list[Any]) -> tuple[bytes, bytes, list[dict[int, Any]]]:
    signer_set = _signer_set(keypairs[:3])
    update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_GENESIS,
            epoch=1,
            predecessor_state_hash=bytes(32),
            signer_set=signer_set,
        ),
    )
    envelope = _envelope(update, [_proof("a", keypairs[0], update), _proof("b", keypairs[1], update)])
    return hashlib.sha256(OWNER_NAME).digest(), envelope, signer_set


def test_valid_genesis_and_ordinary_identity_updates_are_accepted():
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)

    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    assert genesis_state.epoch == 1
    assert genesis_state.seq == 1
    assert genesis_state.signer_set == tuple((entry[1], entry[2]) for entry in signer_set)

    ordinary_update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=signer_set,
        ),
    )
    ordinary_envelope = _envelope(
        ordinary_update,
        [_proof("a", keypairs[0], ordinary_update), _proof("c", keypairs[2], ordinary_update)],
    )

    state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=ordinary_envelope,
        current_state=genesis_state,
    )
    assert state.seq == 2
    assert state.epoch == genesis_state.epoch
    assert state.state_hash == hashlib.sha256(ordinary_update).digest()


def test_valid_provider_ordinary_update_is_accepted():
    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    object_hash = hashlib.sha256(b"object-bytes").digest()

    genesis_update = _provider_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        authorization=_authorization(
            record_kind=RECORD_KIND_PROVIDER,
            operation=OPERATION_GENESIS,
            epoch=1,
            predecessor_state_hash=bytes(32),
            signer_set=signer_set,
        ),
    )
    genesis_envelope = _envelope(
        genesis_update,
        [_proof("a", keypairs[0], genesis_update), _proof("b", keypairs[1], genesis_update)],
    )
    genesis_state = validate_multisignature_update(
        record_key=object_hash,
        envelope_cbor=genesis_envelope,
    )

    ordinary_update = _provider_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_PROVIDER,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=signer_set,
        ),
    )
    state = validate_multisignature_update(
        record_key=object_hash,
        envelope_cbor=_envelope(
            ordinary_update,
            [_proof("b", keypairs[1], ordinary_update), _proof("c", keypairs[2], ordinary_update)],
        ),
        current_state=genesis_state,
    )
    assert state.record_kind == RECORD_KIND_PROVIDER
    assert state.seq == 2


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("seq", 1, "strictly increasing"),
        ("epoch", 2, "epoch"),
        ("predecessor_state_hash", bytes(32), "predecessor"),
    ],
)
def test_ordinary_update_rejects_stale_state_fields(field: str, value: Any, message: str):
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)
    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    fields = {
        "seq": 2,
        "epoch": 1,
        "predecessor_state_hash": genesis_state.state_hash,
    }
    fields[field] = value
    update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=fields["seq"],
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=fields["epoch"],
            predecessor_state_hash=fields["predecessor_state_hash"],
            signer_set=signer_set,
        ),
    )
    with pytest.raises(ValueError, match=message):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(
                update,
                [_proof("a", keypairs[0], update), _proof("b", keypairs[1], update)],
            ),
            current_state=genesis_state,
        )


def test_ordinary_update_rejects_retired_signer_and_changed_signer_set():
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)
    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    changed_set = _signer_set([keypairs[0], keypairs[1], keypairs[3]])
    update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=changed_set,
        ),
    )
    with pytest.raises(ValueError, match="signer set"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(
                update,
                [_proof("a", keypairs[0], update), _proof("b", keypairs[1], update)],
            ),
            current_state=genesis_state,
        )

    retired_proof_update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=signer_set,
        ),
    )
    with pytest.raises(ValueError, match="current Signer Set"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(
                retired_proof_update,
                [_proof("a", keypairs[0], retired_proof_update), _proof("d", keypairs[3], retired_proof_update)],
            ),
            current_state=genesis_state,
        )


def test_ordinary_update_preserves_owner_binding():
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)
    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    update = _identity_update(
        owner_public_key=keypairs[3].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=signer_set,
        ),
    )
    with pytest.raises(ValueError, match="owner binding"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(
                update,
                [_proof("a", keypairs[0], update), _proof("b", keypairs[1], update)],
            ),
            current_state=genesis_state,
        )


def test_signer_replacement_requires_current_quorum_and_installs_complete_next_set():
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)
    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    next_set = _signer_set(
        [keypairs[1], keypairs[2], keypairs[3]], prefix="new-"
    )
    replacement = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_REPLACE_SIGNERS,
            epoch=2,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=next_set,
        ),
    )
    state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=_envelope(
            replacement,
            [_proof("a", keypairs[0], replacement), _proof("b", keypairs[1], replacement)],
        ),
        current_state=genesis_state,
    )
    assert state.epoch == 2
    assert state.signer_set == tuple((entry[1], entry[2]) for entry in next_set)

    self_authorized = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=3,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_REPLACE_SIGNERS,
            epoch=3,
            predecessor_state_hash=state.state_hash,
            signer_set=signer_set,
        ),
    )
    with pytest.raises(ValueError, match="current Signer Set"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(
                self_authorized,
                [_proof("a", keypairs[0], self_authorized), _proof("b", keypairs[1], self_authorized)],
            ),
            current_state=state,
        )


def test_legacy_owner_can_explicitly_upgrade_to_complete_2_of_3_set():
    keypairs = _keypairs()
    legacy_private = keypairs[0].private_key
    legacy_public = keypairs[0].public_key.to_bytes()
    record_key = hashlib.sha256(OWNER_NAME).digest()
    legacy_update = encode_signed_update(
        record_fields={1: OWNER_NAME, 2: legacy_public},
        payload={},
        seq=4,
    )
    legacy_signature = make_signed_update_signature(
        signed_update_bytes_canonical=legacy_update,
        owner_private_key=legacy_private,
    )
    legacy_envelope = encode_signed_envelope(
        signed_update_bytes=legacy_update,
        signature=legacy_signature,
    )

    signer_set = _signer_set(keypairs[:3])
    upgrade = _identity_update(
        owner_public_key=legacy_public,
        seq=5,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_UPGRADE,
            epoch=1,
            predecessor_state_hash=hashlib.sha256(legacy_update).digest(),
            signer_set=signer_set,
        ),
    )
    valid_proof = _proof("a", keypairs[0], upgrade)
    with pytest.raises(ValueError, match="signer_id"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(
                upgrade, [{1: "wrong-owner", 2: valid_proof[2]}]
            ),
            legacy_envelope_cbor=legacy_envelope,
        )

    state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=_envelope(upgrade, [valid_proof]),
        legacy_envelope_cbor=legacy_envelope,
    )
    assert state.epoch == 1
    assert state.seq == 5
    assert state.threshold == 2
    assert len(state.signer_set) == 3


def test_upgrade_rejects_new_set_self_authorization_and_invalid_legacy_state():
    keypairs = _keypairs()
    legacy_public = keypairs[0].public_key.to_bytes()
    record_key = hashlib.sha256(OWNER_NAME).digest()
    legacy_update = encode_signed_update(
        record_fields={1: OWNER_NAME, 2: legacy_public}, payload={}, seq=4
    )
    legacy_signature = make_signed_update_signature(
        signed_update_bytes_canonical=legacy_update,
        owner_private_key=keypairs[0].private_key,
    )
    legacy_envelope = encode_signed_envelope(
        signed_update_bytes=legacy_update, signature=legacy_signature
    )
    signer_set = _signer_set(keypairs[1:4])
    upgrade = _identity_update(
        owner_public_key=legacy_public,
        seq=5,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_UPGRADE,
            epoch=1,
            predecessor_state_hash=hashlib.sha256(legacy_update).digest(),
            signer_set=signer_set,
        ),
    )

    with pytest.raises(ValueError, match="legacy owner"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(upgrade, [_proof("b", keypairs[1], upgrade)]),
            legacy_envelope_cbor=legacy_envelope,
        )

    with pytest.raises(ValueError, match="current multisignature state"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(upgrade, [_proof("legacy-owner", keypairs[0], upgrade)]),
        )


def test_wrong_lookup_key_and_equal_sequence_are_rejected():
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)
    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=signer_set,
        ),
    )
    envelope = _envelope(update, [_proof("a", keypairs[0], update), _proof("b", keypairs[1], update)])
    with pytest.raises(ValueError, match="strictly increasing"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=envelope,
            current_state=genesis_state,
        )
    with pytest.raises(ValueError, match="lookup-key"):
        validate_multisignature_update(
            record_key=hashlib.sha256(b"different").digest(),
            envelope_cbor=envelope,
            current_state=genesis_state,
        )


def test_insufficient_quorum_is_rejected():
    keypairs = _keypairs()
    record_key, genesis_envelope, signer_set = _identity_genesis(keypairs)
    genesis_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=genesis_envelope,
    )
    update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=genesis_state.state_hash,
            signer_set=signer_set,
        ),
    )
    with pytest.raises(ValueError, match="insufficient quorum"):
        validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=_envelope(update, [_proof("a", keypairs[0], update)]),
            current_state=genesis_state,
        )


def test_state_objects_require_validator_provenance():
    with pytest.raises(TypeError):
        MultisignatureState(
            record_key=b"r" * 32,
            record_kind=RECORD_KIND_IDENTITY,
            owner_public_key=b"o" * 32,
            signed_update_bytes=b"u",
            state_hash=b"h" * 32,
            epoch=1,
            seq=1,
            threshold=2,
            signer_set=(),
            _validation_token=object(),
        )


def test_multisignature_update_requires_current_state_for_non_genesis_operations():
    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    update = _identity_update(
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        authorization=_authorization(
            record_kind=RECORD_KIND_IDENTITY,
            operation=OPERATION_ORDINARY_UPDATE,
            epoch=1,
            predecessor_state_hash=bytes(32),
            signer_set=signer_set,
        ),
    )
    with pytest.raises(ValueError, match="current multisignature state"):
        validate_multisignature_update(
            record_key=hashlib.sha256(OWNER_NAME).digest(),
            envelope_cbor=_envelope(
                update,
                [_proof("a", keypairs[0], update), _proof("b", keypairs[1], update)],
            ),
        )
