from __future__ import annotations

import hashlib
from typing import Any

import pytest
import trio
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore
from decent_registry.encoding import (
    OPERATION_ORDINARY_UPDATE,
    OPERATION_UPGRADE,
    encode_signed_update,
)
from decent_registry.multisig_bundle import (
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


OWNER_NAME = b"dht-owner"
OBJECT_HASH = hashlib.sha256(b"dht-object").hexdigest()


def _keypairs(count: int = 4) -> list[Any]:
    return [create_new_key_pair() for _ in range(count)]


def _signer_set(keypairs: list[Any]) -> list[dict[int, Any]]:
    return [
        {1: chr(ord("a") + index), 2: keypair.public_key.to_bytes()}
        for index, keypair in enumerate(keypairs)
    ]


def _finalize(bundle, keypairs: list[Any]) -> bytes:
    first = merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key))
    complete = merge_proof(first, sign_bundle(bundle, keypairs[1].private_key))
    return finalize_bundle(complete)


class FakeKad:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.fail_reads = False

    async def get_value(self, key: str, quorum: int = 0) -> bytes | None:
        if self.fail_reads:
            raise RuntimeError("DHT unavailable")
        return self.values.get(key)

    async def put_value(self, key: str, value: bytes) -> None:
        self.values[key] = value


def _adapter(tmp_path):
    adapter = object.__new__(Libp2pKadDHT)
    adapter._dht = FakeKad()
    adapter._durable_store = LMDBDatastore(
        path=tmp_path / "accepted.lmdb", mapsize_bytes=1024 * 1024
    )
    adapter._validator = RecordValidator()
    adapter._accepted_lock = trio.Lock()
    return adapter


@pytest.mark.trio
async def test_dht_put_get_uses_durable_accepted_state_over_stale_dht(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    fake = adapter.dht
    record_key = bytes.fromhex(OBJECT_HASH)

    genesis_bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url="https://example.com/one.bin",
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)
    validator = RecordValidator()
    genesis_result = validator.validate_provider_overwrite(
        record_key=record_key,
        envelope_cbor=genesis,
    )

    await adapter.put_signed_provider_record(OBJECT_HASH, genesis)

    ordinary_bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url="https://example.com/two.bin",
        endpoints=["/ip4/127.0.0.1/tcp/9001"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_result.state.state_hash,
    )
    ordinary = _finalize(ordinary_bundle, keypairs)
    ordinary_result = validator.validate_provider_overwrite(
        record_key=record_key,
        envelope_cbor=ordinary,
        existing_envelope_cbor=genesis,
    )
    await adapter.put_signed_provider_record(OBJECT_HASH, ordinary)

    stale_conflict_bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url="https://example.com/conflict.bin",
        endpoints=["/ip4/127.0.0.1/tcp/9002"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_result.state.state_hash,
    )
    with pytest.raises(ValueError, match="strictly increasing"):
        await adapter.put_signed_provider_record(
            OBJECT_HASH, _finalize(stale_conflict_bundle, keypairs)
        )
    assert adapter._durable_store.get(
        kind="provider", key=record_key
    ) == ordinary

    fake.values[adapter._kad_key(OBJECT_HASH)] = genesis
    next_bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_url="https://example.com/three.bin",
        endpoints=["/ip4/127.0.0.1/tcp/9003"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=3,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=ordinary_result.state.state_hash,
    )
    next_envelope = _finalize(next_bundle, keypairs)
    await adapter.put_signed_provider_record(OBJECT_HASH, next_envelope)
    assert fake.values[adapter._kad_key(OBJECT_HASH)] == next_envelope

    fake.values[adapter._kad_key(OBJECT_HASH)] = genesis
    resolved = await adapter.get_signed_provider_record(OBJECT_HASH)
    assert resolved is not None
    assert resolved.seq == 3
    assert resolved.provider_url.endswith("three.bin")

    fake.fail_reads = True
    fallback = await adapter.get_signed_provider_record(OBJECT_HASH)
    assert fallback is not None
    assert fallback.seq == 3


@pytest.mark.trio
async def test_dht_identity_put_get_returns_authorization_metadata(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    envelope = _finalize(
        draft_identity_bundle(
            owner_name=OWNER_NAME,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=1,
            signer_set=_signer_set(keypairs[:3]),
        ),
        keypairs,
    )

    await adapter.put_signed_identity_record(identity_key, envelope)
    resolved = await adapter.get_signed_identity_record(identity_key)

    assert resolved is not None
    assert resolved.authorization.threshold == 2
    assert resolved.owner_name_hex == OWNER_NAME.hex()


@pytest.mark.trio
async def test_dht_rejects_legacy_write_after_multisig_upgrade(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    fake = adapter.dht
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    owner_public_key = keypairs[0].public_key.to_bytes()

    legacy_signed_update = encode_signed_update(
        record_fields={1: OWNER_NAME, 2: owner_public_key},
        payload={},
        seq=1,
    )
    legacy = encode_signed_envelope(
        signed_update_bytes=legacy_signed_update,
        signature=make_signed_update_signature(
            signed_update_bytes_canonical=legacy_signed_update,
            owner_private_key=keypairs[0].private_key,
        ),
    )
    await adapter.put_signed_identity_record(identity_key, legacy)

    upgrade_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=owner_public_key,
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_UPGRADE,
        predecessor_state_hash=hashlib.sha256(legacy_signed_update).digest(),
    )
    upgrade = encode_multisignature_envelope(
        signed_update_bytes=upgrade_bundle.signed_update_bytes,
        proofs=[
            {
                1: "a",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=upgrade_bundle.signed_update_bytes,
                    owner_private_key=keypairs[0].private_key,
                ),
            }
        ],
    )
    await adapter.put_signed_identity_record(identity_key, upgrade)

    legacy_after_upgrade_signed_update = encode_signed_update(
        record_fields={1: OWNER_NAME, 2: owner_public_key},
        payload={},
        seq=3,
    )
    legacy_after_upgrade = encode_signed_envelope(
        signed_update_bytes=legacy_after_upgrade_signed_update,
        signature=make_signed_update_signature(
            signed_update_bytes_canonical=legacy_after_upgrade_signed_update,
            owner_private_key=keypairs[0].private_key,
        ),
    )
    with pytest.raises(ValueError, match="legacy writes"):
        await adapter.put_signed_identity_record(identity_key, legacy_after_upgrade)

    assert fake.values[adapter._kad_key(identity_key, kind="identity")] == upgrade
    assert adapter._durable_store.get(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == upgrade


@pytest.mark.trio
async def test_dht_preserves_legacy_put_behavior_with_legacy_durable_cache(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    fake = adapter.dht
    owner_public_key = keypairs[0].public_key.to_bytes()

    def legacy_envelope(*, seq: int, provider_url: str) -> bytes:
        payload = build_provider_payload_dict(
            alg="Ed25519",
            version=1,
            object_hash=OBJECT_HASH,
            provider_url=provider_url,
            endpoints=["/ip4/127.0.0.1/tcp/9000"],
        )
        signed_update = encode_signed_update(
            record_fields={1: owner_public_key},
            payload=payload,
            seq=seq,
        )
        return encode_signed_envelope(
            signed_update_bytes=signed_update,
            signature=make_signed_update_signature(
                signed_update_bytes_canonical=signed_update,
                owner_private_key=keypairs[0].private_key,
            ),
        )

    record_key = bytes.fromhex(OBJECT_HASH)
    adapter._durable_store.put(
        kind="provider",
        key=record_key,
        value=legacy_envelope(seq=9, provider_url="https://example.com/old.bin"),
    )
    current = legacy_envelope(
        seq=1, provider_url="https://example.com/current.bin"
    )

    await adapter.put_signed_provider_record(OBJECT_HASH, current)
    assert fake.values[adapter._kad_key(OBJECT_HASH)] == current
    resolved = await adapter.get_signed_provider_record(OBJECT_HASH)
    assert resolved is not None
    assert resolved.provider_url.endswith("current.bin")
