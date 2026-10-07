from __future__ import annotations

import hashlib
from typing import Any

import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.multisig_bundle import (
    draft_identity_bundle,
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.registry_service import RegistryService

OWNER_NAME = b"service-owner"
OBJECT_HASH = hashlib.sha256(b"service-object").hexdigest()


def _keypairs(count: int = 3) -> list[Any]:
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


class FakeDHT:
    def __init__(self) -> None:
        self.provider_puts: list[tuple[str, bytes]] = []
        self.identity_puts: list[tuple[str, bytes]] = []
        self.identity_conditional_puts: list[tuple[str, bytes, bytes, int]] = []
        self.provider_result: Any = None
        self.identity_result: Any = None
        self.identity_envelope_result: bytes | None = None
        self.identity_envelope_calls: list[tuple[str, int]] = []
        self.identity_envelope_by_hash_result: bytes | None = None
        self.identity_envelope_by_hash_calls: list[tuple[str, bytes]] = []
        self.identity_confirmation_result: Any = None
        self.identity_confirmation_calls: list[tuple[str, bytes]] = []

    async def put_signed_provider_record(self, object_hash: str, envelope_cbor: bytes) -> None:
        self.provider_puts.append((object_hash, envelope_cbor))

    async def put_signed_identity_record(self, object_key_hex: str, envelope_cbor: bytes) -> None:
        self.identity_puts.append((object_key_hex, envelope_cbor))

    async def put_signed_identity_record_if_current(
        self,
        object_key_hex: str,
        envelope_cbor: bytes,
        *,
        expected_state_hash: bytes,
        expires_at: int,
    ) -> None:
        self.identity_conditional_puts.append(
            (object_key_hex, envelope_cbor, expected_state_hash, expires_at)
        )

    async def get_signed_provider_record(self, object_hash: str, quorum: int = 0) -> Any:
        return self.provider_result

    async def get_signed_identity_record(self, object_key_hex: str, quorum: int = 0) -> Any:
        return self.identity_result

    async def get_identity_envelope(
        self, object_key_hex: str, quorum: int = 0
    ) -> bytes | None:
        self.identity_envelope_calls.append((object_key_hex, quorum))
        return self.identity_envelope_result

    async def get_identity_envelope_by_hash(
        self, object_key_hex: str, state_hash: bytes
    ) -> bytes | None:
        self.identity_envelope_by_hash_calls.append((object_key_hex, state_hash))
        return self.identity_envelope_by_hash_result

    async def confirm_identity_owner_key_rotation(
        self, *, owner_name_hex: str, expected_envelope_cbor: bytes
    ) -> Any:
        self.identity_confirmation_calls.append(
            (owner_name_hex, expected_envelope_cbor)
        )
        return self.identity_confirmation_result


def test_registry_service_submits_finalized_multisig_envelopes_without_private_keys():
    keypairs = _keypairs()
    signer_set = _signer_set(keypairs)
    identity_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    provider_bundle = draft_provider_bundle(
        object_hash=OBJECT_HASH,
        provider_urls=["https://example.com/service.bin"],
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    identity_envelope = _finalize(identity_bundle, keypairs)
    provider_envelope = _finalize(provider_bundle, keypairs)
    dht = FakeDHT()
    service = RegistryService(dht=dht)

    import asyncio

    asyncio.run(
        service.put_identity(
            owner_name_hex=OWNER_NAME.hex(),
            envelope_cbor=identity_envelope,
        )
    )
    asyncio.run(
        service.put_provider(
            object_hash=OBJECT_HASH,
            envelope_cbor=provider_envelope,
        )
    )

    assert dht.identity_puts == [
        (hashlib.sha256(OWNER_NAME).hexdigest(), identity_envelope)
    ]
    assert dht.provider_puts == [(OBJECT_HASH, provider_envelope)]


def test_registry_service_get_preserves_typed_results_and_quorum():
    dht = FakeDHT()
    dht.provider_result = object()
    dht.identity_result = object()
    service = RegistryService(dht=dht)

    import asyncio

    provider = asyncio.run(
        service.get_provider(object_hash=OBJECT_HASH, quorum=2)
    )
    identity = asyncio.run(
        service.get_identity(owner_name_hex=OWNER_NAME.hex(), quorum=3)
    )

    assert provider is dht.provider_result
    assert identity is dht.identity_result


def test_registry_service_get_identity_envelope_derives_the_registry_key():
    dht = FakeDHT()
    dht.identity_envelope_result = b"exact-public-envelope"
    service = RegistryService(dht=dht)

    import asyncio

    result = asyncio.run(
        service.get_identity_envelope(owner_name_hex=OWNER_NAME.hex(), quorum=2)
    )

    assert result == dht.identity_envelope_result
    assert dht.identity_envelope_calls == [
        (hashlib.sha256(OWNER_NAME).hexdigest(), 2)
    ]


def test_registry_service_get_identity_envelope_by_hash_uses_owner_name_key():
    dht = FakeDHT()
    dht.identity_envelope_by_hash_result = b"retained-predecessor"
    service = RegistryService(dht=dht)
    state_hash = hashlib.sha256(b"signed-update").digest()

    import asyncio

    result = asyncio.run(
        service.get_identity_envelope_by_hash(
            owner_name_hex=OWNER_NAME.hex(), state_hash=state_hash
        )
    )

    assert result == dht.identity_envelope_by_hash_result
    assert dht.identity_envelope_by_hash_calls == [
        (hashlib.sha256(OWNER_NAME).hexdigest(), state_hash)
    ]


def test_registry_service_conditional_put_preserves_expected_state_and_expiry():
    dht = FakeDHT()
    service = RegistryService(dht=dht)
    envelope = b"finalized-public-envelope"
    expected_state_hash = hashlib.sha256(b"predecessor-update").digest()
    expires_at = 2_000_000_000

    import asyncio

    asyncio.run(
        service.put_identity_envelope_if_current(
            owner_name_hex=OWNER_NAME.hex(),
            envelope_cbor=envelope,
            expected_state_hash=expected_state_hash,
            expires_at=expires_at,
        )
    )

    assert dht.identity_conditional_puts == [
        (
            hashlib.sha256(OWNER_NAME).hexdigest(),
            envelope,
            expected_state_hash,
            expires_at,
        )
    ]


def test_registry_service_conditional_put_rejects_unprovable_absence():
    dht = FakeDHT()
    service = RegistryService(dht=dht)

    import asyncio

    with pytest.raises(ValueError, match="absent"):
        asyncio.run(
            service.put_identity_envelope_if_current(
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=b"candidate",
                expected_state_hash=None,
                expires_at=2_000_000_000,
            )
        )

    assert dht.identity_conditional_puts == []


def test_registry_service_owner_rotation_confirmation_uses_validated_dht_result():
    dht = FakeDHT()
    dht.identity_confirmation_result = object()
    service = RegistryService(dht=dht)
    finalized_envelope = b"finalized-public-envelope"

    import asyncio

    result = asyncio.run(
        service.confirm_identity_owner_key_rotation(
            owner_name_hex=OWNER_NAME.hex(),
            expected_envelope_cbor=finalized_envelope,
        )
    )

    assert result is dht.identity_confirmation_result
    assert dht.identity_confirmation_calls == [(OWNER_NAME.hex(), finalized_envelope)]
