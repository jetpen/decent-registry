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
        self.provider_result: Any = None
        self.identity_result: Any = None

    async def put_signed_provider_record(self, object_hash: str, envelope_cbor: bytes) -> None:
        self.provider_puts.append((object_hash, envelope_cbor))

    async def put_signed_identity_record(self, object_key_hex: str, envelope_cbor: bytes) -> None:
        self.identity_puts.append((object_key_hex, envelope_cbor))

    async def get_signed_provider_record(self, object_hash: str, quorum: int = 0) -> Any:
        return self.provider_result

    async def get_signed_identity_record(self, object_key_hex: str, quorum: int = 0) -> Any:
        return self.identity_result


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
        provider_url="https://example.com/service.bin",
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
