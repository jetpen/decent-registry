from __future__ import annotations

import asyncio
import hashlib

import pytest

from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.envelope_builder import build_provider_envelope
from decent_registry.multisig_bundle import draft_provider_withdrawal_bundle
from decent_registry.registry_service import RegistryService
from decent_registry.record_validator import ProviderWithdrawnResult, RecordValidator
from decent_registry.verification import multisignature_state_hash

REPLACEMENT_HASH = hashlib.sha256(b"service-replacement").hexdigest()



class FakeProviderDHT:
    def __init__(self, current=None, *, inconclusive=False):
        self.current = current
        self._predecessor = current
        self.inconclusive = inconclusive
        self.published = []

    async def get_signed_provider_envelope(self, object_hash: str):
        if self.inconclusive:
            raise RuntimeError("read unavailable")
        return self.current

    async def put_signed_provider_record(self, object_hash: str, envelope_cbor: bytes):
        self._predecessor = self.current
        self.current = envelope_cbor
        self.published.append((object_hash, envelope_cbor))

    async def get_signed_provider_record(self, object_hash: str, quorum: int = 0):
        if self.current is None:
            return None
        return RecordValidator().validate_provider_get(
            record_key=bytes.fromhex(object_hash),
            envelope_cbor=self.current,
            existing_envelope_cbor=self._predecessor,
        )


def _keypair_pem(tmp_path, keypair):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    key_path = tmp_path / "owner.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.from_private_bytes(keypair.private_key.to_bytes()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    return str(key_path)


def test_service_withdraw_provider_submits_legacy_and_returns_withdrawn_lookup(tmp_path):
    owner = create_new_key_pair()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    key_path = tmp_path / "owner.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.from_private_bytes(owner.private_key.to_bytes()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    active = build_provider_envelope(
        object_hash=hashlib.sha256(b"service-object").hexdigest(),
        provider_urls=["https://example.com/active.bin"],
        owner_privkey_pem_path=str(key_path),
        seq=1,
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
    )
    dht = FakeProviderDHT(current=active)
    service = RegistryService(dht=dht)
    object_hash = hashlib.sha256(b"service-object").hexdigest()

    async def run():
        await service.withdraw_provider(
            object_hash=object_hash,
            owner_privkey_pem_path=str(key_path),
            seq=2,
        )
        assert dht._predecessor == active
        return await service.get_provider(object_hash=object_hash)

    result = asyncio.run(run())
    assert dht.published[0][0] == object_hash
    assert result.to_dict() == {
        "status": "withdrawn", "object_key": object_hash, "seq": 2
    }


def test_service_withdraw_provider_submits_finalized_threshold_envelope(tmp_path):
    from decent_registry.multisig_bundle import (
        draft_provider_bundle, finalize_bundle, merge_proof, sign_bundle,
    )

    keypairs = [create_new_key_pair() for _ in range(3)]
    signer_set = [
        {1: chr(ord("a") + i), 2: keypairs[i].public_key.to_bytes()}
        for i in range(3)
    ]
    object_hash = hashlib.sha256(b"multisig-withdrawal-object").hexdigest()
    active_bundle = draft_provider_bundle(
        object_hash=object_hash,
        provider_urls=["https://example.com/active.bin"],
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=4,
        signer_set=signer_set,
    )
    active_bundle = merge_proof(active_bundle, sign_bundle(active_bundle, keypairs[0].private_key))
    active_bundle = merge_proof(active_bundle, sign_bundle(active_bundle, keypairs[1].private_key))
    active = finalize_bundle(active_bundle)
    withdrawal = draft_provider_withdrawal_bundle(
        object_hash=object_hash,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=5,
        signer_set=signer_set,
        predecessor_state_hash=multisignature_state_hash(active_bundle.signed_update_bytes),
        replacement_object_hash=REPLACEMENT_HASH,
    )
    withdrawal = merge_proof(withdrawal, sign_bundle(withdrawal, keypairs[0].private_key))
    withdrawal = merge_proof(withdrawal, sign_bundle(withdrawal, keypairs[1].private_key))
    finalized = finalize_bundle(withdrawal)
    dht = FakeProviderDHT(active)
    service = RegistryService(dht=dht)

    asyncio.run(service.withdraw_provider(object_hash=object_hash, envelope_cbor=finalized))
    assert dht.published == [(object_hash, finalized)]
    result = asyncio.run(service.get_provider(object_hash=object_hash))
    assert isinstance(result, ProviderWithdrawnResult)
    assert result.seq == 5
    assert result.replacement_object_hash == REPLACEMENT_HASH
    assert result.authorization is not None
    assert result.authorization.threshold == 2


def test_service_refuses_withdrawal_when_active_state_read_is_inconclusive(tmp_path):
    owner = create_new_key_pair()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    key_path = tmp_path / "owner.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.from_private_bytes(owner.private_key.to_bytes()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    dht = FakeProviderDHT(inconclusive=True)
    service = RegistryService(dht=dht)
    with pytest.raises(Exception):
        asyncio.run(service.withdraw_provider(
            object_hash=hashlib.sha256(b"unavailable-object").hexdigest(),
            owner_privkey_pem_path=str(key_path), seq=1,
        ))
    assert dht.published == []
