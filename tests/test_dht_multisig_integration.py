from __future__ import annotations

import hashlib
import socket
from typing import Any, cast

import pytest
import trio
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore
from decent_registry.encoding import (
    OPERATION_ORDINARY_UPDATE,
    OPERATION_OWNER_KEY_ROTATION,
    OPERATION_REPLACE_SIGNERS,
    OPERATION_UPGRADE,
    RECORD_KIND_IDENTITY,
    encode_multisignature_signed_update,
    encode_signed_update,
)
from decent_registry.exceptions import (
    IdentityHistoryUnavailable,
    IdentityPublicationExpired,
    IdentityStatePreconditionFailed,
    IdentityStateUnavailable,
)
from decent_registry.multisig_bundle import (
    draft_identity_bundle,
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.record_validator import IdentityRecordResult, RecordValidator
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
    adapter._dht_mode = DHTMode.SERVER
    adapter._accepted_lock = trio.Lock()
    adapter._remote_identity_reader = None
    adapter._bootstrap_peers = []
    return adapter


@pytest.mark.trio
async def test_identity_read_waits_for_inflight_publication_before_caching(tmp_path):
    adapter = _adapter(tmp_path)
    keypair = _keypairs()[0]
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    older = _legacy_identity(keypair, seq=1)
    newer = _legacy_identity(keypair, seq=2)
    await adapter.put_signed_identity_record(identity_key, older)

    class BlockingKad(FakeKad):
        def __init__(self, values):
            super().__init__()
            self.values.update(values)
            self.put_started = trio.Event()
            self.release_put = trio.Event()

        async def put_value(self, key: str, value: bytes) -> None:
            self.values[key] = value
            self.put_started.set()
            await self.release_put.wait()

    kad_key = adapter._kad_key(identity_key, kind="identity")
    blocking_dht = BlockingKad({kad_key: older})
    setattr(adapter, "_dht", blocking_dht)
    signed_update, _ = decode_signed_envelope(older)
    expected_state_hash = hashlib.sha256(signed_update).digest()
    reader_done = trio.Event()
    writer_done = trio.Event()
    read_result = []

    async def publish():
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            newer,
            expected_state_hash=expected_state_hash,
            expires_at=4_000_000_000,
        )
        writer_done.set()

    async def read():
        read_result.append(await adapter.get_identity_envelope(identity_key))
        reader_done.set()

    async with trio.open_nursery() as nursery:
        nursery.start_soon(publish)
        await blocking_dht.put_started.wait()
        nursery.start_soon(read)
        await trio.lowlevel.checkpoint()
        assert not reader_done.is_set()
        assert adapter._durable_get(kind="identity", key=record_key) == older
        blocking_dht.release_put.set()
        await writer_done.wait()
        await reader_done.wait()

    assert read_result == [newer]


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
async def test_dht_identity_envelope_reads_return_exact_current_and_retained_history(
    tmp_path,
):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)

    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, genesis)

    update_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    update = _finalize(update_bundle, keypairs)
    update_hash = hashlib.sha256(update_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, update)

    assert await adapter.get_identity_envelope(identity_key) == update
    assert (
        await adapter.get_identity_envelope_by_hash(identity_key, genesis_hash)
        == genesis
    )
    assert (
        await adapter.get_identity_envelope_by_hash(identity_key, update_hash)
        == update
    )
    assert await adapter.get_identity_envelope_by_hash(
        identity_key, b"\x00" * 32
    ) is None
    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=record_key) == update


@pytest.mark.trio
async def test_dht_history_content_key_serves_durable_predecessor_to_direct_peer(
    tmp_path,
):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    update_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    update = _finalize(update_bundle, keypairs)

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry-history.lmdb")
    ) as registry:
        await registry.put_signed_identity_record(identity_key, genesis)
        await registry.put_signed_identity_record(identity_key, update)

        history_key = registry._identity_history_kad_key(identity_key, genesis_hash)
        assert len(history_key) <= 128
        assert history_key not in registry.dht.value_store.store
        peer_address = registry.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = f"{peer_address}/p2p/{registry.host.get_id().to_string()}"

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            predecessor = await reader.read_remote_identity_envelope_by_hash(
                identity_key, genesis_hash
            )

        assert predecessor == genesis
        assert registry._durable_history(kind="identity", key=record_key) == (
            genesis,
            update,
        )


@pytest.mark.trio
async def test_fresh_dht_client_resolves_post_genesis_identity_from_peer_history(
    tmp_path,
):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)
    update_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=_signer_set(keypairs[:3]),
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    update = _finalize(update_bundle, keypairs)

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry-head.lmdb")
    ) as registry:
        await registry.put_signed_identity_record(identity_key, genesis)
        await registry.put_signed_identity_record(identity_key, update)
        peer_address = registry.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = f"{peer_address}/p2p/{registry.host.get_id().to_string()}"

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            assert reader._durable_store is None
            resolved = await reader.get_signed_identity_record(identity_key)

    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.seq == 2
    assert resolved.authorization.operation == OPERATION_ORDINARY_UPDATE


@pytest.mark.trio
async def test_stateless_client_publishes_post_genesis_update_using_peer_history(
    tmp_path,
):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    update_two_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    update_two = _finalize(update_two_bundle, keypairs)
    update_two_hash = hashlib.sha256(update_two_bundle.signed_update_bytes).digest()
    update_three = _finalize(
        draft_identity_bundle(
            owner_name=OWNER_NAME,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=3,
            signer_set=signer_set,
            operation=OPERATION_ORDINARY_UPDATE,
            predecessor_state_hash=update_two_hash,
        ),
        keypairs,
    )

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry-writer.lmdb")
    ) as registry:
        await registry.put_signed_identity_record(identity_key, genesis)
        await registry.put_signed_identity_record(identity_key, update_two)
        peer_address = registry.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = f"{peer_address}/p2p/{registry.host.get_id().to_string()}"

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as writer:
            await writer.bootstrap(peer_address)
            assert writer._durable_store is None
            await writer.put_signed_identity_record(identity_key, update_three)

        assert registry._durable_get(kind="identity", key=record_key) == update_three
        assert registry._durable_history(kind="identity", key=record_key) == (
            genesis,
            update_two,
            update_three,
        )

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            assert await reader.read_remote_identity_envelope(identity_key) == update_three
            resolved = await reader.get_signed_identity_record(identity_key)

    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.seq == 3


@pytest.mark.trio
async def test_stateless_client_publishes_operation_five_from_legacy_predecessor(
    tmp_path,
):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    legacy = _legacy_identity(keypairs[0])
    rotation = _legacy_rotation_envelope(keypairs)

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry-legacy.lmdb")
    ) as registry:
        await registry.put_signed_identity_record(identity_key, legacy)
        peer_address = registry.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = f"{peer_address}/p2p/{registry.host.get_id().to_string()}"

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as writer:
            await writer.bootstrap(peer_address)
            await writer.put_signed_identity_record(identity_key, rotation)

        assert registry._durable_get(kind="identity", key=record_key) == rotation
        assert registry._durable_history(kind="identity", key=record_key) == (
            legacy,
            rotation,
        )

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            resolved = await reader.get_signed_identity_record(identity_key)

    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.seq == 2
    assert resolved.authorization.operation == OPERATION_OWNER_KEY_ROTATION


@pytest.mark.trio
async def test_fresh_dht_client_reports_unavailable_post_genesis_history(tmp_path):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    update = _finalize(
        draft_identity_bundle(
            owner_name=OWNER_NAME,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=2,
            signer_set=_signer_set(keypairs[:3]),
            operation=OPERATION_ORDINARY_UPDATE,
            predecessor_state_hash=hashlib.sha256(
                genesis_bundle.signed_update_bytes
            ).digest(),
        ),
        keypairs,
    )

    async with Libp2pKadDHT() as registry_without_history:
        identity_key_path = registry_without_history._kad_key(
            identity_key, kind="identity"
        )
        registry_without_history.dht.value_store.put(
            identity_key_path.encode("utf-8"), update
        )
        peer_address = registry_without_history.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = (
                f"{peer_address}/p2p/"
                f"{registry_without_history.host.get_id().to_string()}"
            )

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            with pytest.raises(RuntimeError, match="history"):
                await reader.get_signed_identity_record(identity_key)


@pytest.mark.trio
async def test_registry_peer_serves_current_and_history_after_restart(tmp_path):
    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    db_path = tmp_path / "restarted-registry.lmdb"
    key_pair = create_new_key_pair()

    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    update_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    update = _finalize(update_bundle, keypairs)

    async with Libp2pKadDHT(
        key_pair=key_pair,
        durable_store=LMDBDatastore(path=db_path),
    ) as first_instance:
        await first_instance.put_signed_identity_record(identity_key, genesis)
        await first_instance.put_signed_identity_record(identity_key, update)

    async with Libp2pKadDHT(
        key_pair=key_pair,
        durable_store=LMDBDatastore(path=db_path),
    ) as restarted_instance:
        current_key = restarted_instance._kad_key(identity_key, kind="identity")
        assert current_key.encode("utf-8") not in restarted_instance.dht.value_store.store
        peer_address = restarted_instance.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = (
                f"{peer_address}/p2p/{restarted_instance.host.get_id().to_string()}"
            )

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            resolved = await reader.get_signed_identity_record(identity_key)

    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.seq == 2
    assert restarted_instance._durable_get(kind="identity", key=record_key) == update


@pytest.mark.trio
async def test_dht_same_state_envelopes_with_distinct_proofs_are_not_forks(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    accepted = _finalize(bundle, keypairs)
    alternate = merge_proof(
        merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key)),
        sign_bundle(bundle, keypairs[2].private_key),
    )
    alternate_envelope = finalize_bundle(alternate)
    assert alternate_envelope != accepted
    await adapter.put_signed_identity_record(identity_key, accepted)
    cast(FakeKad, adapter.dht).values[
        adapter._kad_key(identity_key, kind="identity")
    ] = alternate_envelope

    assert await adapter.get_identity_envelope(identity_key) == accepted


@pytest.mark.trio
async def test_dht_extends_local_history_to_validate_remote_owner_rotation(tmp_path):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    legacy = _legacy_identity(keypairs[0])
    legacy_signed_update, _ = decode_signed_envelope(legacy)
    upgrade_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
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
    rotation_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[3].public_key.to_bytes(),
        seq=3,
        signer_set=signer_set,
        operation=OPERATION_OWNER_KEY_ROTATION,
        predecessor_state_hash=hashlib.sha256(
            upgrade_bundle.signed_update_bytes
        ).digest(),
    )
    rotation = _finalize(rotation_bundle, keypairs)

    writer = _adapter(tmp_path / "writer")
    await writer.put_signed_identity_record(identity_key, legacy)
    await writer.put_signed_identity_record(identity_key, upgrade)
    await writer.put_signed_identity_record(identity_key, rotation)

    reader = _adapter(tmp_path / "reader")
    await reader.put_signed_identity_record(identity_key, legacy)
    await reader.put_signed_identity_record(identity_key, upgrade)
    cast(FakeKad, reader.dht).values[
        reader._kad_key(identity_key, kind="identity")
    ] = rotation

    assert await reader.get_identity_envelope(identity_key) == rotation
    store = reader._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get_history(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == (legacy, upgrade, rotation)


@pytest.mark.trio
async def test_conditional_identity_write_rejects_stale_state_before_publish(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])

    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, genesis)

    current_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    current = _finalize(current_bundle, keypairs)
    current_hash = hashlib.sha256(current_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, current)

    candidate_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=3,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=current_hash,
    )
    candidate = _finalize(candidate_bundle, keypairs)

    with pytest.raises(IdentityStatePreconditionFailed, match="expected state"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            candidate,
            expected_state_hash=genesis_hash,
            expires_at=9_999_999_999,
        )

    assert cast(FakeKad, adapter.dht).values[
        adapter._kad_key(identity_key, kind="identity")
    ] == current
    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=bytes.fromhex(identity_key)) == current


@pytest.mark.trio
async def test_conditional_identity_write_types_equal_sequence_fork_as_precondition(
    tmp_path,
):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    current_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    current = _finalize(current_bundle, keypairs)
    current_hash = hashlib.sha256(current_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, current)

    competing_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[1].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    competing = _finalize(competing_bundle, keypairs)
    cast(FakeKad, adapter.dht).values[
        adapter._kad_key(identity_key, kind="identity")
    ] = competing
    candidate_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=current_hash,
    )
    candidate = _finalize(candidate_bundle, keypairs)

    with pytest.raises(IdentityStatePreconditionFailed, match="conflicting"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            candidate,
            expected_state_hash=current_hash,
            expires_at=9_999_999_999,
        )


@pytest.mark.trio
async def test_conditional_identity_write_refuses_unprovable_absence(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)

    with pytest.raises(IdentityStatePreconditionFailed, match="absent"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            genesis,
            expected_state_hash=None,
            expires_at=9_999_999_999,
        )

    assert cast(FakeKad, adapter.dht).values == {}
    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=bytes.fromhex(identity_key)) is None


@pytest.mark.trio
async def test_conditional_identity_write_rejects_inconclusive_empty_lookup(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)

    with pytest.raises(IdentityStatePreconditionFailed, match="expected state"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            genesis,
            expected_state_hash=b"\x11" * 32,
            expires_at=9_999_999_999,
        )

    assert cast(FakeKad, adapter.dht).values == {}
    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=bytes.fromhex(identity_key)) is None


@pytest.mark.trio
async def test_conditional_identity_write_publishes_valid_successor_and_history(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, genesis)
    candidate_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    candidate = _finalize(candidate_bundle, keypairs)
    fake = cast(FakeKad, adapter.dht)
    kad_key = adapter._kad_key(identity_key, kind="identity")
    install = adapter._durable_install

    def require_dht_dispatch_before_local_install(**kwargs):
        if kwargs["value"] == candidate:
            assert fake.values[kad_key] == candidate
        install(**kwargs)

    adapter._durable_install = require_dht_dispatch_before_local_install

    await adapter.put_signed_identity_record_if_current(
        identity_key,
        candidate,
        expected_state_hash=genesis_hash,
        expires_at=9_999_999_999,
    )

    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert cast(FakeKad, adapter.dht).values[
        adapter._kad_key(identity_key, kind="identity")
    ] == candidate
    assert store.get_history(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == (genesis, candidate)


@pytest.mark.trio
async def test_conditional_identity_write_error_does_not_install_local_successor(
    tmp_path,
):
    class FailingPutKad(FakeKad):
        async def put_value(self, key: str, value: bytes) -> None:
            raise RuntimeError("simulated ambiguous DHT write")

    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, genesis)

    candidate_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    candidate = _finalize(candidate_bundle, keypairs)
    failed = FailingPutKad()
    failed.values = cast(FakeKad, adapter.dht).values.copy()
    cast(Any, adapter)._dht = failed

    with pytest.raises(RuntimeError, match="simulated ambiguous"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            candidate,
            expected_state_hash=genesis_hash,
            expires_at=9_999_999_999,
        )

    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=bytes.fromhex(identity_key)) == genesis
    assert store.get_history(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == (genesis,)


@pytest.mark.trio
async def test_conditional_identity_write_rejects_expiry_before_local_install(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, genesis)
    candidate_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=genesis_hash,
    )
    candidate = _finalize(candidate_bundle, keypairs)

    with pytest.raises(IdentityPublicationExpired, match="expired"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            candidate,
            expected_state_hash=genesis_hash,
            expires_at=0,
        )

    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=bytes.fromhex(identity_key)) == genesis
    assert cast(FakeKad, adapter.dht).values[
        adapter._kad_key(identity_key, kind="identity")
    ] == genesis


@pytest.mark.trio
async def test_conditional_identity_write_fails_closed_when_current_read_errors(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=_signer_set(keypairs[:3]),
    )
    genesis = _finalize(genesis_bundle, keypairs)
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    await adapter.put_signed_identity_record(identity_key, genesis)
    cast(FakeKad, adapter.dht).fail_reads = True

    with pytest.raises(IdentityStateUnavailable, match="could not read"):
        await adapter.put_signed_identity_record_if_current(
            identity_key,
            genesis,
            expected_state_hash=genesis_hash,
            expires_at=9_999_999_999,
        )

    store = adapter._durable_store
    assert isinstance(store, LMDBDatastore)
    assert store.get(kind="identity", key=bytes.fromhex(identity_key)) == genesis


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

    assert isinstance(adapter._durable_store, LMDBDatastore)
    store = adapter._durable_store
    assert store.get_history(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == (legacy, upgrade)
    rotation_update = encode_multisignature_signed_update(
        record_fields={1: OWNER_NAME, 2: keypairs[3].public_key.to_bytes()},
        payload={},
        seq=3,
        authorization={
            1: 1,
            2: RECORD_KIND_IDENTITY,
            3: OPERATION_OWNER_KEY_ROTATION,
            4: 1,
            5: 2,
            6: _signer_set(keypairs[:3]),
            7: hashlib.sha256(upgrade_bundle.signed_update_bytes).digest(),
        },
    )
    rotation = encode_multisignature_envelope(
        signed_update_bytes=rotation_update,
        proofs=[
            {
                1: "a",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=rotation_update,
                    owner_private_key=keypairs[0].private_key,
                ),
            },
            {
                1: "b",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=rotation_update,
                    owner_private_key=keypairs[1].private_key,
                ),
            },
        ],
    )
    await adapter.put_signed_identity_record(identity_key, rotation)

    assert fake.values[adapter._kad_key(identity_key, kind="identity")] == rotation
    assert store.get(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == rotation
    assert store.get_history(
        kind="identity", key=bytes.fromhex(identity_key)
    ) == (legacy, upgrade, rotation)
    resolved = await adapter.get_signed_identity_record(identity_key)
    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.owner_public_key == keypairs[3].public_key.to_bytes()

    adapter._remote_identity_reader = FakeRemoteIdentityReader(rotation)
    remote_confirmed = await adapter.confirm_identity_owner_key_rotation(
        owner_name_hex=OWNER_NAME.hex(), expected_envelope_cbor=rotation
    )
    assert isinstance(remote_confirmed, IdentityRecordResult)
    assert remote_confirmed.seq == 3
    assert remote_confirmed.owner_public_key == keypairs[3].public_key.to_bytes()


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


def _legacy_rotation_envelope(keypairs: list[Any], *, seq: int = 2) -> bytes:
    owner_name = OWNER_NAME
    previous = encode_signed_update(
        record_fields={1: owner_name, 2: keypairs[0].public_key.to_bytes()},
        payload={},
        seq=seq - 1,
    )
    signer_set = _signer_set([keypairs[3], keypairs[1], keypairs[2]])
    update = encode_multisignature_signed_update(
        record_fields={1: owner_name, 2: keypairs[3].public_key.to_bytes()},
        payload={},
        seq=seq,
        authorization={
            1: 1,
            2: RECORD_KIND_IDENTITY,
            3: OPERATION_OWNER_KEY_ROTATION,
            4: 1,
            5: 2,
            6: signer_set,
            7: hashlib.sha256(previous).digest(),
        },
    )
    return encode_multisignature_envelope(
        signed_update_bytes=update,
        proofs=[
            {
                1: None,
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=update,
                    owner_private_key=keypairs[0].private_key,
                ),
            }
        ],
    )


def _legacy_identity(keypair: Any, *, seq: int = 1) -> bytes:
    signed_update = encode_signed_update(
        record_fields={1: OWNER_NAME, 2: keypair.public_key.to_bytes()},
        payload={},
        seq=seq,
    )
    return encode_signed_envelope(
        signed_update_bytes=signed_update,
        signature=make_signed_update_signature(
            signed_update_bytes_canonical=signed_update,
            owner_private_key=keypair.private_key,
        ),
    )


@pytest.mark.trio
async def test_dht_accepts_legacy_owner_rotation_and_requires_history_for_readback(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    fake = adapter.dht
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    legacy = _legacy_identity(keypairs[0])
    rotation = _legacy_rotation_envelope(keypairs)
    kad_key = adapter._kad_key(identity_key, kind="identity")

    await adapter.put_signed_identity_record(identity_key, legacy)
    await adapter.put_signed_identity_record(identity_key, rotation)

    assert fake.values[kad_key] == rotation
    assert isinstance(adapter._durable_store, LMDBDatastore)
    store = adapter._durable_store
    assert store.get_history(kind="identity", key=record_key) == (legacy, rotation)
    resolved = await adapter.get_signed_identity_record(identity_key)
    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.owner_public_key == keypairs[3].public_key.to_bytes()

    store.open()
    assert store._env is not None
    assert store._accepted_db is not None
    with store._env.begin(write=True) as txn:
        txn.delete(
            store._history_key(kind="identity", key=record_key),
            db=store._accepted_db,
        )

    with pytest.raises(IdentityHistoryUnavailable, match="history is unavailable"):
        await adapter.get_signed_identity_record(identity_key)


@pytest.mark.trio
async def test_dht_get_rejects_self_authorized_identity_without_history(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    record_key = hashlib.sha256(OWNER_NAME).digest()
    identity_key = record_key.hex()
    envelope = _finalize(
        draft_identity_bundle(
            owner_name=OWNER_NAME,
            owner_public_key=keypairs[3].public_key.to_bytes(),
            seq=2,
            signer_set=_signer_set(keypairs[:3]),
            operation=OPERATION_ORDINARY_UPDATE,
            predecessor_state_hash=bytes(32),
        ),
        keypairs,
    )
    kad_key = adapter._kad_key(identity_key, kind="identity")
    adapter.dht.values[kad_key] = envelope

    with pytest.raises(IdentityHistoryUnavailable, match="history is unavailable"):
        await adapter.get_signed_identity_record(identity_key)
    assert isinstance(adapter._durable_store, LMDBDatastore)
    store = adapter._durable_store
    assert store.get(kind="identity", key=record_key) is None


@pytest.mark.trio
async def test_dht_rejects_rotation_without_predecessor_history_without_writes(tmp_path):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    fake = adapter.dht
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    genesis = _finalize(
        draft_identity_bundle(
            owner_name=OWNER_NAME,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=1,
            signer_set=_signer_set(keypairs[:3]),
        ),
        keypairs,
    )
    kad_key = adapter._kad_key(identity_key, kind="identity")
    await adapter.put_signed_identity_record(identity_key, genesis)

    assert isinstance(adapter._durable_store, LMDBDatastore)
    store = adapter._durable_store
    store.open()
    assert store._env is not None
    assert store._accepted_db is not None
    with store._env.begin(write=True) as txn:
        txn.delete(
            store._history_key(kind="identity", key=record_key),
            db=store._accepted_db,
        )

    candidate = _legacy_rotation_envelope(keypairs, seq=2)
    with pytest.raises(ValueError, match="predecessor history"):
        await adapter.put_signed_identity_record(identity_key, candidate)

    assert fake.values[kad_key] == genesis
    assert store.get(kind="identity", key=record_key) == genesis
    assert store.get_history(kind="identity", key=record_key) is None


class FakeRemoteIdentityReader:
    def __init__(self, envelope: bytes | None) -> None:
        self.envelope = envelope
        self.calls: list[str] = []

    async def read_remote_identity_envelope(self, object_key_hex: str) -> bytes | None:
        self.calls.append(object_key_hex)
        return self.envelope


@pytest.mark.trio
async def test_owner_rotation_confirmation_requires_exact_remote_value_and_history(
    tmp_path,
):
    keypairs = _keypairs()
    adapter = _adapter(tmp_path)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    legacy = _legacy_identity(keypairs[0])
    rotation = _legacy_rotation_envelope(keypairs)

    await adapter.put_signed_identity_record(identity_key, legacy)
    await adapter.put_signed_identity_record(identity_key, rotation)
    reader = FakeRemoteIdentityReader(None)
    adapter._remote_identity_reader = reader

    # A locally accepted/written candidate is not remote evidence.
    assert (
        await adapter.confirm_identity_owner_key_rotation(
            owner_name_hex=OWNER_NAME.hex(), expected_envelope_cbor=rotation
        )
        is None
    )
    assert reader.calls == [identity_key]

    reader.envelope = rotation
    confirmed = await adapter.confirm_identity_owner_key_rotation(
        owner_name_hex=OWNER_NAME.hex(), expected_envelope_cbor=rotation
    )
    assert isinstance(confirmed, IdentityRecordResult)
    assert confirmed.owner_name_hex == OWNER_NAME.hex()
    assert confirmed.owner_public_key == keypairs[3].public_key.to_bytes()
    assert confirmed.seq == 2
    assert confirmed.authorization.operation == OPERATION_OWNER_KEY_ROTATION

    # A remote predecessor does not confirm the exact candidate.
    reader.envelope = legacy
    assert (
        await adapter.confirm_identity_owner_key_rotation(
            owner_name_hex=OWNER_NAME.hex(), expected_envelope_cbor=rotation
        )
        is None
    )

    # Even exact remote bytes are insufficient without the verified local chain.
    assert isinstance(adapter._durable_store, LMDBDatastore)
    adapter._durable_store.open()
    assert adapter._durable_store._env is not None
    assert adapter._durable_store._accepted_db is not None
    with adapter._durable_store._env.begin(write=True) as txn:
        txn.delete(
            adapter._durable_store._history_key(kind="identity", key=record_key),
            db=adapter._durable_store._accepted_db,
        )
    reader.envelope = rotation
    assert (
        await adapter.confirm_identity_owner_key_rotation(
            owner_name_hex=OWNER_NAME.hex(), expected_envelope_cbor=rotation
        )
        is None
    )


@pytest.mark.trio
async def test_remote_identity_read_uses_a_fresh_network_reader_not_writer_cache(
    tmp_path,
):
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    kad_key = f"/decent-registry/identity/{identity_key}"
    fresh_remote_value = _legacy_identity(_keypairs()[0])
    stale_writer_value = b"writer-local-cache"
    unconfigured = _adapter(tmp_path / "unconfigured")
    cast(FakeKad, unconfigured.dht).values[kad_key] = stale_writer_value
    assert await unconfigured.read_remote_identity_envelope(identity_key) is None

    async with Libp2pKadDHT() as remote_peer:
        peer_address = remote_peer.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = f"{peer_address}/p2p/{remote_peer.host.get_id().to_string()}"
        await remote_peer.dht.put_value(kad_key, fresh_remote_value)

        with socket.socket() as closed_listener:
            closed_listener.bind(("127.0.0.1", 0))
            unavailable_port = closed_listener.getsockname()[1]
        unavailable_peer = (
            f"/ip4/127.0.0.1/tcp/{unavailable_port}/p2p/"
            f"{remote_peer.host.get_id().to_string()}"
        )
        unavailable_only = _adapter(tmp_path / "unavailable")
        unavailable_only._bootstrap_peers = [unavailable_peer]
        cast(FakeKad, unavailable_only.dht).values[kad_key] = stale_writer_value
        assert await unavailable_only.read_remote_identity_envelope(identity_key) is None

        adapter = _adapter(tmp_path)
        adapter._bootstrap_peers = [unavailable_peer, peer_address]
        cast(FakeKad, adapter.dht).values[kad_key] = stale_writer_value

        assert (
            await adapter.read_remote_identity_envelope(identity_key)
            == fresh_remote_value
        )


@pytest.mark.trio
async def test_dht_replica_rejects_identity_with_invalid_owner_signature():
    import cbor2

    keypair = _keypairs()[0]
    envelope = _legacy_identity(keypair)
    decoded = cbor2.loads(envelope)
    signature = bytearray(decoded[2])
    signature[0] ^= 1
    forged = cbor2.dumps({1: decoded[1], 2: bytes(signature)}, canonical=True)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    kad_key = f"/decent-registry/identity/{identity_key}"

    async with Libp2pKadDHT() as peer:
        with pytest.raises(ValueError):
            await peer.dht.put_value(kad_key, forged)
        assert peer.dht.value_store.get(kad_key.encode()) is None


@pytest.mark.trio
async def test_dht_replica_rejects_owner_rotation_without_predecessor_history():
    keypairs = _keypairs()
    rotation = _legacy_rotation_envelope(keypairs)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    kad_key = f"/decent-registry/identity/{identity_key}"

    async with Libp2pKadDHT() as peer:
        with pytest.raises(IdentityHistoryUnavailable, match="durable"):
            await peer.dht.put_value(kad_key, rotation)
        assert peer.dht.value_store.get(kad_key.encode()) is None


@pytest.mark.trio
async def test_real_dht_peer_accepts_owner_rotation_with_retained_history(tmp_path):
    from decent_registry.registry_service import RegistryService

    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    legacy = _legacy_identity(keypairs[0])
    legacy_signed_update, _ = decode_signed_envelope(legacy)
    upgrade_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
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
    upgrade_hash = hashlib.sha256(upgrade_bundle.signed_update_bytes).digest()
    rotation_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[3].public_key.to_bytes(),
        seq=3,
        signer_set=signer_set,
        operation=OPERATION_OWNER_KEY_ROTATION,
        predecessor_state_hash=upgrade_hash,
    )
    rotation = _finalize(rotation_bundle, keypairs)
    wallet_store_path = tmp_path / "wallet-accepted.lmdb"

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "seed-accepted.lmdb")
    ) as seed:
        seed_peer = (
            f"{seed.get_listen_multiaddr()}/p2p/{seed.host.get_id().to_string()}"
        )
        seed_service = RegistryService(seed)
        await seed_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
        )
        await seed_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=upgrade
        )

        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=wallet_store_path),
            dht_mode=DHTMode.CLIENT,
        ) as offline_wallet_dht:
            offline_service = RegistryService(offline_wallet_dht)
            await offline_service.put_identity_envelope(
                owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
            )
            await offline_service.put_identity_envelope(
                owner_name_hex=OWNER_NAME.hex(), envelope_cbor=upgrade
            )

        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=wallet_store_path),
            dht_mode=DHTMode.CLIENT,
        ) as wallet_dht:
            await wallet_dht.bootstrap(seed_peer)
            wallet_service = RegistryService(wallet_dht)
            await wallet_service.put_identity_envelope_if_current(
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=rotation,
                expected_state_hash=upgrade_hash,
                expires_at=9_999_999_999,
            )
            assert (
                await wallet_dht.read_remote_identity_envelope(identity_key)
                == rotation
            )
            assert (
                await wallet_service.get_identity_envelope_by_hash(
                    owner_name_hex=OWNER_NAME.hex(), state_hash=upgrade_hash
                )
                == upgrade
            )


@pytest.mark.trio
async def test_remote_signer_replacement_advances_peer_history_before_rotation(
    tmp_path,
):
    from decent_registry.registry_service import RegistryService

    keypairs = _keypairs()
    initial_signers = _signer_set(keypairs[:3])
    next_signers = _signer_set(keypairs[1:4])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    legacy = _legacy_identity(keypairs[0])
    legacy_update, _ = decode_signed_envelope(legacy)

    upgrade_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=initial_signers,
        operation=OPERATION_UPGRADE,
        predecessor_state_hash=hashlib.sha256(legacy_update).digest(),
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
    upgrade_hash = hashlib.sha256(upgrade_bundle.signed_update_bytes).digest()

    replacement_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=3,
        signer_set=next_signers,
        epoch=2,
        predecessor_state_hash=upgrade_hash,
        operation=OPERATION_REPLACE_SIGNERS,
    )
    replacement = encode_multisignature_envelope(
        signed_update_bytes=replacement_bundle.signed_update_bytes,
        proofs=[
            {
                1: "a",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=replacement_bundle.signed_update_bytes,
                    owner_private_key=keypairs[0].private_key,
                ),
            },
            {
                1: "b",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=replacement_bundle.signed_update_bytes,
                    owner_private_key=keypairs[1].private_key,
                ),
            },
        ],
    )
    replacement_hash = hashlib.sha256(
        replacement_bundle.signed_update_bytes
    ).digest()

    rotation_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[3].public_key.to_bytes(),
        seq=4,
        signer_set=next_signers,
        epoch=2,
        predecessor_state_hash=replacement_hash,
        operation=OPERATION_OWNER_KEY_ROTATION,
    )
    rotation = encode_multisignature_envelope(
        signed_update_bytes=rotation_bundle.signed_update_bytes,
        proofs=[
            {
                1: "a",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=rotation_bundle.signed_update_bytes,
                    owner_private_key=keypairs[1].private_key,
                ),
            },
            {
                1: "b",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=rotation_bundle.signed_update_bytes,
                    owner_private_key=keypairs[2].private_key,
                ),
            },
        ],
    )

    wallet_store_path = tmp_path / "wallet-rotation-history.lmdb"
    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "rotation-seed-history.lmdb")
    ) as seed:
        seed_addr = (
            f"{seed.get_listen_multiaddr()}/p2p/{seed.host.get_id().to_string()}"
        )
        seed_service = RegistryService(seed)
        await seed_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
        )
        await seed_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=upgrade
        )

        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=wallet_store_path),
            dht_mode=DHTMode.CLIENT,
        ) as offline_wallet_dht:
            offline_service = RegistryService(offline_wallet_dht)
            await offline_service.put_identity_envelope(
                owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
            )
            await offline_service.put_identity_envelope(
                owner_name_hex=OWNER_NAME.hex(), envelope_cbor=upgrade
            )

        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=wallet_store_path),
            dht_mode=DHTMode.CLIENT,
        ) as wallet_dht:
            await wallet_dht.bootstrap(seed_addr)
            wallet_service = RegistryService(wallet_dht)
            await wallet_service.put_identity_envelope_if_current(
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=replacement,
                expected_state_hash=upgrade_hash,
                expires_at=9_999_999_999,
            )
            assert seed._durable_history(kind="identity", key=record_key) == (
                legacy,
                upgrade,
                replacement,
            )
            await wallet_service.put_identity_envelope_if_current(
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=rotation,
                expected_state_hash=replacement_hash,
                expires_at=9_999_999_999,
            )
            assert (
                await wallet_dht.read_remote_identity_envelope(identity_key)
                == rotation
            )
            assert seed._durable_history(kind="identity", key=record_key) == (
                legacy,
                upgrade,
                replacement,
                rotation,
            )


@pytest.mark.trio
async def test_real_dht_accepts_legacy_predecessor_owner_rotation(tmp_path):
    from decent_registry.registry_service import RegistryService

    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    legacy = _legacy_identity(keypairs[0])
    legacy_update, _ = decode_signed_envelope(legacy)
    expected_state_hash = hashlib.sha256(legacy_update).digest()
    rotation = _legacy_rotation_envelope(keypairs)
    wallet_store_path = tmp_path / "legacy-rotation-wallet.lmdb"

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "legacy-rotation-seed.lmdb")
    ) as seed:
        seed_addr = (
            f"{seed.get_listen_multiaddr()}/p2p/{seed.host.get_id().to_string()}"
        )
        seed_service = RegistryService(seed)
        await seed_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
        )

        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=wallet_store_path),
            dht_mode=DHTMode.CLIENT,
        ) as offline_wallet_dht:
            await RegistryService(offline_wallet_dht).put_identity_envelope(
                owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
            )

        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=wallet_store_path),
            dht_mode=DHTMode.CLIENT,
        ) as wallet_dht:
            await wallet_dht.bootstrap(seed_addr)
            wallet_service = RegistryService(wallet_dht)
            await wallet_service.put_identity_envelope_if_current(
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=rotation,
                expected_state_hash=expected_state_hash,
                expires_at=9_999_999_999,
            )
            assert (
                await wallet_dht.read_remote_identity_envelope(identity_key)
                == rotation
            )
            assert seed._durable_history(kind="identity", key=record_key) == (
                legacy,
                rotation,
            )


@pytest.mark.trio
async def test_legacy_identity_replay_cannot_roll_back_durable_head_after_restart(
    tmp_path,
):
    from decent_registry.registry_service import RegistryService

    keypair = _keypairs()[0]
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    record_key = bytes.fromhex(identity_key)
    older = _legacy_identity(keypair, seq=1)
    newer = _legacy_identity(keypair, seq=2)
    store_path = tmp_path / "legacy-replay-protection.lmdb"

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=store_path)
    ) as first_instance:
        service = RegistryService(first_instance)
        await service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=older
        )
        await service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=newer
        )

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=store_path)
    ) as restarted_instance:
        service = RegistryService(restarted_instance)
        with pytest.raises(ValueError):
            await service.put_identity_envelope(
                owner_name_hex=OWNER_NAME.hex(), envelope_cbor=older
            )
        assert restarted_instance._durable_get(
            kind="identity", key=record_key
        ) == newer


@pytest.mark.trio
async def test_fresh_remote_identity_read_does_not_repair_other_peers(
    tmp_path, monkeypatch
):
    from libp2p.kad_dht.kad_dht import KadDHT

    from decent_registry.registry_service import RegistryService

    def forbid_repairing_get_value(*_args, **_kwargs):
        raise AssertionError("fresh read used repairing KadDHT.get_value")

    keypairs = _keypairs()
    older = _legacy_identity(keypairs[0], seq=1)
    newer = _legacy_identity(keypairs[0], seq=2)
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    kad_key_bytes = f"/decent-registry/identity/{identity_key}".encode()

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "older-peer.lmdb")
    ) as older_peer, Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "newer-peer.lmdb")
    ) as newer_peer:
        older_addr = (
            f"{older_peer.get_listen_multiaddr()}/p2p/"
            f"{older_peer.host.get_id().to_string()}"
        )
        newer_addr = (
            f"{newer_peer.get_listen_multiaddr()}/p2p/"
            f"{newer_peer.host.get_id().to_string()}"
        )
        await RegistryService(older_peer).put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=older
        )
        newer_service = RegistryService(newer_peer)
        await newer_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=older
        )
        await newer_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=newer
        )
        await older_peer.bootstrap(newer_addr)
        await newer_peer.bootstrap(older_addr)

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(older_addr)
            await reader.bootstrap(newer_addr)
            monkeypatch.setattr(KadDHT, "get_value", forbid_repairing_get_value)
            assert await reader.read_remote_identity_envelope(identity_key) == older

        stored = older_peer.dht.value_store.get(kad_key_bytes)
        assert stored is not None and stored.value == older


@pytest.mark.trio
async def test_fresh_remote_identity_read_does_not_treat_writer_as_remote_peer(
    tmp_path,
):
    from decent_registry.registry_service import RegistryService

    keypairs = _keypairs()
    legacy = _legacy_identity(keypairs[0])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "self-read-writer.lmdb")
    ) as writer:
        await RegistryService(writer).put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=legacy
        )
        self_addr = (
            f"{writer.get_listen_multiaddr()}/p2p/{writer.host.get_id().to_string()}"
        )
        writer._bootstrap_peers.append(self_addr)

        assert await writer.read_remote_identity_envelope(identity_key) is None


@pytest.mark.trio
async def test_remote_identity_history_fails_closed_at_entry_limit(
    tmp_path, monkeypatch
):
    import decent_registry.dht.libp2p_dht as dht_module

    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    current_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    current = _finalize(current_bundle, keypairs)
    lookups: list[bytes] = []

    async def fetch_predecessor(object_key_hex: str, state_hash: bytes):
        lookups.append(state_hash)
        return genesis

    adapter = _adapter(tmp_path)
    monkeypatch.setattr(dht_module, "MAX_REMOTE_IDENTITY_HISTORY_ENTRIES", 1)
    monkeypatch.setattr(
        adapter, "read_remote_identity_envelope_by_hash", fetch_predecessor
    )

    assert await adapter._read_remote_identity_predecessor_chain(
        identity_key, current
    ) is None
    assert lookups == []


@pytest.mark.trio
async def test_remote_identity_history_fails_closed_at_byte_limit(
    tmp_path, monkeypatch
):
    import decent_registry.dht.libp2p_dht as dht_module

    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    current_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    current = _finalize(current_bundle, keypairs)
    lookups: list[bytes] = []

    async def fetch_predecessor(object_key_hex: str, state_hash: bytes):
        lookups.append(state_hash)
        return genesis

    adapter = _adapter(tmp_path)
    monkeypatch.setattr(dht_module, "MAX_REMOTE_IDENTITY_HISTORY_BYTES", len(current) - 1)
    monkeypatch.setattr(
        adapter, "read_remote_identity_envelope_by_hash", fetch_predecessor
    )

    assert await adapter._read_remote_identity_predecessor_chain(
        identity_key, current
    ) is None
    assert lookups == []


@pytest.mark.trio
async def test_remote_identity_history_fails_closed_at_time_limit(
    tmp_path, monkeypatch
):
    import decent_registry.dht.libp2p_dht as dht_module

    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    current_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    current = _finalize(current_bundle, keypairs)

    async def slow_lookup(object_key_hex: str, state_hash: bytes):
        await trio.sleep(0.05)
        return _finalize(genesis_bundle, keypairs)

    adapter = _adapter(tmp_path)
    monkeypatch.setattr(
        dht_module, "MAX_REMOTE_IDENTITY_HISTORY_LOOKUP_SECONDS", 0.001
    )
    monkeypatch.setattr(
        adapter, "read_remote_identity_envelope_by_hash", slow_lookup
    )

    assert await adapter._read_remote_identity_predecessor_chain(
        identity_key, current
    ) is None


@pytest.mark.trio
async def test_ephemeral_registry_server_rejects_post_genesis_identity_write(tmp_path):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    legacy = _legacy_identity(keypairs[0])
    rotation = _legacy_rotation_envelope(keypairs)

    async with Libp2pKadDHT(dht_mode=DHTMode.SERVER) as peer:
        assert peer._durable_store is None
        await peer.put_signed_identity_record(identity_key, legacy)
        kad_key = peer._kad_key(identity_key, kind="identity").encode("utf-8")
        previous = peer.dht.value_store.get(kad_key)
        assert previous is not None and previous.value == legacy

        with pytest.raises(IdentityHistoryUnavailable, match="durable"):
            await peer.put_signed_identity_record(identity_key, rotation)

        current = peer.dht.value_store.get(kad_key)
        assert current is not None and current.value == legacy


@pytest.mark.trio
async def test_ephemeral_registry_server_rejects_conditional_post_genesis_write(
    tmp_path,
):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    update_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    update = _finalize(update_bundle, keypairs)
    expected_state_hash = hashlib.sha256(
        genesis_bundle.signed_update_bytes
    ).digest()

    async with Libp2pKadDHT(dht_mode=DHTMode.SERVER) as peer:
        await peer.put_signed_identity_record(identity_key, genesis)
        with pytest.raises(IdentityHistoryUnavailable, match="durable"):
            await peer.put_signed_identity_record_if_current(
                identity_key,
                update,
                expected_state_hash=expected_state_hash,
                expires_at=4_102_444_800,
            )


@pytest.mark.trio
async def test_ephemeral_registry_server_rejects_incoming_post_genesis_put():
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    signer_set = _signer_set(keypairs[:3])
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    update_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    update = _finalize(update_bundle, keypairs)

    async with Libp2pKadDHT(dht_mode=DHTMode.SERVER) as server:
        await server.put_signed_identity_record(identity_key, genesis)
        peer_address = server.get_listen_multiaddr()
        if "/p2p/" not in peer_address:
            peer_address = f"{peer_address}/p2p/{server.host.get_id().to_string()}"

        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as client:
            await client.bootstrap(peer_address)
            await client.put_signed_identity_record(identity_key, update)

        kad_key = server._kad_key(identity_key, kind="identity").encode("utf-8")
        stored = server.dht.value_store.get(kad_key)
        assert stored is not None and stored.value == genesis
