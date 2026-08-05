import hashlib
import sys
import time
from dataclasses import dataclass
from typing import Any

import cbor2
import trio
from multiaddr import Multiaddr
from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.crypto.keys import KeyPair
from libp2p.kad_dht.kad_dht import KadDHT, DHTMode
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.tools.anyio_service.context import background_trio_service

from decent_registry.storage_backend import StorageBackend
from decent_registry.provider_schema import ProviderPayloadV1
from decent_registry.record_validator import (
    IdentityRecordResult,
    ProviderOverwriteResult,
    ProviderRecordResult,
    RecordValidator,
)
from decent_registry.signed_envelope import decode_signed_envelope


def _envelope_signed_update_bytes(envelope_cbor: bytes) -> bytes:
    decoded = cbor2.loads(envelope_cbor)
    if not isinstance(decoded, dict):
        raise ValueError("accepted envelope must be a CBOR map")
    if set(decoded) == {1, 2}:
        signed_update_bytes = decoded[1]
    elif set(decoded) == {1, 2, 3}:
        signed_update_bytes = decoded[2]
    else:
        raise ValueError("accepted envelope has an unsupported shape")
    if not isinstance(signed_update_bytes, (bytes, bytearray)):
        raise ValueError("accepted envelope SignedUpdate must be bytes")
    return bytes(signed_update_bytes)


def _envelope_seq(envelope_cbor: bytes) -> int:
    signed_update_bytes = _envelope_signed_update_bytes(envelope_cbor)
    signed_update = cbor2.loads(signed_update_bytes)
    seq = signed_update[3]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("accepted envelope seq must be a non-negative integer")
    return seq


def _is_multisignature_envelope(envelope_cbor: bytes | None) -> bool:
    if envelope_cbor is None:
        return False
    try:
        decoded = cbor2.loads(envelope_cbor)
    except Exception:
        return False
    return isinstance(decoded, dict) and set(decoded) == {1, 2, 3}


def _select_newest_envelope(
    first: bytes | None, second: bytes | None
) -> bytes | None:
    if first is None:
        return second
    if second is None:
        return first
    if first == second:
        return first
    try:
        first_seq = _envelope_seq(first)
        second_seq = _envelope_seq(second)
    except Exception:
        # Prefer a structurally parseable value when one source is stale or
        # corrupt; the RecordValidator still performs full validation later.
        try:
            _envelope_seq(first)
        except Exception:
            return second
        try:
            _envelope_seq(second)
        except Exception:
            return first
        raise ValueError("conflicting accepted envelopes")
    if first_seq == second_seq:
        raise ValueError("conflicting accepted envelopes at equal seq")
    return first if first_seq > second_seq else second


def _result_seq_and_state_hash(result: Any, envelope_cbor: bytes) -> tuple[int, bytes]:
    seq_value = getattr(result, "seq", None)
    seq = _envelope_seq(envelope_cbor) if seq_value is None else int(seq_value)
    authorization = getattr(result, "authorization", None)
    if authorization is not None:
        return seq, bytes(authorization.state_hash)
    signed_update_bytes = _envelope_signed_update_bytes(envelope_cbor)
    return seq, hashlib.sha256(signed_update_bytes).digest()


class Libp2pKadDHT:
    """Thin adapter over libp2p Python Kad-DHT.

    Uses a namespaced Kad-DHT key to avoid collisions with other app data:
    `'/decent-registry/provider/{object_hash}'`.

    `libp2p.kad_dht` uses a trio-based service runtime; this adapter exposes
    async methods usable with pytest-trio.
    """

    def __init__(
        self,
        listen: str = "/ip4/127.0.0.1/tcp/0",
        *,
        key_pair: KeyPair | None = None,
        durable_store: StorageBackend | None = None,
    ):
        self._key_pair = key_pair if key_pair is not None else create_new_key_pair()
        self._listen = Multiaddr(listen)
        self._host = new_host(key_pair=self._key_pair, enable_tcp=True)
        self._durable_store = durable_store
        self._validator = RecordValidator()
        self._accepted_lock = trio.Lock()

        self._host_ctx: Any | None = None
        self._dht_ctx: Any | None = None
        self._dht: KadDHT | None = None

    @property
    def host(self):
        return self._host

    @property
    def dht(self) -> KadDHT:
        assert self._dht is not None
        return self._dht

    async def __aenter__(self) -> "Libp2pKadDHT":
        if self._durable_store is not None:
            self._durable_store.open()
        self._host_ctx = self._host.run(listen_addrs=[self._listen])
        try:
            await self._host_ctx.__aenter__()
        except Exception:
            self._host_ctx = None
            if self._durable_store is not None:
                self._durable_store.close()
            raise

        # Construct Kad-DHT once the swarm is running
        self._dht = KadDHT(
            self._host,
            DHTMode.SERVER,
            enable_random_walk=False,
            strict_validation=False,
        )
        self._dht_ctx = background_trio_service(self._dht)
        try:
            await self._dht_ctx.__aenter__()
        except Exception:
            # Ensure host context is cleaned up if DHT startup fails.
            if self._host_ctx is not None:
                await self._host_ctx.__aexit__(*sys.exc_info())
            self._dht_ctx = None
            self._host_ctx = None
            if self._durable_store is not None:
                self._durable_store.close()
            raise

        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # Suppress secondary cleanup failures so that primary validation errors
        # (e.g. non-monotonic seq -> ValueError) propagate cleanly to callers.
        # Passing the original exception info into child contexts can trigger
        # Trio internal errors during async-generator finalization.
        if self._dht_ctx is not None:
            try:
                await self._dht_ctx.__aexit__(None, None, None)
            except Exception:
                pass
        if self._host_ctx is not None:
            try:
                await self._host_ctx.__aexit__(None, None, None)
            except Exception:
                pass

        if self._durable_store is not None:
            self._durable_store.close()

    def get_listen_multiaddr(self) -> str:
        addrs = [str(a) for a in self._host.get_addrs()]
        # pick first tcp addr
        for a in addrs:
            if "/tcp/" in a:
                return a
        raise RuntimeError("no tcp addr")

    async def bootstrap(self, remote_tcp_multiaddr: str) -> None:
        # Kad-DHT uses peer routing; host.connect expects a /p2p/<peerid> multiaddr.
        # remote_tcp_multiaddr may already contain /p2p/. Callers must provide an
        # identify-style destination (with /p2p/<peerid>) for routing.
        if "/p2p/" not in remote_tcp_multiaddr:
            raise ValueError(
                "bootstrap requires destination with /p2p/<peerid> (pass identify-style multiaddr)"
            )

        peer_info = info_from_p2p_addr(Multiaddr(remote_tcp_multiaddr))
        await self._host.connect(peer_info)

    def _kad_key(self, object_hash: str, *, kind: str = "provider") -> str:
        return f"/decent-registry/{kind}/{object_hash}"
    def _durable_get(
        self, *, kind: str, key: bytes
    ) -> bytes | None:
        if self._durable_store is None:
            return None
        return self._durable_store.get(kind=kind, key=key)  # type: ignore[arg-type]

    def _durable_install(
        self, *, kind: str, key: bytes, value: bytes, result: Any
    ) -> None:
        if self._durable_store is None:
            return
        seq, state_hash = _result_seq_and_state_hash(result, value)
        put_if_newer = getattr(self._durable_store, "put_if_newer", None)
        if put_if_newer is None:
            self._durable_store.put(kind=kind, key=key, value=value)  # type: ignore[arg-type]
            return
        if not put_if_newer(
            kind=kind,
            key=key,
            value=value,
            seq=seq,
            state_hash=state_hash,
        ):
            raise ValueError("stale or conflicting accepted state")

    def _durable_cache(
        self, *, kind: str, key: bytes, value: bytes, result: Any
    ) -> None:
        if self._durable_store is None:
            return
        seq, state_hash = _result_seq_and_state_hash(result, value)
        put_if_newer = getattr(self._durable_store, "put_if_newer", None)
        if put_if_newer is None:
            self._durable_store.put(kind=kind, key=key, value=value)  # type: ignore[arg-type]
            return
        put_if_newer(
            kind=kind,
            key=key,
            value=value,
            seq=seq,
            state_hash=state_hash,
        )

    async def _read_dht_value(self, kad_key: str, *, quorum: int = 0) -> bytes | None:
        try:
            return await self.dht.get_value(kad_key, quorum=quorum)
        except Exception:
            return None

    async def put_signed_provider_record(
        self, object_hash: str, envelope_cbor: bytes
    ) -> None:
        """Validate and install a provider envelope with legacy compatibility."""
        record_key = bytes.fromhex(object_hash)
        kad_key = self._kad_key(object_hash)
        async with self._accepted_lock:
            raw_dht = await self._read_dht_value(kad_key)
            raw_local = self._durable_get(kind="provider", key=record_key)
            use_accepted_state = (
                _is_multisignature_envelope(envelope_cbor)
                or _is_multisignature_envelope(raw_dht)
                or _is_multisignature_envelope(raw_local)
            )
            if not use_accepted_state:
                result = self._validator.validate_provider_overwrite(
                    record_key=record_key,
                    envelope_cbor=envelope_cbor,
                    existing_envelope_cbor=raw_dht,
                )
                await self.dht.put_value(kad_key, envelope_cbor)
                if self._durable_store is not None:
                    self._durable_store.put(
                        kind="provider", key=record_key, value=envelope_cbor
                    )
                return

            raw_existing = _select_newest_envelope(raw_dht, raw_local)
            result = self._validator.validate_provider_overwrite(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=raw_existing,
            )
            if _is_multisignature_envelope(envelope_cbor):
                self._durable_install(
                    kind="provider", key=record_key, value=envelope_cbor, result=result
                )
            await self.dht.put_value(kad_key, envelope_cbor)

    async def put_signed_identity_record(
        self, object_key_hex: str, envelope_cbor: bytes
    ) -> None:
        """Validate and install an identity envelope with legacy compatibility."""
        record_key = bytes.fromhex(object_key_hex)
        kad_key = self._kad_key(object_key_hex, kind="identity")
        async with self._accepted_lock:
            raw_dht = await self._read_dht_value(kad_key)
            raw_local = self._durable_get(kind="identity", key=record_key)
            use_accepted_state = (
                _is_multisignature_envelope(envelope_cbor)
                or _is_multisignature_envelope(raw_dht)
                or _is_multisignature_envelope(raw_local)
            )
            if not use_accepted_state:
                result = self._validator.validate_identity_overwrite(
                    record_key=record_key,
                    envelope_cbor=envelope_cbor,
                    existing_envelope_cbor=raw_dht,
                )
                await self.dht.put_value(kad_key, envelope_cbor)
                if self._durable_store is not None:
                    self._durable_store.put(
                        kind="identity", key=record_key, value=envelope_cbor
                    )
                return

            raw_existing = _select_newest_envelope(raw_dht, raw_local)
            result = self._validator.validate_identity_overwrite(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=raw_existing,
            )
            if _is_multisignature_envelope(envelope_cbor):
                self._durable_install(
                    kind="identity", key=record_key, value=envelope_cbor, result=result
                )
            await self.dht.put_value(kad_key, envelope_cbor)

    async def get_signed_identity_record(
        self, object_key_hex: str, quorum: int = 0
    ) -> dict[str, Any] | IdentityRecordResult | None:
        record_key = bytes.fromhex(object_key_hex)
        kad_key = self._kad_key(object_key_hex, kind="identity")
        raw_dht = await self._read_dht_value(kad_key, quorum=quorum)
        raw_local = self._durable_get(kind="identity", key=record_key)
        if _is_multisignature_envelope(raw_dht) or _is_multisignature_envelope(raw_local):
            raw_current = _select_newest_envelope(raw_dht, raw_local)
        else:
            raw_current = raw_dht if raw_dht is not None else raw_local
        if raw_current is None:
            return None
        try:
            result = self._validator.validate_identity_get(
                record_key=record_key, envelope_cbor=raw_current
            )
        except Exception:
            return None
        if isinstance(result, IdentityRecordResult):
            decoded: dict[str, Any] | IdentityRecordResult = result
        else:
            decoded = {
                "object_key": object_key_hex,
                "owner_name": result.owner_name_hex,
                "owner_public_key": result.owner_public_key.hex(),
                "seq": int(result.seq),
            }
        if self._durable_store is not None and raw_current == raw_dht:
            self._durable_cache(
                kind="identity", key=record_key, value=raw_current, result=result
            )
        return decoded

    async def get_signed_provider_record(
        self, object_hash: str, quorum: int = 0
    ) -> ProviderPayloadV1 | ProviderRecordResult | None:
        record_key = bytes.fromhex(object_hash)
        kad_key = self._kad_key(object_hash)
        raw_dht = await self._read_dht_value(kad_key, quorum=quorum)
        raw_local = self._durable_get(kind="provider", key=record_key)
        raw_current = _select_newest_envelope(raw_dht, raw_local)
        if raw_current is None:
            return None
        try:
            result = self._validator.validate_provider_get(
                record_key=record_key, envelope_cbor=raw_current
            )
        except Exception:
            return None
        if self._durable_store is not None and raw_current == raw_dht:
            self._durable_cache(
                kind="provider", key=record_key, value=raw_current, result=result
            )
        return result
