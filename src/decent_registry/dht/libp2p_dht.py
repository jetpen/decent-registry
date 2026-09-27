import hashlib
import sys
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

import cbor2
import trio
from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.crypto.keys import KeyPair
from libp2p.kad_dht.kad_dht import DHTMode, KadDHT
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.records.validator import Validator
from libp2p.tools.anyio_service.context import background_trio_service
from multiaddr import Multiaddr

from decent_registry.encoding import (
    OPERATION_GENESIS,
    OPERATION_OWNER_KEY_ROTATION,
    RECORD_KIND_IDENTITY,
    RECORD_KIND_PROVIDER,
    decode_canonical_signed_update,
)
from decent_registry.exceptions import (
    IdentityHistoryUnavailable,
    IdentityPublicationExpired,
    IdentityStatePreconditionFailed,
    IdentityStateUnavailable,
)
from decent_registry.provider_schema import (
    ProviderPayloadV1,
    decode_provider_payload_dict,
)
from decent_registry.record_validator import (
    IdentityRecordResult,
    ProviderOverwriteResult,
    ProviderRecordResult,
    RecordValidator,
)
from decent_registry.signed_envelope import (
    decode_multisignature_envelope,
    decode_signed_envelope,
)
from decent_registry.storage_backend import StorageBackend

RegistryRecordKind = Literal["identity", "provider"]

MAX_REMOTE_IDENTITY_HISTORY_ENTRIES = 256
MAX_REMOTE_IDENTITY_HISTORY_BYTES = 4 * 1024 * 1024
MAX_REMOTE_IDENTITY_HISTORY_LOOKUP_SECONDS = 15.0


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


def _identity_predecessor_state_hash(envelope_cbor: bytes) -> bytes | None:
    signed_update = decode_canonical_signed_update(
        _envelope_signed_update_bytes(envelope_cbor)
    )
    authorization = signed_update.get(4)
    if authorization is None or authorization[3] == OPERATION_GENESIS:
        return None
    predecessor_hash = authorization.get(7)
    if not isinstance(predecessor_hash, bytes) or len(predecessor_hash) != 32:
        raise ValueError("Identity predecessor state hash must be 32 bytes")
    return predecessor_hash


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
        if _envelope_signed_update_bytes(first) == _envelope_signed_update_bytes(second):
            # Proof-set variants of the same SignedUpdate represent one state.
            # Prefer the durable accepted value (the second argument).
            return second
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


class _RegistryDHTValueValidator(Validator):
    """Validate Registry DHT values and choose a deterministic highest head."""

    def __init__(self, owner: Any) -> None:
        self._owner = owner

    @staticmethod
    def _parse_key(key: str) -> tuple[RegistryRecordKind, bytes]:
        parts = key.split("/")
        if (
            len(parts) != 4
            or parts[0] != ""
            or parts[1] != "decent-registry"
            or parts[2] not in {"identity", "provider"}
        ):
            raise ValueError("invalid Registry DHT key")
        try:
            record_key = bytes.fromhex(parts[3])
        except ValueError:
            raise ValueError("invalid Registry DHT key hash") from None
        if len(record_key) != 32:
            raise ValueError("Registry DHT key hash must be 32 bytes")
        return cast(RegistryRecordKind, parts[2]), record_key

    @staticmethod
    def _parse_identity_history_key(key: bytes) -> tuple[bytes, bytes]:
        prefix = b"/decent-registry/history/"
        if len(key) != len(prefix) + 64 or not key.startswith(prefix):
            raise ValueError("invalid Registry Identity history key")
        offset = len(prefix)
        return key[offset : offset + 32], key[offset + 32 :]

    @classmethod
    def _metadata(cls, key: str, value: bytes) -> tuple[int, bytes]:
        kind, record_key = cls._parse_key(key)
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("Registry DHT value must be bytes")
        envelope = bytes(value)
        try:
            decoded = cbor2.loads(envelope)
        except Exception as exc:
            raise ValueError("invalid Registry DHT envelope") from exc
        if not isinstance(decoded, dict):
            raise ValueError("Registry DHT envelope must be a CBOR map")
        if set(decoded) == {1, 2}:
            signed_update_bytes, _signature = decode_signed_envelope(envelope)
        elif set(decoded) == {1, 2, 3}:
            signed_update_bytes = decode_multisignature_envelope(
                envelope
            ).signed_update_bytes
        else:
            raise ValueError("unsupported Registry DHT envelope")

        signed_update = decode_canonical_signed_update(signed_update_bytes)
        record_fields = signed_update[1]
        if not isinstance(record_fields, dict):
            raise ValueError("invalid Registry DHT record fields")
        authorization = signed_update.get(4)
        if kind == "identity":
            owner_name = record_fields.get(1)
            if not isinstance(owner_name, (bytes, bytearray)):
                raise ValueError("Registry Identity owner name must be bytes")
            if hashlib.sha256(bytes(owner_name)).digest() != record_key:
                raise ValueError("Registry Identity key does not match owner name")
            if authorization is not None and authorization[2] != RECORD_KIND_IDENTITY:
                raise ValueError("Registry Identity key has a different record kind")
        else:
            provider_payload = decode_provider_payload_dict(signed_update[2])
            if bytes.fromhex(provider_payload.object_hash) != record_key:
                raise ValueError("Registry Provider key does not match object hash")
            if authorization is not None and authorization[2] != RECORD_KIND_PROVIDER:
                raise ValueError("Registry Provider key has a different record kind")

        seq = signed_update[3]
        return int(seq), hashlib.sha256(signed_update_bytes).digest()

    def validate(self, key: str, value: bytes) -> None:
        self._metadata(key, value)
        self._owner._validate_dht_record(key, value)

    def select(self, key: str, values: list[bytes]) -> int:
        if not values:
            raise ValueError("cannot select from an empty Registry value list")
        best_index = 0
        best_seq, best_state_hash = self._metadata(key, values[0])
        for index, value in enumerate(values[1:], start=1):
            seq, state_hash = self._metadata(key, value)
            if seq > best_seq:
                best_index = index
                best_seq = seq
                best_state_hash = state_hash
            elif seq == best_seq and state_hash != best_state_hash:
                raise ValueError("conflicting Registry states at equal sequence")
        return best_index


class RemoteIdentityEnvelopeReader(Protocol):
    """Read one Identity envelope from a peer without local fallback or repair.

    Implementations must issue a direct peer GET_VALUE, not ``KadDHT.get_value``
    (which can cache and repair values), and must not consult the writer's DHT
    value store, durable accepted-state cache, or write response. The returned
    bytes are raw; callers must validate the envelope and predecessor chain.
    ``None`` means that independent remote evidence was unavailable.
    """

    async def read_remote_identity_envelope(
        self, object_key_hex: str
    ) -> bytes | None: ...


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
        dht_mode: DHTMode = DHTMode.SERVER,
        remote_identity_reader: RemoteIdentityEnvelopeReader | None = None,
    ):
        self._key_pair = key_pair if key_pair is not None else create_new_key_pair()
        self._listen = Multiaddr(listen)
        self._host = new_host(key_pair=self._key_pair, enable_tcp=True)
        self._durable_store = durable_store
        self._dht_mode = dht_mode
        self._remote_identity_reader = remote_identity_reader
        self._bootstrap_peers: list[str] = []
        self._validator = RecordValidator()
        self._accepted_lock = trio.Lock()
        self._local_dht_write: ContextVar[bool] = ContextVar(
            f"registry_local_dht_write_{id(self)}", default=False
        )
        self._local_identity_write_context: ContextVar[
            tuple[bytes, bytes, bytes | None, tuple[bytes, ...] | None] | None
        ] = ContextVar(
            f"registry_local_identity_write_{id(self)}", default=None
        )

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
            self._dht_mode,
            enable_random_walk=False,
            strict_validation=False,
        )
        self._dht.register_validator(
            "decent-registry",
            _RegistryDHTValueValidator(self),
        )
        self._install_value_store_acceptance_hooks()
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
        if remote_tcp_multiaddr not in self._bootstrap_peers:
            self._bootstrap_peers.append(remote_tcp_multiaddr)

    def _kad_key(self, object_hash: str, *, kind: str = "provider") -> str:
        return f"/decent-registry/{kind}/{object_hash}"

    @staticmethod
    def _identity_history_kad_key(object_key_hex: str, state_hash: bytes) -> bytes:
        try:
            object_key = bytes.fromhex(object_key_hex)
        except ValueError:
            raise ValueError("identity object key must be valid hex") from None
        if len(object_key) != 32:
            raise ValueError("identity object key must be 32 bytes")
        if not isinstance(state_hash, bytes) or len(state_hash) != 32:
            raise ValueError("state_hash must be 32 bytes")
        return b"/decent-registry/history/" + object_key + state_hash

    def _durable_get(
        self, *, kind: str, key: bytes
    ) -> bytes | None:
        if self._durable_store is None:
            return None
        return self._durable_store.get(kind=kind, key=key)  # type: ignore[arg-type]

    def _durable_history(
        self, *, kind: str, key: bytes
    ) -> tuple[bytes, ...] | None:
        if self._durable_store is None:
            return None
        get_history = getattr(self._durable_store, "get_history", None)
        if get_history is None:
            return None
        return get_history(kind=kind, key=key)  # type: ignore[arg-type]

    def _validate_dht_record(self, kad_key: str, envelope_cbor: bytes) -> Any | None:
        kind, record_key = _RegistryDHTValueValidator._parse_key(kad_key)
        if (
            kind == "identity"
            and self._dht_mode == DHTMode.SERVER
            and self._durable_store is None
            and _is_multisignature_envelope(envelope_cbor)
            and _identity_predecessor_state_hash(envelope_cbor) is not None
        ):
            raise IdentityHistoryUnavailable(
                "durable Identity history is required to accept post-genesis values on a Registry server"
            )
        record = self.dht.value_store.get(kad_key.encode("utf-8"))
        raw_dht = None if record is None else record.value
        raw_local = self._durable_get(kind=kind, key=record_key)
        use_accepted_state = (
            _is_multisignature_envelope(envelope_cbor)
            or _is_multisignature_envelope(raw_dht)
            or _is_multisignature_envelope(raw_local)
        )
        raw_existing = (
            _select_newest_envelope(raw_dht, raw_local)
            if kind == "identity" or use_accepted_state
            else raw_dht
        )
        if raw_existing == envelope_cbor:
            return

        validator = RecordValidator()
        if kind == "identity":
            pending = self._local_identity_write_context.get()
            if (
                pending is not None
                and pending[0] == record_key
                and pending[1] == envelope_cbor
            ):
                return validator.validate_identity_overwrite(
                    record_key=record_key,
                    envelope_cbor=envelope_cbor,
                    existing_envelope_cbor=pending[2],
                    predecessor_chain=pending[3],
                )
            history = self._durable_history(kind=kind, key=record_key)
            predecessor_chain = self._history_ending_at(history, raw_existing)
            return validator.validate_identity_overwrite(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=raw_existing,
                predecessor_chain=predecessor_chain,
            )
        return validator.validate_provider_overwrite(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
            existing_envelope_cbor=raw_existing,
        )

    def _install_value_store_acceptance_hooks(self) -> None:
        value_store = self.dht.value_store
        original_put = value_store.put
        original_get = value_store.get

        def get(key: bytes):
            try:
                object_key, state_hash = (
                    _RegistryDHTValueValidator._parse_identity_history_key(key)
                )
            except ValueError:
                try:
                    kad_key = key.decode("utf-8")
                    kind, record_key = _RegistryDHTValueValidator._parse_key(kad_key)
                except (UnicodeDecodeError, ValueError):
                    return original_get(key)
                if kind != "identity":
                    return original_get(key)
                envelope = self._durable_get(kind="identity", key=record_key)
                if envelope is None:
                    return original_get(key)
                history = self._durable_history(kind="identity", key=record_key)
                predecessor_chain = self._history_ending_at(history, envelope)
                try:
                    self._validator.validate_identity_get(
                        record_key=record_key,
                        envelope_cbor=envelope,
                        predecessor_chain=predecessor_chain,
                    )
                except Exception:
                    return None
            else:
                envelope = self._get_durable_identity_envelope_by_hash(
                    object_key.hex(), state_hash
                )
                if envelope is None:
                    return None

            cached_record = original_get(key)
            if cached_record is not None and cached_record.value == envelope:
                return cached_record
            # Registry durable acceptance is authoritative over expired, stale,
            # or arbitrary in-memory values for Identity and history keys.
            original_put(key, envelope)
            return original_get(key)

        value_store.get = get

        def put(key: bytes, value: bytes, validity: float = 0.0) -> None:
            accepted = self._prepare_durable_acceptance(key, value)
            original_put(key, value, validity)
            self._commit_durable_acceptance(accepted)

        value_store.put = put
        original_put_record = getattr(value_store, "put_record", None)
        if callable(original_put_record):
            def put_record(key: bytes, record: Any) -> None:
                accepted = self._prepare_durable_acceptance(key, record.value)
                original_put_record(key, record)
                self._commit_durable_acceptance(accepted)

            setattr(value_store, "put_record", put_record)

    def _prepare_durable_acceptance(
        self, key: bytes, value: bytes
    ) -> tuple[RegistryRecordKind, bytes, bytes, Any] | None:
        if self._local_dht_write.get() or self._durable_store is None:
            return None
        try:
            kad_key = key.decode("utf-8")
            kind, record_key = _RegistryDHTValueValidator._parse_key(kad_key)
        except (UnicodeDecodeError, ValueError):
            return None
        envelope = bytes(value)
        result = self._validate_dht_record(kad_key, envelope)
        if result is None:
            return None
        return kind, record_key, envelope, result

    def _commit_durable_acceptance(
        self, accepted: tuple[RegistryRecordKind, bytes, bytes, Any] | None
    ) -> None:
        if accepted is None or self._durable_store is None:
            return
        kind, record_key, envelope, result = accepted
        if self._durable_get(kind=kind, key=record_key) == envelope:
            return
        if kind == "identity" or _is_multisignature_envelope(envelope):
            self._durable_install(
                kind=kind,
                key=record_key,
                value=envelope,
                result=result,
            )
        else:
            self._durable_store.put(kind=kind, key=record_key, value=envelope)

    async def _publish_dht_value(
        self,
        kad_key: str,
        value: bytes,
        *,
        identity_write_context: tuple[
            bytes, bytes, bytes | None, tuple[bytes, ...] | None
        ] | None = None,
    ) -> None:
        local_write = getattr(self, "_local_dht_write", None)
        if local_write is None:
            await self.dht.put_value(kad_key, value)
            return
        local_identity_context = getattr(self, "_local_identity_write_context", None)
        write_token = local_write.set(True)
        identity_token = None
        if identity_write_context is not None and local_identity_context is not None:
            identity_token = local_identity_context.set(identity_write_context)
        try:
            await self.dht.put_value(kad_key, value)
        finally:
            if identity_token is not None:
                local_identity_context.reset(identity_token)
            local_write.reset(write_token)

    @staticmethod
    def _history_ending_at(
        history: tuple[bytes, ...] | None, value: bytes | None
    ) -> tuple[bytes, ...] | None:
        if history and value is not None and history[-1] == value:
            return history
        return None

    @staticmethod
    def _history_to_current(
        history: tuple[bytes, ...] | None,
        local_value: bytes | None,
        current_value: bytes | None,
    ) -> tuple[bytes, ...] | None:
        if current_value is None:
            return None
        if history and history[-1] == current_value:
            return history
        if local_value is None or local_value == current_value:
            return None
        if history is not None:
            if not history or history[-1] != local_value:
                return None
            return history + (current_value,)
        return (local_value, current_value)

    @staticmethod
    def _accepted_state_put_kwargs(
        *,
        kind: str,
        key: bytes,
        value: bytes,
        seq: int,
        state_hash: bytes,
        history: tuple[bytes, ...] | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "kind": kind,
            "key": key,
            "value": value,
            "seq": seq,
            "state_hash": state_hash,
        }
        if kind == "identity":
            kwargs["history"] = history
        return kwargs

    def _require_durable_identity_history(self, result: Any) -> None:
        if (
            getattr(getattr(result, "authorization", None), "operation", None)
            == OPERATION_OWNER_KEY_ROTATION
            and (
                self._durable_store is None
                or getattr(self._durable_store, "get_history", None) is None
                or getattr(self._durable_store, "put_if_newer", None) is None
            )
        ):
            raise ValueError("owner-key rotation requires durable predecessor history")

    def _durable_install(
        self, *, kind: str, key: bytes, value: bytes, result: Any
    ) -> None:
        if kind == "identity":
            self._require_durable_identity_history(result)
        if self._durable_store is None:
            return
        if self._durable_get(kind=kind, key=key) == value:
            return
        seq, state_hash = _result_seq_and_state_hash(result, value)
        put_if_newer = getattr(self._durable_store, "put_if_newer", None)
        if put_if_newer is None:
            self._durable_store.put(kind=kind, key=key, value=value)  # type: ignore[arg-type]
            return
        state = getattr(result, "state", None)
        kwargs = self._accepted_state_put_kwargs(
            kind=kind,
            key=key,
            value=value,
            seq=seq,
            state_hash=state_hash,
            history=getattr(state, "history", None),
        )
        if not put_if_newer(**kwargs):
            if self._durable_get(kind=kind, key=key) == value:
                return
            raise ValueError("stale or conflicting accepted state")

    def _durable_cache(
        self,
        *,
        kind: str,
        key: bytes,
        value: bytes,
        result: Any,
        history: tuple[bytes, ...] | None = None,
    ) -> None:
        if self._durable_store is None:
            return
        seq, state_hash = _result_seq_and_state_hash(result, value)
        put_if_newer = getattr(self._durable_store, "put_if_newer", None)
        if put_if_newer is None:
            self._durable_store.put(kind=kind, key=key, value=value)  # type: ignore[arg-type]
            return
        kwargs = self._accepted_state_put_kwargs(
            kind=kind,
            key=key,
            value=value,
            seq=seq,
            state_hash=state_hash,
            history=history,
        )
        put_if_newer(**kwargs)

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
                await self._publish_dht_value(kad_key, envelope_cbor)
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
            await self._publish_dht_value(kad_key, envelope_cbor)

    async def put_signed_identity_record(
        self, object_key_hex: str, envelope_cbor: bytes
    ) -> None:
        """Validate and install an identity envelope with legacy compatibility."""
        await self._put_signed_identity_record(
            object_key_hex,
            envelope_cbor,
            expected_state_hash=None,
            expires_at=None,
            conditional=False,
        )

    async def put_signed_identity_record_if_current(
        self,
        object_key_hex: str,
        envelope_cbor: bytes,
        *,
        expected_state_hash: bytes,
        expires_at: int,
    ) -> None:
        """Validate and publish against this instance's accepted Identity head.

        A non-null 32-byte expected hash is required because ``get_value``
        cannot distinguish confirmed absence from an inconclusive DHT lookup.
        The state and deadline checks are local to this instance, not a
        network-wide compare-and-swap or remote commit guarantee.
        """
        if expected_state_hash is None:
            raise IdentityStatePreconditionFailed(
                "DHT reads cannot prove that the Identity key is absent"
            )
        if not isinstance(expected_state_hash, bytes) or len(expected_state_hash) != 32:
            raise ValueError("expected_state_hash must be exactly 32 bytes")
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            raise ValueError("expires_at must be an integer Unix timestamp")
        await self._put_signed_identity_record(
            object_key_hex,
            envelope_cbor,
            expected_state_hash=expected_state_hash,
            expires_at=expires_at,
            conditional=True,
        )

    async def _put_signed_identity_record(
        self,
        object_key_hex: str,
        envelope_cbor: bytes,
        *,
        expected_state_hash: bytes | None,
        expires_at: int | None,
        conditional: bool,
    ) -> None:
        record_key = bytes.fromhex(object_key_hex)
        kad_key = self._kad_key(object_key_hex, kind="identity")
        async with self._accepted_lock:
            if conditional:
                try:
                    raw_dht = await self.dht.get_value(kad_key)
                except Exception:
                    raise IdentityStateUnavailable(
                        "could not read current Identity state before publication"
                    ) from None
            else:
                raw_dht = await self._read_dht_value(kad_key)
                if raw_dht is None and self._bootstrap_peers:
                    raw_dht = await self.read_remote_identity_envelope(object_key_hex)
            raw_local = self._durable_get(kind="identity", key=record_key)
            try:
                raw_existing = _select_newest_envelope(raw_dht, raw_local)
            except Exception:
                if conditional:
                    raise IdentityStatePreconditionFailed(
                        "conflicting current Identity state"
                    ) from None
                raise ValueError("conflicting current Identity state") from None
            if conditional:
                try:
                    actual_state_hash = (
                        None
                        if raw_existing is None
                        else hashlib.sha256(
                            _envelope_signed_update_bytes(raw_existing)
                        ).digest()
                    )
                except Exception:
                    raise IdentityStatePreconditionFailed(
                        "could not validate the current Identity state"
                    ) from None
                if actual_state_hash != expected_state_hash:
                    raise IdentityStatePreconditionFailed(
                        "Identity state differs from expected state"
                    )
            is_multisignature = _is_multisignature_envelope(envelope_cbor)
            if (
                is_multisignature
                and self._dht_mode == DHTMode.SERVER
                and self._durable_store is None
                and _identity_predecessor_state_hash(envelope_cbor) is not None
            ):
                raise IdentityHistoryUnavailable(
                    "durable Identity history is required for post-genesis writes on a Registry server"
                )
            use_accepted_state = (
                is_multisignature
                or _is_multisignature_envelope(raw_dht)
                or _is_multisignature_envelope(raw_local)
            )
            if not use_accepted_state:
                result = self._validator.validate_identity_overwrite(
                    record_key=record_key,
                    envelope_cbor=envelope_cbor,
                    existing_envelope_cbor=raw_existing,
                )
                if conditional and expires_at is not None:
                    if expires_at <= int(time.time()):
                        raise IdentityPublicationExpired("Identity consent expired")
                await self._publish_dht_value(
                    kad_key,
                    envelope_cbor,
                    identity_write_context=(
                        record_key,
                        envelope_cbor,
                        raw_existing,
                        None,
                    ),
                )
                self._durable_install(
                    kind="identity", key=record_key, value=envelope_cbor, result=result
                )
                return

            predecessor_chain = self._history_ending_at(
                self._durable_history(kind="identity", key=record_key),
                raw_existing,
            )
            if predecessor_chain is None and raw_existing is not None:
                predecessor_chain = await self._read_remote_identity_predecessor_chain(
                    object_key_hex, raw_existing
                )
                if predecessor_chain is None:
                    try:
                        requires_history = (
                            _identity_predecessor_state_hash(raw_existing) is not None
                        )
                    except Exception:
                        requires_history = False
                    if requires_history:
                        raise IdentityHistoryUnavailable(
                            "authenticated Identity predecessor history is unavailable"
                        )
            result = self._validator.validate_identity_overwrite(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=raw_existing,
                predecessor_chain=predecessor_chain,
            )
            identity_write_context = (
                record_key,
                envelope_cbor,
                raw_existing,
                predecessor_chain,
            )
            if conditional and is_multisignature:
                self._require_durable_identity_history(result)
            if conditional and expires_at is not None:
                if expires_at <= int(time.time()):
                    raise IdentityPublicationExpired("Identity consent expired")
            if conditional:
                # Begin the DHT write immediately after the local deadline check.
                # A later local-store failure is ambiguous and must be read back.
                await self._publish_dht_value(
                    kad_key,
                    envelope_cbor,
                    identity_write_context=identity_write_context,
                )
                if is_multisignature:
                    self._durable_install(
                        kind="identity",
                        key=record_key,
                        value=envelope_cbor,
                        result=result,
                    )
            else:
                if is_multisignature and self._durable_store is not None:
                    self._durable_install(
                        kind="identity",
                        key=record_key,
                        value=envelope_cbor,
                        result=result,
                    )
                await self._publish_dht_value(
                    kad_key,
                    envelope_cbor,
                    identity_write_context=identity_write_context,
                )

    async def read_remote_identity_envelope(self, object_key_hex: str) -> bytes | None:
        """Read raw Identity bytes from a configured peer without DHT repair.

        A fresh client sends direct GET_VALUE requests to configured bootstrap
        peers in order and returns the first record found. It deliberately
        avoids ``KadDHT.get_value``, which can cache and propagate the selected
        value to peers with older values. This method has no local durable store
        and returns unvalidated envelope bytes; callers must validate the exact
        envelope and its predecessor chain. A response proves only that one
        peer returned these bytes at read time, not network-wide currentness.
        """
        try:
            record_key = bytes.fromhex(object_key_hex)
        except ValueError:
            raise ValueError("identity object key must be valid hex") from None
        if len(record_key) != 32:
            raise ValueError("identity object key must be 32 bytes")
        canonical_object_key_hex = record_key.hex()

        remote_reader = self._remote_identity_reader
        if remote_reader is not None:
            try:
                envelope = await remote_reader.read_remote_identity_envelope(
                    canonical_object_key_hex
                )
            except Exception:
                return None
        else:
            bootstrap_peers = tuple(self._bootstrap_peers)
            if not bootstrap_peers:
                return None
            try:
                async with Libp2pKadDHT(
                    listen="/ip4/127.0.0.1/tcp/0",
                    durable_store=None,
                    dht_mode=DHTMode.CLIENT,
                ) as remote_dht:
                    kad_key = remote_dht._kad_key(
                        canonical_object_key_hex, kind="identity"
                    )
                    envelope = None
                    local_host = getattr(self, "_host", None)
                    local_peer_id = (
                        None if local_host is None else local_host.get_id()
                    )
                    for peer in bootstrap_peers:
                        try:
                            peer_info = info_from_p2p_addr(Multiaddr(peer))
                            if (
                                local_peer_id is not None
                                and peer_info.peer_id == local_peer_id
                            ):
                                continue
                            await remote_dht.bootstrap(peer)
                            record = await remote_dht.dht.value_store._get_from_peer(
                                peer_info.peer_id,
                                kad_key.encode("utf-8"),
                                return_record=True,
                            )
                        except Exception:
                            continue
                        if record is None:
                            continue
                        candidate = getattr(record, "value", None)
                        if not isinstance(candidate, (bytes, bytearray)):
                            continue
                        envelope = bytes(candidate)
                        break
            except Exception:
                return None

        if envelope is None:
            return None
        if not isinstance(envelope, (bytes, bytearray)):
            return None
        return bytes(envelope)

    async def read_remote_identity_envelope_by_hash(
        self, object_key_hex: str, state_hash: bytes
    ) -> bytes | None:
        """Read one accepted historical envelope from configured Registry peers.

        The DHT key is content-addressed by the Registry state hash. The peer
        serves from its validated durable history; this reader bypasses local
        caches and Kademlia repair. The returned envelope remains untrusted
        until the caller validates the complete predecessor chain.
        """
        if not self._bootstrap_peers:
            return None
        kad_key = self._identity_history_kad_key(object_key_hex, state_hash)
        local_peer_id = self.host.get_id()
        for peer in tuple(self._bootstrap_peers):
            try:
                peer_info = info_from_p2p_addr(Multiaddr(peer))
                if peer_info.peer_id == local_peer_id:
                    continue
                record = await self.dht.value_store._get_from_peer(
                    peer_info.peer_id,
                    kad_key,
                    return_record=True,
                )
            except Exception:
                continue
            candidate = getattr(record, "value", None)
            if not isinstance(candidate, (bytes, bytearray)):
                continue
            envelope = bytes(candidate)
            try:
                signed_update = _envelope_signed_update_bytes(envelope)
            except Exception:
                continue
            if hashlib.sha256(signed_update).digest() == state_hash:
                return envelope
        return None

    async def _read_remote_identity_predecessor_chain(
        self, object_key_hex: str, current_envelope: bytes
    ) -> tuple[bytes, ...] | None:
        reversed_chain: list[bytes] = []
        seen_state_hashes: set[bytes] = set()
        total_bytes = 0
        envelope = bytes(current_envelope)
        with trio.move_on_after(MAX_REMOTE_IDENTITY_HISTORY_LOOKUP_SECONDS) as timeout:
            while True:
                try:
                    signed_update_bytes = _envelope_signed_update_bytes(envelope)
                    state_hash = hashlib.sha256(signed_update_bytes).digest()
                    predecessor_hash = _identity_predecessor_state_hash(envelope)
                except Exception:
                    return None
                if state_hash in seen_state_hashes:
                    return None
                if len(reversed_chain) >= MAX_REMOTE_IDENTITY_HISTORY_ENTRIES:
                    return None
                next_total_bytes = total_bytes + len(envelope)
                if next_total_bytes > MAX_REMOTE_IDENTITY_HISTORY_BYTES:
                    return None
                seen_state_hashes.add(state_hash)
                reversed_chain.append(envelope)
                total_bytes = next_total_bytes
                if predecessor_hash is None:
                    return tuple(reversed(reversed_chain))
                if len(reversed_chain) >= MAX_REMOTE_IDENTITY_HISTORY_ENTRIES:
                    return None
                predecessor = await self.read_remote_identity_envelope_by_hash(
                    object_key_hex, predecessor_hash
                )
                if predecessor is None:
                    return None
                envelope = predecessor
        if timeout.cancelled_caught:
            return None
        return None

    async def confirm_identity_owner_key_rotation(
        self, *, owner_name_hex: str, expected_envelope_cbor: bytes
    ) -> IdentityRecordResult | None:
        """Return validated public state only after exact independent read-back.

        Local predecessor history is used only to verify the returned remote
        envelope. It is never used as the read-back value or as a fallback.
        """
        try:
            owner_name = bytes.fromhex(owner_name_hex)
        except ValueError:
            raise ValueError("owner_name must be valid hex") from None
        if not isinstance(expected_envelope_cbor, (bytes, bytearray)):
            raise TypeError("expected Identity SignedEnvelope must be bytes")
        expected_envelope = bytes(expected_envelope_cbor)
        record_key = hashlib.sha256(owner_name).digest()
        remote_envelope = await self.read_remote_identity_envelope(record_key.hex())
        if remote_envelope is None or remote_envelope != expected_envelope:
            return None

        history = self._durable_history(kind="identity", key=record_key)
        local_value = self._durable_get(kind="identity", key=record_key)
        predecessor_chain = self._history_to_current(
            history, local_value, remote_envelope
        )
        if predecessor_chain is None:
            return None
        try:
            result = self._validator.validate_identity_get(
                record_key=record_key,
                envelope_cbor=remote_envelope,
                predecessor_chain=predecessor_chain,
            )
        except Exception:
            return None
        if (
            not isinstance(result, IdentityRecordResult)
            or result.owner_name_hex != owner_name.hex()
            or result.authorization.operation != OPERATION_OWNER_KEY_ROTATION
        ):
            return None
        if self._durable_store is not None:
            self._durable_cache(
                kind="identity",
                key=record_key,
                value=remote_envelope,
                result=result,
                history=predecessor_chain,
            )
        return result

    async def _get_validated_identity_envelope(
        self, object_key_hex: str, quorum: int = 0
    ) -> tuple[bytes, Any] | None:
        async with self._accepted_lock:
            return await self._get_validated_identity_envelope_unlocked(
                object_key_hex, quorum=quorum
            )

    async def _get_validated_identity_envelope_unlocked(
        self, object_key_hex: str, quorum: int = 0
    ) -> tuple[bytes, Any] | None:
        record_key = bytes.fromhex(object_key_hex)
        kad_key = self._kad_key(object_key_hex, kind="identity")
        raw_dht = await self._read_dht_value(kad_key, quorum=quorum)
        if raw_dht is None and self._bootstrap_peers:
            raw_dht = await self.read_remote_identity_envelope(object_key_hex)
        raw_local = self._durable_get(kind="identity", key=record_key)
        try:
            raw_current = _select_newest_envelope(raw_dht, raw_local)
        except Exception:
            return None
        if raw_current is None:
            return None
        predecessor_chain = self._history_to_current(
            self._durable_history(kind="identity", key=record_key),
            raw_local,
            raw_current,
        )
        try:
            result = self._validator.validate_identity_get(
                record_key=record_key,
                envelope_cbor=raw_current,
                predecessor_chain=predecessor_chain,
            )
        except Exception:
            predecessor_chain = await self._read_remote_identity_predecessor_chain(
                object_key_hex, raw_current
            )
            if predecessor_chain is None:
                try:
                    requires_history = (
                        _identity_predecessor_state_hash(raw_current) is not None
                    )
                except Exception:
                    return None
                if requires_history:
                    raise IdentityHistoryUnavailable(
                        "authenticated Identity predecessor history is unavailable"
                    ) from None
                return None
            try:
                result = self._validator.validate_identity_get(
                    record_key=record_key,
                    envelope_cbor=raw_current,
                    predecessor_chain=predecessor_chain,
                )
            except Exception:
                raise IdentityHistoryUnavailable(
                    "authenticated Identity predecessor history could not be validated"
                ) from None
        if self._durable_store is not None and raw_current == raw_dht:
            self._durable_cache(
                kind="identity",
                key=record_key,
                value=raw_current,
                result=result,
                history=predecessor_chain,
            )
        return raw_current, result

    async def get_identity_envelope(
        self, object_key_hex: str, quorum: int = 0
    ) -> bytes | None:
        """Return exact bytes for the Registry-validated current Identity Record."""
        accepted = await self._get_validated_identity_envelope(
            object_key_hex, quorum=quorum
        )
        return None if accepted is None else accepted[0]

    def _get_durable_identity_envelope_by_hash(
        self, object_key_hex: str, state_hash: bytes
    ) -> bytes | None:
        if not isinstance(state_hash, bytes) or len(state_hash) != 32:
            raise ValueError("state_hash must be 32 bytes")
        record_key = bytes.fromhex(object_key_hex)
        current = self._durable_get(kind="identity", key=record_key)
        if current is None:
            return None
        history = self._durable_history(kind="identity", key=record_key)
        predecessor_chain = self._history_ending_at(history, current)
        try:
            self._validator.validate_identity_get(
                record_key=record_key,
                envelope_cbor=current,
                predecessor_chain=predecessor_chain,
            )
        except Exception:
            return None
        candidates = predecessor_chain if predecessor_chain is not None else (current,)
        for envelope in candidates:
            try:
                signed_update = _envelope_signed_update_bytes(envelope)
            except Exception:
                return None
            if hashlib.sha256(signed_update).digest() == state_hash:
                return envelope
        return None

    async def get_identity_envelope_by_hash(
        self, object_key_hex: str, state_hash: bytes
    ) -> bytes | None:
        """Return a validated envelope from locally retained accepted history.

        This is not a DHT-wide content-addressed read. Missing or invalid local
        history returns ``None`` so callers can fail closed.
        """
        if len(bytes.fromhex(object_key_hex)) != 32:
            raise ValueError("identity object key must be 32 bytes")
        return self._get_durable_identity_envelope_by_hash(
            object_key_hex, state_hash
        )

    async def get_signed_identity_record(
        self, object_key_hex: str, quorum: int = 0
    ) -> dict[str, Any] | IdentityRecordResult | None:
        accepted = await self._get_validated_identity_envelope(
            object_key_hex, quorum=quorum
        )
        if accepted is None:
            return None
        _, result = accepted
        if isinstance(result, IdentityRecordResult):
            return result
        return {
            "object_key": object_key_hex,
            "owner_name": result.owner_name_hex,
            "owner_public_key": result.owner_public_key.hex(),
            "seq": int(result.seq),
        }

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
