from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from decent_registry.envelope_builder import (
    build_identity_envelope,
    build_provider_envelope,
    build_provider_withdrawal_envelope,
)
from decent_registry.exceptions import (
    IdentityStatePreconditionFailed,
    ProviderAlreadyWithdrawn,
    ProviderStateConflict,
    ProviderStateInvalid,
    ProviderStateUnavailable,
)
from decent_registry.provider_schema import ProviderPayloadV1
from decent_registry.record_validator import (
    IdentityRecordResult,
    ProviderRecordResult,
    ProviderWithdrawnResult,
    RecordValidator,
)


class RegistryDHT(Protocol):
    async def get_signed_provider_envelope(
        self, object_hash: str, quorum: int = 0
    ) -> bytes | None: ...

    async def put_signed_provider_record(
        self, object_hash: str, envelope_cbor: bytes
    ) -> None: ...

    async def get_signed_provider_record(
        self, object_hash: str, quorum: int = 0
    ) -> ProviderPayloadV1 | ProviderWithdrawnResult | ProviderRecordResult | None: ...

    async def put_signed_identity_record(
        self, object_key_hex: str, envelope_cbor: bytes
    ) -> None: ...

    async def put_signed_identity_record_if_current(
        self,
        object_key_hex: str,
        envelope_cbor: bytes,
        *,
        expected_state_hash: bytes,
        expires_at: int,
    ) -> None: ...

    async def get_signed_identity_record(
        self, object_key_hex: str, quorum: int = 0
    ) -> dict[str, Any] | IdentityRecordResult | None: ...

    async def get_identity_envelope(
        self, object_key_hex: str, quorum: int = 0
    ) -> bytes | None: ...

    async def get_identity_envelope_by_hash(
        self, object_key_hex: str, state_hash: bytes
    ) -> bytes | None: ...


    async def confirm_identity_owner_key_rotation(
        self, *, owner_name_hex: str, expected_envelope_cbor: bytes
    ) -> IdentityRecordResult | None: ...


def _parse_hex_bytes(value: str, *, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except Exception:
        raise ValueError(f"{name} must be valid hex") from None


def _derive_identity_object_hash_from_owner_name_hex(owner_name_hex: str) -> str:
    owner_name_bytes = _parse_hex_bytes(owner_name_hex, name="owner_name")
    return hashlib.sha256(owner_name_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class RegistryService:
    dht: RegistryDHT

    async def put_provider(
        self,
        *,
        object_hash: str,
        provider_url: str | None = None,
        owner_privkey_pem_path: str | None = None,
        seq: int | None = None,
        endpoints: list[str] | None = None,
        alg: str = "Ed25519",
        version: int = 1,
        envelope_cbor: bytes | None = None,
    ) -> None:
        """Publish either a legacy single-key record or a finalized envelope."""
        if envelope_cbor is not None:
            if (
                provider_url is not None
                or owner_privkey_pem_path is not None
                or seq is not None
                or endpoints is not None
            ):
                raise ValueError(
                    "envelope_cbor cannot be combined with legacy provider signing arguments"
                )
            await self.put_provider_envelope(
                object_hash=object_hash,
                envelope_cbor=envelope_cbor,
            )
            return

        if (
            provider_url is None
            or owner_privkey_pem_path is None
            or seq is None
            or endpoints is None
        ):
            raise TypeError(
                "legacy provider put requires provider_url, owner_privkey_pem_path, seq, and endpoints"
            )
        envelope_cbor = build_provider_envelope(
            object_hash=object_hash,
            provider_url=provider_url,
            owner_privkey_pem_path=owner_privkey_pem_path,
            seq=seq,
            endpoints=endpoints,
            alg=alg,
            version=version,
        )
        await self.dht.put_signed_provider_record(object_hash, envelope_cbor)

    async def put_provider_envelope(
        self, *, object_hash: str, envelope_cbor: bytes
    ) -> None:
        """Publish a finalized legacy or multisignature provider envelope."""
        await self.dht.put_signed_provider_record(object_hash, envelope_cbor)

    async def withdraw_provider(
        self,
        *,
        object_hash: str,
        owner_privkey_pem_path: str | None = None,
        seq: int | None = None,
        replacement_object_hash: str | None = None,
        envelope_cbor: bytes | None = None,
    ) -> None:
        """Publish a withdrawal only after validating an available active predecessor.

        Legacy mode takes the bound Owner Public Key's private key and a Seq.
        Finalized mode accepts a Provider multisignature tombstone envelope.
        The selected-head check is local to one Registry; DHT propagation is not
        compare-and-swap across the network.
        """
        if envelope_cbor is not None:
            if owner_privkey_pem_path is not None or seq is not None or replacement_object_hash is not None:
                raise ValueError("finalized withdrawal cannot be combined with legacy signing arguments")
            candidate = bytes(envelope_cbor)
        else:
            if owner_privkey_pem_path is None or seq is None:
                raise TypeError("legacy withdrawal requires owner_privkey_pem_path and seq")
            candidate = build_provider_withdrawal_envelope(
                object_hash=object_hash,
                owner_privkey_pem_path=owner_privkey_pem_path,
                seq=seq,
                replacement_object_hash=replacement_object_hash,
            )

        try:
            current_envelope = await self.dht.get_signed_provider_envelope(object_hash)
        except ProviderStateConflict:
            raise
        except Exception as exc:
            raise ProviderStateUnavailable(
                "could not read current Provider Record before withdrawal"
            ) from exc
        if current_envelope is None:
            raise ProviderStateUnavailable(
                "no valid active Provider Record was available for withdrawal"
            )

        validator = RecordValidator()
        try:
            current = validator.validate_provider_get(
                record_key=bytes.fromhex(object_hash),
                envelope_cbor=current_envelope,
            )
        except Exception as exc:
            raise ProviderStateInvalid("current Provider Record is invalid") from exc
        if isinstance(current, ProviderWithdrawnResult):
            raise ProviderAlreadyWithdrawn("Provider Record is already withdrawn")

        try:
            proposed = validator.validate_provider_overwrite(
                record_key=bytes.fromhex(object_hash),
                envelope_cbor=candidate,
                existing_envelope_cbor=current_envelope,
            )
        except ProviderAlreadyWithdrawn:
            raise
        except Exception as exc:
            raise ValueError("withdrawal envelope is invalid for the selected Provider state") from exc
        if not isinstance(proposed, ProviderWithdrawnResult):
            raise ValueError("withdrawal envelope does not contain a Provider tombstone")
        await self.dht.put_signed_provider_record(object_hash, candidate)

    async def put_provider_multisig(
        self, *, object_hash: str, envelope_cbor: bytes
    ) -> None:
        """Explicit alias for publishing a finalized multisignature provider envelope."""
        await self.put_provider_envelope(
            object_hash=object_hash,
            envelope_cbor=envelope_cbor,
        )

    async def get_provider(
        self,
        *,
        object_hash: str,
        quorum: int = 0,
    ) -> ProviderPayloadV1 | ProviderWithdrawnResult | ProviderRecordResult | None:
        return await self.dht.get_signed_provider_record(object_hash, quorum=quorum)

    async def put_identity(
        self,
        *,
        owner_name_hex: str,
        owner_privkey_pem_path: str | None = None,
        seq: int | None = None,
        envelope_cbor: bytes | None = None,
    ) -> None:
        """Publish either a legacy single-key record or a finalized envelope."""
        if envelope_cbor is not None:
            if owner_privkey_pem_path is not None or seq is not None:
                raise ValueError(
                    "envelope_cbor cannot be combined with legacy identity signing arguments"
                )
            await self.put_identity_envelope(
                owner_name_hex=owner_name_hex,
                envelope_cbor=envelope_cbor,
            )
            return

        if owner_privkey_pem_path is None or seq is None:
            raise TypeError(
                "legacy identity put requires owner_privkey_pem_path and seq"
            )
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(
            owner_name_hex
        )
        envelope_cbor = build_identity_envelope(
            owner_name_hex=owner_name_hex,
            owner_privkey_pem_path=owner_privkey_pem_path,
            seq=seq,
        )
        await self.dht.put_signed_identity_record(object_key_hex, envelope_cbor)

    async def put_identity_envelope(
        self, *, owner_name_hex: str, envelope_cbor: bytes
    ) -> None:
        """Publish a finalized legacy or multisignature identity envelope."""
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(
            owner_name_hex
        )
        await self.dht.put_signed_identity_record(object_key_hex, envelope_cbor)

    async def put_identity_envelope_if_current(
        self,
        *,
        owner_name_hex: str,
        envelope_cbor: bytes,
        expected_state_hash: bytes,
        expires_at: int,
    ) -> None:
        """Conditionally publish against one Registry instance's existing head.

        A non-null 32-byte state hash is required. DHT ``None`` reads cannot
        distinguish an absent key from an inconclusive lookup.
        """
        if expected_state_hash is None:
            raise IdentityStatePreconditionFailed(
                "DHT reads cannot prove that the Identity key is absent"
            )
        if not isinstance(expected_state_hash, bytes) or len(expected_state_hash) != 32:
            raise ValueError("expected_state_hash must be exactly 32 bytes")
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(
            owner_name_hex
        )
        await self.dht.put_signed_identity_record_if_current(
            object_key_hex,
            envelope_cbor,
            expected_state_hash=expected_state_hash,
            expires_at=expires_at,
        )

    async def put_identity_multisig(
        self, *, owner_name_hex: str, envelope_cbor: bytes
    ) -> None:
        """Explicit alias for publishing a finalized multisignature identity envelope."""
        await self.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=envelope_cbor,
        )

    async def get_identity(
        self,
        *,
        owner_name_hex: str,
        quorum: int = 0,
    ) -> dict[str, Any] | IdentityRecordResult | None:
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(owner_name_hex)
        return await self.dht.get_signed_identity_record(object_key_hex, quorum=quorum)

    async def get_identity_envelope(
        self,
        *,
        owner_name_hex: str,
        quorum: int = 0,
    ) -> bytes | None:
        """Return exact raw bytes for the Registry-validated current Identity Record."""
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(owner_name_hex)
        return await self.dht.get_identity_envelope(object_key_hex, quorum=quorum)

    async def get_identity_envelope_by_hash(
        self,
        *,
        owner_name_hex: str,
        state_hash: bytes,
    ) -> bytes | None:
        """Return an envelope by state hash from local accepted Identity history."""
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(owner_name_hex)
        return await self.dht.get_identity_envelope_by_hash(object_key_hex, state_hash)


    async def confirm_identity_owner_key_rotation(
        self, *, owner_name_hex: str, expected_envelope_cbor: bytes
    ) -> IdentityRecordResult | None:
        """Return verified public state only after exact independent DHT read-back.

        The result is read-back evidence, not a wallet confirmation capability.
        """
        return await self.dht.confirm_identity_owner_key_rotation(
            owner_name_hex=owner_name_hex,
            expected_envelope_cbor=expected_envelope_cbor,
        )
