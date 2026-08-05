from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from decent_registry.envelope_builder import (
    build_identity_envelope,
    build_provider_envelope,
)
from decent_registry.provider_schema import ProviderPayloadV1
from decent_registry.record_validator import IdentityRecordResult, ProviderRecordResult


class RegistryDHT(Protocol):
    async def put_signed_provider_record(
        self, object_hash: str, envelope_cbor: bytes
    ) -> None: ...

    async def get_signed_provider_record(
        self, object_hash: str, quorum: int = 0
    ) -> ProviderPayloadV1 | ProviderRecordResult | None: ...

    async def put_signed_identity_record(
        self, object_key_hex: str, envelope_cbor: bytes
    ) -> None: ...

    async def get_signed_identity_record(
        self, object_key_hex: str, quorum: int = 0
    ) -> dict[str, Any] | IdentityRecordResult | None: ...


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
    ) -> ProviderPayloadV1 | ProviderRecordResult | None:
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
