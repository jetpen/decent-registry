from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from decent_registry.envelope_builder import (
    build_identity_envelope,
    build_provider_envelope,
)
from decent_registry.provider_schema import ProviderPayloadV1


class RegistryDHT(Protocol):
    async def put_signed_provider_record(
        self, object_hash: str, envelope_cbor: bytes
    ) -> None: ...

    async def get_signed_provider_record(
        self, object_hash: str, quorum: int = 0
    ) -> ProviderPayloadV1 | None: ...

    async def put_signed_identity_record(
        self, object_key_hex: str, envelope_cbor: bytes
    ) -> None: ...

    async def get_signed_identity_record(
        self, object_key_hex: str, quorum: int = 0
    ) -> dict[str, Any] | None: ...


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
        provider_url: str,
        owner_privkey_pem_path: str,
        seq: int,
        endpoints: list[str],
        alg: str = "Ed25519",
        version: int = 1,
    ) -> None:
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

    async def get_provider(
        self,
        *,
        object_hash: str,
        quorum: int = 0,
    ) -> ProviderPayloadV1 | None:
        return await self.dht.get_signed_provider_record(object_hash, quorum=quorum)

    async def put_identity(
        self,
        *,
        owner_name_hex: str,
        owner_privkey_pem_path: str,
        seq: int,
    ) -> None:
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(
            owner_name_hex
        )
        envelope_cbor = build_identity_envelope(
            owner_name_hex=owner_name_hex,
            owner_privkey_pem_path=owner_privkey_pem_path,
            seq=seq,
        )
        await self.dht.put_signed_identity_record(object_key_hex, envelope_cbor)

    async def get_identity(
        self,
        *,
        owner_name_hex: str,
        quorum: int = 0,
    ) -> dict[str, Any] | None:
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(owner_name_hex)
        return await self.dht.get_signed_identity_record(object_key_hex, quorum=quorum)
