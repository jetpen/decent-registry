from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from decent_registry.crypto_utils import (
    load_ed25519_keypair_from_privkey_pem_path,
)
from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import ProviderPayloadV1, build_provider_payload_dict
from decent_registry.signed_envelope import encode_signed_envelope
from decent_registry.verification import make_signed_update_signature


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
        provider_id: str,
        owner_privkey_pem_path: str,
        seq: int,
        endpoints: list[str],
        alg: str = "Ed25519",
        version: int = 1,
    ) -> None:
        owner_priv, owner_pub_bytes = (
            load_ed25519_keypair_from_privkey_pem_path(owner_privkey_pem_path)
        )

        payload_dict: dict[int, Any] = build_provider_payload_dict(
            alg=alg,
            version=version,
            object_hash=object_hash,
            provider_id=provider_id,
            endpoints=endpoints,
        )
        record_fields: dict[int, Any] = {1: owner_pub_bytes}

        signed_update_bytes = encode_signed_update(
            record_fields=record_fields,
            payload=payload_dict,
            seq=int(seq),
        )
        signature = make_signed_update_signature(
            signed_update_bytes_canonical=signed_update_bytes,
            owner_private_key=owner_priv,
        )
        envelope_cbor = encode_signed_envelope(
            signed_update_bytes=signed_update_bytes,
            signature=signature,
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
        object_key_hex = _derive_identity_object_hash_from_owner_name_hex(owner_name_hex)

        owner_priv, owner_pub_bytes = (
            load_ed25519_keypair_from_privkey_pem_path(owner_privkey_pem_path)
        )
        owner_name_bytes = _parse_hex_bytes(owner_name_hex, name="owner_name")

        record_fields: dict[int, Any] = {
            1: owner_name_bytes,
            2: owner_pub_bytes,
        }

        signed_update_bytes = encode_signed_update(
            record_fields=record_fields,
            payload={},
            seq=int(seq),
        )
        signature = make_signed_update_signature(
            signed_update_bytes_canonical=signed_update_bytes,
            owner_private_key=owner_priv,
        )
        envelope_cbor = encode_signed_envelope(
            signed_update_bytes=signed_update_bytes,
            signature=signature,
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
