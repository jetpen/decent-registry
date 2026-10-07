from __future__ import annotations

from typing import Any

from decent_registry.crypto_utils import (
    load_ed25519_keypair_from_privkey_pem_path,
)
from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import (
    build_provider_payload_dict,
    build_provider_withdrawal_payload_dict,
)
from decent_registry.signed_envelope import encode_signed_envelope
from decent_registry.verification import make_signed_update_signature


def _parse_hex_bytes(value: str, *, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except Exception:
        raise ValueError(f"{name} must be valid hex") from None



def build_provider_envelope(
    *,
    object_hash: str,
    provider_urls: list[str],
    owner_privkey_pem_path: str,
    seq: int,
    endpoints: list[str],
    alg: str = "Ed25519",
) -> bytes:
    """Deep module: builds the canonical SignedUpdate -> Ed25519 signature ->
    canonical signed envelope bytes for a provider record.

    Returns the CBOR-encoded signed envelope bytes.
    """

    owner_priv, owner_pub_bytes = (
        load_ed25519_keypair_from_privkey_pem_path(owner_privkey_pem_path)
    )

    payload_dict: dict[int, Any] = build_provider_payload_dict(
        alg=alg,
        version=3,
        object_hash=object_hash,
        provider_urls=provider_urls,
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

    return encode_signed_envelope(
        signed_update_bytes=signed_update_bytes,
        signature=signature,
    )


def build_provider_withdrawal_envelope(
    *,
    object_hash: str,
    owner_privkey_pem_path: str,
    seq: int,
    replacement_object_hash: str | None = None,
    alg: str = "Ed25519",
) -> bytes:
    """Build a canonical legacy SignedEnvelope carrying a Provider v2 tombstone."""
    owner_priv, owner_pub_bytes = load_ed25519_keypair_from_privkey_pem_path(
        owner_privkey_pem_path
    )
    payload = build_provider_withdrawal_payload_dict(
        alg=alg,
        object_hash=object_hash,
        replacement_object_hash=replacement_object_hash,
    )
    signed_update_bytes = encode_signed_update(
        record_fields={1: owner_pub_bytes}, payload=payload, seq=seq
    )
    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=owner_priv,
    )
    return encode_signed_envelope(
        signed_update_bytes=signed_update_bytes, signature=signature
    )


def build_identity_envelope(
    *,
    owner_name_hex: str,
    owner_privkey_pem_path: str,
    seq: int,
) -> bytes:
    """Deep module: builds the canonical SignedUpdate -> Ed25519 signature ->
    canonical signed envelope bytes for an identity record.

    Returns the CBOR-encoded signed envelope bytes.
    """

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

    return encode_signed_envelope(
        signed_update_bytes=signed_update_bytes,
        signature=signature,
    )
