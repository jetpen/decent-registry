from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, MutableMapping

from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import decode_canonical_signed_update
from decent_registry.provider_schema import decode_provider_payload_dict


@dataclass
class SeqStateEntry:
    owner_public_key: bytes
    seq: int


# Cache the concrete Ed25519 public key class (the one libp2p returns).
_PUBKEY_CLS = type(create_new_key_pair().public_key)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _pubkey_from_bytes(raw: bytes) -> Any:
    return _PUBKEY_CLS.from_bytes(raw)  # type: ignore[attr-defined]


def verify_ed25519_signature(
    *,
    owner_public_key: bytes,
    signed_update_bytes_canonical: bytes,
    signature: bytes,
) -> bool:
    """Verify Ed25519 signature where the signing message is:

        sha256(canonical_cbor(SignedUpdate))

    libp2p `sign()` signs the provided message bytes directly, and
    `verify(data, signature)` expects (data, signature).
    """

    pub = _pubkey_from_bytes(owner_public_key)
    digest_msg = _sha256(signed_update_bytes_canonical)
    return bool(pub.verify(digest_msg, signature))


def _extract_identity_and_keys(
    *,
    record_fields: dict[int, Any],
    payload: dict[int, Any],
) -> tuple[bytes, bytes]:
    # Identity: record_fields[1]=owner_name_bytes, record_fields[2]=owner_public_key.
    owner_name = record_fields.get(1)
    owner_pk = record_fields.get(2)
    if (
        isinstance(owner_name, (bytes, bytearray))
        and isinstance(owner_pk, (bytes, bytearray))
    ):
        derived_record_key = _sha256(bytes(owner_name))
        return derived_record_key, bytes(owner_pk)

    raise ValueError("not an identity record")


def _extract_provider_and_keys(
    *,
    record_fields: dict[int, Any],
    payload: dict[int, Any],
) -> tuple[bytes, bytes]:
    # Provider/object: record_fields[1]=owner_public_key, payload[3]=object_hash(hex).
    owner_pk = record_fields.get(1)
    if not isinstance(owner_pk, (bytes, bytearray)):
        raise ValueError("not a provider record")

    try:
        provider_payload = decode_provider_payload_dict(payload)
    except Exception as e:
        raise ValueError("invalid provider payload") from e

    object_hash = provider_payload.object_hash
    if not isinstance(object_hash, str):
        raise ValueError("object_hash must be a hex string")

    # object_hash is K_obj = sha256(object_content_bytes), represented as 64-hex.
    if len(object_hash) != 64:
        raise ValueError("object_hash must be 64 hex chars")
    try:
        derived_record_key = bytes.fromhex(object_hash)
    except Exception as e:
        raise ValueError("object_hash must be valid hex") from e

    return derived_record_key, bytes(owner_pk)


def _decode_signed_update_strict(
    *,
    signed_update_bytes_canonical: bytes,
) -> tuple[dict[int, Any], dict[int, Any], dict[int, Any], int]:
    signed_update = decode_canonical_signed_update(signed_update_bytes_canonical)

    if set(signed_update.keys()) != {1, 2, 3}:
        raise ValueError("SignedUpdate must have keys {1,2,3}")

    record_fields_raw = signed_update[1]
    payload_raw = signed_update[2]
    seq_raw = signed_update[3]

    if not isinstance(record_fields_raw, dict) or not isinstance(payload_raw, dict):
        raise ValueError("SignedUpdate record_fields and payload must be CBOR maps")

    if not isinstance(seq_raw, int) or seq_raw < 0:
        raise ValueError("SignedUpdate seq must be a non-negative int")

    record_fields: dict[int, Any] = record_fields_raw
    payload: dict[int, Any] = payload_raw
    seq = seq_raw
    return signed_update, record_fields, payload, seq


def _enforce_seq_and_owner_binding(
    *,
    record_key: bytes,
    seq: int,
    owner_public_key: bytes,
    seq_state: MutableMapping[bytes, SeqStateEntry],
    update_state_on_success: bool,
) -> None:
    prev = seq_state.get(record_key)
    if prev is not None:
        if seq <= prev.seq:
            raise ValueError("seq must be strictly increasing")
        if owner_public_key != prev.owner_public_key:
            raise ValueError("owner collision")

    if update_state_on_success and prev is None:
        seq_state[record_key] = SeqStateEntry(
            owner_public_key=owner_public_key, seq=seq
        )
    elif update_state_on_success and prev is not None:
        seq_state[record_key] = SeqStateEntry(
            owner_public_key=prev.owner_public_key, seq=seq
        )


def validate_provider_update(
    *,
    record_key: bytes,
    signed_update_bytes_canonical: bytes,
    signature: bytes,
    seq_state: MutableMapping[bytes, SeqStateEntry],
    update_state_on_success: bool = True,
) -> dict[int, Any]:
    signed_update, record_fields, payload, seq = _decode_signed_update_strict(
        signed_update_bytes_canonical=signed_update_bytes_canonical
    )

    derived_record_key, owner_public_key = _extract_provider_and_keys(
        record_fields=record_fields, payload=payload
    )

    if derived_record_key != record_key:
        raise ValueError("lookup-key mismatch")

    if not verify_ed25519_signature(
        owner_public_key=owner_public_key,
        signed_update_bytes_canonical=signed_update_bytes_canonical,
        signature=signature,
    ):
        raise ValueError("wrong signature")

    _enforce_seq_and_owner_binding(
        record_key=record_key,
        seq=seq,
        owner_public_key=owner_public_key,
        seq_state=seq_state,
        update_state_on_success=update_state_on_success,
    )

    return signed_update


def validate_identity_update(
    *,
    record_key: bytes,
    signed_update_bytes_canonical: bytes,
    signature: bytes,
    seq_state: MutableMapping[bytes, SeqStateEntry],
    update_state_on_success: bool = True,
) -> dict[int, Any]:
    signed_update, record_fields, payload, seq = _decode_signed_update_strict(
        signed_update_bytes_canonical=signed_update_bytes_canonical
    )

    derived_record_key, owner_public_key = _extract_identity_and_keys(
        record_fields=record_fields, payload=payload
    )

    if derived_record_key != record_key:
        raise ValueError("lookup-key mismatch")

    if not verify_ed25519_signature(
        owner_public_key=owner_public_key,
        signed_update_bytes_canonical=signed_update_bytes_canonical,
        signature=signature,
    ):
        raise ValueError("wrong signature")

    _enforce_seq_and_owner_binding(
        record_key=record_key,
        seq=seq,
        owner_public_key=owner_public_key,
        seq_state=seq_state,
        update_state_on_success=update_state_on_success,
    )

    return signed_update


def validate_signed_update_overwrite(
    *,
    record_key: bytes,
    signed_update_bytes_canonical: bytes,
    signature: bytes,
    seq_state: MutableMapping[bytes, SeqStateEntry],
    update_state_on_success: bool = True,
) -> dict[int, Any]:
    """Backward-compatible delegator.

    Dispatches using the same heuristic as the prior implementation:
    attempt identity key extraction; on failure, attempt provider key extraction.

    Validation errors after dispatch (e.g. wrong signature / seq monotonic)
    are not masked.
    """

    _, record_fields, payload, _seq = _decode_signed_update_strict(
        signed_update_bytes_canonical=signed_update_bytes_canonical
    )

    identity_ok = False
    try:
        _extract_identity_and_keys(record_fields=record_fields, payload=payload)
        identity_ok = True
    except Exception:
        identity_ok = False

    if identity_ok:
        return validate_identity_update(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes_canonical,
            signature=signature,
            seq_state=seq_state,
            update_state_on_success=update_state_on_success,
        )

    return validate_provider_update(
        record_key=record_key,
        signed_update_bytes_canonical=signed_update_bytes_canonical,
        signature=signature,
        seq_state=seq_state,
        update_state_on_success=update_state_on_success,
    )


def make_signed_update_signature(
    *,
    signed_update_bytes_canonical: bytes,
    owner_private_key: Any,
) -> bytes:
    """Helper for tests.

    Issue #21 is ambiguous; callers should choose the exact message scheme
    they want. This helper signs sha256(canonical SignedUpdate bytes).
    """

    digest_msg = _sha256(signed_update_bytes_canonical)
    return owner_private_key.sign(digest_msg)
