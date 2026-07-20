from __future__ import annotations

from dataclasses import dataclass
from typing import Any


from decent_registry.encoding import decode_canonical_signed_update
from decent_registry.provider_schema import ProviderPayloadV1, decode_provider_payload_dict
from decent_registry.signed_envelope import decode_signed_envelope
from decent_registry.verification import SeqStateEntry, validate_signed_update_overwrite


@dataclass(frozen=True, slots=True)
class ProviderOverwriteResult:
    record_key: bytes
    object_hash_hex: str
    owner_public_key: bytes
    seq: int


@dataclass(frozen=True, slots=True)
class IdentityOverwriteResult:
    record_key: bytes
    object_key_hex: str
    owner_public_key: bytes
    owner_name_hex: str
    seq: int


class RecordValidator:
    """Pure validation and key-derivation for signed records (issue #38).

    No network I/O. All methods operate on CBOR/bytes and call the pure
    cryptographic/validation primitives from `verification.py`.
    """

    @staticmethod
    def _extract_provider_prev_seq_state(
        *, existing_envelope_cbor: bytes
    ) -> SeqStateEntry | None:
        try:
            existing_signed_update_bytes, _existing_signature = decode_signed_envelope(
                existing_envelope_cbor
            )
            existing_signed_update = decode_canonical_signed_update(
                existing_signed_update_bytes
            )
            seq = existing_signed_update[3]
            record_fields = existing_signed_update[1]
            if (
                isinstance(record_fields, dict)
                and 1 in record_fields
                and isinstance(record_fields[1], (bytes, bytearray))
            ):
                owner_public_key = bytes(record_fields[1])
                return SeqStateEntry(owner_public_key=owner_public_key, seq=int(seq))
            return None
        except Exception:
            return None

    @staticmethod
    def _extract_identity_prev_seq_state(
        *, existing_envelope_cbor: bytes
    ) -> SeqStateEntry | None:
        try:
            existing_signed_update_bytes, _existing_signature = decode_signed_envelope(
                existing_envelope_cbor
            )
            existing_signed_update = decode_canonical_signed_update(
                existing_signed_update_bytes
            )
            seq = existing_signed_update[3]
            record_fields = existing_signed_update[1]
            if (
                isinstance(record_fields, dict)
                and 2 in record_fields
                and isinstance(record_fields[2], (bytes, bytearray))
            ):
                owner_public_key = bytes(record_fields[2])
                return SeqStateEntry(owner_public_key=owner_public_key, seq=int(seq))
            return None
        except Exception:
            return None

    def validate_provider_overwrite(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        existing_envelope_cbor: bytes | None = None,
    ) -> ProviderOverwriteResult:
        seq_state: dict[bytes, SeqStateEntry] = {}
        if existing_envelope_cbor is not None:
            prev = self._extract_provider_prev_seq_state(
                existing_envelope_cbor=existing_envelope_cbor
            )
            if prev is not None:
                seq_state[record_key] = prev

        signed_update_bytes, signature = decode_signed_envelope(envelope_cbor)
        validate_signed_update_overwrite(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state=seq_state,
            update_state_on_success=False,
        )

        signed_update = decode_canonical_signed_update(signed_update_bytes)
        record_fields = signed_update[1]
        payload = signed_update[2]
        seq = int(signed_update[3])

        if not isinstance(record_fields, dict) or 1 not in record_fields:
            raise ValueError("unrecognized provider record_fields")
        owner_public_key = record_fields[1]
        if not isinstance(owner_public_key, (bytes, bytearray)):
            raise ValueError("provider owner_public_key must be bytes")

        provider_payload: ProviderPayloadV1 = decode_provider_payload_dict(payload)

        return ProviderOverwriteResult(
            record_key=record_key,
            object_hash_hex=provider_payload.object_hash,
            owner_public_key=bytes(owner_public_key),
            seq=seq,
        )

    def validate_identity_overwrite(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        existing_envelope_cbor: bytes | None = None,
    ) -> IdentityOverwriteResult:
        seq_state: dict[bytes, SeqStateEntry] = {}
        if existing_envelope_cbor is not None:
            prev = self._extract_identity_prev_seq_state(
                existing_envelope_cbor=existing_envelope_cbor
            )
            if prev is not None:
                seq_state[record_key] = prev

        signed_update_bytes, signature = decode_signed_envelope(envelope_cbor)
        validate_signed_update_overwrite(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state=seq_state,
            update_state_on_success=False,
        )

        signed_update = decode_canonical_signed_update(signed_update_bytes)
        record_fields = signed_update[1]
        seq = int(signed_update[3])

        if not isinstance(record_fields, dict):
            raise ValueError("unrecognized identity record_fields")
        owner_name_bytes = record_fields.get(1)
        owner_pub_bytes = record_fields.get(2)
        if not isinstance(owner_name_bytes, (bytes, bytearray)):
            raise ValueError("identity owner_name must be bytes")
        if not isinstance(owner_pub_bytes, (bytes, bytearray)):
            raise ValueError("identity owner_public_key must be bytes")

        return IdentityOverwriteResult(
            record_key=record_key,
            object_key_hex=record_key.hex(),
            owner_public_key=bytes(owner_pub_bytes),
            owner_name_hex=bytes(owner_name_bytes).hex(),
            seq=seq,
        )

    def validate_provider_get(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
    ) -> ProviderPayloadV1:
        signed_update_bytes, signature = decode_signed_envelope(envelope_cbor)
        validate_signed_update_overwrite(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state={},
            update_state_on_success=False,
        )

        signed_update = decode_canonical_signed_update(signed_update_bytes)
        payload_map = signed_update[2]
        return decode_provider_payload_dict(payload_map)

    def validate_identity_get(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
    ) -> IdentityOverwriteResult:
        signed_update_bytes, signature = decode_signed_envelope(envelope_cbor)
        validate_signed_update_overwrite(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state={},
            update_state_on_success=False,
        )

        signed_update = decode_canonical_signed_update(signed_update_bytes)
        record_fields = signed_update[1]
        seq = int(signed_update[3])

        if not isinstance(record_fields, dict):
            raise ValueError("unrecognized identity record_fields")
        owner_name_bytes = record_fields.get(1)
        owner_pub_bytes = record_fields.get(2)
        if not isinstance(owner_name_bytes, (bytes, bytearray)):
            raise ValueError("identity owner_name must be bytes")
        if not isinstance(owner_pub_bytes, (bytes, bytearray)):
            raise ValueError("identity owner_public_key must be bytes")

        return IdentityOverwriteResult(
            record_key=record_key,
            object_key_hex=record_key.hex(),
            owner_public_key=bytes(owner_pub_bytes),
            owner_name_hex=bytes(owner_name_bytes).hex(),
            seq=seq,
        )
