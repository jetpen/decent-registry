from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import cbor2

from decent_registry.encoding import (
    decode_canonical_signed_update,
    decode_multisignature_signed_update,
)
from decent_registry.provider_schema import ProviderPayloadV1, decode_provider_payload_dict
from decent_registry.signed_envelope import decode_signed_envelope
from decent_registry.verification import (
    MultisignatureState,
    SeqStateEntry,
    validate_identity_update,
    validate_multisignature_envelope,
    validate_multisignature_update,
    validate_provider_update,
    validate_signed_update_overwrite,
)


def _is_multisignature_envelope(envelope_cbor: bytes) -> bool:
    try:
        decoded = cbor2.loads(envelope_cbor)
    except Exception:
        return False
    return isinstance(decoded, dict) and set(decoded) == {1, 2, 3}


@dataclass(frozen=True, slots=True)
class AuthorizationMetadata:
    version: int
    operation: int
    epoch: int
    threshold: int
    signer_set: tuple[tuple[str, bytes], ...]
    predecessor_state_hash: bytes
    state_hash: bytes

    @classmethod
    def from_state(cls, state: MultisignatureState) -> "AuthorizationMetadata":
        signed_update = decode_multisignature_signed_update(state.signed_update_bytes)
        authorization = signed_update[4]
        return cls(
            version=1,
            operation=authorization[3],
            epoch=authorization[4],
            threshold=authorization[5],
            signer_set=state.signer_set,
            predecessor_state_hash=bytes(authorization[7]),
            state_hash=state.state_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "operation": self.operation,
            "epoch": self.epoch,
            "threshold": self.threshold,
            "signer_set": [
                {"signer_id": signer_id, "public_key": public_key.hex()}
                for signer_id, public_key in self.signer_set
            ],
            "predecessor_state_hash": self.predecessor_state_hash.hex(),
            "state_hash": self.state_hash.hex(),
        }


@dataclass(frozen=True, slots=True)
class ProviderRecordResult:
    payload: ProviderPayloadV1
    seq: int
    authorization: AuthorizationMetadata

    @property
    def alg(self) -> str:
        return self.payload.alg

    @property
    def version(self) -> int:
        return self.payload.version

    @property
    def object_hash(self) -> str:
        return self.payload.object_hash

    @property
    def provider_url(self) -> str:
        return self.payload.provider_url

    @property
    def endpoints(self) -> list[str]:
        return self.payload.endpoints


@dataclass(frozen=True, slots=True)
class IdentityRecordResult:
    record_key: bytes
    object_key_hex: str
    owner_public_key: bytes
    owner_name_hex: str
    seq: int
    authorization: AuthorizationMetadata

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_key": self.object_key_hex,
            "owner_name": self.owner_name_hex,
            "owner_public_key": self.owner_public_key.hex(),
            "seq": self.seq,
            "authorization": self.authorization.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ProviderOverwriteResult:
    record_key: bytes
    object_hash_hex: str
    owner_public_key: bytes
    seq: int
    authorization: AuthorizationMetadata | None = None
    state: MultisignatureState | None = None


@dataclass(frozen=True, slots=True)
class IdentityOverwriteResult:
    record_key: bytes
    object_key_hex: str
    owner_public_key: bytes
    owner_name_hex: str
    seq: int
    authorization: AuthorizationMetadata | None = None
    state: MultisignatureState | None = None


class RecordValidator:
    """Pure validation and key-derivation for legacy and versioned records."""

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

    @staticmethod
    def _validate_multisignature_transition(
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        existing_envelope_cbor: bytes | None,
    ) -> MultisignatureState:
        current_state: MultisignatureState | None = None
        legacy_envelope_cbor: bytes | None = None
        if existing_envelope_cbor is not None:
            if _is_multisignature_envelope(existing_envelope_cbor):
                current_state = validate_multisignature_envelope(
                    record_key=record_key,
                    envelope_cbor=existing_envelope_cbor,
                )
            else:
                legacy_envelope_cbor = existing_envelope_cbor
        return validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
            current_state=current_state,
            legacy_envelope_cbor=legacy_envelope_cbor,
        )

    @staticmethod
    def _metadata(state: MultisignatureState) -> AuthorizationMetadata:
        return AuthorizationMetadata.from_state(state)

    def validate_provider_overwrite(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        existing_envelope_cbor: bytes | None = None,
    ) -> ProviderOverwriteResult:
        if _is_multisignature_envelope(envelope_cbor):
            state = self._validate_multisignature_transition(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=existing_envelope_cbor,
            )
            signed_update = decode_multisignature_signed_update(
                state.signed_update_bytes
            )
            record_fields = signed_update[1]
            provider_payload = decode_provider_payload_dict(signed_update[2])
            owner_public_key = record_fields[1]
            return ProviderOverwriteResult(
                record_key=record_key,
                object_hash_hex=provider_payload.object_hash,
                owner_public_key=bytes(owner_public_key),
                seq=int(signed_update[3]),
                authorization=self._metadata(state),
                state=state,
            )

        if existing_envelope_cbor is not None and _is_multisignature_envelope(
            existing_envelope_cbor
        ):
            raise ValueError("legacy writes are rejected after multisignature upgrade")

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
        if _is_multisignature_envelope(envelope_cbor):
            state = self._validate_multisignature_transition(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=existing_envelope_cbor,
            )
            signed_update = decode_multisignature_signed_update(
                state.signed_update_bytes
            )
            record_fields = signed_update[1]
            owner_name_bytes = record_fields[1]
            owner_pub_bytes = record_fields[2]
            return IdentityOverwriteResult(
                record_key=record_key,
                object_key_hex=record_key.hex(),
                owner_public_key=bytes(owner_pub_bytes),
                owner_name_hex=bytes(owner_name_bytes).hex(),
                seq=int(signed_update[3]),
                authorization=self._metadata(state),
                state=state,
            )

        if existing_envelope_cbor is not None and _is_multisignature_envelope(
            existing_envelope_cbor
        ):
            raise ValueError("legacy writes are rejected after multisignature upgrade")

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
    ) -> ProviderPayloadV1 | ProviderRecordResult:
        if _is_multisignature_envelope(envelope_cbor):
            state = validate_multisignature_envelope(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
            )
            signed_update = decode_multisignature_signed_update(
                state.signed_update_bytes
            )
            return ProviderRecordResult(
                payload=decode_provider_payload_dict(signed_update[2]),
                seq=int(signed_update[3]),
                authorization=self._metadata(state),
            )

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
    ) -> IdentityOverwriteResult | IdentityRecordResult:
        if _is_multisignature_envelope(envelope_cbor):
            state = validate_multisignature_envelope(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
            )
            signed_update = decode_multisignature_signed_update(
                state.signed_update_bytes
            )
            record_fields = signed_update[1]
            return IdentityRecordResult(
                record_key=record_key,
                object_key_hex=record_key.hex(),
                owner_public_key=bytes(record_fields[2]),
                owner_name_hex=bytes(record_fields[1]).hex(),
                seq=int(signed_update[3]),
                authorization=self._metadata(state),
            )

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
