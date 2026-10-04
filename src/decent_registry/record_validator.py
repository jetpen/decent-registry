from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import cbor2

from decent_registry.encoding import (
    OPERATION_OWNER_KEY_ROTATION,
    RECORD_KIND_IDENTITY,
    RECORD_KIND_PROVIDER,
    canonical_cbor,
    decode_canonical_signed_update,
    decode_multisignature_signed_update,
)
from decent_registry.exceptions import ProviderAlreadyWithdrawn

from decent_registry.provider_schema import (
    ProviderPayloadV1,
    ProviderWithdrawnPayloadV2,
    decode_provider_payload_dict,
    is_provider_withdrawn_payload,
)
from decent_registry.signed_envelope import (
    decode_multisignature_envelope,
    decode_signed_envelope,
)
from decent_registry.verification import (
    MultisignatureState,
    SeqStateEntry,
    validate_identity_update,
    validate_multisignature_envelope,
    validate_multisignature_genesis,
    validate_multisignature_history,
    validate_multisignature_update,
    validate_provider_update,
    validate_signed_update_overwrite,
    verify_ed25519_signature,
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
class ProviderWithdrawnResult:
    object_hash: str
    seq: int
    replacement_object_hash: str | None
    authorization: AuthorizationMetadata | None = None
    predecessor_envelope_cbor: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "withdrawn",
            "object_key": self.object_hash,
            "seq": self.seq,
        }
        if self.replacement_object_hash is not None:
            result["replacement_object_key"] = self.replacement_object_hash
        if self.authorization is not None:
            result["authorization"] = self.authorization.to_dict()
        return result


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_key": self.object_hash,
            "object_hash": self.object_hash,
            "alg": self.alg,
            "version": self.version,
            "provider_url": self.provider_url,
            "endpoints": self.endpoints,
            "seq": self.seq,
            "authorization": self.authorization.to_dict(),
        }


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
    def _require_history_ending_at(
        *,
        predecessor_chain: tuple[bytes, ...] | None,
        envelope_cbor: bytes,
        state_label: str,
    ) -> None:
        if not predecessor_chain or predecessor_chain[-1] != envelope_cbor:
            raise ValueError(
                f"predecessor history does not end at {state_label}"
            )

    @staticmethod
    def _validate_multisignature_transition(
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        existing_envelope_cbor: bytes | None,
        predecessor_chain: tuple[bytes, ...] | None = None,
    ) -> MultisignatureState:
        current_state: MultisignatureState | None = None
        legacy_envelope_cbor: bytes | None = None
        candidate = decode_multisignature_envelope(envelope_cbor)
        candidate_update = decode_multisignature_signed_update(
            candidate.signed_update_bytes
        )
        candidate_operation = candidate_update[4][3]
        candidate_record_kind = candidate_update[4][2]
        candidate_provider_payload = None
        if candidate_record_kind == RECORD_KIND_PROVIDER:
            candidate_provider_payload = decode_provider_payload_dict(candidate_update[2])
            if isinstance(candidate_provider_payload, ProviderWithdrawnPayloadV2) and existing_envelope_cbor is None:
                raise ValueError("a Provider withdrawal requires an active predecessor state")
        if existing_envelope_cbor is not None:
            if _is_multisignature_envelope(existing_envelope_cbor):
                if predecessor_chain is not None:
                    RecordValidator._require_history_ending_at(
                        predecessor_chain=predecessor_chain,
                        envelope_cbor=existing_envelope_cbor,
                        state_label="current state",
                    )
                    current_state = validate_multisignature_history(
                        record_key=record_key,
                        envelopes=predecessor_chain,
                    )
                elif candidate_operation == OPERATION_OWNER_KEY_ROTATION:
                    raise ValueError("complete predecessor history is required for owner rotation")
                else:
                    current_state = validate_multisignature_envelope(
                        record_key=record_key,
                        envelope_cbor=existing_envelope_cbor,
                    )
                    if (
                        candidate_record_kind == RECORD_KIND_IDENTITY
                        and current_state.history is None
                    ):
                        raise ValueError(
                            "complete predecessor history is required for Identity state"
                        )
            else:
                if candidate_provider_payload is not None and isinstance(
                    candidate_provider_payload, ProviderWithdrawnPayloadV2
                ):
                    existing_update_bytes, existing_signature = decode_signed_envelope(
                        existing_envelope_cbor
                    )
                    existing_update = decode_canonical_signed_update(
                        existing_update_bytes
                    )
                    existing_payload = decode_provider_payload_dict(existing_update[2])
                    existing_owner = bytes(existing_update[1][1])
                    candidate_owner = bytes(candidate_update[1][1])
                    if not verify_ed25519_signature(
                        owner_public_key=existing_owner,
                        signed_update_bytes_canonical=existing_update_bytes,
                        signature=existing_signature,
                    ):
                        raise ValueError("invalid active predecessor signature")
                    if existing_owner != candidate_owner:
                        raise ValueError("owner collision")
                    if isinstance(existing_payload, ProviderWithdrawnPayloadV2):
                        raise ProviderAlreadyWithdrawn(
                            "Provider Record is already withdrawn"
                        )
                    if not isinstance(existing_payload, ProviderPayloadV1):
                        raise ValueError("active predecessor Provider Record is invalid")
                legacy_envelope_cbor = existing_envelope_cbor
        state = validate_multisignature_update(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
            current_state=current_state,
            legacy_envelope_cbor=legacy_envelope_cbor,
        )
        if isinstance(candidate_provider_payload, ProviderWithdrawnPayloadV2):
            if current_state is None or current_state.record_kind != RECORD_KIND_PROVIDER:
                raise ValueError("a Provider withdrawal requires a valid active predecessor")
            current_update = decode_multisignature_signed_update(
                current_state.signed_update_bytes
            )
            current_payload = decode_provider_payload_dict(current_update[2])
            if not isinstance(current_payload, ProviderPayloadV1):
                raise ProviderAlreadyWithdrawn("Provider Record is already withdrawn")
        return state

    @staticmethod
    def _metadata(state: MultisignatureState) -> AuthorizationMetadata:
        return AuthorizationMetadata.from_state(state)

    def _verify_provider_tombstone_signatures(
        self, *, envelope_cbor: bytes, signed_update: dict[int, Any]
    ) -> None:
        envelope = decode_multisignature_envelope(envelope_cbor)
        authorization = signed_update[4]
        if authorization[2] != RECORD_KIND_PROVIDER:
            raise ValueError("expected a Provider Record withdrawal")
        signer_set = {entry[1]: bytes(entry[2]) for entry in authorization[6]}
        if len(envelope.proofs) < authorization[5]:
            raise ValueError("insufficient quorum")
        for proof in envelope.proofs:
            public_key = signer_set.get(proof[1])
            if public_key is None or not verify_ed25519_signature(
                owner_public_key=public_key,
                signed_update_bytes_canonical=envelope.signed_update_bytes,
                signature=proof[2],
            ):
                raise ValueError("invalid withdrawal proof")

    def _metadata_from_multisignature_signed_update(
        self, signed_update: dict[int, Any]
    ) -> AuthorizationMetadata:
        authorization = signed_update[4]
        return AuthorizationMetadata(
            version=authorization[1],
            operation=authorization[3],
            epoch=authorization[4],
            threshold=authorization[5],
            signer_set=tuple(
                (entry[1], bytes(entry[2])) for entry in authorization[6]
            ),
            predecessor_state_hash=bytes(authorization[7]),
            state_hash=hashlib.sha256(canonical_cbor(signed_update)).digest(),
        )

    def _metadata_from_multisignature_envelope(
        self, envelope_cbor: bytes
    ) -> AuthorizationMetadata:
        envelope = decode_multisignature_envelope(envelope_cbor)
        signed_update = decode_multisignature_signed_update(
            envelope.signed_update_bytes
        )
        return self._metadata_from_multisignature_signed_update(signed_update)

    @staticmethod
    def _provider_payload_from_envelope(envelope_cbor: bytes) -> dict[int, Any]:
        if _is_multisignature_envelope(envelope_cbor):
            signed_update_bytes = decode_multisignature_envelope(envelope_cbor).signed_update_bytes
        else:
            signed_update_bytes, _signature = decode_signed_envelope(envelope_cbor)
        return decode_canonical_signed_update(signed_update_bytes)[2]

    def validate_provider_overwrite(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        existing_envelope_cbor: bytes | None = None,
    ) -> ProviderOverwriteResult | ProviderWithdrawnResult:
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
            seq = int(signed_update[3])
            if isinstance(provider_payload, ProviderWithdrawnPayloadV2):
                if existing_envelope_cbor is None:
                    raise ValueError("a Provider withdrawal requires an active predecessor state")
                current_update = decode_multisignature_signed_update(
                    decode_multisignature_envelope(existing_envelope_cbor).signed_update_bytes
                )
                current_payload = decode_provider_payload_dict(current_update[2])
                if not isinstance(current_payload, ProviderPayloadV1):
                    raise ProviderAlreadyWithdrawn("Provider Record is already withdrawn")
                current_owner = bytes(current_update[1][1])
                proposed_owner = bytes(signed_update[1][1])
                if current_owner != proposed_owner:
                    raise ValueError("owner binding mismatch")
                if seq <= int(current_update[3]):
                    raise ValueError("seq must be strictly increasing")
                return ProviderWithdrawnResult(
                    object_hash=provider_payload.object_hash,
                    seq=seq,
                    replacement_object_hash=provider_payload.replacement_object_hash,
                    authorization=self._metadata(state),
                    predecessor_envelope_cbor=existing_envelope_cbor,
                )
            return ProviderOverwriteResult(
                record_key=record_key,
                object_hash_hex=provider_payload.object_hash,
                owner_public_key=bytes(owner_public_key),
                seq=seq,
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

        provider_payload = decode_provider_payload_dict(payload)
        if isinstance(provider_payload, ProviderWithdrawnPayloadV2):
            if existing_envelope_cbor is None:
                raise ValueError("a Provider withdrawal requires an active predecessor state")
            if _is_multisignature_envelope(existing_envelope_cbor):
                existing_state = validate_multisignature_envelope(
                    record_key=record_key, envelope_cbor=existing_envelope_cbor
                )
                if existing_state.owner_public_key != bytes(owner_public_key):
                    raise ValueError("owner binding mismatch")
                existing_update = decode_multisignature_signed_update(
                    existing_state.signed_update_bytes
                )
                existing_payload = decode_provider_payload_dict(existing_update[2])
                if not isinstance(existing_payload, ProviderPayloadV1):
                    raise ProviderAlreadyWithdrawn("Provider Record is already withdrawn")
                if seq <= existing_state.seq:
                    raise ValueError("seq must be strictly increasing")
            else:
                existing_update_bytes, existing_signature = decode_signed_envelope(existing_envelope_cbor)
                existing_update = decode_canonical_signed_update(existing_update_bytes)
                if not verify_ed25519_signature(
                    owner_public_key=bytes(existing_update[1][1]),
                    signed_update_bytes_canonical=existing_update_bytes,
                    signature=existing_signature,
                ) or bytes(existing_update[1][1]) != bytes(owner_public_key):
                    raise ValueError("invalid or mismatched active predecessor owner")
                existing_payload = decode_provider_payload_dict(existing_update[2])
                if not isinstance(existing_payload, ProviderPayloadV1):
                    raise ProviderAlreadyWithdrawn("Provider Record is already withdrawn")
                if existing_payload.object_hash != provider_payload.object_hash:
                    raise ValueError("active predecessor Object Hash does not match")
                if int(seq) <= int(existing_update[3]):
                    raise ValueError("seq must be strictly increasing")
            if bytes.fromhex(provider_payload.object_hash) != record_key:
                raise ValueError("lookup-key mismatch")
        if isinstance(provider_payload, ProviderWithdrawnPayloadV2):
            return ProviderWithdrawnResult(
                object_hash=provider_payload.object_hash,
                seq=seq,
                replacement_object_hash=provider_payload.replacement_object_hash,
                predecessor_envelope_cbor=existing_envelope_cbor,
            )
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
        predecessor_chain: tuple[bytes, ...] | None = None,
    ) -> IdentityOverwriteResult:
        if _is_multisignature_envelope(envelope_cbor):
            state = self._validate_multisignature_transition(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=existing_envelope_cbor,
                predecessor_chain=predecessor_chain,
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
        existing_envelope_cbor: bytes | None = None,
    ) -> ProviderPayloadV1 | ProviderWithdrawnResult | ProviderRecordResult:
        if _is_multisignature_envelope(envelope_cbor):
            signed_update_bytes = decode_multisignature_envelope(
                envelope_cbor
            ).signed_update_bytes
            signed_update = decode_multisignature_signed_update(signed_update_bytes)
            payload = decode_provider_payload_dict(signed_update[2])
            if isinstance(payload, ProviderWithdrawnPayloadV2):
                if existing_envelope_cbor is None:
                    raise ValueError("withdrawn Provider result requires a verified predecessor")
                state = self._validate_multisignature_transition(
                    record_key=record_key,
                    envelope_cbor=envelope_cbor,
                    existing_envelope_cbor=existing_envelope_cbor,
                )
                return ProviderWithdrawnResult(
                    object_hash=payload.object_hash,
                    seq=int(signed_update[3]),
                    replacement_object_hash=payload.replacement_object_hash,
                    authorization=self._metadata(state),
                    predecessor_envelope_cbor=existing_envelope_cbor,
                )
            state = validate_multisignature_envelope(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
            )
            decoded_payload = decode_provider_payload_dict(signed_update[2])
            if not isinstance(decoded_payload, ProviderPayloadV1):
                raise ValueError("invalid Provider Record payload state")
            return ProviderRecordResult(
                payload=decoded_payload,
                seq=int(signed_update[3]),
                authorization=self._metadata(state),
            )

        signed_update_bytes, _signature = decode_signed_envelope(envelope_cbor)
        signed_update = decode_canonical_signed_update(signed_update_bytes)
        payload = decode_provider_payload_dict(signed_update[2])
        if isinstance(payload, ProviderWithdrawnPayloadV2):
            if existing_envelope_cbor is None:
                raise ValueError("withdrawn Provider result requires a verified predecessor")
            return self._validate_legacy_provider_withdrawal(
                record_key=record_key,
                envelope_cbor=envelope_cbor,
                existing_envelope_cbor=existing_envelope_cbor,
            )
        validate_signed_update_overwrite(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=_signature,
            seq_state={},
            update_state_on_success=False,
        )
        return payload

    def _validate_legacy_provider_withdrawal(
        self, *, record_key: bytes, envelope_cbor: bytes, existing_envelope_cbor: bytes | None
    ) -> ProviderWithdrawnResult:
        signed_update_bytes, signature = decode_signed_envelope(envelope_cbor)
        validate_signed_update_overwrite(
            record_key=record_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
            seq_state={},
            update_state_on_success=False,
        )
        signed_update = decode_canonical_signed_update(signed_update_bytes)
        decoded_payload = decode_provider_payload_dict(signed_update[2])
        if not isinstance(decoded_payload, ProviderWithdrawnPayloadV2):
            raise ValueError("expected a Provider v2 tombstone")
        if existing_envelope_cbor is None:
            raise ValueError("withdrawal lookup requires its validated active predecessor")
        existing_update_bytes, existing_signature = decode_signed_envelope(existing_envelope_cbor)
        existing_update = decode_canonical_signed_update(existing_update_bytes)
        if not isinstance(existing_update[1], dict) or 1 not in existing_update[1]:
            raise ValueError("invalid active Provider predecessor")
        existing_owner = bytes(existing_update[1][1])
        tombstone_owner = bytes(signed_update[1][1])
        existing_payload = decode_provider_payload_dict(existing_update[2])
        if isinstance(existing_payload, ProviderWithdrawnPayloadV2):
            raise ProviderAlreadyWithdrawn("Provider Record is already withdrawn")
        if existing_owner != tombstone_owner:
            raise ValueError("withdrawal owner does not match active predecessor")
        if not verify_ed25519_signature(
            owner_public_key=existing_owner,
            signed_update_bytes_canonical=existing_update_bytes,
            signature=existing_signature,
        ):
            raise ValueError("invalid active predecessor signature")
        if not isinstance(existing_payload, ProviderPayloadV1):
            raise ValueError("withdrawal predecessor is not active")
        if existing_payload.object_hash != decoded_payload.object_hash:
            raise ValueError("active predecessor Object Hash does not match")
        if bytes.fromhex(decoded_payload.object_hash) != record_key:
            raise ValueError("lookup-key mismatch")
        if int(signed_update[3]) <= int(existing_update[3]):
            raise ValueError("seq must be strictly increasing")
        return ProviderWithdrawnResult(
            object_hash=decoded_payload.object_hash,
            seq=int(signed_update[3]),
            replacement_object_hash=decoded_payload.replacement_object_hash,
            predecessor_envelope_cbor=existing_envelope_cbor,
        )

    def validate_identity_get(
        self,
        *,
        record_key: bytes,
        envelope_cbor: bytes,
        predecessor_chain: tuple[bytes, ...] | None = None,
    ) -> IdentityOverwriteResult | IdentityRecordResult:
        if _is_multisignature_envelope(envelope_cbor):
            if predecessor_chain is not None:
                self._require_history_ending_at(
                    predecessor_chain=predecessor_chain,
                    envelope_cbor=envelope_cbor,
                    state_label="accepted state",
                )
                state = validate_multisignature_history(
                    record_key=record_key,
                    envelopes=predecessor_chain,
                )
            else:
                state = validate_multisignature_envelope(
                    record_key=record_key,
                    envelope_cbor=envelope_cbor,
                )
            if state.record_kind != RECORD_KIND_IDENTITY:
                raise ValueError("expected an Identity Record")
            if state.history is None:
                raise ValueError(
                    "complete predecessor history is required for Identity state"
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
