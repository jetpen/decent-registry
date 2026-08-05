from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, MutableMapping

from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import (
    OPERATION_GENESIS,
    OPERATION_ORDINARY_UPDATE,
    OPERATION_REPLACE_SIGNERS,
    OPERATION_UPGRADE,
    RECORD_KIND_IDENTITY,
    RECORD_KIND_PROVIDER,
    decode_canonical_signed_update,
    decode_multisignature_signed_update,
)
from decent_registry.provider_schema import decode_provider_payload_dict
from decent_registry.signed_envelope import (
    MultisignatureEnvelope,
    decode_multisignature_envelope,
    decode_signed_envelope,
)


@dataclass
class SeqStateEntry:
    owner_public_key: bytes
    seq: int


@dataclass(frozen=True, slots=True)
class MultisignatureState:
    """Accepted state needed to validate the next multisignature update."""

    record_key: bytes
    record_kind: int
    signed_update_bytes: bytes
    state_hash: bytes
    epoch: int
    seq: int
    threshold: int
    signer_set: tuple[tuple[str, bytes], ...]

    @classmethod
    def from_envelope(
        cls, *, record_key: bytes, envelope_cbor: bytes
    ) -> "MultisignatureState":
        (
            signed_update_bytes,
            _envelope,
            _signed_update,
            _record_fields,
            _payload,
            _seq,
            _derived_record_key,
            authorization,
        ) = _decode_multisignature_candidate(envelope_cbor)
        if _derived_record_key != record_key:
            raise ValueError("lookup-key mismatch")
        return cls(
            record_key=bytes(record_key),
            record_kind=authorization[2],
            signed_update_bytes=signed_update_bytes,
            state_hash=_sha256(signed_update_bytes),
            epoch=authorization[4],
            seq=_seq,
            threshold=authorization[5],
            signer_set=_signer_tuple(authorization),
        )


# Cache the concrete Ed25519 public key class (the one libp2p returns).
_PUBKEY_CLS = type(create_new_key_pair().public_key)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def multisignature_state_hash(signed_update_bytes: bytes) -> bytes:
    """Hash one canonical SignedUpdate to bind the next predecessor state."""
    if not isinstance(signed_update_bytes, (bytes, bytearray)):
        raise TypeError("signed_update_bytes must be bytes")
    signed_update = bytes(signed_update_bytes)
    decode_multisignature_signed_update(signed_update)
    return _sha256(signed_update)


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


def _signer_tuple(authorization: dict[int, Any]) -> tuple[tuple[str, bytes], ...]:
    return tuple(
        (entry[1], bytes(entry[2]))
        for entry in authorization[6]
    )


def _decode_multisignature_candidate(
    envelope_cbor: bytes,
) -> tuple[
    bytes,
    MultisignatureEnvelope,
    dict[int, Any],
    dict[int, Any],
    dict[int, Any],
    int,
    bytes,
    dict[int, Any],
]:
    envelope = decode_multisignature_envelope(envelope_cbor)
    signed_update_bytes = envelope.signed_update_bytes
    signed_update = decode_multisignature_signed_update(signed_update_bytes)
    record_fields = signed_update[1]
    payload = signed_update[2]
    seq = signed_update[3]
    authorization = signed_update[4]

    if authorization[2] == RECORD_KIND_IDENTITY:
        derived_record_key, _owner_public_key = _extract_identity_and_keys(
            record_fields=record_fields,
            payload=payload,
        )
    elif authorization[2] == RECORD_KIND_PROVIDER:
        derived_record_key, _owner_public_key = _extract_provider_and_keys(
            record_fields=record_fields,
            payload=payload,
        )
    else:
        raise ValueError("unsupported record kind")

    return (
        signed_update_bytes,
        envelope,
        signed_update,
        record_fields,
        payload,
        seq,
        derived_record_key,
        authorization,
    )


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


def _candidate_state(
    *,
    record_key: bytes,
    parsed: tuple[
        bytes,
        MultisignatureEnvelope,
        dict[int, Any],
        dict[int, Any],
        dict[int, Any],
        int,
        bytes,
        dict[int, Any],
    ],
) -> MultisignatureState:
    return MultisignatureState(
        record_key=bytes(record_key),
        record_kind=parsed[7][2],
        signed_update_bytes=parsed[0],
        state_hash=_sha256(parsed[0]),
        epoch=parsed[7][4],
        seq=parsed[5],
        threshold=parsed[7][5],
        signer_set=_signer_tuple(parsed[7]),
    )


def _require_complete_2_of_3(authorization: dict[int, Any]) -> None:
    if authorization[5] != 2 or len(authorization[6]) != 3:
        raise ValueError("complete 2-of-3 Signer Set required")


def _validate_threshold_proofs(
    *,
    signed_update_bytes: bytes,
    envelope: MultisignatureEnvelope,
    signer_set: tuple[tuple[str, bytes], ...],
    threshold: int,
) -> None:
    expected = dict(signer_set)
    if len(envelope.proofs) < threshold:
        raise ValueError("insufficient quorum")

    seen: set[str] = set()
    for proof in envelope.proofs:
        signer_id = proof[1]
        if signer_id in seen:
            raise ValueError("duplicate proof signer")
        seen.add(signer_id)
        public_key = expected.get(signer_id)
        if public_key is None:
            raise ValueError("proof is not from current Signer Set")
        try:
            valid = verify_ed25519_signature(
                owner_public_key=public_key,
                signed_update_bytes_canonical=signed_update_bytes,
                signature=proof[2],
            )
        except Exception as exc:
            raise ValueError("invalid proof signature") from exc
        if not valid:
            raise ValueError("invalid proof signature")

    if len(seen) < threshold:
        raise ValueError("insufficient quorum")


def _validate_common_transition(
    *,
    record_key: bytes,
    parsed: tuple[
        bytes,
        MultisignatureEnvelope,
        dict[int, Any],
        dict[int, Any],
        dict[int, Any],
        int,
        bytes,
        dict[int, Any],
    ],
    current_state: MultisignatureState,
) -> None:
    if parsed[6] != record_key or current_state.record_key != record_key:
        raise ValueError("lookup-key mismatch")
    authorization = parsed[7]
    if authorization[2] != current_state.record_kind:
        raise ValueError("wrong record kind")
    if parsed[5] <= current_state.seq:
        raise ValueError("seq must be strictly increasing")
    if authorization[7] != current_state.state_hash:
        raise ValueError("predecessor state mismatch")


def validate_multisignature_genesis(
    *, record_key: bytes, envelope_cbor: bytes
) -> MultisignatureState:
    parsed = _decode_multisignature_candidate(envelope_cbor)
    authorization = parsed[7]
    if authorization[3] != OPERATION_GENESIS:
        raise ValueError("expected genesis operation")
    if authorization[4] != 1:
        raise ValueError("genesis epoch must be 1")
    if authorization[7] != bytes(32):
        raise ValueError("genesis predecessor must be zero")
    if parsed[6] != record_key:
        raise ValueError("lookup-key mismatch")
    _require_complete_2_of_3(authorization)
    _validate_threshold_proofs(
        signed_update_bytes=parsed[0],
        envelope=parsed[1],
        signer_set=_signer_tuple(authorization),
        threshold=authorization[5],
    )
    return _candidate_state(record_key=record_key, parsed=parsed)


def validate_multisignature_ordinary_update(
    *, record_key: bytes, envelope_cbor: bytes, current_state: MultisignatureState
) -> MultisignatureState:
    parsed = _decode_multisignature_candidate(envelope_cbor)
    authorization = parsed[7]
    if authorization[3] != OPERATION_ORDINARY_UPDATE:
        raise ValueError("expected ordinary update operation")
    _validate_common_transition(
        record_key=record_key,
        parsed=parsed,
        current_state=current_state,
    )
    if authorization[4] != current_state.epoch:
        raise ValueError("epoch does not match current state")
    if authorization[5] != current_state.threshold:
        raise ValueError("signer set threshold changed during ordinary update")
    if _signer_tuple(authorization) != current_state.signer_set:
        raise ValueError("signer set must remain unchanged")
    _validate_threshold_proofs(
        signed_update_bytes=parsed[0],
        envelope=parsed[1],
        signer_set=current_state.signer_set,
        threshold=current_state.threshold,
    )
    return _candidate_state(record_key=record_key, parsed=parsed)


def validate_multisignature_signer_replacement(
    *, record_key: bytes, envelope_cbor: bytes, current_state: MultisignatureState
) -> MultisignatureState:
    parsed = _decode_multisignature_candidate(envelope_cbor)
    authorization = parsed[7]
    if authorization[3] != OPERATION_REPLACE_SIGNERS:
        raise ValueError("expected signer replacement operation")
    _validate_common_transition(
        record_key=record_key,
        parsed=parsed,
        current_state=current_state,
    )
    if authorization[4] <= current_state.epoch:
        raise ValueError("replacement epoch must increase")
    _require_complete_2_of_3(authorization)
    if _signer_tuple(authorization) == current_state.signer_set:
        raise ValueError("signer replacement must install a new signer set")
    _validate_threshold_proofs(
        signed_update_bytes=parsed[0],
        envelope=parsed[1],
        signer_set=current_state.signer_set,
        threshold=current_state.threshold,
    )
    return _candidate_state(record_key=record_key, parsed=parsed)


def _decode_legacy_state(
    *, record_key: bytes, envelope_cbor: bytes
) -> tuple[bytes, dict[int, Any], dict[int, Any], int, int, bytes]:
    signed_update_bytes, signature = decode_signed_envelope(envelope_cbor)
    signed_update = decode_canonical_signed_update(signed_update_bytes)
    if set(signed_update) != {1, 2, 3}:
        raise ValueError("legacy owner state must use the legacy SignedUpdate shape")
    record_fields = signed_update[1]
    payload = signed_update[2]
    seq = signed_update[3]
    try:
        record_key_from_update, owner_public_key = _extract_identity_and_keys(
            record_fields=record_fields,
            payload=payload,
        )
        record_kind = RECORD_KIND_IDENTITY
    except ValueError:
        record_key_from_update, owner_public_key = _extract_provider_and_keys(
            record_fields=record_fields,
            payload=payload,
        )
        record_kind = RECORD_KIND_PROVIDER
    if record_key_from_update != record_key:
        raise ValueError("legacy lookup-key mismatch")
    try:
        valid = verify_ed25519_signature(
            owner_public_key=owner_public_key,
            signed_update_bytes_canonical=signed_update_bytes,
            signature=signature,
        )
    except Exception as exc:
        raise ValueError("invalid legacy owner signature") from exc
    if not valid:
        raise ValueError("invalid legacy owner signature")
    return (
        signed_update_bytes,
        record_fields,
        payload,
        seq,
        record_kind,
        owner_public_key,
    )


def validate_multisignature_upgrade(
    *, record_key: bytes, envelope_cbor: bytes, legacy_envelope_cbor: bytes
) -> MultisignatureState:
    parsed = _decode_multisignature_candidate(envelope_cbor)
    authorization = parsed[7]
    if authorization[3] != OPERATION_UPGRADE:
        raise ValueError("expected upgrade operation")
    (
        legacy_signed_update,
        legacy_record_fields,
        _legacy_payload,
        legacy_seq,
        legacy_record_kind,
        legacy_owner_public_key,
    ) = _decode_legacy_state(
        record_key=record_key,
        envelope_cbor=legacy_envelope_cbor,
    )
    if parsed[6] != record_key:
        raise ValueError("lookup-key mismatch")
    if authorization[2] != legacy_record_kind:
        raise ValueError("wrong record kind")
    if parsed[5] <= legacy_seq:
        raise ValueError("seq must be strictly increasing")
    if authorization[4] != 1:
        raise ValueError("upgrade epoch must be 1")
    if authorization[7] != _sha256(legacy_signed_update):
        raise ValueError("predecessor state mismatch")
    _require_complete_2_of_3(authorization)

    if legacy_record_kind == RECORD_KIND_IDENTITY:
        if parsed[3].get(2) != legacy_record_fields.get(2):
            raise ValueError("legacy owner binding changed during upgrade")
    else:
        if parsed[3].get(1) != legacy_record_fields.get(1):
            raise ValueError("legacy owner binding changed during upgrade")

    if len(parsed[1].proofs) != 1:
        raise ValueError("upgrade requires one legacy owner proof")
    legacy_proof = parsed[1].proofs[0]
    try:
        valid = verify_ed25519_signature(
            owner_public_key=legacy_owner_public_key,
            signed_update_bytes_canonical=parsed[0],
            signature=legacy_proof[2],
        )
    except Exception as exc:
        raise ValueError("invalid legacy owner proof") from exc
    if not valid:
        raise ValueError("invalid legacy owner proof")
    return _candidate_state(record_key=record_key, parsed=parsed)


def validate_multisignature_update(
    *,
    record_key: bytes,
    envelope_cbor: bytes,
    current_state: MultisignatureState | None = None,
    legacy_envelope_cbor: bytes | None = None,
) -> MultisignatureState:
    """Validate one explicit-signer state transition and return its state."""
    parsed = _decode_multisignature_candidate(envelope_cbor)
    operation = parsed[7][3]
    if operation == OPERATION_GENESIS:
        if current_state is not None or legacy_envelope_cbor is not None:
            raise ValueError("genesis cannot extend an existing state")
        return validate_multisignature_genesis(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
        )
    if operation == OPERATION_UPGRADE:
        if legacy_envelope_cbor is None or current_state is not None:
            raise ValueError(
                "current multisignature state or legacy owner state is required"
            )
        return validate_multisignature_upgrade(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
            legacy_envelope_cbor=legacy_envelope_cbor,
        )
    if current_state is None:
        raise ValueError("current multisignature state is required")
    if legacy_envelope_cbor is not None:
        raise ValueError("legacy state is only valid for an upgrade")
    if operation == OPERATION_ORDINARY_UPDATE:
        return validate_multisignature_ordinary_update(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
            current_state=current_state,
        )
    if operation == OPERATION_REPLACE_SIGNERS:
        return validate_multisignature_signer_replacement(
            record_key=record_key,
            envelope_cbor=envelope_cbor,
            current_state=current_state,
        )
    raise ValueError(f"unsupported multisignature operation: {operation}")


# Short aliases keep the state-machine entry points discoverable.
validate_multisig_update = validate_multisignature_update
validate_multisig_genesis = validate_multisignature_genesis
validate_multisig_upgrade = validate_multisignature_upgrade
validate_multisig_signer_replacement = validate_multisignature_signer_replacement
