from __future__ import annotations

from typing import Any, Mapping

import cbor2


# Version 1 of the explicit-signer authorization wire protocol.
AUTHORIZATION_SCHEME_ED25519 = 1
RECORD_KIND_IDENTITY = 1
RECORD_KIND_PROVIDER = 2
OPERATION_GENESIS = 1
OPERATION_ORDINARY_UPDATE = 2
OPERATION_REPLACE_SIGNERS = 3
OPERATION_UPGRADE = 4

_AUTHORIZATION_KEYS = set(range(1, 8))
_SIGNER_ENTRY_KEYS = {1, 2}


def _require_uint(value: Any, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(f"{name} must be a non-negative integer; got {value!r}")
    return int(value)


def _signer_sort_key(signer_id: str) -> bytes:
    return signer_id.encode("utf-8")


def _validate_signer_entries(
    entries: Any, *, sort_entries: bool, require_sorted: bool
) -> list[dict[int, Any]]:
    if not isinstance(entries, list) or not entries:
        raise ValueError("signer_set must be a non-empty list")

    normalized: list[dict[int, Any]] = []
    seen_ids: set[str] = set()
    seen_keys: set[bytes] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _SIGNER_ENTRY_KEYS:
            raise ValueError("signer entry must be a map with keys {1,2}")
        signer_id = entry[1]
        public_key = entry[2]
        if not isinstance(signer_id, str) or not signer_id:
            raise ValueError("signer_id must be a non-empty text string")
        if len(signer_id.encode("utf-8")) > 256:
            raise ValueError("signer_id must be at most 256 UTF-8 bytes")
        if not isinstance(public_key, (bytes, bytearray)):
            raise TypeError("signer public key must be bytes")
        public_key_bytes = bytes(public_key)
        if len(public_key_bytes) != 32:
            raise ValueError("signer public key must be exactly 32 bytes")
        if signer_id in seen_ids:
            raise ValueError("duplicate signer identifier")
        if public_key_bytes in seen_keys:
            raise ValueError("duplicate public key")
        seen_ids.add(signer_id)
        seen_keys.add(public_key_bytes)
        normalized.append({1: signer_id, 2: public_key_bytes})

    ordered = sorted(normalized, key=lambda item: _signer_sort_key(item[1]))
    if require_sorted and normalized != ordered:
        raise ValueError("signer entries must be canonically ordered")
    return ordered if sort_entries else normalized


def validate_authorization_map(
    authorization: Mapping[int, Any], *, sort_signers: bool = False
) -> dict[int, Any]:
    """Validate and normalize the shared authorization map.

    Wire keys are: 1 scheme, 2 record kind, 3 operation, 4 epoch,
    5 threshold, 6 signer set, and 7 predecessor state hash.
    """
    if not isinstance(authorization, Mapping):
        raise TypeError("authorization must be a CBOR map")
    if set(authorization) != _AUTHORIZATION_KEYS:
        raise ValueError("authorization must contain keys {1,2,3,4,5,6,7}")

    scheme = _require_uint(authorization[1], name="authorization scheme")
    if scheme != AUTHORIZATION_SCHEME_ED25519:
        raise ValueError(f"unsupported authorization scheme: {scheme}")
    record_kind = _require_uint(authorization[2], name="record_kind")
    if record_kind not in {RECORD_KIND_IDENTITY, RECORD_KIND_PROVIDER}:
        raise ValueError(f"unsupported record_kind: {record_kind}")
    operation = _require_uint(authorization[3], name="operation")
    if operation not in {
        OPERATION_GENESIS,
        OPERATION_ORDINARY_UPDATE,
        OPERATION_REPLACE_SIGNERS,
        OPERATION_UPGRADE,
    }:
        raise ValueError(f"unsupported operation: {operation}")
    epoch = _require_uint(authorization[4], name="epoch")
    threshold = _require_uint(authorization[5], name="threshold")
    signer_set = _validate_signer_entries(
        authorization[6],
        sort_entries=sort_signers,
        require_sorted=not sort_signers,
    )
    if threshold < 1 or threshold > len(signer_set):
        raise ValueError("threshold must be between 1 and the signer-set size")
    predecessor = authorization[7]
    if not isinstance(predecessor, (bytes, bytearray)):
        raise TypeError("predecessor_state_hash must be bytes")
    predecessor_bytes = bytes(predecessor)
    if len(predecessor_bytes) != 32:
        raise ValueError("predecessor_state_hash must be exactly 32 bytes")

    return {
        1: scheme,
        2: record_kind,
        3: operation,
        4: epoch,
        5: threshold,
        6: signer_set,
        7: predecessor_bytes,
    }


def canonical_cbor(value: Any) -> bytes:
    """RFC 7049 canonical CBOR (as implemented by cbor2 with canonical=True)."""

    return cbor2.dumps(value, canonical=True)


def is_canonical_cbor(data: bytes) -> bool:
    """Return True iff `data` is valid CBOR and canonical re-encoding matches."""
    try:
        decoded = cbor2.loads(data)
        canonical = cbor2.dumps(decoded, canonical=True)
    except Exception:
        return False
    return canonical == data


def _validate_uint_keys(m: Mapping[int, Any], *, name: str) -> dict[int, Any]:
    out: dict[int, Any] = {}
    for k, v in m.items():
        if isinstance(k, bool) or not isinstance(k, int) or k < 0:
            raise TypeError(f"{name} keys must be non-negative ints; got {k!r}")
        out[int(k)] = v
    return out


def _validate_record_kind_binding(
    *, record_fields: Mapping[int, Any], payload: Mapping[int, Any], record_kind: int
) -> None:
    """Reject a structurally valid authorization map bound to the wrong record."""
    if record_kind == RECORD_KIND_IDENTITY:
        if set(record_fields) != {1, 2} or payload:
            raise ValueError("record_kind identity does not match SignedUpdate")
        if not isinstance(record_fields[1], (bytes, bytearray)):
            raise ValueError("identity owner_name must be bytes")
        if not isinstance(record_fields[2], (bytes, bytearray)):
            raise ValueError("identity owner public key must be bytes")
        if len(record_fields[2]) != 32:
            raise ValueError("identity owner public key must be exactly 32 bytes")
        return

    if record_kind == RECORD_KIND_PROVIDER:
        if set(record_fields) != {1}:
            raise ValueError("record_kind provider does not match SignedUpdate")
        if not isinstance(record_fields[1], (bytes, bytearray)):
            raise ValueError("provider owner public key must be bytes")
        if len(record_fields[1]) != 32:
            raise ValueError("provider owner public key must be exactly 32 bytes")
        # Import lazily because provider_schema imports canonical_cbor from here.
        from decent_registry.provider_schema import decode_provider_payload_dict

        try:
            decode_provider_payload_dict(payload)
        except Exception as exc:
            raise ValueError("record_kind provider does not match SignedUpdate") from exc
        return

    raise ValueError(f"unsupported record_kind: {record_kind}")


def encode_signed_update(
    *,
    record_fields: Mapping[int, Any],
    payload: Mapping[int, Any],
    seq: int,
    authorization: Mapping[int, Any] | None = None,
) -> bytes:
    """Encode a canonical legacy or version-1 multisignature SignedUpdate.

    Legacy SignedUpdate is ``{1: record_fields, 2: payload, 3: seq}``.
    Supplying ``authorization`` adds key 4. The legacy form remains
    byte-for-byte unchanged.
    """
    seq = _require_uint(seq, name="seq")
    rf = _validate_uint_keys(record_fields, name="record_fields")
    pl = _validate_uint_keys(payload, name="payload")

    signed_update: dict[int, Any] = {1: rf, 2: pl, 3: seq}
    if authorization is not None:
        normalized_auth = validate_authorization_map(
            authorization, sort_signers=True
        )
        _validate_record_kind_binding(
            record_fields=rf, payload=pl, record_kind=normalized_auth[2]
        )
        signed_update[4] = normalized_auth
    return canonical_cbor(signed_update)


def encode_multisignature_signed_update(
    *,
    record_fields: Mapping[int, Any],
    payload: Mapping[int, Any],
    seq: int,
    authorization: Mapping[int, Any],
) -> bytes:
    """Encode a version-1 multisignature SignedUpdate explicitly."""
    return encode_signed_update(
        record_fields=record_fields,
        payload=payload,
        seq=seq,
        authorization=authorization,
    )


def _validate_decoded_signed_update(decoded: dict[int, Any]) -> dict[int, Any]:
    if set(decoded) not in ({1, 2, 3}, {1, 2, 3, 4}):
        raise ValueError("SignedUpdate must have keys {1,2,3} or {1,2,3,4}")
    if not isinstance(decoded[1], dict) or not isinstance(decoded[2], dict):
        raise ValueError("SignedUpdate record_fields and payload must be CBOR maps")
    _validate_uint_keys(decoded[1], name="record_fields")
    _validate_uint_keys(decoded[2], name="payload")
    _require_uint(decoded[3], name="seq")
    if 4 in decoded:
        decoded[4] = validate_authorization_map(decoded[4], sort_signers=False)
        _validate_record_kind_binding(
            record_fields=decoded[1],
            payload=decoded[2],
            record_kind=decoded[4][2],
        )
    return decoded


def decode_canonical_signed_update(data: bytes) -> dict[int, Any]:
    """Decode a legacy or multisignature SignedUpdate if canonical."""
    if not isinstance(data, (bytes, bytearray)) or not is_canonical_cbor(bytes(data)):
        raise ValueError("non-canonical or invalid CBOR")

    decoded = cbor2.loads(bytes(data))
    if not isinstance(decoded, dict):
        raise ValueError("SignedUpdate must be a CBOR map")
    return _validate_decoded_signed_update(decoded)


def decode_multisignature_signed_update(data: bytes) -> dict[int, Any]:
    """Decode a canonical SignedUpdate carrying authorization key 4."""
    decoded = decode_canonical_signed_update(data)
    if set(decoded) != {1, 2, 3, 4}:
        raise ValueError("multisignature SignedUpdate requires authorization key 4")
    return decoded
