from __future__ import annotations

from typing import Any, Mapping

import cbor2


def canonical_cbor(value: Any) -> bytes:
    """RFC 7049 canonical CBOR (as implemented by cbor2 with canonical=True)."""

    return cbor2.dumps(value, canonical=True)


def is_canonical_cbor(data: bytes) -> bool:
    """Return True iff `data` is valid CBOR and re-encoding it canonically yields
    identical bytes.

    This rejects non-canonical encodings even when they decode to the same
    logical value.
    """

    try:
        decoded = cbor2.loads(data)
    except Exception:
        return False

    try:
        canonical = cbor2.dumps(decoded, canonical=True)
    except Exception:
        return False

    return canonical == data


def _validate_uint_keys(m: Mapping[int, Any], *, name: str) -> dict[int, Any]:
    out: dict[int, Any] = {}
    for k, v in m.items():
        if not isinstance(k, int) or k < 0:
            raise TypeError(f"{name} keys must be non-negative ints; got {k!r}")
        out[int(k)] = v
    return out


def encode_signed_update(
    *,
    record_fields: Mapping[int, Any],
    payload: Mapping[int, Any],
    seq: int,
) -> bytes:
    """Encode SignedUpdate for signature digest input.

    SignedUpdate = {1: record_fields(map<uint,any>), 2: payload(map<uint,any>), 3: seq(uint)}
    encoded as canonical CBOR.
    """

    if not isinstance(seq, int) or seq < 0:
        raise TypeError(f"seq must be a non-negative int; got {seq!r}")

    rf = _validate_uint_keys(record_fields, name="record_fields")
    pl = _validate_uint_keys(payload, name="payload")

    signed_update = {1: rf, 2: pl, 3: int(seq)}
    return canonical_cbor(signed_update)


def decode_canonical_signed_update(data: bytes) -> dict[int, Any]:
    """Decode SignedUpdate only if `data` is canonical CBOR."""

    if not is_canonical_cbor(data):
        raise ValueError("non-canonical or invalid CBOR")

    decoded = cbor2.loads(data)
    if not isinstance(decoded, dict):
        raise ValueError("SignedUpdate must be a CBOR map")
    return decoded
