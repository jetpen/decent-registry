from __future__ import annotations

from typing import Any, Tuple

import cbor2

from decent_registry.encoding import is_canonical_cbor


def encode_signed_envelope(*, signed_update_bytes: bytes, signature: bytes) -> bytes:
    """Canonical CBOR envelope.

    Envelope = {1: signed_update_bytes, 2: signature}
    """

    if not isinstance(signed_update_bytes, (bytes, bytearray)):
        raise TypeError("signed_update_bytes must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes")

    envelope = {1: bytes(signed_update_bytes), 2: bytes(signature)}
    return cbor2.dumps(envelope, canonical=True)


def decode_signed_envelope(envelope_cbor: bytes) -> Tuple[bytes, bytes]:
    if not is_canonical_cbor(envelope_cbor):
        raise ValueError("non-canonical or invalid signed envelope")

    decoded: Any = cbor2.loads(envelope_cbor)
    if not isinstance(decoded, dict):
        raise ValueError("signed envelope must be a CBOR map")

    if set(decoded.keys()) != {1, 2}:
        raise ValueError("signed envelope must contain keys {1,2}")

    signed_update_bytes = decoded[1]
    signature = decoded[2]

    if not isinstance(signed_update_bytes, (bytes, bytearray)):
        raise ValueError("signed_update_bytes must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("signature must be bytes")

    return bytes(signed_update_bytes), bytes(signature)
