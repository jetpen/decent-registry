from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Tuple

import cbor2

from decent_registry.encoding import (
    decode_multisignature_signed_update,
    is_canonical_cbor,
)


MULTISIG_ENVELOPE_VERSION = 1
_PROOF_KEYS = {1, 2}


def _proof_sort_key(proof: Mapping[int, Any]) -> bytes:
    return proof[1].encode("utf-8")


def _validate_proofs(
    proofs: Any, *, sort_proofs: bool, require_sorted: bool
) -> list[dict[int, Any]]:
    if not isinstance(proofs, list):
        raise TypeError("proofs must be a CBOR array")

    normalized: list[dict[int, Any]] = []
    seen: set[str] = set()
    for proof in proofs:
        if not isinstance(proof, dict) or set(proof) != _PROOF_KEYS:
            raise ValueError("proof must be a map with keys {1,2}")
        signer_id = proof[1]
        signature = proof[2]
        if not isinstance(signer_id, str) or not signer_id:
            raise ValueError("proof signer_id must be a non-empty text string")
        if len(signer_id.encode("utf-8")) > 256:
            raise ValueError("proof signer_id must be at most 256 UTF-8 bytes")
        if signer_id in seen:
            raise ValueError("duplicate proof signer identifier")
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("proof signature must be bytes")
        signature_bytes = bytes(signature)
        if len(signature_bytes) != 64:
            raise ValueError("proof signature must be exactly 64 bytes")
        seen.add(signer_id)
        normalized.append({1: signer_id, 2: signature_bytes})

    ordered = sorted(normalized, key=_proof_sort_key)
    if require_sorted and normalized != ordered:
        raise ValueError("proofs must be canonically ordered")
    return ordered if sort_proofs else normalized


@dataclass(frozen=True, slots=True)
class MultisignatureEnvelope:
    version: int
    signed_update_bytes: bytes
    proofs: tuple[dict[int, Any], ...]


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

    # Keep the legacy decoder from silently accepting a multisignature
    # SignedUpdate inside the legacy envelope shape. Malformed legacy
    # SignedUpdate bytes remain the responsibility of the legacy validator.
    try:
        nested_update = cbor2.loads(bytes(signed_update_bytes))
    except Exception:
        nested_update = None
    if isinstance(nested_update, dict) and 4 in nested_update:
        raise ValueError("legacy envelope cannot carry multisignature SignedUpdate")

    return bytes(signed_update_bytes), bytes(signature)


def encode_multisignature_envelope(
    *,
    signed_update_bytes: bytes,
    proofs: list[Mapping[int, Any]],
    version: int = MULTISIG_ENVELOPE_VERSION,
    sort_proofs: bool = True,
) -> bytes:
    """Encode the versioned multisignature SignedEnvelope.

    Version 1 is ``{1: version, 2: signed_update_bytes, 3: proofs}``.
    The embedded SignedUpdate must contain authorization key 4. Proofs are
    sorted by signer identifier for deterministic wire bytes.
    """
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("envelope version must be an integer")
    if version != MULTISIG_ENVELOPE_VERSION:
        raise ValueError(f"unsupported envelope version: {version}")
    if not isinstance(signed_update_bytes, (bytes, bytearray)):
        raise TypeError("signed_update_bytes must be bytes")
    signed_update = bytes(signed_update_bytes)
    decode_multisignature_signed_update(signed_update)
    normalized_proofs = _validate_proofs(
        proofs,
        sort_proofs=sort_proofs,
        require_sorted=not sort_proofs,
    )
    return cbor2.dumps(
        {1: version, 2: signed_update, 3: normalized_proofs}, canonical=True
    )


def decode_multisignature_envelope(
    envelope_cbor: bytes,
) -> MultisignatureEnvelope:
    """Decode and validate a canonical versioned multisignature envelope."""
    if not isinstance(envelope_cbor, (bytes, bytearray)) or not is_canonical_cbor(
        bytes(envelope_cbor)
    ):
        raise ValueError("non-canonical or invalid multisignature envelope")
    decoded: Any = cbor2.loads(bytes(envelope_cbor))
    if not isinstance(decoded, dict) or set(decoded) != {1, 2, 3}:
        raise ValueError("multisignature envelope must contain keys {1,2,3}")
    version = decoded[1]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("envelope version must be an integer")
    if version != MULTISIG_ENVELOPE_VERSION:
        raise ValueError(f"unsupported envelope version: {version}")
    signed_update_bytes = decoded[2]
    if not isinstance(signed_update_bytes, (bytes, bytearray)):
        raise ValueError("signed_update_bytes must be bytes")
    signed_update = bytes(signed_update_bytes)
    decode_multisignature_signed_update(signed_update)
    proofs = _validate_proofs(
        decoded[3], sort_proofs=False, require_sorted=True
    )
    return MultisignatureEnvelope(
        version=version,
        signed_update_bytes=signed_update,
        proofs=tuple(proofs),
    )


# Explicit aliases keep the protocol name discoverable without changing the
# legacy encode_signed_envelope/decode_signed_envelope API.
encode_versioned_signed_envelope = encode_multisignature_envelope
decode_versioned_signed_envelope = decode_multisignature_envelope
