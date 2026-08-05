from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from decent_registry.encoding import (
    OPERATION_GENESIS,
    RECORD_KIND_IDENTITY,
    RECORD_KIND_PROVIDER,
    encode_multisignature_signed_update,
    decode_multisignature_signed_update,
)
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.signed_envelope import (
    decode_multisignature_envelope,
    encode_multisignature_envelope,
)
from decent_registry.verification import (
    make_signed_update_signature,
    verify_ed25519_signature,
)


_ZERO_STATE_HASH = bytes(32)


def _proof_sort_key(proof: "MultisignatureProof") -> bytes:
    return proof.signer_id.encode("utf-8")


@dataclass(frozen=True, slots=True)
class MultisignatureProof:
    """One detached signature bound to one exact canonical SignedUpdate."""

    signed_update_bytes: bytes
    signer_id: str
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.signed_update_bytes, (bytes, bytearray)):
            raise TypeError("signed_update_bytes must be bytes")
        if not isinstance(self.signer_id, str) or not self.signer_id:
            raise ValueError("proof signer_id must be a non-empty text string")
        if not isinstance(self.signature, (bytes, bytearray)):
            raise TypeError("proof signature must be bytes")
        object.__setattr__(self, "signed_update_bytes", bytes(self.signed_update_bytes))
        object.__setattr__(self, "signature", bytes(self.signature))

    def to_wire(self) -> dict[int, Any]:
        return {1: self.signer_id, 2: self.signature}


@dataclass(frozen=True, slots=True)
class MultisignatureBundle:
    """Immutable local bundle containing canonical update bytes and detached proofs."""

    signed_update_bytes: bytes
    proofs: tuple[MultisignatureProof, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.signed_update_bytes, (bytes, bytearray)):
            raise TypeError("signed_update_bytes must be bytes")
        signed_update = bytes(self.signed_update_bytes)
        decode_multisignature_signed_update(signed_update)
        normalized = tuple(self.proofs)
        if any(not isinstance(proof, MultisignatureProof) for proof in normalized):
            raise TypeError("proofs must contain MultisignatureProof values")
        object.__setattr__(self, "signed_update_bytes", signed_update)
        object.__setattr__(self, "proofs", tuple(sorted(normalized, key=_proof_sort_key)))

    @property
    def signed_update(self) -> dict[int, Any]:
        return decode_multisignature_signed_update(self.signed_update_bytes)

    @property
    def authorization(self) -> dict[int, Any]:
        return self.signed_update[4]

    @property
    def record_kind(self) -> int:
        return self.authorization[2]

    @property
    def threshold(self) -> int:
        return self.authorization[5]

    @property
    def signer_set(self) -> tuple[tuple[str, bytes], ...]:
        return tuple(
            (entry[1], bytes(entry[2])) for entry in self.authorization[6]
        )

    @property
    def signer_ids(self) -> tuple[str, ...]:
        return tuple(signer_id for signer_id, _public_key in self.signer_set)

    def to_cbor(self) -> bytes:
        """Serialize a local, possibly partial, bundle as canonical versioned CBOR."""
        return encode_multisignature_envelope(
            signed_update_bytes=self.signed_update_bytes,
            proofs=[proof.to_wire() for proof in self.proofs],
        )

    @classmethod
    def from_cbor(cls, bundle_cbor: bytes) -> "MultisignatureBundle":
        """Restore a local bundle without treating it as an accepted Registry state."""
        envelope = decode_multisignature_envelope(bundle_cbor)
        return cls(
            signed_update_bytes=envelope.signed_update_bytes,
            proofs=tuple(
                MultisignatureProof(
                    signed_update_bytes=envelope.signed_update_bytes,
                    signer_id=proof[1],
                    signature=proof[2],
                )
                for proof in envelope.proofs
            ),
        )


def _authorization(
    *,
    record_kind: int,
    operation: int,
    epoch: int,
    threshold: int,
    signer_set: Sequence[Mapping[int, Any]],
    predecessor_state_hash: bytes,
) -> dict[int, Any]:
    return {
        1: 1,
        2: record_kind,
        3: operation,
        4: epoch,
        5: threshold,
        6: list(signer_set),
        7: predecessor_state_hash,
    }


def draft_bundle(
    *,
    record_kind: int,
    record_fields: Mapping[int, Any],
    payload: Mapping[int, Any],
    seq: int,
    signer_set: Sequence[Mapping[int, Any]],
    threshold: int = 2,
    epoch: int = 1,
    predecessor_state_hash: bytes = _ZERO_STATE_HASH,
    operation: int = OPERATION_GENESIS,
) -> MultisignatureBundle:
    """Create an unsigned bundle with a complete canonical SignedUpdate."""
    authorization = _authorization(
        record_kind=record_kind,
        operation=operation,
        epoch=epoch,
        threshold=threshold,
        signer_set=signer_set,
        predecessor_state_hash=predecessor_state_hash,
    )
    signed_update_bytes = encode_multisignature_signed_update(
        record_fields=record_fields,
        payload=payload,
        seq=seq,
        authorization=authorization,
    )
    return MultisignatureBundle(signed_update_bytes=signed_update_bytes)


def draft_identity_bundle(
    *,
    owner_name: bytes,
    owner_public_key: bytes,
    seq: int,
    signer_set: Sequence[Mapping[int, Any]],
    threshold: int = 2,
    epoch: int = 1,
    predecessor_state_hash: bytes = _ZERO_STATE_HASH,
    operation: int = OPERATION_GENESIS,
) -> MultisignatureBundle:
    return draft_bundle(
        record_kind=RECORD_KIND_IDENTITY,
        record_fields={1: owner_name, 2: owner_public_key},
        payload={},
        seq=seq,
        signer_set=signer_set,
        threshold=threshold,
        epoch=epoch,
        predecessor_state_hash=predecessor_state_hash,
        operation=operation,
    )


def draft_provider_bundle(
    *,
    object_hash: str,
    provider_url: str,
    endpoints: Sequence[str],
    owner_public_key: bytes,
    seq: int,
    signer_set: Sequence[Mapping[int, Any]],
    threshold: int = 2,
    epoch: int = 1,
    predecessor_state_hash: bytes = _ZERO_STATE_HASH,
    operation: int = OPERATION_GENESIS,
    alg: str = "Ed25519",
    version: int = 1,
) -> MultisignatureBundle:
    payload = build_provider_payload_dict(
        alg=alg,
        version=version,
        object_hash=object_hash,
        provider_url=provider_url,
        endpoints=list(endpoints),
    )
    return draft_bundle(
        record_kind=RECORD_KIND_PROVIDER,
        record_fields={1: owner_public_key},
        payload=payload,
        seq=seq,
        signer_set=signer_set,
        threshold=threshold,
        epoch=epoch,
        predecessor_state_hash=predecessor_state_hash,
        operation=operation,
    )


def _public_key_bytes(private_key: Any) -> bytes:
    try:
        return bytes(private_key.get_public_key().to_bytes())
    except Exception as exc:
        raise TypeError("signer_private_key must be one local Ed25519 private key") from exc


def sign_bundle(
    bundle: MultisignatureBundle, signer_private_key: Any
) -> MultisignatureProof:
    """Sign exact bundle bytes with one local private key and return a detached proof."""
    if not isinstance(bundle, MultisignatureBundle):
        raise TypeError("bundle must be a MultisignatureBundle")
    public_key = _public_key_bytes(signer_private_key)
    signer_id = next(
        (
            signer_id
            for signer_id, member_public_key in bundle.signer_set
            if member_public_key == public_key
        ),
        None,
    )
    if signer_id is None:
        raise ValueError("signer is not a member of the bundle Signer Set")
    signature = make_signed_update_signature(
        signed_update_bytes_canonical=bundle.signed_update_bytes,
        owner_private_key=signer_private_key,
    )
    return MultisignatureProof(
        signed_update_bytes=bundle.signed_update_bytes,
        signer_id=signer_id,
        signature=signature,
    )


def _validate_proof(bundle: MultisignatureBundle, proof: MultisignatureProof) -> None:
    if proof.signed_update_bytes != bundle.signed_update_bytes:
        raise ValueError("proof is not bound to the exact bundle SignedUpdate")
    expected_public_key = dict(bundle.signer_set).get(proof.signer_id)
    if expected_public_key is None:
        raise ValueError("proof signer is not a member of the bundle Signer Set")
    if len(proof.signature) != 64:
        raise ValueError("proof signature is malformed")
    try:
        valid = verify_ed25519_signature(
            owner_public_key=expected_public_key,
            signed_update_bytes_canonical=bundle.signed_update_bytes,
            signature=proof.signature,
        )
    except Exception as exc:
        raise ValueError("proof signature is invalid") from exc
    if not valid:
        raise ValueError("proof signature is invalid")


def merge_proof(
    bundle: MultisignatureBundle, proof: MultisignatureProof
) -> MultisignatureBundle:
    """Verify and merge one detached proof without centralizing private keys."""
    if not isinstance(bundle, MultisignatureBundle):
        raise TypeError("bundle must be a MultisignatureBundle")
    if not isinstance(proof, MultisignatureProof):
        raise TypeError("proof must be a MultisignatureProof")
    if any(existing.signer_id == proof.signer_id for existing in bundle.proofs):
        raise ValueError("duplicate proof signer")
    _validate_proof(bundle, proof)
    return MultisignatureBundle(
        signed_update_bytes=bundle.signed_update_bytes,
        proofs=bundle.proofs + (proof,),
    )


def merge_proofs(
    bundle: MultisignatureBundle, proofs: Sequence[MultisignatureProof]
) -> MultisignatureBundle:
    merged = bundle
    for proof in proofs:
        merged = merge_proof(merged, proof)
    return merged


def finalize_bundle(bundle: MultisignatureBundle) -> bytes:
    """Return a finalized versioned SignedEnvelope only after quorum validation."""
    if not isinstance(bundle, MultisignatureBundle):
        raise TypeError("bundle must be a MultisignatureBundle")
    seen: set[str] = set()
    for proof in bundle.proofs:
        if proof.signer_id in seen:
            raise ValueError("duplicate proof signer")
        seen.add(proof.signer_id)
        _validate_proof(bundle, proof)
    if len(seen) < bundle.threshold:
        raise ValueError("threshold not met")
    return encode_multisignature_envelope(
        signed_update_bytes=bundle.signed_update_bytes,
        proofs=[proof.to_wire() for proof in bundle.proofs],
    )
