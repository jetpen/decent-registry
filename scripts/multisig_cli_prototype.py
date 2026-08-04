#!/usr/bin/env python3
"""Throwaway prototype for issue #91.

This is a local flow simulation, not production protocol code. It demonstrates
how a CLI can draft one canonical SignedUpdate, circulate exact bytes, collect
one detached Ed25519 proof per signer, reject an incomplete bundle, and
finalize a versioned multisignature envelope. It never touches the DHT and it
never prints private key material.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import cbor2
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.encoding import canonical_cbor, is_canonical_cbor
from decent_registry.verification import (
    make_signed_update_signature,
    verify_ed25519_signature,
)

THRESHOLD = 2
RECORD_KIND_IDENTITY = 1
PROTOTYPE_ENVELOPE_VERSION = "multisig-prototype-v1"


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _state_hash(signed_update: bytes) -> bytes:
    return hashlib.sha256(signed_update).digest()


def _public_key_hex(key_pair: Any) -> str:
    return key_pair.public_key.to_bytes().hex()


def _render_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    auth = bundle["authorization"]
    return {
        "phase": bundle["phase"],
        "record_kind": auth["record_kind"],
        "operation": auth["operation"],
        "epoch": auth["epoch"],
        "seq": bundle["seq"],
        "threshold": auth["threshold"],
        "signer_set": auth["signer_set"],
        "predecessor_state_hash": auth["predecessor_state_hash"].hex(),
        "proofs": [
            {
                "signer_id": proof["signer_id"],
                "signature": _b64(proof["signature"]),
            }
            for proof in bundle["proofs"]
        ],
        "signed_update_sha256": _state_hash(bundle["signed_update"]).hex(),
    }


def show(action: str, bundle: dict[str, Any]) -> None:
    print(json.dumps({"action": action, "state": _render_bundle(bundle)}, indent=2))


def draft_bundle(key_pairs: list[Any]) -> dict[str, Any]:
    signer_set = [
        {"signer_id": f"signer-{index}", "public_key": _public_key_hex(key_pair)}
        for index, key_pair in enumerate(key_pairs, start=1)
    ]
    signer_set.sort(key=lambda entry: entry["signer_id"])

    # The exact integer assignments are intentionally not production decisions
    # here. This prototype uses a readable nested map to exercise the agreed
    # invariants: record binding, threshold, epoch, predecessor binding, and
    # the complete signer set are all inside the signed bytes.
    authorization = {
        "record_kind": RECORD_KIND_IDENTITY,
        "operation": "genesis",
        "threshold": THRESHOLD,
        "epoch": 1,
        "predecessor_state_hash": bytes(32),
        "signer_set": signer_set,
    }
    record_fields = {
        1: b"prototype-owner-name",
        2: bytes.fromhex(signer_set[0]["public_key"]),
    }
    signed_update = canonical_cbor(
        {
            1: record_fields,
            2: {},
            3: 1,
            4: authorization,
        }
    )
    return {
        "phase": "draft",
        "signed_update": signed_update,
        "authorization": authorization,
        "seq": 1,
        "proofs": [],
    }


def sign_bundle(bundle: dict[str, Any], signer_id: str, key_pair: Any) -> dict[str, Any]:
    expected_public_key = next(
        entry["public_key"]
        for entry in bundle["authorization"]["signer_set"]
        if entry["signer_id"] == signer_id
    )
    actual_public_key = _public_key_hex(key_pair)
    if actual_public_key != expected_public_key:
        raise ValueError("private key does not match the requested signer_id")

    signature = make_signed_update_signature(
        signed_update_bytes_canonical=bundle["signed_update"],
        owner_private_key=key_pair.private_key,
    )
    return {"signer_id": signer_id, "signature": signature}


def merge_proof(bundle: dict[str, Any], proof: dict[str, Any]) -> None:
    signer_id = proof["signer_id"]
    signer = next(
        (entry for entry in bundle["authorization"]["signer_set"] if entry["signer_id"] == signer_id),
        None,
    )
    if signer is None:
        raise ValueError("proof signer is not a member of the current signer set")
    if any(existing["signer_id"] == signer_id for existing in bundle["proofs"]):
        raise ValueError("duplicate signer proof")

    public_key = bytes.fromhex(signer["public_key"])
    if not verify_ed25519_signature(
        owner_public_key=public_key,
        signed_update_bytes_canonical=bundle["signed_update"],
        signature=proof["signature"],
    ):
        raise ValueError("proof does not verify against the exact bundle bytes")

    bundle["proofs"].append(proof)
    bundle["proofs"].sort(key=lambda item: item["signer_id"])
    bundle["phase"] = "proof-collection"


def finalize_bundle(bundle: dict[str, Any]) -> bytes:
    threshold = bundle["authorization"]["threshold"]
    if len(bundle["proofs"]) < threshold:
        raise ValueError(
            f"threshold not met: {len(bundle['proofs'])} valid proof(s), {threshold} required"
        )

    envelope = {
        1: PROTOTYPE_ENVELOPE_VERSION,
        2: bundle["signed_update"],
        3: [
            {"signer_id": proof["signer_id"], "signature": proof["signature"]}
            for proof in bundle["proofs"]
        ],
    }
    bundle["phase"] = "finalized"
    return canonical_cbor(envelope)


def validate_finalized(envelope_bytes: bytes) -> dict[str, Any]:
    if not is_canonical_cbor(envelope_bytes):
        raise ValueError("finalized envelope is not canonical CBOR")
    envelope = cbor2.loads(envelope_bytes)
    if envelope.get(1) != PROTOTYPE_ENVELOPE_VERSION:
        raise ValueError("unsupported prototype envelope version")

    signed_update = envelope[2]
    if not is_canonical_cbor(signed_update):
        raise ValueError("embedded SignedUpdate is not canonical CBOR")
    update = cbor2.loads(signed_update)
    authorization = update[4]
    signer_by_id = {
        entry["signer_id"]: entry for entry in authorization["signer_set"]
    }
    proofs = envelope[3]
    if len(proofs) < authorization["threshold"]:
        raise ValueError("finalized envelope contains fewer than threshold proofs")

    seen: set[str] = set()
    for proof in proofs:
        signer_id = proof["signer_id"]
        if signer_id in seen:
            raise ValueError("finalized envelope contains duplicate signer proofs")
        seen.add(signer_id)
        signer = signer_by_id.get(signer_id)
        if signer is None:
            raise ValueError("finalized envelope contains a non-member proof")
        if not verify_ed25519_signature(
            owner_public_key=bytes.fromhex(signer["public_key"]),
            signed_update_bytes_canonical=signed_update,
            signature=proof["signature"],
        ):
            raise ValueError("finalized envelope contains an invalid proof")

    return {
        "record_kind": authorization["record_kind"],
        "operation": authorization["operation"],
        "epoch": authorization["epoch"],
        "seq": update[3],
        "valid_proofs": len(proofs),
        "threshold": authorization["threshold"],
    }


def main() -> None:
    key_pairs = [create_new_key_pair() for _ in range(3)]
    bundle = draft_bundle(key_pairs)
    show("draft", bundle)

    proof_1 = sign_bundle(bundle, "signer-1", key_pairs[0])
    merge_proof(bundle, proof_1)
    show("merge signer-1 proof", bundle)

    print(json.dumps({"action": "finalize incomplete bundle", "result": "rejected", "reason": "threshold not met"}))
    try:
        finalize_bundle(bundle)
    except ValueError as error:
        print(json.dumps({"validation_error": str(error)}))

    proof_2 = sign_bundle(bundle, "signer-2", key_pairs[1])
    merge_proof(bundle, proof_2)
    show("merge signer-2 proof", bundle)

    envelope = finalize_bundle(bundle)
    show("finalize", bundle)
    print(json.dumps({"action": "validate finalized envelope", "result": validate_finalized(envelope)}, indent=2))
    print(json.dumps({"action": "put", "result": "not executed: prototype does not contact the DHT"}))


if __name__ == "__main__":
    main()
