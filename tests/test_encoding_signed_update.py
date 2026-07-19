import pytest

import cbor2

from decent_registry.encoding import (
    decode_canonical_signed_update,
    encode_signed_update,
    is_canonical_cbor,
)


def test_is_canonical_rejects_non_canonical_map_key_order():
    # Create a logically-equivalent value whose *bytes* depend on map insertion order
    # (cbor2 canonical=True reorders keys by encoded key bytes).
    record_fields_noncanonical = {2: "b", 1: "a"}
    payload_noncanonical = {10: "x", 0: "y"}

    signed_update_noncanonical = {
        1: record_fields_noncanonical,
        2: payload_noncanonical,
        3: 7,
    }

    noncanonical_bytes = cbor2.dumps(signed_update_noncanonical, canonical=False)
    canonical_bytes = cbor2.dumps(signed_update_noncanonical, canonical=True)

    assert noncanonical_bytes != canonical_bytes

    assert is_canonical_cbor(noncanonical_bytes) is False
    assert is_canonical_cbor(canonical_bytes) is True

    with pytest.raises(ValueError):
        decode_canonical_signed_update(noncanonical_bytes)

    decoded = decode_canonical_signed_update(canonical_bytes)
    assert decoded[3] == 7
    assert decoded[1] == {1: "a", 2: "b"}
    assert decoded[2] == {0: "y", 10: "x"}


def test_encode_signed_update_is_deterministic_for_same_logical_data():
    # Insertion order should not affect canonical signed-bytes.
    record_fields_a = {2: "b", 1: "a"}
    record_fields_b = {1: "a", 2: "b"}

    payload_a = {10: "x", 0: "y"}
    payload_b = {0: "y", 10: "x"}

    a = encode_signed_update(record_fields=record_fields_a, payload=payload_a, seq=42)
    b = encode_signed_update(record_fields=record_fields_b, payload=payload_b, seq=42)

    assert a == b


def test_decode_rejects_invalid_cbOR_bytes():
    assert is_canonical_cbor(b"\xff") is False
    with pytest.raises(ValueError):
        decode_canonical_signed_update(b"\xff")
