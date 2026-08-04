from __future__ import annotations

import cbor2
import pytest

from decent_registry.encoding import (
    AUTHORIZATION_SCHEME_ED25519,
    OPERATION_ORDINARY_UPDATE,
    RECORD_KIND_IDENTITY,
    RECORD_KIND_PROVIDER,
    decode_multisignature_signed_update,
    encode_signed_update,
)
from decent_registry.signed_envelope import (
    MULTISIG_ENVELOPE_VERSION,
    MultisignatureEnvelope,
    decode_multisignature_envelope,
    decode_signed_envelope,
    encode_multisignature_envelope,
    encode_signed_envelope,
)


KEY_A = bytes(range(32))
KEY_B = bytes(range(1, 33))
KEY_C = bytes(range(2, 34))
HASH = bytes(range(32, 64))
SIG_A = bytes(range(64))
SIG_B = bytes(range(1, 65))


def authorization() -> dict[int, object]:
    return {
        1: AUTHORIZATION_SCHEME_ED25519,
        2: RECORD_KIND_IDENTITY,
        3: OPERATION_ORDINARY_UPDATE,
        4: 7,
        5: 2,
        6: [
            {1: "signer-c", 2: KEY_C},
            {1: "signer-a", 2: KEY_A},
            {1: "signer-b", 2: KEY_B},
        ],
        7: HASH,
    }


def provider_payload() -> dict[int, object]:
    return {
        1: "Ed25519",
        2: 1,
        3: "ab" * 32,
        4: "https://example.com/object",
        5: ["/ip4/127.0.0.1/tcp/9000"],
    }


def provider_authorization() -> dict[int, object]:
    auth = authorization()
    auth[2] = RECORD_KIND_PROVIDER
    return auth


def test_multisig_signed_update_canonicalizes_signer_set_and_round_trips():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )

    assert signed_update == cbor2.dumps(cbor2.loads(signed_update), canonical=True)
    decoded = decode_multisignature_signed_update(signed_update)
    assert decoded[3] == 8
    assert decoded[4][6] == [
        {1: "signer-a", 2: KEY_A},
        {1: "signer-b", 2: KEY_B},
        {1: "signer-c", 2: KEY_C},
    ]


def test_record_kind_binding_covers_identity_and_provider_records():
    identity_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    provider_update = encode_signed_update(
        record_fields={1: KEY_A},
        payload=provider_payload(),
        seq=8,
        authorization=provider_authorization(),
    )

    assert decode_multisignature_signed_update(identity_update)[4][2] == RECORD_KIND_IDENTITY
    assert decode_multisignature_signed_update(provider_update)[4][2] == RECORD_KIND_PROVIDER

    with pytest.raises(ValueError, match="record_kind"):
        encode_signed_update(
            record_fields={1: b"owner-name", 2: KEY_A},
            payload={},
            seq=8,
            authorization=provider_authorization(),
        )
    with pytest.raises(ValueError, match="record_kind"):
        encode_signed_update(
            record_fields={1: KEY_A},
            payload=provider_payload(),
            seq=8,
            authorization=authorization(),
        )


def test_versioned_multisignature_envelope_round_trip_preserves_signed_bytes():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    envelope = encode_multisignature_envelope(
        signed_update_bytes=signed_update,
        proofs=[{1: "signer-b", 2: SIG_B}, {1: "signer-a", 2: SIG_A}],
    )

    decoded = decode_multisignature_envelope(envelope)
    assert isinstance(decoded, MultisignatureEnvelope)
    assert decoded.version == MULTISIG_ENVELOPE_VERSION
    assert decoded.signed_update_bytes == signed_update
    assert decoded.proofs == (
        {1: "signer-a", 2: SIG_A},
        {1: "signer-b", 2: SIG_B},
    )
    assert encode_multisignature_envelope(
        signed_update_bytes=decoded.signed_update_bytes,
        proofs=list(decoded.proofs),
    ) == envelope


def test_provider_multisignature_envelope_round_trip_preserves_signed_bytes():
    signed_update = encode_signed_update(
        record_fields={1: KEY_A},
        payload=provider_payload(),
        seq=8,
        authorization=provider_authorization(),
    )
    envelope = encode_multisignature_envelope(
        signed_update_bytes=signed_update,
        proofs=[{1: "signer-a", 2: SIG_A}],
    )
    assert signed_update.hex() == (
        "a401a1015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "02a501674564323535313902010378406162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616204781a68747470733a2f2f6578616d706c652e636f6d2f6f626a6563740581772f6970342f3132372e302e302e312f7463702f39303030030804a7010102020302040705020683"
        "a201687369676e65722d61025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "a201687369676e65722d620258200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "20a201687369676e65722d6302582002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        "21075820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )
    assert envelope.hex() == (
        "a301010259016aa401a1015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "02a501674564323535313902010378406162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616204781a68747470733a2f2f6578616d706c652e636f6d2f6f626a6563740581772f6970342f3132372e302e302e312f7463702f39303030030804a7010102020302040705020683"
        "a201687369676e65722d61025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "a201687369676e65722d620258200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "20a201687369676e65722d6302582002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        "21075820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0381a201687369676e65722d61025840000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    )

    decoded = decode_multisignature_envelope(envelope)
    assert decoded.signed_update_bytes == signed_update
    assert decode_multisignature_signed_update(decoded.signed_update_bytes)[4][2] == RECORD_KIND_PROVIDER
    assert encode_multisignature_envelope(
        signed_update_bytes=decoded.signed_update_bytes,
        proofs=list(decoded.proofs),
    ) == envelope


def test_legacy_envelope_shape_is_not_reinterpreted_by_multisig_decoder():
    signed_update = encode_signed_update(record_fields={1: KEY_A}, payload={}, seq=1)
    legacy_like = cbor2.dumps({1: signed_update, 2: SIG_A}, canonical=True)

    with pytest.raises(ValueError, match="keys"):
        decode_multisignature_envelope(legacy_like)
    assert decode_signed_envelope(legacy_like) == (signed_update, SIG_A)
    assert encode_signed_envelope(
        signed_update_bytes=signed_update, signature=SIG_A
    ) == legacy_like


def test_multisig_decoder_rejects_noncanonical_signed_update_and_envelope():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    noncanonical_update = cbor2.dumps(cbor2.loads(signed_update), canonical=False)
    if noncanonical_update == signed_update:
        noncanonical_update = cbor2.dumps(
            {4: cbor2.loads(signed_update)[4], 3: 8, 2: {}, 1: {2: KEY_A, 1: b"owner-name"}},
            canonical=False,
        )
    with pytest.raises(ValueError, match="canonical"):
        decode_multisignature_signed_update(noncanonical_update)

    envelope = cbor2.dumps({1: 1, 2: signed_update, 3: []}, canonical=True)
    noncanonical_envelope = cbor2.dumps(cbor2.loads(envelope), canonical=False)
    if noncanonical_envelope == envelope:
        noncanonical_envelope = cbor2.dumps(
            {3: [], 2: signed_update, 1: 1}, canonical=False
        )
    with pytest.raises(ValueError, match="canonical"):
        decode_multisignature_envelope(noncanonical_envelope)


def test_schema_rejects_duplicate_ids_duplicate_keys_bad_threshold_and_bad_keys():
    cases = [
        ({**authorization(), 5: 4}, "threshold"),
        (
            {
                **authorization(),
                6: [{1: "same", 2: KEY_A}, {1: "same", 2: KEY_B}],
            },
            "duplicate signer identifier",
        ),
        (
            {
                **authorization(),
                6: [{1: "a", 2: KEY_A}, {1: "b", 2: KEY_A}],
            },
            "duplicate public key",
        ),
        ({**authorization(), 6: [{1: "a", 2: b"short"}]}, "public key"),
        ({**authorization(), 7: b"short"}, "predecessor"),
        ({**authorization(), 1: 99}, "scheme"),
        ({**authorization(), 2: 99}, "record_kind"),
    ]

    for bad_auth, message in cases:
        with pytest.raises((TypeError, ValueError), match=message):
            encode_signed_update(
                record_fields={1: b"owner-name", 2: KEY_A},
                payload={},
                seq=8,
                authorization=bad_auth,
            )


def test_decoder_rejects_unsupported_scheme_and_malformed_proofs():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    bad_authorization = cbor2.loads(signed_update)[4]
    bad_authorization[1] = 99
    bad_update = cbor2.dumps(
        {1: {1: b"owner-name", 2: KEY_A}, 2: {}, 3: 8, 4: bad_authorization},
        canonical=True,
    )
    with pytest.raises(ValueError, match="scheme"):
        decode_multisignature_signed_update(bad_update)

    bad_proof_map = cbor2.dumps(
        {1: 1, 2: signed_update, 3: [{1: "signer-a", 2: "not-bytes"}]},
        canonical=True,
    )
    with pytest.raises((TypeError, ValueError), match="signature"):
        decode_multisignature_envelope(bad_proof_map)

    wrong_proof_keys = cbor2.dumps(
        {1: 1, 2: signed_update, 3: [{1: "signer-a", 3: SIG_A}]},
        canonical=True,
    )
    with pytest.raises(ValueError, match="proof"):
        decode_multisignature_envelope(wrong_proof_keys)


def test_schema_rejects_malformed_authorization_maps_and_threshold_edges():
    malformed_authorizations = [
        ({key: value for key, value in authorization().items() if key != 7}, "authorization"),
        ({**authorization(), 8: 0}, "authorization"),
        ({**authorization(), 5: 0}, "threshold"),
        ({**authorization(), 5: 4}, "threshold"),
        ({**authorization(), 6: "not-a-list"}, "signer_set"),
        ({**authorization(), 6: []}, "signer_set"),
        ({**authorization(), 6: [{1: "a"}]}, "signer entry"),
        ({**authorization(), 6: [{1: "a", 2: KEY_A, 3: 0}]}, "signer entry"),
        ({**authorization(), 7: "not-bytes"}, "predecessor"),
        ({**authorization(), 3: 99}, "operation"),
        ({**authorization(), 2: 99}, "record_kind"),
    ]
    for bad_auth, message in malformed_authorizations:
        with pytest.raises((TypeError, ValueError), match=message):
            encode_signed_update(
                record_fields={1: b"owner-name", 2: KEY_A},
                payload={},
                seq=8,
                authorization=bad_auth,
            )


def test_schema_rejects_malformed_proof_collections():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    malformed_proofs = [
        ("not-a-list", "proofs"),
        ([{1: 1, 2: SIG_A}], "signer_id"),
        ([{1: "", 2: SIG_A}], "signer_id"),
        ([{1: "a" * 257, 2: SIG_A}], "signer_id"),
        ([{1: "a", 2: b"short"}], "signature"),
    ]
    for proofs, message in malformed_proofs:
        with pytest.raises((TypeError, ValueError), match=message):
            encode_multisignature_envelope(
                signed_update_bytes=signed_update,
                proofs=proofs,
            )


def test_multisignature_envelope_is_not_accepted_by_legacy_decoder():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    envelope = encode_multisignature_envelope(
        signed_update_bytes=signed_update,
        proofs=[],
    )
    with pytest.raises(ValueError, match="keys"):
        decode_signed_envelope(envelope)

    legacy_like = cbor2.dumps({1: signed_update, 2: SIG_A}, canonical=True)
    with pytest.raises(ValueError, match="legacy envelope"):
        decode_signed_envelope(legacy_like)


def test_decoder_rejects_wrong_record_kind_in_canonical_wire_bytes():
    bad_authorization = authorization()
    bad_authorization[2] = RECORD_KIND_PROVIDER
    bad_authorization[6] = [
        {1: "signer-a", 2: KEY_A},
        {1: "signer-b", 2: KEY_B},
        {1: "signer-c", 2: KEY_C},
    ]
    bad_update = cbor2.dumps(
        {
            1: {1: b"owner-name", 2: KEY_A},
            2: {},
            3: 8,
            4: bad_authorization,
        },
        canonical=True,
    )
    with pytest.raises(ValueError, match="record_kind"):
        decode_multisignature_signed_update(bad_update)


def test_decoder_rejects_unsupported_version_and_unsorted_wire_values():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    unsupported = cbor2.dumps({1: 2, 2: signed_update, 3: []}, canonical=True)
    with pytest.raises(ValueError, match="version"):
        decode_multisignature_envelope(unsupported)

    unsorted_auth = authorization()
    unsorted_auth[6] = [
        {1: "signer-b", 2: KEY_B},
        {1: "signer-a", 2: KEY_A},
        {1: "signer-c", 2: KEY_C},
    ]
    noncanonical = cbor2.dumps(
        {1: {1: b"owner-name", 2: KEY_A}, 2: {}, 3: 8, 4: unsorted_auth},
        canonical=True,
    )
    with pytest.raises(ValueError, match="ordered"):
        decode_multisignature_signed_update(noncanonical)

    with pytest.raises(ValueError, match="ordered"):
        encode_multisignature_envelope(
            signed_update_bytes=signed_update,
            proofs=[{1: "signer-b", 2: SIG_B}, {1: "signer-a", 2: SIG_A}],
            sort_proofs=False,
        )


def test_non_multisig_signed_update_remains_legacy_shape():
    encoded = encode_signed_update(record_fields={1: KEY_A}, payload={}, seq=1)
    assert set(cbor2.loads(encoded).keys()) == {1, 2, 3}
    with pytest.raises(ValueError, match="authorization"):
        decode_multisignature_signed_update(encoded)


def test_multisignature_envelope_requires_canonical_signed_update_shape():
    with pytest.raises(ValueError, match="SignedUpdate"):
        encode_multisignature_envelope(
            signed_update_bytes=cbor2.dumps({1: {}, 2: {}, 3: 1}, canonical=True),
            proofs=[],
        )


def test_multisignature_envelope_decoder_rejects_duplicate_proofs():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    envelope = cbor2.dumps(
        {1: 1, 2: signed_update, 3: [{1: "signer-a", 2: SIG_A}, {1: "signer-a", 2: SIG_A}]},
        canonical=True,
    )
    with pytest.raises(ValueError, match="duplicate"):
        decode_multisignature_envelope(envelope)


def test_canonical_vectors():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization={
            1: AUTHORIZATION_SCHEME_ED25519,
            2: RECORD_KIND_IDENTITY,
            3: OPERATION_ORDINARY_UPDATE,
            4: 7,
            5: 2,
            6: [{1: "b", 2: KEY_B}, {1: "a", 2: KEY_A}],
            7: bytes(32),
        },
    )
    envelope = encode_multisignature_envelope(
        signed_update_bytes=signed_update,
        proofs=[
            {1: "b", 2: bytes(range(1, 65))},
            {1: "a", 2: bytes(range(64))},
        ],
    )
    assert signed_update.hex() == (
        "a401a2014a6f776e65722d6e616d65025820000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f02a0030804a7010102010302040705020682"
        "a2016161025820000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
        "1c1d1e1fa20161620258200102030405060708090a0b0c0d0e0f101112131415161718"
        "191a1b1c1d1e1f200758200000000000000000000000000000000000000000000000000000000000000000"
    )
    assert envelope.hex() == (
        "a301010258b5a401a2014a6f776e65722d6e616d65025820000102030405060708090a"
        "0b0c0d0e0f101112131415161718191a1b1c1d1e1f02a0030804a701010201030204"
        "0705020682a2016161025820000102030405060708090a0b0c0d0e0f101112131415"
        "161718191a1b1c1d1e1fa20161620258200102030405060708090a0b0c0d0e0f101112"
        "131415161718191a1b1c1d1e1f2007582000000000000000000000000000000000000000000000000000000000000000000382"
        "a2016161025840000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
        "1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e"
        "3fa20161620258400102030405060708090a0b0c0d0e0f101112131415161718191a1b"
        "1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e"
        "3f40"
    )


def test_empty_proof_collection_is_valid_for_a_draft():
    signed_update = encode_signed_update(
        record_fields={1: b"owner-name", 2: KEY_A},
        payload={},
        seq=8,
        authorization=authorization(),
    )
    envelope = encode_multisignature_envelope(
        signed_update_bytes=signed_update,
        proofs=[],
    )
    assert decode_multisignature_envelope(envelope).proofs == ()
