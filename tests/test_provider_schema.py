import pytest
import cbor2

from decent_registry.provider_schema import (
    decode_provider_payload,
    encode_provider_payload,
    normalize_sorted_endpoints,
)


def test_encode_provider_payload_sorts_endpoints_deterministically():
    endpoints_a = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
    endpoints_b = list(reversed(endpoints_a))

    b1 = encode_provider_payload(
        alg="Ed25519",
        version=1,
        object_hash="01" * 32,
        provider_id="02" * 32,
        endpoints=endpoints_a,
    )
    b2 = encode_provider_payload(
        alg="Ed25519",
        version=1,
        object_hash="01" * 32,
        provider_id="02" * 32,
        endpoints=endpoints_b,
    )

    assert b1 == b2

    payload = decode_provider_payload(b1)
    assert payload.endpoints == normalize_sorted_endpoints(endpoints_a)


def test_decode_rejects_unsorted_endpoints():
    # Same field values as encode_provider_payload, but with endpoint order preserved.
    payload = {
        1: "Ed25519",  # alg
        2: 1,  # version
        3: "01" * 32,  # object_hash
        4: "02" * 32,  # provider_id
        5: ["/ip4/2/tcp/1", "/ip4/1/tcp/9"],  # intentionally unsorted
    }
    data = cbor2.dumps(payload, canonical=True)
    with pytest.raises(ValueError, match="sorted"):
        decode_provider_payload(data)


def test_constraints_endpoints_max_32():
    endpoints = [f"/ip4/{i}/tcp/1" for i in range(32)]
    encode_provider_payload(
        alg="Ed25519",
        version=1,
        object_hash="01" * 32,
        provider_id="02" * 32,
        endpoints=endpoints,
    )

    endpoints.append("/ip4/999/tcp/1")
    with pytest.raises(ValueError):
        encode_provider_payload(
            alg="Ed25519",
            version=1,
            object_hash="01" * 32,
            provider_id="02" * 32,
            endpoints=endpoints,
        )


def test_constraints_endpoint_must_start_with_slash():
    with pytest.raises(ValueError, match="multiaddr"):
        encode_provider_payload(
            alg="Ed25519",
            version=1,
            object_hash="01" * 32,
            provider_id="02" * 32,
            endpoints=["tcp://127.0.0.1:1"],
        )
