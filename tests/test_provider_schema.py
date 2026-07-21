import pytest
import cbor2

from decent_registry.provider_schema import (
    decode_provider_payload,
    encode_provider_payload,
    normalize_sorted_endpoints,
)


PROVIDER_URL = "https://example.com/object.bin"


def test_encode_provider_payload_sorts_endpoints_deterministically():
    endpoints_a = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
    endpoints_b = list(reversed(endpoints_a))

    b1 = encode_provider_payload(
        alg="Ed25519",
        version=1,
        object_hash="01" * 32,
        provider_url=PROVIDER_URL,
        endpoints=endpoints_a,
    )
    b2 = encode_provider_payload(
        alg="Ed25519",
        version=1,
        object_hash="01" * 32,
        provider_url=PROVIDER_URL,
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
        4: PROVIDER_URL,
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
        provider_url=PROVIDER_URL,
        endpoints=endpoints,
    )

    endpoints.append("/ip4/999/tcp/1")
    with pytest.raises(ValueError):
        encode_provider_payload(
            alg="Ed25519",
            version=1,
            object_hash="01" * 32,
            provider_url=PROVIDER_URL,
            endpoints=endpoints,
        )


def test_constraints_endpoint_must_start_with_slash():
    with pytest.raises(ValueError, match="multiaddr"):
        encode_provider_payload(
            alg="Ed25519",
            version=1,
            object_hash="01" * 32,
            provider_url=PROVIDER_URL,
            endpoints=["tcp://127.0.0.1:1"],
        )


def test_object_url_max_2048_bytes_accepted():
    prefix = "https://example.com/"
    prefix_bytes_len = len(prefix.encode("utf-8"))
    filler_len = 2048 - prefix_bytes_len
    assert filler_len > 0

    url = prefix + ("a" * filler_len)
    # Exactly at the configured max.
    assert len(url.encode("utf-8")) == 2048

    endpoints = ["/ip4/1/tcp/1"]
    data = encode_provider_payload(
        alg="Ed25519",
        version=1,
        object_hash="01" * 32,
        provider_url=url,
        endpoints=endpoints,
    )
    payload = decode_provider_payload(data)
    assert payload.provider_url == url


def test_object_url_too_long_rejected():
    prefix = "https://example.com/"
    prefix_bytes_len = len(prefix.encode("utf-8"))
    filler_len = 2048 - prefix_bytes_len + 1
    assert filler_len > 0

    url = prefix + ("a" * filler_len)
    assert len(url.encode("utf-8")) == 2049

    endpoints = ["/ip4/1/tcp/1"]
    with pytest.raises(ValueError, match="max 2048"):
        encode_provider_payload(
            alg="Ed25519",
            version=1,
            object_hash="01" * 32,
            provider_url=url,
            endpoints=endpoints,
        )
