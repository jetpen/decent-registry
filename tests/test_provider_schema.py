import pytest
import cbor2

from decent_registry.provider_schema import (
    ProviderPayloadV3,
    decode_provider_payload,
    encode_provider_payload,
    normalize_sorted_endpoints,
)


PROVIDER_URL = "https://example.com/object.bin"
PROVIDER_URLS = [
    "bittorrent://tracker.example/01010101010101010101010101010101",
    "https://u:p@example.com/object",
    "https://[2001:db8::1]/object",
    "file:///absolute/path/object.bin",
    "https://mirror.example/object.bin",
    "https://bad_host.example/object",
]


def test_active_v3_payload_sorts_and_round_trips_protocol_agnostic_urls():
    encoded = encode_provider_payload(
        alg="Ed25519",
        version=3,
        object_hash="01" * 32,
        provider_urls=list(reversed(PROVIDER_URLS)),
        endpoints=["/ip4/127.0.0.1/tcp/9000"],
    )

    decoded = decode_provider_payload(encoded)
    assert isinstance(decoded, ProviderPayloadV3)

    assert decoded.version == 3
    assert decoded.provider_urls == sorted(PROVIDER_URLS)


def test_provider_url_list_accepts_uri_schemes_without_authority_restrictions():
    uris = [
        "custom://a!.b-/x",
        "https://bad_host.example/object",
        "https://example.com./object",
        "custom://!tracker/path",
        "urn:isbn:0451450523",
        "file:///absolute/path/object.bin",
    ]

    payload = decode_provider_payload(
        encode_provider_payload(
            alg="Ed25519",
            object_hash="01" * 32,
            provider_urls=uris,
            endpoints=[],
        )
    )
    assert isinstance(payload, ProviderPayloadV3)
    assert payload.provider_urls == sorted(uris)


def test_provider_url_list_accepts_valid_rfc3986_authority_edge_cases():
    uris = [
        "https:",
        "x://[V1.a]/",
        "custom://a!.b-/x",
        "https://example.com:/path",
        "https://[2001:db8::1]:/path",
        "urn:x?q=a/b?c",
    ]
    payload = decode_provider_payload(
        encode_provider_payload(
            alg="Ed25519",
            object_hash="01" * 32,
            provider_urls=uris,
            endpoints=[],
        )
    )
    assert isinstance(payload, ProviderPayloadV3)
    assert payload.provider_urls == sorted(uris)


def test_active_v1_payload_is_rejected():
    payload = {1: "Ed25519", 2: 1, 3: "01" * 32, 4: PROVIDER_URL, 5: []}

    with pytest.raises(ValueError, match="unsupported provider payload version"):
        decode_provider_payload(cbor2.dumps(payload, canonical=True))


@pytest.mark.parametrize(
    "provider_urls",
    [
        [],
        ["https://mirror.example/object.bin"] * 33,
        ["https://mirror.example/object.bin"] * 2,
        ["/relative/path"],
        ["https://mirror.example/bad path"],
        ["https://mirror.example/%GG"],
        ["https://example.com/a[b]"],
        ["https://bad[host]/path"],
        ["https://example.com:80:90/path"],
        ["https://example.com/a%2Fb%ZZ"],
        ["urn:x?q=[bad]"],
        ["urn:x#fragment"],
    ],
)
def test_provider_url_list_rejects_invalid_values(provider_urls):
    with pytest.raises((TypeError, ValueError)):
        encode_provider_payload(
            alg="Ed25519",
            version=3,
            object_hash="01" * 32,
            provider_urls=provider_urls,
            endpoints=[],
        )


def test_active_v3_uri_rejects_non_ascii():
    with pytest.raises(ValueError, match="visible ASCII"):
        encode_provider_payload(
            alg="Ed25519",
            object_hash="01" * 32,
            provider_urls=["ipfs://mirror.example/café"],
            endpoints=[],
        )


def test_provider_url_list_accepts_32_entries_and_rejects_33():
    urls = [f"ipfs://mirror.example/{index}" for index in range(32)]

    payload = decode_provider_payload(
        encode_provider_payload(
            alg="Ed25519",
            version=3,
            object_hash="01" * 32,
            provider_urls=urls,
            endpoints=[],
        )
    )

    assert isinstance(payload, ProviderPayloadV3)
    assert len(payload.provider_urls) == 32
    with pytest.raises(ValueError, match="1 to 32"):
        encode_provider_payload(
            alg="Ed25519",
            version=3,
            object_hash="01" * 32,
            provider_urls=[*urls, "ipfs://mirror.example/extra"],
            endpoints=[],
        )


def test_decode_rejects_unsorted_provider_urls():
    payload = {
        1: "Ed25519",
        2: 3,
        3: "01" * 32,
        4: list(reversed(PROVIDER_URLS)),
        5: [],
    }

    with pytest.raises(ValueError, match="provider_urls.*sorted"):
        decode_provider_payload(cbor2.dumps(payload, canonical=True))


def test_decode_rejects_malformed_provider_urls():
    invalid_urls = [
        ["https://a@b@c/x"],
        ["https://example.com:123:456/x"],
        ["urn:x?x[y]"],
        ["urn:x#fragment"],
    ]
    for urls in invalid_urls:
        payload = {
            1: "Ed25519",
            2: 3,
            3: "01" * 32,
            4: urls,
            5: [],
        }
        with pytest.raises(ValueError):
            decode_provider_payload(cbor2.dumps(payload, canonical=True))


def test_decode_rejects_duplicate_provider_urls():
    payload = {
        1: "Ed25519",
        2: 3,
        3: "01" * 32,
        4: [PROVIDER_URL, PROVIDER_URL],
        5: [],
    }
    with pytest.raises(ValueError, match="duplicates"):
        decode_provider_payload(cbor2.dumps(payload, canonical=True))


def test_encode_provider_payload_sorts_endpoints_deterministically():
    endpoints_a = ["/ip4/2/tcp/1", "/ip4/1/tcp/9", "/ip4/1/tcp/1"]
    endpoints_b = list(reversed(endpoints_a))

    b1 = encode_provider_payload(
        alg="Ed25519",
        version=3,
        object_hash="01" * 32,
        provider_urls=[PROVIDER_URL],
        endpoints=endpoints_a,
    )
    b2 = encode_provider_payload(
        alg="Ed25519",
        version=3,
        object_hash="01" * 32,
        provider_urls=[PROVIDER_URL],
        endpoints=endpoints_b,
    )

    assert b1 == b2

    payload = decode_provider_payload(b1)
    assert payload.endpoints == normalize_sorted_endpoints(endpoints_a)


def test_decode_rejects_unsorted_endpoints():
    # Same field values as encode_provider_payload, but with endpoint order preserved.
    payload = {
        1: "Ed25519",  # alg
        2: 3,  # version
        3: "01" * 32,  # object_hash
        4: [PROVIDER_URL],
        5: ["/ip4/2/tcp/1", "/ip4/1/tcp/9"],  # intentionally unsorted
    }
    data = cbor2.dumps(payload, canonical=True)
    with pytest.raises(ValueError, match="sorted"):
        decode_provider_payload(data)


def test_constraints_endpoints_max_32():
    endpoints = [f"/ip4/{i}/tcp/1" for i in range(32)]
    encode_provider_payload(
        alg="Ed25519",
        version=3,
        object_hash="01" * 32,
        provider_urls=[PROVIDER_URL],
        endpoints=endpoints,
    )

    endpoints.append("/ip4/999/tcp/1")
    with pytest.raises(ValueError):
        encode_provider_payload(
            alg="Ed25519",
            version=3,
            object_hash="01" * 32,
            provider_urls=[PROVIDER_URL],
            endpoints=endpoints,
        )


def test_constraints_endpoint_must_start_with_slash():
    with pytest.raises(ValueError, match="multiaddr"):
        encode_provider_payload(
            alg="Ed25519",
            version=3,
            object_hash="01" * 32,
            provider_urls=[PROVIDER_URL],
            endpoints=["tcp://127.0.0.1:1"],
        )


def test_provider_uri_length_is_limited_by_utf8_bytes():
    uri = "bittorrent://tracker.example/" + "a" * 2019
    assert len(uri.encode("utf-8")) == 2048
    encode_provider_payload(
        alg="Ed25519",
        object_hash="01" * 32,
        provider_urls=[uri],
        endpoints=[],
    )

    oversized = uri + "a"
    assert len(oversized.encode("utf-8")) == 2049
    with pytest.raises(ValueError, match="max 2048"):
        encode_provider_payload(
            alg="Ed25519",
            object_hash="01" * 32,
            provider_urls=[oversized],
            endpoints=[],
        )


def test_provider_uri_over_utf8_byte_limit_rejected():
    uri = "https://example.com/" + "a" * 2029
    assert len(uri.encode("utf-8")) == 2049
    with pytest.raises(ValueError, match="max 2048"):
        encode_provider_payload(
            alg="Ed25519",
            object_hash="01" * 32,
            provider_urls=[uri],
            endpoints=[],
        )
