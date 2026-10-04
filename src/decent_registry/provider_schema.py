from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import cbor2

from decent_registry.encoding import canonical_cbor, is_canonical_cbor


def _validate_endpoints(endpoints: Iterable[str]) -> list[str]:
    eps = list(endpoints)
    if len(eps) > 32:
        raise ValueError(f"endpoints max 32; got {len(eps)}")
    out: list[str] = []
    for e in eps:
        if not isinstance(e, str):
            raise TypeError(f"endpoint must be str; got {type(e)}")
        if not e.startswith("/"):
            raise ValueError(
                f"endpoint must be multiaddr starting with '/'; got {e!r}"
            )
        if len(e.encode("utf-8")) > 256:
            raise ValueError("endpoint max 256 bytes")
        out.append(e)
    return out


def normalize_sorted_endpoints(endpoints: Iterable[str]) -> list[str]:
    """Validate endpoint constraints and return lexicographically sorted endpoints."""
    eps = _validate_endpoints(endpoints)
    return sorted(eps)


def _require_endpoints_sorted(endpoints: list[str]) -> None:
    if endpoints != sorted(endpoints):
        raise ValueError(
            "endpoints must be lexicographically sorted before signing"
        )


def _validate_object_url(url: str) -> str:
    if not isinstance(url, str):
        raise TypeError(f"object_url must be str; got {type(url)}")
    if not url:
        raise ValueError("object_url must be non-empty")
    if any(c.isspace() for c in url):
        raise ValueError("object_url must not contain whitespace")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("object_url must start with http:// or https://")
    if len(url.encode("utf-8")) > 2048:
        raise ValueError("object_url max 2048 bytes")
    return url


@dataclass(frozen=True, slots=True)
class ProviderPayloadV1:
    alg: str
    version: int
    object_hash: str
    provider_url: str
    endpoints: list[str]


@dataclass(frozen=True, slots=True)
class ProviderWithdrawnPayloadV2:
    alg: str
    version: int
    object_hash: str
    status: str
    replacement_object_hash: str | None = None


# CBOR shape for the provider "signed-field list" in issue #23.
# Encoded as a CBOR map with unsigned integer keys so it fits the
# SignedUpdate requirement of `payload(map<uint, any>)`.
_PROVIDER_PAYLOAD_FIELDS = {1, 2, 3, 4, 5}

_FIELD_ALG = 1
_FIELD_VERSION = 2
_FIELD_OBJECT_HASH = 3
_FIELD_PROVIDER_URL = 4
_FIELD_ENDPOINTS = 5
_OBJECT_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_object_hash(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not _OBJECT_HASH_RE.fullmatch(value):
        raise ValueError(f"{name} must be exactly 64 hexadecimal characters")
    return value


def build_provider_payload_dict(
    *,
    alg: str,
    version: int,
    object_hash: str,
    provider_url: str,
    endpoints: list[str],
) -> dict[int, Any]:
    """Build the in-memory payload dict for the provider signed-field list."""
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise ValueError("active Provider Record version must be 1")
    if not isinstance(alg, str) or not alg:
        raise ValueError("alg must be a non-empty string")

    norm_eps = normalize_sorted_endpoints(endpoints)
    provider_url = _validate_object_url(provider_url)
    object_hash = _validate_object_hash(object_hash, name="object_hash")

    return {
        _FIELD_ALG: alg,
        _FIELD_VERSION: int(version),
        _FIELD_OBJECT_HASH: object_hash,
        _FIELD_PROVIDER_URL: provider_url,
        _FIELD_ENDPOINTS: norm_eps,
    }


def decode_provider_payload_dict(
    payload: Mapping[int, Any],
) -> ProviderPayloadV1 | ProviderWithdrawnPayloadV2:
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")

    keys = set(payload.keys())
    version = payload.get(_FIELD_VERSION)
    if version == 2 and not isinstance(version, bool):
        required = {1, 2, 3, 4}
        if not required.issubset(keys) or keys - (required | {5}):
            raise ValueError("Provider payload v2 has missing or extra fields")
        alg = payload[1]
        if not isinstance(alg, str) or not alg:
            raise ValueError("alg must be a non-empty string")
        object_hash = _validate_object_hash(payload[3], name="object_hash")
        if payload[4] != "withdrawn" or not isinstance(payload[4], str):
            raise ValueError("Provider payload v2 status must be 'withdrawn'")
        replacement = None
        if 5 in keys:
            replacement = _validate_object_hash(
                payload[5], name="replacement_object_hash"
            )
            if bytes.fromhex(replacement) == bytes.fromhex(object_hash):
                raise ValueError("replacement_object_hash must not reference itself")
        return ProviderWithdrawnPayloadV2(
            alg=alg,
            version=2,
            object_hash=object_hash,
            status="withdrawn",
            replacement_object_hash=replacement,
        )

    if keys != _PROVIDER_PAYLOAD_FIELDS:
        missing = _PROVIDER_PAYLOAD_FIELDS - keys
        extra = keys - _PROVIDER_PAYLOAD_FIELDS
        raise ValueError(
            f"provider payload keys mismatch; missing={missing} extra={extra}"
        )

    if not isinstance(payload[_FIELD_VERSION], int) or isinstance(
        payload[_FIELD_VERSION], bool
    ):
        raise ValueError("provider version must be an integer")
    if payload[_FIELD_VERSION] != 1:
        raise ValueError(
            f"unsupported provider payload version: {payload[_FIELD_VERSION]}"
        )
    alg = payload[_FIELD_ALG]
    if not isinstance(alg, str) or not alg:
        raise ValueError("alg must be a non-empty string")
    endpoints = payload[_FIELD_ENDPOINTS]
    if not isinstance(endpoints, list) or not all(
        isinstance(x, str) for x in endpoints
    ):
        raise ValueError("endpoints must be list[str]")
    endpoints = _validate_endpoints(endpoints)
    _require_endpoints_sorted(endpoints)

    provider_url_raw = payload[_FIELD_PROVIDER_URL]
    if not isinstance(provider_url_raw, str):
        raise ValueError("object_url must be str")
    provider_url = _validate_object_url(provider_url_raw)

    return ProviderPayloadV1(
        alg=alg,
        version=int(payload[_FIELD_VERSION]),
        object_hash=_validate_object_hash(
            payload[_FIELD_OBJECT_HASH], name="object_hash"
        ),
        provider_url=provider_url,
        endpoints=endpoints,
    )


def build_provider_withdrawal_payload_dict(
    *, alg: str, object_hash: str, replacement_object_hash: str | None = None
) -> dict[int, Any]:
    """Build a v2 signed tombstone payload for an existing Provider Record."""
    if not isinstance(alg, str) or not alg:
        raise ValueError("alg must be a non-empty string")
    object_hash = _validate_object_hash(object_hash, name="object_hash")
    payload: dict[int, Any] = {1: alg, 2: 2, 3: object_hash, 4: "withdrawn"}
    if replacement_object_hash is not None:
        replacement = _validate_object_hash(
            replacement_object_hash, name="replacement_object_hash"
        )
        if bytes.fromhex(replacement) == bytes.fromhex(object_hash):
            raise ValueError("replacement_object_hash must not reference itself")
        payload[5] = replacement
    return payload


def encode_provider_withdrawal_payload(
    *, alg: str, object_hash: str, replacement_object_hash: str | None = None
) -> bytes:
    """Canonical CBOR encode of a Provider v2 tombstone payload."""
    return canonical_cbor(
        build_provider_withdrawal_payload_dict(
            alg=alg,
            object_hash=object_hash,
            replacement_object_hash=replacement_object_hash,
        )
    )


def is_provider_withdrawn_payload(payload: Mapping[int, Any]) -> bool:
    """Return whether a valid Provider payload represents a tombstone."""
    return isinstance(decode_provider_payload_dict(payload), ProviderWithdrawnPayloadV2)


def encode_provider_payload(
    *,
    alg: str,
    version: int,
    object_hash: str,
    provider_url: str,
    endpoints: list[str],
) -> bytes:
    """Canonical CBOR encode of the provider signed-field list payload."""
    payload_dict = build_provider_payload_dict(
        alg=alg,
        version=version,
        object_hash=object_hash,
        provider_url=provider_url,
        endpoints=endpoints,
    )
    return canonical_cbor(payload_dict)


def decode_provider_payload(data: bytes) -> ProviderPayloadV1 | ProviderWithdrawnPayloadV2:
    # Reject non-canonical encodings: requirement that signatures bind to
    # canonical CBOR.
    if not is_canonical_cbor(data):
        raise ValueError("non-canonical or invalid CBOR")

    try:
        decoded: Any = cbor2.loads(data)
    except Exception as e:
        raise ValueError("invalid CBOR") from e

    if not isinstance(decoded, dict):
        raise ValueError("provider payload must be a CBOR map")

    return decode_provider_payload_dict(decoded)


def format_get_result(
    *,
    object_key: str,
    provider_url: str,
    endpoints: list[str],
) -> dict[str, Any]:
    """Minimal JSON-API formatting for `get(object_hash)` results (issue #23)."""
    return {
        "object_key": object_key,
        "provider_url": provider_url,
        "endpoints": normalize_sorted_endpoints(endpoints),
    }
