from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

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


@dataclass(frozen=True, slots=True)
class ProviderPayloadV1:
    alg: str
    version: int
    object_hash: str
    provider_id: str
    endpoints: list[str]


# CBOR shape for the provider "signed-field list" in issue #23.
# Encoded as a CBOR map with unsigned integer keys so it fits the
# SignedUpdate requirement of `payload(map<uint, any>)`.
_PROVIDER_PAYLOAD_FIELDS = {1, 2, 3, 4, 5}

_FIELD_ALG = 1
_FIELD_VERSION = 2
_FIELD_OBJECT_HASH = 3
_FIELD_PROVIDER_ID = 4
_FIELD_ENDPOINTS = 5


def encode_provider_payload(
    *,
    alg: str,
    version: int,
    object_hash: str,
    provider_id: str,
    endpoints: list[str],
) -> bytes:
    if not isinstance(version, int) or version < 0:
        raise TypeError("version must be a non-negative int")

    norm_eps = normalize_sorted_endpoints(endpoints)

    payload = {
        _FIELD_ALG: alg,
        _FIELD_VERSION: int(version),
        _FIELD_OBJECT_HASH: object_hash,
        _FIELD_PROVIDER_ID: provider_id,
        _FIELD_ENDPOINTS: norm_eps,
    }
    return canonical_cbor(payload)


def decode_provider_payload(data: bytes) -> ProviderPayloadV1:
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

    keys = set(decoded.keys())
    if keys != _PROVIDER_PAYLOAD_FIELDS:
        missing = _PROVIDER_PAYLOAD_FIELDS - keys
        extra = keys - _PROVIDER_PAYLOAD_FIELDS
        raise ValueError(
            f"provider payload keys mismatch; missing={missing} extra={extra}"
        )

    endpoints = decoded.get(_FIELD_ENDPOINTS)
    if not isinstance(endpoints, list) or not all(
        isinstance(x, str) for x in endpoints
    ):
        raise ValueError("endpoints must be list[str]")

    endpoints = _validate_endpoints(endpoints)
    _require_endpoints_sorted(endpoints)

    return ProviderPayloadV1(
        alg=str(decoded[_FIELD_ALG]),
        version=int(decoded[_FIELD_VERSION]),
        object_hash=str(decoded[_FIELD_OBJECT_HASH]),
        provider_id=str(decoded[_FIELD_PROVIDER_ID]),
        endpoints=endpoints,
    )


def format_get_result(*, object_key: str, endpoints: list[str]) -> dict[str, Any]:
    """Minimal JSON-API formatting for `get(object_hash)` results (issue #23)."""

    return {
        "object_key": object_key,
        "endpoints": normalize_sorted_endpoints(endpoints),
    }
