from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

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


_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_BAD_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HEX_DIGITS = set("0123456789ABCDEFabcdef")
_URI_UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_URI_SUB_DELIMITERS = set("!$&'()*+,;=")
_URI_PCHAR = _URI_UNRESERVED | _URI_SUB_DELIMITERS | set(":@%")
_URI_ALLOWED = _URI_PCHAR | set("/?#[]")
_AUTHORITY_SCHEMES = {"http", "https", "ftp", "ws", "wss"}
_PORT_RE = re.compile(r"^[0-9]+$")


def _valid_uri_component(value: str, allowed: set[str]) -> bool:
    return all(
        char in allowed
        or (
            char == "%"
            and index + 2 < len(value)
            and value[index + 1] in _HEX_DIGITS
            and value[index + 2] in _HEX_DIGITS
        )
        for index, char in enumerate(value)
    )


def _validate_uri_authority(authority: str) -> None:
    if authority.count("@") > 1:
        raise ValueError("provider URI contains an invalid authority")
    userinfo, separator, host_port = authority.rpartition("@")
    userinfo_allowed = _URI_PCHAR - {"@", "/", "?", "#"}
    if separator and not _valid_uri_component(userinfo, userinfo_allowed):
        raise ValueError("provider URI contains an invalid userinfo")

    if host_port.startswith("["):
        closing = host_port.find("]")
        if closing < 0:
            raise ValueError("provider URI contains an invalid IP literal")
        literal = host_port[1:closing]
        if literal[:1].lower() == "v":
            ipvfuture_re = re.compile(
                r"[Vv][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+"
            )
            if not ipvfuture_re.fullmatch(literal):
                raise ValueError("provider URI contains an invalid IP literal")
        else:
            ipv6_literal, zone_separator, zone = literal.partition("%25")
            ipaddress.IPv6Address(ipv6_literal)
            zone_allowed = _URI_UNRESERVED | {"%"}
            if zone_separator and not _valid_uri_component(zone, zone_allowed):
                raise ValueError("provider URI contains an invalid IPv6 zone")
        suffix = host_port[closing + 1 :]
        if suffix and (
            not suffix.startswith(":")
            or (suffix[1:] and not _PORT_RE.fullmatch(suffix[1:]))
        ):
            raise ValueError("provider URI contains an invalid port")
        return

    if "[" in host_port or "]" in host_port or host_port.count(":") > 1:
        raise ValueError("provider URI contains an invalid authority")
    host, separator, port = host_port.partition(":")
    host_allowed = _URI_UNRESERVED | _URI_SUB_DELIMITERS | {"%"}
    if not _valid_uri_component(host, host_allowed):
        raise ValueError("provider URI contains an invalid registered name")
    if separator and port and not _PORT_RE.fullmatch(port):
        raise ValueError("provider URI contains an invalid port")


def _validate_provider_uri(uri: str) -> str:
    if not isinstance(uri, str):
        raise TypeError(f"provider URL must be str; got {type(uri)}")
    if not uri:
        raise ValueError("provider URL must be non-empty")
    if any(char.isspace() or ord(char) < 0x21 or ord(char) > 0x7E for char in uri):
        raise ValueError("provider URL must contain only visible ASCII characters")
    if len(uri.encode("utf-8")) > 2048:
        raise ValueError("provider URL max 2048 bytes")
    colon = uri.find(":")
    scheme_match = _URI_SCHEME_RE.fullmatch(uri[: colon + 1]) if colon >= 0 else None
    if not scheme_match:
        raise ValueError("provider URL must be an absolute URI with a scheme")
    if not uri.isascii() or any(char not in _URI_ALLOWED for char in uri):
        raise ValueError("provider URL contains characters not allowed in a URI")
    if _BAD_PERCENT_ESCAPE_RE.search(uri):
        raise ValueError("provider URL contains an invalid percent escape")

    if uri.count("#") > 0:
        raise ValueError("provider URL must not contain a fragment")
    if uri == scheme_match.group(0):
        return uri

    try:
        parsed = urlsplit(uri)
        scheme = parsed.scheme.lower()
        remainder = uri[len(scheme_match.group(0)) :]
        if remainder.startswith("//"):
            _validate_uri_authority(parsed.netloc)
        elif (
            scheme in _AUTHORITY_SCHEMES
            and not remainder.startswith("//")
            and not remainder
        ):
            raise ValueError("provider URI requires an authority")
        authority_tail = parsed.netloc.rsplit("@", 1)[-1]
        if authority_tail.startswith("["):
            closing = authority_tail.find("]")
            if closing < 0:
                raise ValueError("provider URI contains an invalid IP literal")
            literal = authority_tail[1:closing]
            if literal[:1].lower() == "v":
                ipvfuture_re = re.compile(
                    r"[Vv][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+"
                )
                if not ipvfuture_re.fullmatch(literal):
                    raise ValueError("provider URI contains an invalid IP literal")
            else:
                ipv6_literal, zone_separator, zone = literal.partition("%25")
                ipaddress.IPv6Address(ipv6_literal)
                zone_allowed = _URI_UNRESERVED | {"%"}
                if zone_separator and not _valid_uri_component(zone, zone_allowed):
                    raise ValueError("provider URI contains an invalid IPv6 zone")
            suffix = authority_tail[closing + 1 :]
            if suffix and (
                not suffix.startswith(":")
                or (suffix[1:] and not _PORT_RE.fullmatch(suffix[1:]))
            ):
                raise ValueError("provider URI contains an invalid port")
        elif ":" in authority_tail:
            authority_port = authority_tail.rsplit(":", 1)[-1]
            if authority_port and not _PORT_RE.fullmatch(authority_port):
                raise ValueError("provider URI contains an invalid port")
        if scheme in _AUTHORITY_SCHEMES and parsed.netloc and "[" in parsed.path:
            raise ValueError("provider URI contains brackets outside an IP literal")
        if (
            scheme in _AUTHORITY_SCHEMES
            and parsed.netloc
            and parsed.path
            and not parsed.path.startswith("/")
        ):
            raise ValueError("provider URI authority path must begin with a slash")
        path_allowed = _URI_PCHAR | {"/"}
        if not _valid_uri_component(parsed.path, path_allowed):
            raise ValueError("provider URI contains invalid path characters")
        query_allowed = _URI_PCHAR | {"/", "?"}
        if not _valid_uri_component(parsed.query, query_allowed):
            raise ValueError("provider URI contains invalid query characters")
        fragment_allowed = _URI_PCHAR | {"/", "?"}
        if not _valid_uri_component(parsed.fragment, fragment_allowed):
            raise ValueError("provider URI contains invalid fragment characters")
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise ValueError("provider URL is not a valid absolute URI") from exc
    return uri


def normalize_sorted_provider_urls(provider_urls: Iterable[str]) -> list[str]:
    """Validate and sort unique active Provider Record URI locators."""
    urls = list(provider_urls)
    if not 1 <= len(urls) <= 32:
        raise ValueError(f"provider_urls must contain 1 to 32 URLs; got {len(urls)}")
    normalized = [_validate_provider_uri(url) for url in urls]
    if len(set(normalized)) != len(normalized):
        raise ValueError("provider_urls must not contain duplicates")
    return sorted(normalized)


@dataclass(frozen=True, slots=True)
class ProviderPayloadV3:
    alg: str
    version: int
    object_hash: str
    provider_urls: list[str]
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
_FIELD_PROVIDER_URLS = 4
_FIELD_ENDPOINTS = 5
_OBJECT_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_object_hash(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not _OBJECT_HASH_RE.fullmatch(value):
        raise ValueError(f"{name} must be exactly 64 hexadecimal characters")
    return value


def build_provider_payload_dict(
    *,
    version: int = 3,
    alg: str,
    object_hash: str,
    provider_urls: list[str],
    endpoints: list[str],
) -> dict[int, Any]:
    """Build the canonical payload map for an active Provider Record v3.

    The version is fixed at 3; active v1 records are not supported.
    """
    if isinstance(version, bool) or not isinstance(version, int) or version != 3:
        raise ValueError("active Provider Record version must be 3")
    if not isinstance(alg, str) or not alg:
        raise ValueError("alg must be a non-empty string")

    norm_eps = normalize_sorted_endpoints(endpoints)
    norm_urls = normalize_sorted_provider_urls(provider_urls)
    object_hash = _validate_object_hash(object_hash, name="object_hash")

    return {
        _FIELD_ALG: alg,
        _FIELD_VERSION: int(version),
        _FIELD_OBJECT_HASH: object_hash,
        _FIELD_PROVIDER_URLS: norm_urls,
        _FIELD_ENDPOINTS: norm_eps,
    }


def decode_provider_payload_dict(
    payload: Mapping[int, Any],
) -> ProviderPayloadV3 | ProviderWithdrawnPayloadV2:
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
    if payload[_FIELD_VERSION] != 3:
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

    provider_urls_raw = payload[_FIELD_PROVIDER_URLS]
    if not isinstance(provider_urls_raw, list) or not all(
        isinstance(x, str) for x in provider_urls_raw
    ):
        raise ValueError("provider_urls must be list[str]")
    provider_urls = normalize_sorted_provider_urls(provider_urls_raw)
    if provider_urls_raw != provider_urls:
        raise ValueError("provider_urls must be lexicographically sorted")

    return ProviderPayloadV3(
        alg=alg,
        version=int(payload[_FIELD_VERSION]),
        object_hash=_validate_object_hash(
            payload[_FIELD_OBJECT_HASH], name="object_hash"
        ),
        provider_urls=provider_urls,
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
    version: int = 3,
    alg: str,
    object_hash: str,
    provider_urls: list[str],
    endpoints: list[str],
) -> bytes:
    """Canonical CBOR encode of the active v3 provider payload."""
    payload_dict = build_provider_payload_dict(
        alg=alg,
        version=version,
        object_hash=object_hash,
        provider_urls=provider_urls,
        endpoints=endpoints,
    )
    return canonical_cbor(payload_dict)


def decode_provider_payload(data: bytes) -> ProviderPayloadV3 | ProviderWithdrawnPayloadV2:
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
    provider_urls: list[str],
    endpoints: list[str],
) -> dict[str, Any]:
    """Format a provider lookup result as a minimal JSON object."""
    return {
        "object_key": object_key,
        "provider_urls": normalize_sorted_provider_urls(provider_urls),
        "endpoints": normalize_sorted_endpoints(endpoints),
    }
