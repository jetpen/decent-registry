# Research: Registry service URL format (protocol + multiaddr + context paths) (#69)

## Background / repo facts (current implementation anchors)
- Provider records stored under Kad-DHT key pattern:
  - `/decent-registry/provider/{object_hash}`
- Identity records stored under Kad-DHT key pattern:
  - `/decent-registry/identity/{object_key_hex}`
- Current identity object key derivation:
  - `object_key_hex = sha256(owner_name_bytes).hexdigest()`
- Provider payload already includes:
  - `provider_url` (validated to be `http://` or `https://`)
  - `endpoints` (validated as multiaddrs starting with `/`)

This doc specifies a *custom URL grammar* for a registry service that routes requests to the DHT via:
1) a protocol scheme identifying the service API,
2) a libp2p multiaddr identifying the target registry node/endpoint,
3) a context path selecting a lookup mode.

## Core URL grammar

### Canonical form
```
<scheme>:<multiaddr>//<context-path>[?<query>]
```

Where:
- `<scheme>` is a new, repo-specific identifier for the registry service (proposed: `decent-registry`).
- `<multiaddr>` is a valid libp2p multiaddr string that starts with `/`.
- The delimiter `//` marks the end of the multiaddr and the beginning of the context path.
  - Rationale: network multiaddrs use `/proto/value` segments and normally do not contain empty segments; therefore `//` is an unambiguous boundary for the supported network transports.
  - Limitation: multiaddrs with empty path components, such as Unix-socket forms (`/unix//path`), would conflict with this delimiter. Either exclude those transports from v1 or replace the delimiter before implementation.
  - Alternative rejected: `decent-registry://<multiaddr>/<context>` is problematic because `<multiaddr>` begins with `/` and would be parsed as an “authority” component by conventional URI parsers, making boundary detection ambiguous.
- `<context-path>` starts at the first path segment after the delimiter.
- `<query>` is optional; this doc does not define query parameters beyond reserving space for future options (e.g., `quorum`).

This is not an RFC 3986 authority-style URL. A custom parser is required:
1) split at the first literal `:` into scheme and remainder,
2) split the remainder at the first literal `//` into multiaddr and context,
3) validate the left part as a `Multiaddr`,
4) route the right part as the context path and query.

The parser MUST NOT collapse repeated slashes or apply generic URL normalization before the split.

### Resolution semantics
The registry node is assumed to expose an HTTP(S)-compatible request surface:
1) parse the custom URL and validate the multiaddr,
2) dial the registry endpoint identified by the multiaddr,
3) issue the context-path request,
4) return a JSON response with `Content-Type: application/json`, or return the provider redirect with `302 Found` and a `Location` header.

### Examples of the “multiaddr//context” boundary
- Multiaddr part contains `/p2p/<peerid>`.
- Context begins immediately after the first `//`.

## Encoding rules

### Hashes
- `<sha256hex>`: 64 lowercase hex chars.
- Reject:
  - uppercase hex,
  - non-hex,
  - wrong length.

### Ed25519 public keys (owner public key lookup)
- `<ed25519-pubkey-hex>`: 64 lowercase hex chars (raw 32-byte key, hex-encoded).

### Owner name / alias strings
- `<owner-name>` and `<alias>` are percent-encoded UTF-8 byte strings.
- Reserved path characters, including `/`, `?`, `#`, and `%`, MUST be percent-encoded when part of a name or alias value.
- The server MUST:
  1) percent-decode to raw bytes,
  2) apply `sha256(raw_bytes)` directly (no Unicode normalization, no whitespace trimming, no case folding beyond what the user encoded).

This matches the repo’s “hash-scope from raw UTF-8 bytes” constraint: the SHA-256 input bytes are the exact post-decoding bytes.

## Context path routing

All routes below are relative to `<context-path>`.

### 1) Hash-only lookup (unknown record type)
Use case: given only a SHA-256 hash, locate whichever record exists.

Route:
- `by-hash/<sha256hex>`

Server-side interpretation (current v1 index constraints + proposed behavior):
- Perform independent Provider and Identity lookups; implementations may run them in parallel.
- Provider lookup:
  - provider key uses `{object_hash} = <sha256hex>`
  - returns provider payload if present.
- Identity lookup:
  - identity key uses `{object_key_hex} = <sha256hex>`
  - returns identity object fields if present.
- If both are present, order `matches` deterministically as `identity`, then `provider`.

Ambiguity handling rule (hash-only type collision):
- If both provider and identity records exist for the same `sha256hex`, return a discriminated response containing both.
- If exactly one exists, return only that record.

Response shape (proposed; JSON):
- `{ "matches": [ {"type": "provider", ...}, {"type": "identity", ...} ] }`
- or `{ "type": "provider", ... }` / `{ "type": "identity", ... }` when unambiguous.
- If neither namespace contains a record, return HTTP `404 Not Found` with `{ "matches": [] }`.

### 2) Identity lookup by owner name or alias
#### 2a) Owner name
Route:
- `identity/by-name/<owner-name>`

Server-side behavior (current code-backed):
- Compute `object_key_hex = sha256(owner_name_bytes).hexdigest()`
- Fetch identity record by DHT key:
  - `/decent-registry/identity/{object_key_hex}`

#### 2b) Alias
Route:
- `identity/by-alias/<alias>`

Proposed server-side behavior consistent with the #68 “primary/alias” design documented in `docs/research/identity-recovery-research.md`:
- Compute `alias_object_key_hex = sha256(alias_bytes).hexdigest()` and fetch the identity record stored under:
  - `/decent-registry/identity/{alias_object_key_hex}`
- The alias record payload must be interpreted (requires v2 validator logic) to:
  - identify role == `alias`
  - extract `primary_link` (reference to the primary identity object key)
- The server then fetches the primary identity record under:
  - `/decent-registry/identity/{primary_object_key_hex}`

Note: the current v1 code does not implement parsing/validation of `payload.role` / `primary_link`; this route is specified as a v2 extension in routing/response semantics. Until that validator logic exists, return `501 Not Implemented`; after implementation, malformed alias linkage returns `400 Bad Request` and a missing `primary_link` target returns `404 Not Found`.

### 3) Identity lookup by owner public key
Route:
- `identity/by-owner-pubkey/<ed25519-pubkey-hex>`

Server-side status:
- Current v1 index does not provide a direct reverse lookup from public key to identity object key, because identity records are keyed by owner name.
- This route can be implemented only by one of:
  1) **recommended:** add `/decent-registry/owner-pubkey/{pubkey_hex}` as a reverse-index namespace whose value points to one or more identity object keys, or
  2) scan/enumerate identity records (expensive and not appropriate for general use).

The route is a required URL surface but a follow-up implementation area. Until the reverse index exists, return `501 Not Implemented` rather than silently performing an unbounded scan.

### 4) Provider record lookup returning only the provider record (including target object URL)
Route:
- `provider/by-hash/<sha256hex>`

Server-side behavior (current code-backed):
- Fetch provider record under:
  - `/decent-registry/provider/<sha256hex>`
- Return the provider record payload.
- If no provider record exists, return HTTP `404 Not Found`.

The payload includes:
- `provider_url` = URL of the target object.
- `endpoints` = multiaddrs where the provider can be reached.

### 5) Provider lookup returning a redirect to the target object URL
Route:
- `provider/by-hash/<sha256hex>/redirect`

Server-side behavior:
- Fetch provider record (same as #4).
- Set `Location` header to `provider_url`.
- Return `302 Found` with `Location` set to the validated `provider_url`.
- When no provider record exists, respond `404 Not Found` with no redirect.

Security note:
- `provider_url` is validated to start with `http://` or `https://` by the provider schema; this reduces open-redirect risk.

## Concrete example URLs

Let the target registry node multiaddr be:
- `<MA> = /ip4/127.0.0.1/tcp/4001/p2p/<PEERID>`

Let a 64-hex object hash be:
- `<H> = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

Let an owner name be the raw string `alice` (UTF-8 bytes). Its percent-encoding is `alice`.

Let an alias string be `alice-alias`.

Let an Ed25519 pubkey be:
- `<PK> = 1111111111111111111111111111111111111111111111111111111111111111`

1) Hash-only lookup:
- `decent-registry:<MA>//by-hash/<H>`

2) Identity by owner name:
- `decent-registry:<MA>//identity/by-name/alice`

3) Identity by alias:
- `decent-registry:<MA>//identity/by-alias/alice-alias`

4) Provider record:
- `decent-registry:<MA>//provider/by-hash/<H>`

5) Redirect to target object URL:
- `decent-registry:<MA>//provider/by-hash/<H>/redirect`

## Future extension points (non-normative)
- Add optional query params (e.g., `?quorum=1`) to control DHT fetch quorum.
- Add additional context routes for v2 identity payload semantics.
- Add a reverse-index mechanism for `identity/by-owner-pubkey/*`.

## Open decisions
- Confirm the scheme name `decent-registry` before implementation.
- Confirm that the registry node exposes an HTTP(S)-compatible request surface for resolving these URLs.
- Confirm the custom `//` delimiter and custom-parser requirement, including the `/unix//path` limitation.
- Confirm whether redirect uses `302 Found` or `303 See Other`; this research chooses `302`.
- Define the v2 alias payload semantics (`role`, `primary_link`) and alias-cycle handling.
- Define reverse-index update and consistency rules for owner-public-key lookup.

## Backward compatibility
- This repository does not currently document any canonical registry-service URL grammar.
- The namespace keys in this doc match the current Kad-DHT keying logic (`_kad_key(kind=provider|identity)`), so the URL routes map cleanly to current storage.
- Alias semantics require future validator logic. Owner-pubkey lookup requires a reverse index; until it exists, that route returns `501 Not Implemented` as specified above.
