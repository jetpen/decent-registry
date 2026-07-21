# Protocol concepts and configuration vocabulary

This document covers the core protocol concepts and how they map to the CLI flags and YAML config fields in this repo.

This document is standalone: it defines the core protocol concepts, data schemas, and how they map to CLI flags and YAML configuration in this repo.

---

## 1) Transport and lookup: libp2p Kad-DHT (Kademlia)

`decent-registry` uses **libp2p Python Kad-DHT** in server mode.

- A node runs `decent-registry node` which starts:
  - a libp2p host bound to `--host` / `--port` (TCP enabled)
  - a Kad-DHT instance
  - (optional) a local LMDB durable datastore for fallback caching

When storing or retrieving records, the DHT key is namespaced to avoid collisions:

- provider records (payload = provider schema)
  - DHT key: `/decent-registry/provider/{object_hash}`
- identity records (payload = empty; identity data is taken from `record_fields`)
  - DHT key: `/decent-registry/identity/{object_key}`

In code: `_kad_key(object_hash, kind='provider'|'identity')` returns `f"/decent-registry/{kind}/{object_hash}"`.

---

## 2) Bootstrap: how nodes discover each other

**Bootstrap** is the initial connectivity step for routing in the DHT.

Implementation details:
- CLI/YAML `bootstrap` values must be **identify-style multiaddrs** that include `/p2p/<peerid>`.
- `Libp2pKadDHT.bootstrap(remote_tcp_multiaddr)` rejects destinations missing `/p2p/`.
- It then parses the multiaddr with `info_from_p2p_addr(Multiaddr(...))` and calls `host.connect(peer_info)`.

CLI config / flags:
- `decent-registry node` accepts repeated `--bootstrap` values
- `decent-registry put ...` and `decent-registry get ...` accept the same `--bootstrap` list

Note: in this repo, the command line `--bootstrap` values are passed as the *same list* to all client commands, and clients bootstrap their host before performing `put`/`get`.

---

## 3) Multiaddr endpoints (provider record payload)

Only **provider records** include a list of endpoints. The endpoints live in the **provider payload** and are not part of the signed identity.

Validation and signing constraints (from `provider_schema.py`):
- each endpoint must be a string starting with `/` (multiaddr syntax)
- max 32 endpoints
- each endpoint string must be <= 256 bytes (UTF-8)
- endpoints are **lexicographically sorted** before signing

How sorting is enforced:
- `build_provider_payload_dict(...)` calls `normalize_sorted_endpoints(endpoints)`
  - validates each endpoint
  - sorts lexicographically (`sorted(eps)`) before returning the payload dict
- `decode_provider_payload_dict(...)` calls `_require_endpoints_sorted(endpoints)`
  - rejects payloads where `endpoints != sorted(endpoints)`

CLI-to-payload mapping:
- `decent-registry put provider --endpoint ...`:
  - `--endpoint` is repeatable and may be comma-separated
  - `_parse_endpoints()` splits on commas and strips whitespace
  - `RegistryService.put_provider()` passes the resulting list to `build_provider_payload_dict()` which sorts before signing

---

## 4) SHA-256 lookup keys: `object_key` and `object_hash`

The protocol uses SHA-256 digests to derive DHT lookup keys.

### Identity lookup key

For an **identity record**, the CLI derives the DHT key from `--owner-name`:

- `owner_name_bytes = bytes.fromhex(owner_name_hex)`
- `object_key_hex = sha256(owner_name_bytes).hexdigest()`

This derivation appears in `RegistryService._derive_identity_object_hash_from_owner_name_hex()` and is used by:
- `RegistryService.put_identity(...)`
- `RegistryService.get_identity(...)`

So:
- `decent-registry put identity --owner-name <hex>` stores under `/decent-registry/identity/{sha256(owner_name_bytes).hex}`
- `decent-registry get identity --owner-name <hex>` queries the same key

### Provider lookup key

For a **provider record**, the DHT key is supplied explicitly as `--object-hash`.

In this repo:
- the DHT key bytes for provider are `bytes.fromhex(object_hash)` (must be 64 hex chars)
- the provider payload also includes `object_hash` as a signed field

So `--object-hash` must be a 64-hex string.

---

## 5) Record types: identity vs provider

This repo supports two record types:

### Identity record

Stored as a SignedUpdate where:
- `record_fields[1]` = `owner_name_bytes` (bytes)
- `record_fields[2]` = `owner_public_key` bytes (Ed25519 public key bytes)
- `payload` is `{}`

On get, the client prints:
- `object_key` (the DHT key queried)
- `owner_name` (hex of `record_fields[1]`)
- `owner_public_key` (hex of `record_fields[2]`)
- `seq`

Key derivation and owner binding:
- DHT identity key derives from `owner_name_bytes`
- signature verification derives the identity record key from `owner_name_bytes`
- overwrite authorization binds identity to the `owner_public_key` bytes

### Provider record

Stored as a SignedUpdate where:
- `record_fields[1]` = `owner_public_key` bytes (Ed25519 public key bytes)
- `payload` includes a provider schema with unsigned integer keys:
  - `1`: `alg` (currently `Ed25519`)
  - `2`: `version` (uint)
  - `3`: `object_hash` (64-hex string)
  - `4`: `provider_url` (downloadable object URL, max 2048 UTF-8 bytes)
  - `5`: `endpoints` (list<string>, sorted)

On get, the client prints:
- `object_key` (the queried `object_hash` string)
- `provider_url`
- `endpoints` (already validated/sorted)

---

## 6) Keys and signatures: Ed25519 + canonical CBOR

### Private/public key material

- CLI keygen produces an Ed25519 private key in **PKCS#8 PEM** format.
- The CLI config field `crypto.owner_privkey_pem_path` supplies the PEM path.

The key content is never printed or logged; it is loaded via `load_ed25519_keypair_from_privkey_pem_path()`.

### SignedUpdate digest input

The signature binds a deterministic, canonical encoding.

The signature digest input is:
- `SignedUpdate = { 1: record_fields, 2: payload, 3: seq }`
- encoded with canonical CBOR
- then signed as Ed25519 over `sha256(canonical_signed_update_bytes)`

In code:
- `encode_signed_update(record_fields, payload, seq)` produces canonical CBOR bytes
- `make_signed_update_signature(...)` computes `digest_msg = sha256(signed_update_bytes_canonical)` and calls `owner_private_key.sign(digest_msg)`

### SignedEnvelope

The stored DHT value is a canonical CBOR envelope:

- `SignedEnvelope = { 1: signed_update_bytes, 2: signature }`

`encode_signed_envelope(...)` uses `cbor2.dumps(..., canonical=True)`.

Verification requires canonical CBOR:
- SignedEnvelope must be canonical (`is_canonical_cbor(envelope_cbor)`)
- SignedUpdate bytes inside the envelope must also be canonical (`decode_canonical_signed_update`) 

---

## 7) Overwrite rules: seq monotonicity + owner binding

For a fixed DHT key, later updates are accepted only if they satisfy:

1) **Canonical SignedUpdate** decoding
2) **Ed25519 signature validity**
3) **`seq` strictly increases** for that record key
4) **Owner binding / collision prevention**

Enforcement details in `verification.py`:
- prev state is extracted from the existing envelope:
  - provider prev owner pk is from `existing_signed_update[1][1]`
  - identity prev owner pk is from `existing_signed_update[1][2]`
  - prev seq is `existing_signed_update[3]`
- checks:
  - if `seq <= prev.seq`: reject (`seq must be strictly increasing`)
  - if `owner_public_key != prev.owner_public_key`: reject (`owner collision`)

Consequence:
- First accepted update for a key binds the record to its `owner_public_key`.

Key revocation is specified as a future design in closed issue #15 (allow object rewrites signed with an identity key that has been revoked).
- Later overwrites must be signed by the same owner public key.

---

## 8) Configuration vocabulary and CLI flag mapping

All CLI commands accept a YAML config and a subset of CLI overrides.

### Server YAML (`~/.decent/registry.yaml`)

Module: `src/decent_registry/config.py`.

Fields:
- `network.host` (string, default `127.0.0.1`)
- `network.port` (int, default `None`; required for `node`)
- `network.bootstrap` (list<string>, default `[]`)
- `datastore.path` (string; default `~/.decent/registry`)
- `datastore.mapsize_bytes` (int|null; optional)
- `logging.verbosity` (int; 0=WARNING, 1=INFO, >=2=DEBUG)

`decent-registry node` resolves requiredness after merging config + CLI overrides.

CLI flags for server:
- `--config <path>` (defaults to `~/.decent/registry.yaml`)
- `--host <ip>`
- `--port <int>` (required after resolution)
- `--bootstrap <multiaddr>` (repeatable; list)
- `--datastore-path <path>` (LMDB path)
- `--mapsize <int>`
- `--run-seconds <float>`
- `-v/--verbose` (count)

### Client YAML (`~/.decent/registry_cli.yaml`)

Fields:
- `network.host` (string, default `127.0.0.1`)
- `network.port` (int, required for client commands)
- `network.bootstrap` (list<string>, default `[]`)
- `datastore.path` (string; default `.scratch/decent-registry.lmdb`)
- `datastore.mapsize_bytes` (int|null; optional)
- `logging.verbosity` (int; 0=WARNING, 1=INFO, >=2=DEBUG)
- `crypto.owner_privkey_pem_path` (string|null; required for `put ...`)

CLI config override semantics:
- CLI flags overwrite corresponding YAML fields after loading.
- `--owner-privkey` (for `put provider` / `put identity`) overwrites `crypto.owner_privkey_pem_path`.

Client CLI flags common to `put`/`get`:
- `--config <path>` (defaults to `~/.decent/registry_cli.yaml`)
- `--host <ip>`
- `--port <int>`
- `--bootstrap <multiaddr>` (repeatable)
- `--datastore-path <path>`
- `--mapsize <int>`
- `-v/--verbose` (count)

---

## 9) How `decent-registry` exposes protocol concepts via CLI

### Node/server

- `decent-registry node --host <ip> --port <node_port> [--bootstrap <identify-maddr>]`
- Prints node peer id and listen multiaddr when `-v/--verbose` is enabled (via logger).

### `put identity`

- Inputs:
  - `--owner-name <hex bytes>`
  - `--owner-privkey <pem path>`
  - `--seq <monotonic int>`
- Key derivation:
  - `object_key = sha256(owner_name_bytes)`
- Stored value:
  - SignedEnvelope over canonical CBOR SignedUpdate

### `get identity`

- Inputs:
  - `--owner-name <hex bytes>`
- Output JSON:
  - includes `seq`, `owner_name`, `owner_public_key`

### `put provider`

- Inputs:
  - `--object-hash <64-hex>`
  - `--provider-url <url>`
  - `--owner-privkey <pem path>`
  - `--seq <monotonic int>`
  - `--endpoint <multiaddr>` (repeatable/comma-separated)
- Provider payload requirements:
  - endpoints must be valid multiaddr strings starting with `/`
  - max 32 endpoints, each <=256 bytes
  - endpoints are sorted lexicographically before signing

### `get provider`

- Inputs:
  - `--object-hash <64-hex>`
- Output JSON:
  - `provider_url` and sorted `endpoints`
