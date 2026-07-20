# decent-registry

A decentralized, eventually consistent DHT-based registry prototype.

## Protocol overview

### Canonical CBOR and signing

All signed data is encoded with canonical CBOR (RFC 7049 canonical encoding via `cbor2.dumps(..., canonical=True)`).

**SignedUpdate** (input to the signature digest) is a canonical CBOR map:

- `1`: `record_fields` (`map<uint, any>`)
- `2`: `payload` (`map<uint, any>`)
- `3`: `seq` (`uint`)

**SignedEnvelope** is a canonical CBOR map:

- `1`: `signed_update_bytes` (the canonical CBOR bytes of SignedUpdate)
- `2`: `signature` (Ed25519 over `sha256(signed_update_bytes)`) 

### Verification and overwrite rules

When storing an update for a given `object_hash` key:

- the signed envelope must be canonical
- the Ed25519 signature must verify
- `seq` must be strictly increasing for that `object_hash`
- the first accepted owner binds the record; later overwrites must use the same owner public key
- key revocation is specified as a future design in closed issue #15 (allow object rewrites signed with an identity key that has been revoked)

### Provider record schema (payload)

The provider payload is a CBOR map with unsigned integer keys:

- `1`: `alg` (currently `Ed25519`)
- `2`: `version` (`uint`)
- `3`: `object_hash` (64-hex string)
- `4`: `provider_id` (64-hex string)
- `5`: `endpoints` (`list<string>`)

Endpoint validation/signing constraints:

- each endpoint must be a multiaddr string starting with `/`
- endpoints are normalized and **lexicographically sorted before signing**
- endpoints list is limited to 32 entries; each endpoint string is limited to 256 bytes

### Identity record schema (verification inputs)

SignedUpdate `record_fields` for an identity record are interpreted as:

- `record_fields[1]`: `owner_name` bytes
- `record_fields[2]`: `owner_public_key` bytes (Ed25519 public key)

Identity record lookup key derivation (and owner binding):

- `record_key = sha256(owner_name_bytes)`
- verification binds the signed update to `owner_public_key` for that `record_key`

Current implementation note:
- current verification logic derives the identity key and owner binding from the `record_fields` above; it does not enforce additional identity payload fields at this layer (payload fields are reserved for the tagged-union identity schema from issues #11–#14).

### DHT storage

libp2p Kad-DHT stores the **SignedEnvelope CBOR bytes** under a namespaced key:

- provider: `/decent-registry/provider/{object_hash}`

`get` reads the envelope, verifies it, and returns the decoded provider payload.

## CLI

Console script: `decent-registry`

### `node`

Runs a libp2p Kad-DHT node.

- Emits the node peer id and listen multiaddr (when `-v/--verbose` is used).
- `--bootstrap` is optional; when provided it must be a libp2p **identify-style multiaddr** that includes `/p2p/<peerid>`.
- `--run-seconds` runs bootstrap + listen for N seconds then exits.

Example (seed node, run until Ctrl-C):

```bash
decent-registry node --host 127.0.0.1 --port 9000 -v
```

To form a bootstrap destination from this output:

```
bootstrap = <listen_multiaddr>/p2p/<peer_id>
```

### `put`

Publishes a **signed provider update** for `--object-hash` (the DHT key).

Requires an Ed25519 owner private key (`--owner-privkey`) and a strictly monotonic `--seq` per `--object-hash`.

Provider endpoints must be **multiaddrs** starting with `/` (e.g. `/ip4/127.0.0.1/tcp/9000`).

```bash
decent-registry put \
  --host 127.0.0.1 --port <node_port> \
  --bootstrap <bootstrap> \
  --object-hash <64-hex> \
  --provider-id <64-hex> \
  --owner-privkey <ed25519_privkey_hex_64> \
  --seq 1 \
  --endpoint <multiaddr> \
  --endpoint <multiaddr>   # optional (repeatable)
```

Notes:
- `--endpoint` may also be passed comma-separated; endpoints are normalized to lexicographic order before signing.
- The stored value is a canonical-CBOR signed envelope; verification enforces signature validity and seq monotonicity at overwrite time.
- The signed-provider path currently has no TTL/expiry fields; TTL/expiry exists only in the legacy JSON `ProviderRecord` API in the DHT layer.

### `get`

Resolves `--object-hash` to provider endpoints.

```bash
decent-registry get \
  --host 127.0.0.1 --port <node_port> \
  --bootstrap <bootstrap> \
  --object-hash <64-hex>
```

On success prints JSON:
- `object_key`: the queried `--object-hash`
- `provider_id`: value from `--provider-id`
- `endpoints`: provider endpoints (as provided, normalized/sorted)

On missing prints `not found` and exits non-zero.

### Keys (Ed25519)

Example: generate an owner private key hex for `--owner-privkey`.

```bash
python3 - <<'PY'
from libp2p.crypto.ed25519 import create_new_key_pair
kp = create_new_key_pair()
print(kp.private_key.to_bytes().hex())
PY
```

### Identity records

Identity record `put`/`get` is not exposed by the current CLI; see #25 for the README coverage plan and the finalized identity hashing rules.