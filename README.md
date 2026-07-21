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
- identity: `/decent-registry/identity/{object_key}`

`get` reads the envelope, verifies it, and returns the decoded record for the requested type.

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

Publishes a **signed record** into the DHT.

Usage:
- `decent-registry put provider ...`
- `decent-registry put identity ...`

`decent-registry put --help` lists record types; each record type has its own `--help` output.

#### `put provider`

Publishes a signed **provider update** under `--object-hash` (the DHT key).

Required:
- `--host`, `--port`, `--bootstrap`
- `--object-hash <64-hex>`
- `--provider-id <64-hex>`
- `--owner-privkey <owner_privkey_pem_path>`
- `--seq <monotonic int>`
- `--endpoint <multiaddr>` (repeatable; also accepts comma-separated)

Example:
```bash
decent-registry put provider \
  --host 127.0.0.1 --port <node_port> \
  --bootstrap <bootstrap> \
  --object-hash <64-hex> \
  --provider-id <64-hex> \
  --owner-privkey <owner_privkey_pem_path> \
  --seq 1 \
  --endpoint /ip4/127.0.0.1/tcp/9000
```

Notes:
- `--endpoint` values must start with `/` and are normalized/sorted lexicographically before signing.
- The stored value is a canonical-CBOR signed envelope; verification enforces signature validity and seq monotonicity.

#### `put identity`

Publishes a signed **identity update** under the DHT key:

- `object_key = sha256(owner_name_bytes)`

Required:
- `--host`, `--port`, `--bootstrap`
- `--owner-name <hex bytes>`
- `--owner-privkey <owner_privkey_pem_path>`
- `--seq <monotonic int>`

Example:
```bash
decent-registry put identity \
  --host 127.0.0.1 --port <node_port> \
  --bootstrap <bootstrap> \
  --owner-name <owner_name_hex> \
  --owner-privkey <owner_privkey_pem_path> \
  --seq 1
```

### `get`

Resolves a **signed record** from the DHT.

Usage:
- `decent-registry get provider ...`
- `decent-registry get identity ...`

#### `get provider`

Required:
- `--host`, `--port`, `--bootstrap`
- `--object-hash <64-hex>`

On success prints JSON:
- `object_key`: the queried DHT key
- `provider_id`
- `endpoints`: normalized/sorted provider endpoints

On missing prints `not found` and exits non-zero.

#### `get identity`

Required:
- `--host`, `--port`, `--bootstrap`
- `--owner-name <hex bytes>` (the DHT key is derived as `sha256(owner_name_bytes)`)

On success prints JSON:
- `object_key`
- `owner_name`
- `owner_public_key`
- `seq`

On missing prints `not found` and exits non-zero.

### Keys (Ed25519)

Generate an unencrypted PEM (PKCS#8) file for `--owner-privkey`:

```bash
decent-registry keygen [--output <path>]
```

CLI must receive the path to this PEM file. Private key contents must never be echoed or logged.

## Development

### Virtual environment / dependency install

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -e .[dev]
```

`.venv/` is ignored by Git (see `.gitignore`).

### Build the server and CLI

There is no separate build step: the CLI entry point is defined in `pyproject.toml` as:

- `decent-registry = "decent_registry.cli:main"`

After `pip install -e .[dev]`, the `decent-registry` executable is available from your shell.

### Running tests

```bash
pytest -q
```

Test discovery is configured in `pyproject.toml` via `testpaths = ["tests"]`.

### Packaging and release

Build artifacts:

```bash
pip install build twine
python -m build
```

This writes distributions to `dist/`.

(Optional) Publish to PyPI:

```bash
twine upload dist/*
```

### Repository organization

- `src/decent_registry/`: main package source (CLI, DHT adapter, signing/verification, schemas)
- `tests/`: pytest test suite
- `docs/`: project documentation
- `pyproject.toml`: build metadata + dependencies + pytest config
- `AGENTS.md`: agent coordination rules for this repo
- `README.md`: this document
- `.gitignore`: ignored paths (notably `.venv/`, `build/`, `dist/`, LMDB scratch)

See also:
- `docs/identity-put-get-examples.md` for a runnable end-to-end `put identity` / `get identity` example.
- `docs/provider-put-get-examples.md` for a runnable end-to-end `put provider` / `get provider` example.

