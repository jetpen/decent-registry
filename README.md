# Decentralized Registry (decent-registry)

## Overview

decent-registry enables applications and services to publish and resolve signed registry records without central coordination. This supports the broader vision of decentralization on the Internet by providing authenticated information that can be updated over time while remaining verifiable and ordered per key.

A record update is accepted only when it is cryptographically valid and consistent with prior state for that key, preventing unauthorized overwrites and making registry data tamper-evident for clients.

## Scalability

Record lookup keys in this repo are SHA-256 digests of raw identifier bytes. Collision risk is therefore the probability that two distinct identifiers map to the same 256-bit digest.

Birthday bound (for n distinct identifiers stored/used):
- Exact: p ≈ 1 - exp(-n(n-1)/(2*2^256))
- Small-p approximation: p ≈ n^2 / 2^257

Numerical examples (approx):
- n = 1e9  => p ≈ 4.318e-60
- n = 1e12 => p ≈ 4.318e-54
- n = 1e18 => p ≈ 4.318e-42
- n for p ≈ 1e-2 (1%) => n ≈ 4.812e37

Conclusion: for any foreseeable number of identity/provider records, SHA-256 key clashes are effectively impossible; scaling is limited by storage/DHT capacity and not by digest collisions.

## Documentation

### Ecosystem and user documentation

- [Vision and ecosystem](docs/vision-and-ecosystem.md)
- [Companion services](docs/companion-services.md)
- [End-user scenarios](docs/end-user-scenarios.md)

### Application developer documentation

- [Developer guide](docs/developer-guide.md)

### Operator and integrator documentation

- Protocol concepts: [`docs/protocol-concepts.md`](docs/protocol-concepts.md)
- Server setup:
  - [`docs/single-node-server-setup.md`](docs/single-node-server-setup.md)
  - [`docs/multi-node-cluster-setup.md`](docs/multi-node-cluster-setup.md)
- Client key generation + configuration: [`docs/client-keygen-cli-config.md`](docs/client-keygen-cli-config.md)
- Multisignature records and migration: [`docs/multisignature-records.md`](docs/multisignature-records.md)
- End-to-end examples:
  - [`docs/provider-put-get-examples.md`](docs/provider-put-get-examples.md)
  - [`docs/identity-put-get-examples.md`](docs/identity-put-get-examples.md)

## CLI

Console script: `decent-registry`

### `node`

Runs a libp2p Kad-DHT node.

- Emits the node peer id and listen multiaddr (when `-v/--verbose` is used).
- `--bootstrap` is optional; when provided it must be a libp2p **identify-style multiaddr** that includes `/p2p/<peerid>`.
- `--run-seconds` runs bootstrap + listen for N seconds then exits.

Example (seed node, run until Ctrl-C):

```bash
decent-registry -v node --host 127.0.0.1 --port 9000
```

To form a bootstrap destination from this output:

```
bootstrap = <listen_multiaddr>/p2p/<peer_id>
```

### `bundle`

Creates and circulates a local **Multisignature Bundle** without centralizing private keys:

- `decent-registry bundle draft identity ...`
- `decent-registry bundle draft provider ...`
- `decent-registry bundle sign --input <bundle> --signer-privkey <pem> --output <proof-bundle>`
- `decent-registry bundle merge --input <bundle> --proof <proof-bundle> --output <merged-bundle>`
- `decent-registry bundle finalize --input <merged-bundle> --output <signed-envelope>`

`bundle sign` reads one local Ed25519 private-key PEM and emits a detached proof. `bundle merge` verifies proof binding, signer membership, duplicate rejection, and signature validity. `bundle finalize` requires the threshold or explicit legacy-owner upgrade proof rule. Partial bundles are local artifacts and must never be published. Signer replacement and explicit legacy upgrade are documented in [`docs/multisignature-records.md`](docs/multisignature-records.md), which contains the complete Identity and Provider workflows, wire format, migration rules, and compatibility matrix.

### `put`

Publishes a **legacy single-key or finalized version-1 multisignature record** into the DHT.

Usage:
- `decent-registry put provider ...`
- `decent-registry put identity ...`

`decent-registry put --help` lists record types; each record type has its own `--help` output.

#### `put provider`

Publishes a signed **provider update** under `--object-hash` (the DHT key).

Common:
- `--host`, `--port`, `--bootstrap`
- `--object-hash <64-hex>`

`legacy mode` requires:
- `--provider-url <url>`
- `--owner-privkey <owner_privkey_pem_path>`
- `--seq <monotonic int>`
- optional `--endpoint <multiaddr>` (repeatable; also accepts comma-separated)

Finalized mode requires:
- `--finalized-envelope <path>`

Finalized mode reads the Provider Record, sequence, and authorization from the finalized SignedEnvelope and cannot be combined with legacy signing arguments.

Example:
```bash
decent-registry put provider \
  --host 127.0.0.1 --port <node_port> \
  --bootstrap <bootstrap> \
  --object-hash <64-hex> \
  --provider-url <url> \
  --owner-privkey <owner_privkey_pem_path> \
  --seq 1 \
  --endpoint /ip4/127.0.0.1/tcp/9000
```

Notes:
- `--endpoint` values must start with `/` and are normalized/sorted lexicographically before signing.
- `legacy mode` stores a canonical-CBOR legacy SignedEnvelope; finalized mode stores a validated SignedEnvelope. A finalized version-1 multisignature SignedEnvelope is produced by the Bundle workflow.
- Verification enforces signature validity, lookup-key binding, Owner Binding, and strictly increasing `Seq` values.

#### `put identity`

Publishes a signed **identity update** under the DHT key:

- `object_key = sha256(owner_name_bytes)`

Common:
- `--host`, `--port`, `--bootstrap`
- `--owner-name <hex bytes>`

`legacy mode` requires:
- `--owner-privkey <owner_privkey_pem_path>`
- `--seq <monotonic int>`

Finalized mode requires:
- `--finalized-envelope <path>`

Finalized mode reads the Identity Record, sequence, and authorization from the finalized SignedEnvelope and cannot be combined with legacy signing arguments.

Example:
```bash
decent-registry put identity \
  --host 127.0.0.1 --port <node_port> \
  --bootstrap <bootstrap> \
  --owner-name <owner_name_hex> \
  --owner-privkey <owner_privkey_pem_path> \
  --seq 1
```

`legacy mode` creates a legacy SignedEnvelope. Finalized mode uses `--finalized-envelope` and accepts the versioned multisignature SignedEnvelope produced by the Bundle workflow without private-key material.

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
- `object_hash`
- `alg` and payload `version`
- `provider_url`
- `endpoints`: normalized/sorted provider endpoints
- `seq` and `authorization` for version-1 multisignature records; `authorization` includes the Signer Set, threshold, epoch, operation, predecessor-state hash, and accepted state hash

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
- `authorization` for version-1 multisignature records, including the Signer Set, threshold, epoch, operation, predecessor-state hash, and accepted state hash

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
- [`AGENTS.md`](AGENTS.md): agent coordination rules for this repo
- [`README.md`](README.md): this document
- `.gitignore`: ignored paths (notably `.venv/`, `build/`, `dist/`, LMDB scratch)

