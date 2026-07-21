# decent-registry

## Overview

decent-registry enables applications and services to publish and resolve signed registry records without central coordination. This supports the broader vision of decentralization on the Internet by providing authenticated information that can be updated over time while remaining verifiable and ordered per key.

A record update is accepted only when it is cryptographically valid and consistent with prior state for that key, preventing unauthorized overwrites and making registry data tamper-evident for clients.

## Documentation

- Protocol concepts: `docs/protocol-concepts.md`
- Server setup:
  - `docs/single-node-server-setup.md`
  - `docs/multi-node-cluster-setup.md`
- Client key generation + configuration: `docs/client-keygen-cli-config.md`
- End-to-end examples:
  - `docs/provider-put-get-examples.md`
  - `docs/identity-put-get-examples.md`

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
- `--provider-url <url>`
- `--owner-privkey <owner_privkey_pem_path>`
- `--seq <monotonic int>`
- `--endpoint <multiaddr>` (repeatable; also accepts comma-separated)

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
- `provider_url`
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

