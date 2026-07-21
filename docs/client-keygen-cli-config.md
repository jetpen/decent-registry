# Client key generation and CLI configuration

This document covers how a client (CLI) is configured to sign updates and talk to one or more `decent-registry` nodes.

Links:
- Protocol concepts: `docs/protocol-concepts.md`
- Implemented modules: `src/decent_registry/config.py`, `src/decent_registry/cli.py`, `src/decent_registry/registry_service.py`

Private key handling is file-path based. Private key material must never be printed/logged.

---

## 1) Generate an Ed25519 private key (`decent-registry keygen`)

Command:

```bash
decent-registry keygen --output <owner_privkey_pem_path>
```

Behavior (from `src/decent_registry/cli.py`):
- Generates an unencrypted Ed25519 private key in **PKCS#8 PEM** format.
- Writes the PEM to `<owner_privkey_pem_path>`.
- Sets file permissions to `0600` (`os.chmod(output_path, 0o600)`).
- Does not print key material.

Example:

```bash
mkdir -p ~/.decent
chmod 700 ~/.decent

decent-registry keygen --output ~/.decent/owner_privkey.pem
```

(Notes: ensure the output path is readable only by the current user.)

---

## 2) Client config file (`~/.decent/registry_cli.yaml`)

Default path (from `src/decent_registry/config.py` and `src/decent_registry/cli.py`):

- `~/.decent/registry_cli.yaml`

YAML structure:

```yaml
network:
  host: 127.0.0.1
  # Client commands require a TCP port number.
  port: 9000
  # Repeatable multiaddr(s) containing /p2p/<peerid>.
  # May be overridden per-command via CLI --bootstrap.
  bootstrap: []

datastore:
  # LMDB path used as the CLI local durable cache.
  # Default is repo-local .scratch/decent-registry.lmdb
  path: .scratch/decent-registry.lmdb
  # Optional LMDB mapsize_bytes.
  # mapsize_bytes: 1099511627776

logging:
  # 0=WARNING, 1=INFO, >=2=DEBUG
  verbosity: 0

crypto:
  # Filesystem path to an Ed25519 private key PEM.
  # Required when issuing `put identity` or `put provider`.
  owner_privkey_pem_path: ~/.decent/owner_privkey.pem
```

Config fields and their meanings:

### `network`
- `host`: client binds its libp2p host to this IP (default `127.0.0.1`).
- `port`: TCP port number the client host listens on (required for client commands after config/CLI merge).
- `bootstrap`: list of libp2p seed destinations used to connect peers before doing `put`/`get`.
  - Each bootstrap entry must be an identify-style multiaddr containing `/p2p/<peerid>`.

### `datastore`
- `path`: LMDB storage location for the CLI durable cache.
  - The CLI uses `LMDBDatastore` (see `src/decent_registry/durable_store.py`).
  - The value may point to a directory (server-style) or an `.lmdb` file (legacy-style).
- `mapsize_bytes`: optional LMDB map size; if omitted, LMDBDatastore’s default is used.

### `logging`
- `verbosity`: integer controlling logger level.
  - `0` => WARNING, `1` => INFO, `>=2` => DEBUG.

### `crypto`
- `owner_privkey_pem_path`: filesystem path to the Ed25519 private key PEM.
  - Required for signing.

---

## 3) CLI flag precedence (config vs flags)

Every client command accepts `--config <path>` plus the following common overrides (from `src/decent_registry/cli.py` and `src/decent_registry/config.py`):

- `--host`, `--port`
- `--bootstrap <multiaddr>` (repeatable / may repeat comma-separated depending on parsing)
- `--datastore-path`
- `--mapsize`
- `-v/--verbose`

Override semantics:
- The CLI loads `~/.decent/registry_cli.yaml` (or `--config`).
- It applies any CLI flags on top of the loaded config.
- After overrides, it enforces required fields (e.g., client `network.port`).

Special case: signing key override
- `put identity` and `put provider` accept `--owner-privkey <pem path>`.
- This overrides `crypto.owner_privkey_pem_path` from the YAML config.

---

## 4) Runnable examples

### 4.1 Generate a key

```bash
decent-registry keygen --output ~/.decent/owner_privkey.pem
```

### 4.2 Minimal client config

Create `~/.decent/registry_cli.yaml`:

```yaml
network:
  host: 127.0.0.1
  port: 9001
  bootstrap:
    - "/ip4/127.0.0.1/tcp/9000/p2p/<NODE1_PEERID>"

datastore:
  path: .scratch/decent-registry.lmdb

logging:
  verbosity: 0

crypto:
  owner_privkey_pem_path: ~/.decent/owner_privkey.pem
```

### 4.3 Override signing key per command

```bash
decent-registry put identity \
  --config ~/.decent/registry_cli.yaml \
  --owner-name <OWNER_NAME_HEX> \
  --owner-privkey ~/.decent/other_owner_privkey.pem \
  --seq 1
```

Security requirement:
- The CLI must never echo private key material.

---

## 5) Parameter meaning cheat-sheet

- `--config`: path to `registry_cli.yaml`.
- `network.host` / `--host`: local IP bind for the libp2p host.
- `network.port` / `--port`: local TCP port bind (required for client commands).
- `network.bootstrap` / `--bootstrap`: list of identify-style multiaddrs containing `/p2p/<peerid>` used as DHT bootstrap destinations.
- `datastore.path` / `--datastore-path`: LMDB file/dir used for local durable caching.
- `datastore.mapsize_bytes` / `--mapsize`: LMDB mapsize_bytes.
- `logging.verbosity` / `--verbose`: log verbosity level.
- `crypto.owner_privkey_pem_path` / `--owner-privkey`: Ed25519 private key PEM path used to sign updates.
