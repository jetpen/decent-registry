# decent-registry

A decentralized, eventually consistent DHT-based registry prototype.

## CLI

Console script: `decent-registry`

### `node`

Runs a libp2p Kad-DHT node.

- Emits the node peer id and listen multiaddr (when `-v/--verbose` is used).
- `--bootstrap` is optional; when provided it must be a libp2p **identify-style multiaddr** that includes `/p2p/<peerid>`.

Example (seed node, run until Ctrl-C):

```bash
decent-registry node --host 127.0.0.1 --port 9000 -v
```

To form a bootstrap destination from this output:

```
bootstrap = <listen_multiaddr>/p2p/<peer_id>
```

### `put`

Publishes a provider record for an `--object-hash`.

```bash
decent-registry put \
  --host 127.0.0.1 --port 0 \
  --bootstrap <bootstrap> \
  --object-hash <64-hex> \
  --provider-id <64-hex> \
  --ttl-seconds 600 \
  --endpoint tcp://host:port
```

### `get`

Resolves an `--object-hash` to provider endpoints.

```bash
decent-registry get \
  --host 127.0.0.1 --port 0 \
  --bootstrap <bootstrap> \
  --object-hash <64-hex>
```

Returns machine-readable JSON on success; prints `not found` and exits non-zero when expired/not present.
