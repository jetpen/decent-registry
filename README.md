# decent-registry

A decentralized, eventually consistent DHT-based registry prototype.

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

On missing/expired prints `not found` and exits non-zero.

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