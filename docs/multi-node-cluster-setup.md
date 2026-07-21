# Multi-node cluster setup (ticket #45)

## What `bootstrap` means in this implementation

In this repo, node-to-node discovery for Kad-DHT is driven by libp2p Kad-DHT “bootstrap” connections.

- The `decent-registry node` command reads `network.bootstrap` from the server YAML config.
- Each `network.bootstrap` entry is passed to `Libp2pKadDHT.bootstrap(seed)`.
- `Libp2pKadDHT.bootstrap()` requires an **identify-style multiaddr containing** `/p2p/<peerid>`.
- It parses that multiaddr into a peer-info and calls `host.connect(peer_info)`.

The CLI/client commands also use a `--bootstrap` argument with the same requirement (`/p2p/<peerid>`).

## Which values differ per node (2-node example)

For two nodes on one machine:

1) `network.port` (different listen TCP ports)
2) `datastore.path` (distinct LMDB directories per node)
3) node2 `network.bootstrap` (points node2 at node1 via node1’s listen multiaddr + `/p2p/<node1_peerid>`)

Everything else can be the same (e.g. `network.host: 127.0.0.1`, `logging.verbosity`).

## Copy/paste: Node1 + Node2 (node2 bootstraps to node1)

### Pre-step: pick ports

Example:
- node1 listen port: `9000`
- node2 listen port: `9001`

### Terminal 1: start node1 (seed)

Create node1 config:

```bash
mkdir -p ~/.decent

cat > ~/.decent/registry-node1.yaml <<'YAML'
network:
  host: 127.0.0.1
  port: 9000
  bootstrap: []

datastore:
  path: ~/.decent/registry-node1

logging:
  verbosity: 1
YAML
```

Run node1 (keep it running):

```bash
# -v forces INFO logging so you can capture the startup line
decent-registry node --config ~/.decent/registry-node1.yaml -v
```

At startup, capture the logged values:

- line shape (INFO):
  - `Node <node1_peer_id> listening on <node1_listen_multiaddr>`
- typically `<node1_listen_multiaddr>` is of the form:
  - `/ip4/127.0.0.1/tcp/9000`

Form the node2 bootstrap multiaddr:

```text
NODE1_BOOTSTRAP=<node1_listen_multiaddr>/p2p/<node1_peer_id>
```

Example shape:

```text
NODE1_BOOTSTRAP=/ip4/127.0.0.1/tcp/9000/p2p/<NODE1_PEERID>
```

In Terminal 2, set `NODE1_BOOTSTRAP` to the exact computed string above (copy/paste) before running the node2 config block.

### Terminal 2: start node2 (bootstraps to node1)

Create node2 config:

```bash
cat > ~/.decent/registry-node2.yaml <<YAML
network:
  host: 127.0.0.1
  port: 9001
  bootstrap:
    - "$NODE1_BOOTSTRAP"

datastore:
  path: ~/.decent/registry-node2

logging:
  verbosity: 1
YAML
```

Run node2 (keep it running):

```bash
decent-registry node --config ~/.decent/registry-node2.yaml -v
```

Expected behavior:
- node1 starts with empty `bootstrap`.
- node2 starts and attempts to connect to node1 using `network.bootstrap`.

If node2’s `bootstrap` multiaddr does not contain `/p2p/`, node startup will fail in `Libp2pKadDHT.bootstrap()`.

## Optional: quick sanity check (put/get via client)

Use the same bootstrap multiaddr in client commands.

1) In Terminal 3, generate an owner key:

```bash
decent-registry keygen --output ~/.decent/owner_privkey.pem
```

2) In Terminal 3, put an identity (seq=1):

```bash
OWNER_NAME_HEX=000102030405060708090a0b0c0d0e0f
SEQ=1

# Client ports are local to the client host; use ports distinct from node ports.
CLIENT_PORT=9100

decent-registry put identity \
  --host 127.0.0.1 \
  --port $CLIENT_PORT \
  --bootstrap $NODE1_BOOTSTRAP \
  --owner-name $OWNER_NAME_HEX \
  --owner-privkey ~/.decent/owner_privkey.pem \
  --seq $SEQ
```

3) In Terminal 3, get the identity:

```bash
CLIENT_PORT=9101

decent-registry get identity \
  --host 127.0.0.1 \
  --port $CLIENT_PORT \
  --bootstrap $NODE1_BOOTSTRAP \
  --owner-name $OWNER_NAME_HEX
```

On success, `get identity` prints a JSON object with `seq` matching the latest accepted update.

---

EOF
