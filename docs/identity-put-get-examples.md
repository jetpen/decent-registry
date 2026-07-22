# Client identity record put/get (ticket #47)

## CLI subcommands

- `decent-registry put identity` publishes a signed identity record.
- `decent-registry get identity` resolves an identity record.

Both commands use the same key derivation from `--owner-name`.

---

## Key derivation: DHT lookup key

Identity record DHT key object
a) CLI input: `--owner-name <hex>`

b) In code (`src/decent_registry/registry_service.py`):

- `owner_name_bytes = bytes.fromhex(owner_name_hex)`
- `object_key_hex = sha256(owner_name_bytes).hexdigest()`

So the DHT lookup key is:

- `/decent-registry/identity/{sha256(owner_name_bytes).hexdigest()}`

---

## `put identity` usage

### Minimal invocation

```bash
# Generate a signing key (once)
decent-registry keygen --output ~/.decent/owner_privkey.pem

# Put seq=1
# Note: --bootstrap origin
#       - Start a seed node
#       - Copy the startup line printed by the server:
#         `[BOOTSTRAP] <listen_multiaddr>/p2p/<peer_id>`
#       - Use that entire multiaddr as the --bootstrap value
#       Walk-through: docs/multi-node-cluster-setup.md.
decent-registry put identity \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEERID> \
  --owner-name <OWNER_NAME_HEX> \
  --owner-privkey ~/.decent/owner_privkey.pem \
  --seq 1
```

### Stdout / stderr behavior

- On success the CLI prints the integer `1` to stdout.
- On failure it prints `put failed` to stderr and exits non-zero.

---

## `get identity` usage

### Minimal invocation

```bash
# Note: --bootstrap origin
# - Start a seed node; capture the printed line:
#   [BOOTSTRAP] <listen_multiaddr>/p2p/<peer_id>
# - Use that entire multiaddr as the --bootstrap value
# See docs/multi-node-cluster-setup.md.
decent-registry get identity \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEERID> \
  --owner-name <OWNER_NAME_HEX>
```

### What `get identity` prints

`get identity` prints a single JSON object (pretty-printed, `sort_keys=True`) with keys:

```json
{
  "object_key": "<sha256(owner_name_bytes).hexdigest()>",
  "owner_name": "<OWNER_NAME_HEX>",
  "owner_public_key": "<ED25519_PUBLIC_KEY_HEX>",
  "seq": 1
}
```

These fields come from the decoded/validated identity update in `src/decent_registry/dht/libp2p_dht.py`.

---

## Seq monotonic overwrite behavior

For a fixed identity DHT key, overwrite is accepted only if:

- `seq` is strictly increasing (strict monotonicity)
- the `owner_public_key` stays identical across updates (owner collision is rejected)
- the update is canonical and signature-valid

Concretely:

1. First `put identity --seq 1` succeeds.
2. Second `put identity --seq 2` succeeds.
3. Third `put identity` with `--seq 1` (or `--seq 2`) is rejected (non-zero exit).
4. `get identity` returns the highest accepted `seq`.

---

## Runnable end-to-end example (single copy/paste)

This script:

- starts a temporary libp2p Kad-DHT seed node (for routing)
- generates an Ed25519 private key PEM file
- performs `put identity` seq=1, then seq=2
- verifies that a seq=1 overwrite is rejected
- performs `get identity` and prints the resolved record

Run from the repo root (`/home/ben/projects/decent-registry`):

```bash
python3 - <<'PY'
import hashlib
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import trio

from pathlib import Path

# Ensure local imports (repo layout uses src/)
ROOT = Path(__file__).resolve().parent
SRC = (ROOT / "src").resolve()
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.dht.libp2p_dht import Libp2pKadDHT


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def cli_exe() -> str:
    exe = shutil.which("decent-registry")
    if not exe:
        raise RuntimeError("decent-registry not found in PATH")
    return exe


def write_privkey_pem(tmpdir: Path):
    # Use libp2p test pattern: generate an Ed25519 keypair seed, convert to OpenSSL/PKCS#8 PEM via cryptography
    kp = create_new_key_pair()
    seed = kp.private_key.to_bytes()  # 32-byte Ed25519 seed

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pem_bytes = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    pem_path = tmpdir / "owner_privkey.pem"
    pem_path.write_bytes(pem_bytes)
    os.chmod(pem_path, 0o600)
    return pem_path


def start_seed(seed_port: int, alive_seconds: float = 20.0):
    ready_q: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=1)

    def runner():
        async def seed_main():
            async with Libp2pKadDHT(listen=f"/ip4/127.0.0.1/tcp/{seed_port}") as dht:
                peer_id = dht.host.get_id().to_string()
                listen = dht.get_listen_multiaddr()
                ready_q.put((peer_id, listen))
                await trio.sleep(alive_seconds)

        trio.run(seed_main)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    peer_id, listen = ready_q.get(timeout=10)
    bootstrap = f"{listen}/p2p/{peer_id}"
    return t, bootstrap


exe = cli_exe()

with tempfile.TemporaryDirectory() as td:
    tmpdir = Path(td)

    owner_name_bytes = b"owner-name-doc"
    owner_name_hex = owner_name_bytes.hex()
    expected_object_key = hashlib.sha256(owner_name_bytes).hexdigest()

    seed_port = free_port()
    _, seed_bootstrap = start_seed(seed_port, alive_seconds=25.0)

    client_port_1 = free_port()
    client_port_2 = free_port()
    client_port_3 = free_port()
    client_port_get = free_port()

    owner_priv_pem_path = write_privkey_pem(tmpdir)

    def run_cli(args):
        cp = subprocess.run(
            [exe] + args,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return cp

    # put seq=1
    put1 = run_cli([
        "put",
        "identity",
        "--host", "127.0.0.1",
        "--port", str(client_port_1),
        "--bootstrap", seed_bootstrap,
        "--owner-name", owner_name_hex,
        "--owner-privkey", str(owner_priv_pem_path),
        "--seq", "1",
    ])
    assert put1.returncode == 0, (put1.stdout, put1.stderr)

    # put seq=2 (should succeed)
    put2 = run_cli([
        "put",
        "identity",
        "--host", "127.0.0.1",
        "--port", str(client_port_2),
        "--bootstrap", seed_bootstrap,
        "--owner-name", owner_name_hex,
        "--owner-privkey", str(owner_priv_pem_path),
        "--seq", "2",
    ])
    assert put2.returncode == 0, (put2.stdout, put2.stderr)

    # put seq=1 again (should fail)
    put3 = run_cli([
        "put",
        "identity",
        "--host", "127.0.0.1",
        "--port", str(client_port_3),
        "--bootstrap", seed_bootstrap,
        "--owner-name", owner_name_hex,
        "--owner-privkey", str(owner_priv_pem_path),
        "--seq", "1",
    ])
    assert put3.returncode != 0, put3.stdout

    # get (should return seq=2)
    get1 = run_cli([
        "get",
        "identity",
        "--host", "127.0.0.1",
        "--port", str(client_port_get),
        "--bootstrap", seed_bootstrap,
        "--owner-name", owner_name_hex,
    ])
    assert get1.returncode == 0, (get1.stdout, get1.stderr)

    record = json.loads(get1.stdout)
    assert record["object_key"] == expected_object_key
    assert record["owner_name"] == owner_name_hex
    assert record["seq"] == 2

    print(json.dumps(record, indent=2, sort_keys=True))
PY
```

Expected behavior:

- `put identity --seq 1` returns exit code 0.
- `put identity --seq 2` returns exit code 0.
- `put identity --seq 1` second attempt returns non-zero.
- `get identity` returns the record with `seq = 2`.
