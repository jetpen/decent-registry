# Client provider record put/get (ticket #48)

## CLI subcommands

- `decent-registry put provider` publishes a signed provider update.
- `decent-registry get provider` resolves a provider record.

---

## Provider lookup key

DHT key is the literal `--object-hash` value (64 hex chars).

- `put provider` stores a canonical signed envelope under:

  `/decent-registry/provider/{object_hash}`

- `get provider` queries the same DHT key.

In code: `src/decent_registry/dht/libp2p_dht.py` uses:
- `kad_key = f"/decent-registry/provider/{object_hash}"` for provider records.

---

## `put provider` usage

### Minimal invocation

```bash
# Generate a signing key (once)
decent-registry keygen --output ~/.decent/owner_privkey.pem

# Put seq=1
# Note: --bootstrap must be an identify-style multiaddr containing /p2p/<peerid>.
decent-registry put provider \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEERID> \
  --object-hash <OBJECT_HASH_64HEX> \
  --provider-id <PROVIDER_ID_64HEX> \
  --owner-privkey ~/.decent/owner_privkey.pem \
  --seq 1 \
  --endpoint /ip4/127.0.0.1/tcp/9000
```

### Endpoint validation and signing

From `src/decent_registry/provider_schema.py`:

- `--endpoint` values are repeatable and are merged by the CLI into a list (comma-separated supported by the CLI).
- Each endpoint must:
  - start with `/` (multiaddr syntax)
  - be ≤ 256 UTF-8 bytes
- The endpoint list is limited to **32** entries.
- Before signing, endpoints are normalized to **lexicographically sorted order**.

So: the payload committed to the signature always uses `endpoints = sorted(endpoints)`.

---

## `get provider` usage

### Minimal invocation

```bash
decent-registry get provider \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEERID> \
  --object-hash <OBJECT_HASH_64HEX>
```

### What `get provider` prints

On success, stdout is a single JSON object (`json.dumps(..., indent=2, sort_keys=True)`), with keys:

```json
{
  "object_key": "<OBJECT_HASH_64HEX>",
  "provider_id": "<PROVIDER_ID_64HEX>",
  "endpoints": ["<multiaddr>", ...] 
}
```

- `endpoints` are returned in the normalized/sorted form.

On missing, stdout is:
- `not found`

and the command exits non-zero.

---

## Seq monotonic overwrite and owner collision rules

From `src/decent_registry/verification.py` (via `RecordValidator.validate_provider_overwrite`): for a fixed provider DHT key (= `object_hash`):

- `seq` must be **strictly increasing** (`seq <= prev.seq` is rejected).
- An overwrite is rejected if the signer’s `owner_public_key` changes ("owner collision").
- Canonical CBOR + signature validity are required.

Concretely:

1. `put provider --seq 1` succeeds.
2. `put provider --seq 2` succeeds.
3. `put provider --seq 1` (or any `<= prev.seq`) is rejected (non-zero exit).
4. `get provider` returns the latest accepted `seq`’s payload.

---

## Runnable end-to-end example (single copy/paste)

This script:

- starts a temporary libp2p Kad-DHT seed node
- generates an Ed25519 private key PEM file
- performs `put provider` seq=1, then seq=2
- verifies that a seq=1 overwrite is rejected
- performs `get provider` and verifies returned fields

Run from the repo root (`/home/ben/projects/decent-registry`):

```bash
python3 - <<'PY'
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
import hashlib

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from libp2p.crypto.ed25519 import create_new_key_pair


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_seed(seed_port: int, alive_seconds: float = 25.0):
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


def write_privkey_pem(tmpdir: Path) -> Path:
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


# Import after defining functions (keeps imports visible in the snippet)
from decent_registry.dht.libp2p_dht import Libp2pKadDHT

# Prefer the project venv (avoids collisions with other venvs on PATH).
exe_path = Path.cwd() / ".venv" / "bin" / "decent-registry"
if exe_path.exists():
    exe = str(exe_path)
else:
    exe = shutil.which("decent-registry")
    if not exe:
        raise RuntimeError(
            "decent-registry not found. Run from repo root with the project venv: "
            "cd <repo-root> && . .venv/bin/activate"
        )

obj = "f" * 64
provider_id = "a" * 64

endpoints = [
    "/ip4/127.0.0.1/tcp/10002",
    "/ip4/127.0.0.1/tcp/10001",  # intentionally unsorted
]
expected_endpoints = sorted(endpoints)

with tempfile.TemporaryDirectory() as td:
    tmpdir = Path(td)

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
            timeout=60,
        )
        return cp

    put1 = run_cli([
        "put",
        "provider",
        "--host", "127.0.0.1",
        "--port", str(client_port_1),
        "--bootstrap", seed_bootstrap,
        "--object-hash", obj,
        "--provider-id", provider_id,
        "--owner-privkey", str(owner_priv_pem_path),
        "--seq", "1",
        "--endpoint", ",".join(endpoints),
    ])
    assert put1.returncode == 0, (put1.stdout, put1.stderr)

    put2 = run_cli([
        "put",
        "provider",
        "--host", "127.0.0.1",
        "--port", str(client_port_2),
        "--bootstrap", seed_bootstrap,
        "--object-hash", obj,
        "--provider-id", provider_id,
        "--owner-privkey", str(owner_priv_pem_path),
        "--seq", "2",
        "--endpoint", ",".join(endpoints),
    ])
    assert put2.returncode == 0, (put2.stdout, put2.stderr)

    put3 = run_cli([
        "put",
        "provider",
        "--host", "127.0.0.1",
        "--port", str(client_port_3),
        "--bootstrap", seed_bootstrap,
        "--object-hash", obj,
        "--provider-id", provider_id,
        "--owner-privkey", str(owner_priv_pem_path),
        "--seq", "1",
        "--endpoint", ",".join(endpoints),
    ])
    assert put3.returncode != 0, (put3.stdout, put3.stderr)

    get1 = run_cli([
        "get",
        "provider",
        "--host", "127.0.0.1",
        "--port", str(client_port_get),
        "--bootstrap", seed_bootstrap,
        "--object-hash", obj,
    ])
    assert get1.returncode == 0, (get1.stdout, get1.stderr)

    record = json.loads(get1.stdout)
    assert record["object_key"] == obj
    assert record["provider_id"] == provider_id
    assert record["endpoints"] == expected_endpoints

    print(json.dumps(record, indent=2, sort_keys=True))
PY
```

---

EOF
