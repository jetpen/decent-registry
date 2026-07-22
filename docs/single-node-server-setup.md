# Single-node server setup and run (ticket #44)

## Server YAML config: `~/.decent/registry.yaml`

`decent-registry node` loads a server config YAML file from `--config` (default: `~/.decent/registry.yaml`).

YAML fields (from `src/decent_registry/config.py`):

### `network`

- `host` (default: `127.0.0.1`)
- `port` (**required**) integer in `1..65535`
- `bootstrap` (default: `[]`)
  - list of libp2p *seed* destinations
  - each entry must be an identify-style multiaddr containing `/p2p/<peerid>`
  - example: `"/ip4/127.0.0.1/tcp/9000/p2p/<PEERID>"`

### `datastore`

- `path` (default: `~/.decent/registry`)
  - can be a directory (server-style) or a file path ending in `.lmdb` (legacy-style)
- `mapsize_bytes` (optional)

### `logging`

- `verbosity` (default: `0`)
  - `0` => WARNING
  - `1` => INFO
  - `>=2` => DEBUG

Minimal example:

```yaml
network:
  host: 127.0.0.1
  port: 9000
  bootstrap: []

datastore:
  # Stored locally as LMDB durable cache.
  # Default is ~/.decent/registry
  path: ~/.decent/registry
  # mapsize_bytes: 1099511627776

logging:
  verbosity: 1
```

---

## `decent-registry node` command

From `src/decent_registry/cli.py`, the `node` subcommand supports:

- `--config <path>` (default: `~/.decent/registry.yaml`)
- `--host <ip>`
- `--port <int>`
- `--bootstrap <multiaddr>` (repeatable)
- `--datastore-path <path>`
- `--mapsize <bytes>`
- `--run-seconds <float>`: run bootstrap+listen for N seconds then exit
- `-v` / `--verbose`: sets logging verbosity (`-v` => INFO, `-vv` => DEBUG)

Notes:

- `--bootstrap` entries must include `/p2p/<peerid>`.
- In this codebase, the DHT node logs (at INFO level):

  `Node <peer_id> listening on <listen_multiaddr>`

  The server also prints the ready-to-use bootstrap multiaddr to stdout as:

  `[BOOTSTRAP] <listen_multiaddr>/p2p/<peer_id>`

  where `<listen_multiaddr>` is typically of the form:

  `/ip4/<host>/tcp/<port>`

---

## Single-node run (copy/paste)

### 1) Start the node

```bash
mkdir -p ~/.decent

cat > ~/.decent/registry.yaml <<'YAML'
network:
  host: 127.0.0.1
  port: 9000
  bootstrap: []

datastore:
  path: ~/.decent/registry

logging:
  verbosity: 1
YAML

# Run long enough to observe output; replace 30 with the duration you want.
# -v forces INFO even if your YAML sets a different verbosity.

decent-registry node \
  --config ~/.decent/registry.yaml \
  -v \
  --run-seconds 30
```

(Keep stdout/stderr from this command; the next step uses the printed values.)

### 2) Form the identify-style bootstrap multiaddr

From the server output:

- The full bootstrap multiaddr is printed as:
  `[BOOTSTRAP] <listen_multiaddr>/p2p/<peer_id>`
- Use the entire multiaddr after `[BOOTSTRAP]` as the value of `--bootstrap` in client commands.

Example shape:

```text
/ip4/127.0.0.1/tcp/9000/p2p/<PEERID>
```

---

## Optional: bounded demo script (prints derived bootstrap)

Runs the node briefly, extracts the server's `[BOOTSTRAP] ...` line, then prints the bootstrap multiaddr.

```bash
python3 - <<'PY'
import re
import subprocess
import sys
from pathlib import Path

import tempfile
import textwrap

with tempfile.TemporaryDirectory() as td:
    td_path = Path(td)
    cfg = td_path / 'registry.yaml'
    datastore_path = td_path / 'registry'

    cfg.write_text(
        textwrap.dedent(
            f"""\
            network:
              host: 127.0.0.1
              port: 9000
              bootstrap: []

            datastore:
              path: {datastore_path}

            logging:
              verbosity: 1
            """
        ),
        encoding='utf-8',
    )

    cmd = [
        'decent-registry','node',
        '--config', str(cfg),
        '-v',
        '--run-seconds','3'
    ]

    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr

    m = re.search(r"^\[BOOTSTRAP\]\s+(\S+)$", out, re.MULTILINE)
    if not m:
        print(out)
        raise SystemExit('could not parse [BOOTSTRAP] line')
    bootstrap = m.group(1)
    print(f"BOOTSTRAP={bootstrap}")
    print(f"exit_code={p.returncode}")


PY
```

This is meant as a demo for extracting the bootstrap multiaddr; record operations are covered in the client docs.

See:
- [`docs/identity-put-get-examples.md`](docs/identity-put-get-examples.md)
- [`docs/provider-put-get-examples.md`](docs/provider-put-get-examples.md)
