from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import threading

import pytest
import trio

from libp2p.crypto.ed25519 import create_new_key_pair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from decent_registry.dht.libp2p_dht import Libp2pKadDHT


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _decent_registry_exe() -> str:
    import os

    cli_exe = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "decent-registry")
    )
    assert os.path.exists(cli_exe), f"console script not found: {cli_exe}"
    return cli_exe


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    exe = _decent_registry_exe()
    cmd = [exe] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def _start_libp2p_seed(seed_port: int, alive_seconds: float = 15.0):
    ready_q: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=1)

    def _runner():
        async def _seed_main():
            async with Libp2pKadDHT(listen=f"/ip4/127.0.0.1/tcp/{seed_port}") as dht:
                peer_id = dht.host.get_id().to_string()
                listen = dht.get_listen_multiaddr()
                ready_q.put((peer_id, listen))
                await trio.sleep(alive_seconds)

        trio.run(_seed_main)

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    peer_id, listen = ready_q.get(timeout=20)
    bootstrap = f"{listen}/p2p/{peer_id}"
    return t, bootstrap


def _write_ed25519_privkey_pem(tmp_path, *, filename: str = "owner_privkey.pem") -> str:
    owner_kp = create_new_key_pair()
    owner_seed = owner_kp.private_key.to_bytes()  # 32-byte Ed25519 seed

    crypto_priv = Ed25519PrivateKey.from_private_bytes(owner_seed)
    pem_bytes = crypto_priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    path = tmp_path / filename
    path.write_bytes(pem_bytes)
    os.chmod(path, 0o600)
    return str(path)


ASSET_URL = "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64"


@pytest.mark.acceptance
def test_provider_record_stores_downloadable_object_url(tmp_path):
    # Default: skip (internet-dependent and DHT-end-to-end).
    if os.getenv("DECENT_REGISTRY_RUN_ACCEPTANCE") != "1":
        pytest.skip("set DECENT_REGISTRY_RUN_ACCEPTANCE=1 to run")

    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=12.0)

    obj_hash = "f" * 64
    provider_url = ASSET_URL
    owner_priv_pem_path = _write_ed25519_privkey_pem(tmp_path)
    endpoints = ["/ip4/127.0.0.1/tcp/9999"]

    put_res = _run_cli(
        [
            "put",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--object-hash",
            obj_hash,
            "--provider-url",
            provider_url,
            "--owner-privkey",
            owner_priv_pem_path,
            "--seq",
            "1",
            "--endpoint",
            ",".join(endpoints),
        ]
    )

    assert put_res.returncode == 0, (
        f"put failed: stdout={put_res.stdout} stderr={put_res.stderr}"
    )

    get_res = _run_cli(
        [
            "get",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--object-hash",
            obj_hash,
        ]
    )

    assert get_res.returncode == 0, (
        f"get failed: stdout={get_res.stdout} stderr={get_res.stderr}"
    )

    record = json.loads(get_res.stdout)
    assert record["object_key"] == obj_hash
    assert record["provider_url"] == provider_url

    # Optional: verify the URL is actually a downloadable binary (ELF magic).
    if os.getenv("DECENT_REGISTRY_RUN_ACCEPTANCE_DOWNLOAD") == "1":
        import urllib.request

        req = urllib.request.Request(
            provider_url,
            headers={"User-Agent": "decent-registry-tests", "Range": "bytes=0-63"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            head = r.read(64)
        assert head.startswith(b"\x7fELF"), "expected an ELF binary" 
