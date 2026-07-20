import hashlib
import json
import os
import queue
import socket
import subprocess
import threading
import time

import pytest
import trio

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from libp2p.crypto.ed25519 import create_new_key_pair


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _decent_registry_exe() -> str:
    cli_exe = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "decent-registry")
    )
    assert os.path.exists(cli_exe), f"console script not found: {cli_exe}"
    return cli_exe


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    exe = _decent_registry_exe()
    cmd = [exe] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


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

    peer_id, listen = ready_q.get(timeout=10)
    bootstrap = f"{listen}/p2p/{peer_id}"
    return t, bootstrap


def _normalize_endpoints(endpoints: list[str]) -> list[str]:
    return sorted(endpoints)


def test_cli_put_get_round_trip_libp2p_kad_dht():
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=12.0)

    obj = "f" * 64
    provider_id = "a" * 64
    owner_priv_hex = create_new_key_pair().private_key.to_bytes().hex()

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
            obj,
            "--provider-id",
            provider_id,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "1",
            "--endpoint",
            ",".join(endpoints),
        ]
    )
    assert put_res.returncode == 0, f"put failed: {put_res.stdout} {put_res.stderr}"

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
            obj,
        ]
    )
    assert get_res.returncode == 0, f"get failed: {get_res.stdout} {get_res.stderr}"

    record = json.loads(get_res.stdout)
    assert record["object_key"] == obj
    assert record["provider_id"] == provider_id
    assert record["endpoints"] == _normalize_endpoints(endpoints)


def test_cli_seq_monotonic_overwrite_libp2p_kad_dht():
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=20.0)

    obj = "e" * 64
    provider_id = "b" * 64
    owner_priv_hex = create_new_key_pair().private_key.to_bytes().hex()

    endpoints_1 = ["/ip4/127.0.0.1/tcp/10001"]
    endpoints_2 = ["/ip4/127.0.0.1/tcp/10002"]
    endpoints_3 = ["/ip4/127.0.0.1/tcp/10003"]

    put1 = _run_cli(
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
            obj,
            "--provider-id",
            provider_id,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "1",
            "--endpoint",
            ",".join(endpoints_1),
        ]
    )
    assert put1.returncode == 0, f"put1 failed: {put1.stdout} {put1.stderr}"

    put2 = _run_cli(
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
            obj,
            "--provider-id",
            provider_id,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "2",
            "--endpoint",
            ",".join(endpoints_2),
        ]
    )
    assert put2.returncode == 0, f"put2 failed: {put2.stdout} {put2.stderr}"

    # Attempt overwrite with lower seq; should be rejected.
    put3 = _run_cli(
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
            obj,
            "--provider-id",
            provider_id,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "1",
            "--endpoint",
            ",".join(endpoints_3),
        ]
    )
    assert put3.returncode != 0, "expected lower-seq overwrite to fail"

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
            obj,
        ]
    )
    assert get_res.returncode == 0, f"get failed: {get_res.stdout} {get_res.stderr}"

    record = json.loads(get_res.stdout)
    assert record["object_key"] == obj
    assert record["provider_id"] == provider_id
    assert record["endpoints"] == _normalize_endpoints(endpoints_2)


def test_cli_identity_put_get_round_trip_libp2p_kad_dht():
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=20.0)

    owner_priv_hex = create_new_key_pair().private_key.to_bytes().hex()
    owner_name_bytes = b"owner-name-1"
    owner_name_hex = owner_name_bytes.hex()
    expected_object_key = hashlib.sha256(owner_name_bytes).hexdigest()

    # Derive expected owner pubkey from the owner privkey.
    owner_priv_cls = type(create_new_key_pair().private_key)
    owner_priv = owner_priv_cls.from_bytes(bytes.fromhex(owner_priv_hex))
    owner_pub_hex = owner_priv.get_public_key().to_bytes().hex()

    put_res = _run_cli(
        [
            "put",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--owner-name",
            owner_name_hex,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "1",
        ]
    )
    assert put_res.returncode == 0, f"put identity failed: {put_res.stdout} {put_res.stderr}"

    get_res = _run_cli(
        [
            "get",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--owner-name",
            owner_name_hex,
        ]
    )
    assert get_res.returncode == 0, f"get identity failed: {get_res.stdout} {get_res.stderr}"

    record = json.loads(get_res.stdout)
    assert record["object_key"] == expected_object_key
    assert record["owner_name"] == owner_name_hex
    assert record["owner_public_key"] == owner_pub_hex
    assert record["seq"] == 1


def test_cli_identity_seq_monotonic_overwrite_rejected():
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=25.0)

    owner_priv_hex = create_new_key_pair().private_key.to_bytes().hex()
    owner_name_bytes = b"owner-name-2"
    owner_name_hex = owner_name_bytes.hex()

    put1 = _run_cli(
        [
            "put",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--owner-name",
            owner_name_hex,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "1",
        ]
    )
    assert put1.returncode == 0, f"put identity 1 failed: {put1.stdout} {put1.stderr}"

    put2 = _run_cli(
        [
            "put",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--owner-name",
            owner_name_hex,
            "--owner-privkey",
            owner_priv_hex,
            "--seq",
            "1",
        ]
    )
    assert put2.returncode != 0, "expected lower/equal-seq overwrite to fail"

    get_res = _run_cli(
        [
            "get",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            seed_bootstrap,
            "--owner-name",
            owner_name_hex,
        ]
    )
    assert get_res.returncode == 0, f"get identity failed: {get_res.stdout} {get_res.stderr}"
    record = json.loads(get_res.stdout)
    assert record["seq"] == 1
