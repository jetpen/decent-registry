import json
import os
import queue
import socket
import subprocess
import threading
import time

import trio

from decent_registry.dht.libp2p_dht import Libp2pKadDHT


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


def test_cli_put_get_round_trip_libp2p_kad_dht():
    # Start seed node inside the test process (trio runtime in a background thread)
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=12.0)

    obj = "f" * 64
    provider_id = "a" * 64
    endpoints = ["tcp://127.0.0.1:9999"]

    put_res = _run_cli(
        [
            "put",
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
            "--ttl-seconds",
            "10",
            "--endpoint",
            ",".join(endpoints),
        ]
    )
    assert put_res.returncode == 0, f"put failed: {put_res.stdout} {put_res.stderr}"

    get_res = _run_cli(
        [
            "get",
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
    assert record["object_hash"] == obj
    assert record["providers"][0]["provider_id"] == provider_id
    assert record["providers"][0]["endpoints"] == endpoints


def test_cli_get_expired_returns_not_found_libp2p_kad_dht():
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=25.0)

    obj = "e" * 64
    provider_id = "b" * 64
    endpoints = ["tcp://127.0.0.1:8888"]

    put_res = _run_cli(
        [
            "put",
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
            "--ttl-seconds",
            "5",
            "--endpoint",
            ",".join(endpoints),
        ]
    )
    assert put_res.returncode == 0, f"put failed: {put_res.stdout} {put_res.stderr}"

    # Ensure the record appears before waiting for expiry.
    found = False
    for _ in range(25):
        time.sleep(0.4)
        get_res = _run_cli(
            [
                "get",
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
        if get_res.returncode == 0:
            found = True
            break

    assert found, f"record never appeared before expiry: {get_res.stdout}"

    # TTL=5; wait for expiry.
    time.sleep(6.5)

    get_res2 = _run_cli(
        [
            "get",
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
    assert get_res2.returncode == 1
    assert "not found" in get_res2.stdout.lower()
