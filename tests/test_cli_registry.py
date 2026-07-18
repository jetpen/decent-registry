import json
import os
import socket
import subprocess
import time

from decent_registry.dht.protocol import DHTNode


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _decent_registry_exe() -> str:
    # Use absolute path to the venv console-script to avoid PATH issues
    # inside subprocesses.
    cli_exe = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "decent-registry")
    )
    assert os.path.exists(cli_exe), f"console script not found: {cli_exe}"
    return cli_exe


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    exe = _decent_registry_exe()
    cmd = [exe] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def test_cli_put_get_round_trip():
    seed_port = _free_port()
    seed = DHTNode("127.0.0.1", seed_port, k=5)
    seed.start()
    try:
        time.sleep(0.2)

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
                "--k",
                "5",
                "--bootstrap",
                f"tcp://127.0.0.1:{seed_port}",
                "--object-hash",
                obj,
                "--provider-id",
                provider_id,
                "--ttl-seconds",
                "60",
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
                f"tcp://127.0.0.1:{seed_port}",
                "--object-hash",
                obj,
            ]
        )
        assert get_res.returncode == 0, f"get failed: {get_res.stdout} {get_res.stderr}"

        record = json.loads(get_res.stdout)
        assert record["object_hash"] == obj
        assert record["providers"][0]["provider_id"] == provider_id
        assert record["providers"][0]["endpoints"] == endpoints

    finally:
        seed.stop()


def test_cli_get_expired_returns_not_found():
    seed_port = _free_port()
    seed = DHTNode("127.0.0.1", seed_port, k=5)
    seed.start()
    try:
        time.sleep(0.2)

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
                "--k",
                "5",
                "--bootstrap",
                f"tcp://127.0.0.1:{seed_port}",
                "--object-hash",
                obj,
                "--provider-id",
                provider_id,
                "--ttl-seconds",
                "1",
                "--endpoint",
                ",".join(endpoints),
            ]
        )
        assert put_res.returncode == 0, f"put failed: {put_res.stdout} {put_res.stderr}"

        time.sleep(1.6)

        get_res = _run_cli(
            [
                "get",
                "--host",
                "127.0.0.1",
                "--port",
                str(_free_port()),
                "--bootstrap",
                f"tcp://127.0.0.1:{seed_port}",
                "--object-hash",
                obj,
            ]
        )
        assert get_res.returncode == 1
        assert "not found" in get_res.stdout.lower()

    finally:
        seed.stop()
