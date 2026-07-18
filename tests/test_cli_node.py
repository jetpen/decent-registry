import os
import queue
import socket
import subprocess
import threading

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
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)


def _start_libp2p_seed(seed_port: int, alive_seconds: float = 10.0):
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


def test_node_cli_bootstrap_success_exit_code_zero():
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=8.0)

    node_port = _free_port()
    res = _run_cli(
        [
            "node",
            "--host",
            "127.0.0.1",
            "--port",
            str(node_port),
            "--bootstrap",
            seed_bootstrap,
            "--run-seconds",
            "0.5",
        ]
    )

    assert res.returncode == 0, (
        f"expected exit code 0, got {res.returncode}\n"
        f"stdout:\n{res.stdout}\n"
        f"stderr:\n{res.stderr}\n"
    )


def test_node_cli_bootstrap_failure_exit_code_nonzero():
    # Missing /p2p/<peerid> -> libp2p adapter should reject quickly.
    bad_seed = "tcp://10.255.255.1:1"

    node_port = _free_port()
    res = _run_cli(
        [
            "node",
            "--host",
            "127.0.0.1",
            "--port",
            str(node_port),
            "--bootstrap",
            bad_seed,
            "--run-seconds",
            "0.2",
        ]
    )

    assert res.returncode == 1, (
        f"expected exit code 1, got {res.returncode}\n"
        f"stdout:\n{res.stdout}\n"
        f"stderr:\n{res.stderr}\n"
    )
