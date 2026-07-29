import os
import re

from .test_cli_node import _decent_registry_exe, _free_port, _run_cli


def _extract_peer_id(stdout: str) -> str:
    # Node prints: [BOOTSTRAP] <listen_maddr>/p2p/<peer_id>
    m = re.search(r"\[BOOTSTRAP\]\s+.*?/p2p/([^\s]+)", stdout)
    assert m, f"no peer id found in stdout: {stdout}"
    return m.group(1)


def test_node_identity_private_key_is_persisted_across_restarts(tmp_path):
    exe = _decent_registry_exe()
    assert os.path.exists(exe)

    datastore_path = tmp_path / "node-datastore"

    port1 = _free_port()
    res1 = _run_cli(
        [
            "node",
            "--host",
            "127.0.0.1",
            "--port",
            str(port1),
            "--run-seconds",
            "0.3",
            "--datastore-path",
            str(datastore_path),
        ]
    )
    assert res1.returncode == 0, f"stdout={res1.stdout} stderr={res1.stderr}"
    peer1 = _extract_peer_id(res1.stdout)

    key_path = datastore_path / "node_privkey.bin"
    assert key_path.exists()
    assert (os.stat(key_path).st_mode & 0o777) == 0o600

    port2 = _free_port()
    res2 = _run_cli(
        [
            "node",
            "--host",
            "127.0.0.1",
            "--port",
            str(port2),
            "--run-seconds",
            "0.3",
            "--datastore-path",
            str(datastore_path),
        ]
    )
    assert res2.returncode == 0, f"stdout={res2.stdout} stderr={res2.stderr}"
    peer2 = _extract_peer_id(res2.stdout)

    assert peer1 == peer2
