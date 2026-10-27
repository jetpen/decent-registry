"""Opt-in native Registry regression for DHT referral eligibility.

Run only with explicit authorization by setting
``DECENT_REGISTRY_RUN_NATIVE_ISSUE_124=1`` and selecting this test. It starts
one real Registry node and separate CLI processes, so it is excluded from the
default suite.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from libp2p.crypto.ed25519 import create_new_key_pair

NATIVE_QUALIFICATION_ENV = "DECENT_REGISTRY_RUN_NATIVE_ISSUE_124"


@pytest.mark.acceptance
@pytest.mark.skipif(
    os.environ.get(NATIVE_QUALIFICATION_ENV) != "1",
    reason=f"requires explicit native qualification authorization via {NATIVE_QUALIFICATION_ENV}=1",
)
def test_separate_clients_publish_and_read_after_prior_clients_exit(tmp_path):
    with TemporaryDirectory(prefix="issue124-", dir=tmp_path) as temp_root:
        owned_path = Path(temp_root)
        python, runner = _write_instrumented_cli_runner(owned_path)
        owner_a_path, owner_a_pub = _write_owner_key(owned_path / "owner-a.pem")
        owner_b_path, owner_b_pub = _write_owner_key(owned_path / "owner-b.pem")
        owner_a = b"issue-124-owner-a-" + uuid.uuid4().bytes
        owner_b = b"issue-124-owner-b-" + uuid.uuid4().bytes
        client_peers = []
        used_ports: set[int] = set()

        with _running_registry(python, runner, owned_path, used_ports) as (
            bootstrap,
            server,
        ):
            _, publish_a = _put_identity(
                python,
                runner,
                owned_path,
                used_ports,
                bootstrap,
                client_name="publish-a",
                owner_name=owner_a,
                owner_key=owner_a_path,
            )
            client_peers.append(publish_a)

            # Each call is a distinct process with its own local datastore. Both
            # processes exit before the next operation starts.
            _, read_a_one = _get_identity(
                python,
                runner,
                owned_path,
                used_ports,
                bootstrap,
                "read-a-one",
                owner_a,
                owner_a_pub,
            )
            client_peers.append(read_a_one)
            _, read_a_two = _get_identity(
                python,
                runner,
                owned_path,
                used_ports,
                bootstrap,
                "read-a-two",
                owner_a,
                owner_a_pub,
            )
            client_peers.append(read_a_two)

            # This publish performs the existing-state lookup after both readers
            # have exited, exercising stale-referral handling against one live
            # Registry process.
            _, publish_b = _put_identity(
                python,
                runner,
                owned_path,
                used_ports,
                bootstrap,
                client_name="publish-b",
                owner_name=owner_b,
                owner_key=owner_b_path,
            )
            client_peers.append(publish_b)
            _, read_b = _get_identity(
                python,
                runner,
                owned_path,
                used_ports,
                bootstrap,
                "read-b-fresh",
                owner_b,
                owner_b_pub,
            )
            client_peers.append(read_b)

        _assert_independent_peers([server, *client_peers])


def _write_instrumented_cli_runner(tmp_path: Path) -> tuple[str, Path]:
    import sys

    python = Path(sys.executable)
    if not python.is_file():
        pytest.fail("locked-environment Python executable is unavailable")
    runner = tmp_path / "issue_124_registry_cli.py"
    runner.write_text(
        dedent(
            """
            import json
            import os
            import decent_registry.cli as cli

            _OriginalDHT = cli.Libp2pKadDHT

            class _ObservedDHT(_OriginalDHT):
                async def __aenter__(self):
                    result = await super().__aenter__()
                    print('__ISSUE124_DHT__' + json.dumps({
                        'pid': os.getpid(),
                        'peer_id': self.host.get_id().to_string(),
                        'listen': str(self.get_listen_multiaddr()),
                    }), flush=True)
                    return result

            cli.Libp2pKadDHT = _ObservedDHT
            cli.main()
            """
        ),
        encoding="utf-8",
    )
    return str(python), runner


def _free_port(used_ports: set[int]) -> int:
    for _ in range(100):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in used_ports:
            used_ports.add(port)
            return port
    raise RuntimeError("could not allocate a unique loopback port")


@contextmanager
def _running_registry(
    python: str, runner: Path, tmp_path: Path, used_ports: set[int]
) -> Iterator[tuple[str, dict[str, object]]]:
    port = _free_port(used_ports)
    stderr_path = tmp_path / "registry-node.stderr"
    datastore = tmp_path / "registry-node.lmdb"
    output: queue.Queue[str] = queue.Queue(maxsize=2)
    with stderr_path.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(
            [
                python,
                str(runner),
                "node",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--datastore-path",
                str(datastore),
            ],
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            bufsize=1,
        )
        stdout = process.stdout
        reader: threading.Thread | None = None
        try:
            if stdout is None:
                raise AssertionError("Registry stdout pipe was not created")

            def drain_stdout() -> None:
                for line in stdout:
                    if line.startswith(("[BOOTSTRAP] ", "__ISSUE124_DHT__")):
                        output.put(line)

            reader = threading.Thread(target=drain_stdout, daemon=True)
            reader.start()
            bootstrap, peer = _wait_for_bootstrap(process, output)
            if peer.get("pid") != process.pid:
                raise AssertionError("Registry child PID witness did not match")
            peer["port"] = port
            peer["datastore"] = str(datastore)
            yield bootstrap, peer
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if stdout is not None:
                stdout.close()
            if reader is not None:
                reader.join(timeout=1)


def _wait_for_bootstrap(
    process: subprocess.Popen[str], output: queue.Queue[str]
) -> tuple[str, dict[str, object]]:
    deadline = time.monotonic() + 30
    bootstrap: str | None = None
    peer: dict[str, object] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail("Registry node exited before advertising its bootstrap address")
        try:
            line = output.get(timeout=min(0.25, deadline - time.monotonic()))
        except queue.Empty:
            continue
        if line.startswith("[BOOTSTRAP] "):
            bootstrap = line.removeprefix("[BOOTSTRAP] ").strip()
        elif line.startswith("__ISSUE124_DHT__"):
            try:
                peer = json.loads(line.removeprefix("__ISSUE124_DHT__"))
            except json.JSONDecodeError:
                pytest.fail("Registry readiness witness was malformed")
        if bootstrap is not None and peer is not None:
            return bootstrap, peer
    pytest.fail("Registry node did not become ready before the startup deadline")
    raise AssertionError("unreachable")


def _write_owner_key(path: Path) -> tuple[str, str]:
    key_pair = create_new_key_pair()
    private_key = Ed25519PrivateKey.from_private_bytes(key_pair.private_key.to_bytes())
    path.write_bytes(
        private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )
    path.chmod(0o600)
    return str(path), key_pair.public_key.to_bytes().hex()


def _run_client(
    python: str,
    runner: Path,
    tmp_path: Path,
    used_ports: set[int],
    bootstrap: str,
    client_name: str,
    command: list[str],
) -> tuple[str, dict[str, object]]:
    port = _free_port(used_ports)
    datastore = tmp_path / f"{client_name}.lmdb"
    process = subprocess.Popen(
        [
            python,
            str(runner),
            *command,
            "--datastore-path",
            str(datastore),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--bootstrap",
            bootstrap,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, _stderr = process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise AssertionError(
            f"Registry client operation {client_name} timed out (output redacted)"
        ) from None
    if process.returncode != 0:
        pytest.fail(f"Registry client operation {client_name} failed (output redacted)")

    markers = [
        line.removeprefix("__ISSUE124_DHT__")
        for line in stdout.splitlines()
        if line.startswith("__ISSUE124_DHT__")
    ]
    if len(markers) != 1:
        raise AssertionError(f"Registry client {client_name} readiness witness missing")
    try:
        peer = json.loads(markers[0])
    except json.JSONDecodeError:
        raise AssertionError(
            f"Registry client {client_name} readiness witness malformed"
        ) from None
    if not isinstance(peer, dict):
        raise TypeError(f"Registry client {client_name} readiness witness malformed")
    if peer.get("pid") != process.pid:
        raise AssertionError(f"Registry client {client_name} PID witness did not match")
    peer["port"] = port
    peer["datastore"] = str(datastore)
    clean_stdout = "\n".join(
        line for line in stdout.splitlines() if not line.startswith("__ISSUE124_DHT__")
    )
    return clean_stdout, peer


def _put_identity(
    python: str,
    runner: Path,
    tmp_path: Path,
    used_ports: set[int],
    bootstrap: str,
    *,
    client_name: str,
    owner_name: bytes,
    owner_key: str,
) -> tuple[str, dict[str, object]]:
    return _run_client(
        python,
        runner,
        tmp_path,
        used_ports,
        bootstrap,
        client_name,
        [
            "put",
            "identity",
            "--owner-name",
            owner_name.hex(),
            "--owner-privkey",
            owner_key,
            "--seq",
            "1",
        ],
    )


def _get_identity(
    python: str,
    runner: Path,
    tmp_path: Path,
    used_ports: set[int],
    bootstrap: str,
    client_name: str,
    owner_name: bytes,
    owner_public_key: str,
) -> tuple[dict[str, object], dict[str, object]]:
    stdout, peer = _run_client(
        python,
        runner,
        tmp_path,
        used_ports,
        bootstrap,
        client_name,
        ["get", "identity", "--owner-name", owner_name.hex()],
    )
    try:
        record = json.loads(stdout)
    except json.JSONDecodeError:
        raise AssertionError(
            f"Registry returned a non-record response for {client_name}"
        ) from None
    if not isinstance(record, dict):
        raise TypeError(f"Registry returned a non-record response for {client_name}")
    _assert_identity(record, owner_name, owner_public_key)
    return record, peer


def _assert_independent_peers(peers: list[dict[str, object]]) -> None:
    for field in ("pid", "peer_id", "listen", "port", "datastore"):
        values = [peer.get(field) for peer in peers]
        if None in values or len(set(values)) != len(peers):
            pytest.fail(f"native DHT peers did not have distinct {field} values")


def _assert_identity(
    record: dict[str, object], owner_name: bytes, owner_public_key: str
) -> None:
    expected = (
        hashlib.sha256(owner_name).hexdigest(),
        owner_name.hex(),
        owner_public_key,
        1,
    )
    observed = (
        record.get("object_key"),
        record.get("owner_name"),
        record.get("owner_public_key"),
        record.get("seq"),
    )
    if observed != expected:
        pytest.fail("identity readback mismatch (record details redacted)")
