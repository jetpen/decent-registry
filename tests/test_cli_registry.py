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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from decent_registry.cli import _load_ed25519_keypair_from_privkey_pem_path
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


def _write_ed25519_privkey_pem(tmp_path, *, filename: str = "owner_privkey.pem") -> tuple[str, str]:
    """Return (path, owner_public_key_hex)."""
    owner_kp = create_new_key_pair()
    owner_seed = owner_kp.private_key.to_bytes()  # 32-byte Ed25519 seed
    owner_pub_hex = owner_kp.public_key.to_bytes().hex()

    crypto_priv = Ed25519PrivateKey.from_private_bytes(owner_seed)
    pem_bytes = crypto_priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    path = tmp_path / filename
    path.write_bytes(pem_bytes)
    os.chmod(path, 0o600)
    return str(path), owner_pub_hex


def test_cli_put_get_round_trip_libp2p_kad_dht(tmp_path):
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=12.0)

    obj = "f" * 64
    provider_id = "a" * 64
    owner_priv_pem_path, _ = _write_ed25519_privkey_pem(tmp_path)

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
            owner_priv_pem_path,
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


def test_cli_seq_monotonic_overwrite_libp2p_kad_dht(tmp_path):
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=20.0)

    obj = "e" * 64
    provider_id = "b" * 64
    owner_priv_pem_path, _ = _write_ed25519_privkey_pem(tmp_path)

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
            owner_priv_pem_path,
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
            owner_priv_pem_path,
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
            owner_priv_pem_path,
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


def test_cli_identity_put_get_round_trip_libp2p_kad_dht(tmp_path):
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=20.0)

    owner_priv_pem_path, owner_pub_hex = _write_ed25519_privkey_pem(tmp_path)

    owner_name_bytes = b"owner-name-1"
    owner_name_hex = owner_name_bytes.hex()
    expected_object_key = hashlib.sha256(owner_name_bytes).hexdigest()

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
            owner_priv_pem_path,
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


def test_cli_identity_seq_monotonic_overwrite_rejected(tmp_path):
    seed_port = _free_port()
    _, seed_bootstrap = _start_libp2p_seed(seed_port, alive_seconds=25.0)

    owner_priv_pem_path, _ = _write_ed25519_privkey_pem(tmp_path)

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
            owner_priv_pem_path,
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
            owner_priv_pem_path,
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


def test_load_ed25519_keypair_from_pem_valid(tmp_path):
    pem_path, owner_pub_hex = _write_ed25519_privkey_pem(tmp_path)
    owner_priv, owner_pub_bytes = _load_ed25519_keypair_from_privkey_pem_path(pem_path)
    assert owner_pub_bytes.hex() == owner_pub_hex


def test_load_ed25519_keypair_from_pem_missing_file(tmp_path):
    missing_path = str(tmp_path / "missing-owner_privkey.pem")
    with pytest.raises(ValueError) as exc:
        _load_ed25519_keypair_from_privkey_pem_path(missing_path)
    assert str(exc.value) == "cannot read owner private key file"


def test_load_ed25519_keypair_from_pem_invalid_format(tmp_path):
    bad_path = tmp_path / "bad-owner_privkey.pem"
    bad_path.write_bytes(b"not a valid pem")
    with pytest.raises(ValueError) as exc:
        _load_ed25519_keypair_from_privkey_pem_path(str(bad_path))
    assert str(exc.value) == "invalid owner private key file"


def test_load_ed25519_keypair_from_pem_wrong_key_type(tmp_path):
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pem_bytes = rsa_priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pem_path = tmp_path / "rsa-owner_privkey.pem"
    pem_path.write_bytes(pem_bytes)

    with pytest.raises(ValueError) as exc:
        _load_ed25519_keypair_from_privkey_pem_path(str(pem_path))
    assert str(exc.value) == "invalid owner private key file"
