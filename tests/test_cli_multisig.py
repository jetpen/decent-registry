from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import subprocess
import threading
from pathlib import Path

import trio

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.encoding import is_canonical_cbor
from decent_registry.multisig_bundle import (
    MultisignatureBundle,
    draft_identity_bundle,
    draft_provider_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.record_validator import IdentityRecordResult, RecordValidator
from decent_registry.signed_envelope import decode_multisignature_envelope


def _cli_exe() -> str:
    exe = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "decent-registry")
    )
    assert os.path.exists(exe)
    return exe


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_cli_exe(), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _write_keypair_pem(tmp_path: Path, keypair, filename: str) -> Path:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(keypair.private_key.to_bytes())
    path = tmp_path / filename
    path.write_bytes(
        private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return path


def _signer_args(keypairs) -> list[str]:
    return [
        value
        for index, keypair in enumerate(keypairs)
        for value in ("--signer", f"{chr(ord('a') + index)}={keypair.public_key.to_bytes().hex()}")
    ]


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _start_libp2p_seed(seed_port: int, alive_seconds: float = 30.0):
    ready: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=1)

    def _runner() -> None:
        async def _seed_main() -> None:
            async with Libp2pKadDHT(listen=f"/ip4/127.0.0.1/tcp/{seed_port}") as dht:
                ready.put((dht.host.get_id().to_string(), dht.get_listen_multiaddr()))
                await trio.sleep(alive_seconds)

        trio.run(_seed_main)

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    peer_id, listen = ready.get(timeout=10)
    return thread, f"{listen}/p2p/{peer_id}"


def test_cli_bundle_identity_draft_sign_merge_finalize(tmp_path: Path):
    keypairs = [create_new_key_pair() for _ in range(3)]
    owner_name = b"cli-bundle-owner"
    draft_path = tmp_path / "draft.bundle.cbor"
    proof_a_path = tmp_path / "proof-a.bundle.cbor"
    proof_b_path = tmp_path / "proof-b.bundle.cbor"
    merged_path = tmp_path / "merged.bundle.cbor"
    finalized_path = tmp_path / "finalized.signed-envelope.cbor"

    draft = _run_cli(
        [
            "bundle",
            "draft",
            "identity",
            "--owner-name",
            owner_name.hex(),
            "--owner-public-key",
            keypairs[0].public_key.to_bytes().hex(),
            "--seq",
            "1",
            *_signer_args(keypairs),
            "--output",
            str(draft_path),
        ]
    )
    assert draft.returncode == 0, f"draft failed: {draft.stdout} {draft.stderr}"
    draft_bytes = draft_path.read_bytes()
    assert is_canonical_cbor(draft_bytes)
    assert keypairs[0].private_key.to_bytes() not in draft_bytes
    assert decode_multisignature_envelope(draft_bytes).proofs == ()

    for keypair, proof_path in (
        (keypairs[0], proof_a_path),
        (keypairs[1], proof_b_path),
    ):
        private_path = _write_keypair_pem(tmp_path, keypair, f"{proof_path.stem}.pem")
        signed = _run_cli(
            [
                "bundle",
                "sign",
                "--input",
                str(draft_path),
                "--signer-privkey",
                str(private_path),
                "--output",
                str(proof_path),
            ]
        )
        assert signed.returncode == 0, f"sign failed: {signed.stdout} {signed.stderr}"
        assert len(decode_multisignature_envelope(proof_path.read_bytes()).proofs) == 1

    merged = _run_cli(
        [
            "bundle",
            "merge",
            "--input",
            str(proof_a_path),
            "--proof",
            str(proof_b_path),
            "--output",
            str(merged_path),
        ]
    )
    assert merged.returncode == 0, f"merge failed: {merged.stdout} {merged.stderr}"
    assert [
        proof[1] for proof in decode_multisignature_envelope(merged_path.read_bytes()).proofs
    ] == ["a", "b"]

    finalized = _run_cli(
        [
            "bundle",
            "finalize",
            "--input",
            str(merged_path),
            "--output",
            str(finalized_path),
        ]
    )
    assert finalized.returncode == 0, f"finalize failed: {finalized.stdout} {finalized.stderr}"
    finalized_bytes = finalized_path.read_bytes()
    assert is_canonical_cbor(finalized_bytes)
    resolved = RecordValidator().validate_identity_get(
        record_key=hashlib.sha256(owner_name).digest(),
        envelope_cbor=finalized_bytes,
    )
    assert isinstance(resolved, IdentityRecordResult)
    assert resolved.owner_name_hex == owner_name.hex()
    assert resolved.authorization.threshold == 2


def test_cli_bundle_provider_draft_is_resolvable(tmp_path: Path):
    keypairs = [create_new_key_pair() for _ in range(3)]
    object_hash = "a" * 64
    output = tmp_path / "provider.bundle.cbor"
    result = _run_cli(
        [
            "bundle",
            "draft",
            "provider",
            "--object-hash",
            object_hash,
            "--provider-url",
            "https://example.com/provider.bin",
            "--endpoint",
            "/ip4/127.0.0.1/tcp/9000",
            "--owner-public-key",
            keypairs[0].public_key.to_bytes().hex(),
            "--seq",
            "1",
            *_signer_args(keypairs),
            "--output",
            str(output),
        ]
    )
    assert result.returncode == 0, f"provider draft failed: {result.stdout} {result.stderr}"
    draft_bytes = output.read_bytes()
    assert is_canonical_cbor(draft_bytes)
    bundle = MultisignatureBundle.from_cbor(draft_bytes)
    assert bundle.record_kind == 2
    assert bundle.threshold == 2
    assert bundle.proofs == ()


def test_cli_bundle_rejects_incomplete_duplicate_and_nonmember_proofs(tmp_path: Path):
    keypairs = [create_new_key_pair() for _ in range(4)]
    draft_path = tmp_path / "draft.cbor"
    partial_path = tmp_path / "partial.cbor"
    finalized_path = tmp_path / "should-not-exist.cbor"
    owner_name = b"cli-rejection-owner"

    draft = _run_cli(
        [
            "bundle",
            "draft",
            "identity",
            "--owner-name",
            owner_name.hex(),
            "--owner-public-key",
            keypairs[0].public_key.to_bytes().hex(),
            "--seq",
            "1",
            *_signer_args(keypairs[:3]),
            "--output",
            str(draft_path),
        ]
    )
    assert draft.returncode == 0

    incomplete = _run_cli(
        [
            "bundle",
            "finalize",
            "--input",
            str(draft_path),
            "--output",
            str(finalized_path),
        ]
    )
    assert incomplete.returncode != 0
    assert not finalized_path.exists()

    signer_path = _write_keypair_pem(tmp_path, keypairs[0], "member-a.pem")
    signed = _run_cli(
        [
            "bundle",
            "sign",
            "--input",
            str(draft_path),
            "--signer-privkey",
            str(signer_path),
            "--output",
            str(partial_path),
        ]
    )
    assert signed.returncode == 0

    resign_path = _write_keypair_pem(tmp_path, keypairs[1], "member-b.pem")
    resign = _run_cli(
        [
            "bundle",
            "sign",
            "--input",
            str(partial_path),
            "--signer-privkey",
            str(resign_path),
            "--output",
            str(tmp_path / "resigned.cbor"),
        ]
    )
    assert resign.returncode != 0

    other_draft_path = tmp_path / "other-draft.cbor"
    other_partial_path = tmp_path / "other-partial.cbor"
    other_draft = _run_cli(
        [
            "bundle",
            "draft",
            "identity",
            "--owner-name",
            b"different-owner".hex(),
            "--owner-public-key",
            keypairs[0].public_key.to_bytes().hex(),
            "--seq",
            "1",
            *_signer_args(keypairs[:3]),
            "--output",
            str(other_draft_path),
        ]
    )
    assert other_draft.returncode == 0
    wrong_bundle_proof = _run_cli(
        [
            "bundle",
            "sign",
            "--input",
            str(other_draft_path),
            "--signer-privkey",
            str(signer_path),
            "--output",
            str(other_partial_path),
        ]
    )
    assert wrong_bundle_proof.returncode == 0
    wrong_bundle_merge = _run_cli(
        [
            "bundle",
            "merge",
            "--input",
            str(partial_path),
            "--proof",
            str(other_partial_path),
            "--output",
            str(tmp_path / "wrong-bundle.cbor"),
        ]
    )
    assert wrong_bundle_merge.returncode != 0

    duplicate = _run_cli(
        [
            "bundle",
            "merge",
            "--input",
            str(partial_path),
            "--proof",
            str(partial_path),
            "--output",
            str(tmp_path / "duplicate.cbor"),
        ]
    )
    assert duplicate.returncode != 0

    nonmember_path = _write_keypair_pem(tmp_path, keypairs[3], "nonmember.pem")
    nonmember = _run_cli(
        [
            "bundle",
            "sign",
            "--input",
            str(draft_path),
            "--signer-privkey",
            str(nonmember_path),
            "--output",
            str(tmp_path / "nonmember.cbor"),
        ]
    )
    assert nonmember.returncode != 0

    mixed = _run_cli(
        [
            "put",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--datastore-path",
            str(tmp_path / "mixed.lmdb"),
            "--object-hash",
            "d" * 64,
            "--provider-url",
            "https://example.com/legacy.bin",
            "--finalized-envelope",
            str(draft_path),
        ]
    )
    assert mixed.returncode != 0

    missing_provider_key = _run_cli(
        [
            "put",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--object-hash",
            "e" * 64,
            "--provider-url",
            "https://example.com/missing-key.bin",
        ]
    )
    assert missing_provider_key.returncode != 0

    missing_identity_key = _run_cli(
        [
            "put",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--owner-name",
            owner_name.hex(),
        ]
    )
    assert missing_identity_key.returncode != 0


def test_cli_bundle_finalize_accepts_single_proof_upgrade(tmp_path: Path):
    keypairs = [create_new_key_pair() for _ in range(3)]
    draft_path = tmp_path / "upgrade-draft.cbor"
    partial_path = tmp_path / "upgrade-partial.cbor"
    finalized_path = tmp_path / "upgrade-finalized.cbor"
    owner_name = b"cli-upgrade-owner"

    draft = _run_cli(
        [
            "bundle",
            "draft",
            "identity",
            "--owner-name",
            owner_name.hex(),
            "--owner-public-key",
            keypairs[0].public_key.to_bytes().hex(),
            "--seq",
            "2",
            "--operation",
            "upgrade",
            *_signer_args(keypairs),
            "--output",
            str(draft_path),
        ]
    )
    assert draft.returncode == 0
    signer_path = _write_keypair_pem(tmp_path, keypairs[0], "upgrade-owner.pem")
    signed = _run_cli(
        [
            "bundle",
            "sign",
            "--input",
            str(draft_path),
            "--signer-privkey",
            str(signer_path),
            "--output",
            str(partial_path),
        ]
    )
    assert signed.returncode == 0
    finalized = _run_cli(
        [
            "bundle",
            "finalize",
            "--input",
            str(partial_path),
            "--output",
            str(finalized_path),
        ]
    )
    assert finalized.returncode == 0, f"upgrade finalize failed: {finalized.stdout} {finalized.stderr}"
    assert len(decode_multisignature_envelope(finalized_path.read_bytes()).proofs) == 1


def _finalize_bundle(bundle, keypairs):
    return finalize_bundle(
        merge_proof(
            merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key)),
            sign_bundle(bundle, keypairs[1].private_key),
        )
    )


def test_cli_put_get_finalized_envelopes_without_private_keys(tmp_path: Path):
    keypairs = [create_new_key_pair() for _ in range(3)]
    signer_set = [
        {1: chr(ord("a") + index), 2: keypair.public_key.to_bytes()}
        for index, keypair in enumerate(keypairs)
    ]
    owner_name = b"cli-finalized-owner"
    object_hash = "b" * 64
    provider_envelope = _finalize_bundle(
        draft_provider_bundle(
            object_hash=object_hash,
            provider_url="https://example.com/finalized.bin",
            endpoints=["/ip4/127.0.0.1/tcp/9001"],
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=1,
            signer_set=signer_set,
        ),
        keypairs,
    )
    identity_envelope = _finalize_bundle(
        draft_identity_bundle(
            owner_name=owner_name,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=1,
            signer_set=signer_set,
        ),
        keypairs,
    )
    provider_path = tmp_path / "provider-finalized.cbor"
    identity_path = tmp_path / "identity-finalized.cbor"
    provider_path.write_bytes(provider_envelope)
    identity_path.write_bytes(identity_envelope)

    _seed_thread, bootstrap = _start_libp2p_seed(_free_port(), alive_seconds=45.0)
    provider_store = tmp_path / "provider.lmdb"
    put_provider = _run_cli(
        [
            "put",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(provider_store),
            "--object-hash",
            object_hash,
            "--finalized-envelope",
            str(provider_path),
        ]
    )
    assert put_provider.returncode == 0, f"provider put failed: {put_provider.stdout} {put_provider.stderr}"
    get_provider = _run_cli(
        [
            "get",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(provider_store),
            "--object-hash",
            object_hash,
        ]
    )
    assert get_provider.returncode == 0, f"provider get failed: {get_provider.stdout} {get_provider.stderr}"
    provider_record = json.loads(get_provider.stdout)
    assert provider_record["object_key"] == object_hash
    assert provider_record["object_hash"] == object_hash
    assert provider_record["alg"] == "Ed25519"
    assert provider_record["version"] == 1
    assert provider_record["provider_url"] == "https://example.com/finalized.bin"
    assert provider_record["seq"] == 1
    assert provider_record["authorization"]["threshold"] == 2

    identity_store = tmp_path / "identity.lmdb"
    put_identity = _run_cli(
        [
            "put",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(identity_store),
            "--owner-name",
            owner_name.hex(),
            "--finalized-envelope",
            str(identity_path),
        ]
    )
    assert put_identity.returncode == 0, f"identity put failed: {put_identity.stdout} {put_identity.stderr}"
    get_identity = _run_cli(
        [
            "get",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(identity_store),
            "--owner-name",
            owner_name.hex(),
        ]
    )
    assert get_identity.returncode == 0, f"identity get failed: {get_identity.stdout} {get_identity.stderr}"
    identity_record = json.loads(get_identity.stdout)
    assert identity_record["owner_name"] == owner_name.hex()
    assert identity_record["seq"] == 1
    assert identity_record["authorization"]["threshold"] == 2

    stale_provider_path = tmp_path / "stale-provider.cbor"
    stale_provider_path.write_bytes(
        _finalize_bundle(
            draft_provider_bundle(
                object_hash=object_hash,
                provider_url="https://example.com/stale.bin",
                endpoints=["/ip4/127.0.0.1/tcp/9002"],
                owner_public_key=keypairs[0].public_key.to_bytes(),
                seq=1,
                signer_set=signer_set,
            ),
            keypairs,
        )
    )
    stale_put = _run_cli(
        [
            "put",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(provider_store),
            "--object-hash",
            object_hash,
            "--finalized-envelope",
            str(stale_provider_path),
        ]
    )
    assert stale_put.returncode != 0
    get_after_stale = _run_cli(
        [
            "get",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(provider_store),
            "--object-hash",
            object_hash,
        ]
    )
    assert get_after_stale.returncode == 0
    assert json.loads(get_after_stale.stdout)["provider_url"] == "https://example.com/finalized.bin"

    invalid_provider_hash = "c" * 64
    invalid_provider_path = tmp_path / "invalid-provider.cbor"
    invalid_provider_path.write_bytes(
        draft_provider_bundle(
            object_hash=invalid_provider_hash,
            provider_url="https://example.com/never-published.bin",
            endpoints=["/ip4/127.0.0.1/tcp/9003"],
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=1,
            signer_set=signer_set,
        ).to_cbor()
    )
    invalid_provider_put = _run_cli(
        [
            "put",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(tmp_path / "invalid-provider.lmdb"),
            "--object-hash",
            invalid_provider_hash,
            "--finalized-envelope",
            str(invalid_provider_path),
        ]
    )
    assert invalid_provider_put.returncode != 0
    invalid_provider_get = _run_cli(
        [
            "get",
            "provider",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(tmp_path / "invalid-provider.lmdb"),
            "--object-hash",
            invalid_provider_hash,
        ]
    )
    assert invalid_provider_get.returncode != 0

    invalid_owner_name = b"never-published-identity"
    invalid_identity_path = tmp_path / "invalid-identity.cbor"
    invalid_identity_path.write_bytes(
        draft_identity_bundle(
            owner_name=invalid_owner_name,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=1,
            signer_set=signer_set,
        ).to_cbor()
    )
    invalid_identity_store = tmp_path / "invalid-identity.lmdb"
    invalid_identity_put = _run_cli(
        [
            "put",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(invalid_identity_store),
            "--owner-name",
            invalid_owner_name.hex(),
            "--finalized-envelope",
            str(invalid_identity_path),
        ]
    )
    assert invalid_identity_put.returncode != 0
    invalid_identity_get = _run_cli(
        [
            "get",
            "identity",
            "--host",
            "127.0.0.1",
            "--port",
            str(_free_port()),
            "--bootstrap",
            bootstrap,
            "--datastore-path",
            str(invalid_identity_store),
            "--owner-name",
            invalid_owner_name.hex(),
        ]
    )
    assert invalid_identity_get.returncode != 0
