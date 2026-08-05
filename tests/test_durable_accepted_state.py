from __future__ import annotations

from pathlib import Path

from decent_registry.durable_store import LMDBDatastore


def test_put_if_newer_rejects_stale_and_equal_conflicts(tmp_path: Path) -> None:
    store = LMDBDatastore(path=tmp_path / "accepted.lmdb", mapsize_bytes=1024 * 1024)
    state_hash_1 = b"1" * 32
    state_hash_2 = b"2" * 32
    with store:
        assert store.put_if_newer(
            kind="identity",
            key=b"owner",
            value=b"state-1",
            seq=1,
            state_hash=state_hash_1,
        )
        assert not store.put_if_newer(
            kind="identity",
            key=b"owner",
            value=b"state-1-conflict",
            seq=1,
            state_hash=state_hash_2,
        )
        assert not store.put_if_newer(
            kind="identity",
            key=b"owner",
            value=b"state-1",
            seq=1,
            state_hash=state_hash_1,
        )
        assert not store.put_if_newer(
            kind="identity",
            key=b"owner",
            value=b"state-0",
            seq=0,
            state_hash=b"0" * 32,
        )
        assert store.get(kind="identity", key=b"owner") == b"state-1"
        assert store.put_if_newer(
            kind="identity",
            key=b"owner",
            value=b"state-2",
            seq=2,
            state_hash=state_hash_2,
        )
        assert store.get(kind="identity", key=b"owner") == b"state-2"


def test_accepted_state_metadata_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "accepted-restart.lmdb"
    state_hash = b"a" * 32
    with LMDBDatastore(path=path, mapsize_bytes=1024 * 1024) as store:
        assert store.put_if_newer(
            kind="provider",
            key=b"object",
            value=b"state-1",
            seq=1,
            state_hash=state_hash,
        )

    with LMDBDatastore(path=path, mapsize_bytes=1024 * 1024) as store:
        assert not store.put_if_newer(
            kind="provider",
            key=b"object",
            value=b"state-1-conflict",
            seq=1,
            state_hash=b"b" * 32,
        )
        assert store.put_if_newer(
            kind="provider",
            key=b"object",
            value=b"state-2",
            seq=2,
            state_hash=b"b" * 32,
        )
        assert store.get(kind="provider", key=b"object") == b"state-2"
