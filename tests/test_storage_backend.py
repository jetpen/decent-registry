from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from decent_registry.storage_backend import StorageBackend
from decent_registry.durable_store import LMDBDatastore


def test_storage_backend_protocol_is_satisfied_by_lmdb(tmp_path) -> None:
    store = LMDBDatastore(path=tmp_path / "store.lmdb", mapsize_bytes=1024 * 1024)
    assert isinstance(store, StorageBackend)


@dataclass
class FakeStorageBackend:
    def __post_init__(self) -> None:
        self._data: dict[tuple[str, bytes], bytes] = {}

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def put(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
        value: bytes,
    ) -> None:
        self._data[(kind, key)] = value

    def get(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
    ) -> bytes | None:
        return self._data.get((kind, key))


def test_fake_storage_backend_put_get_round_trip() -> None:
    store = FakeStorageBackend()
    store.put(kind="provider", key=b"k", value=b"v")
    assert store.get(kind="provider", key=b"k") == b"v"
    assert store.get(kind="provider", key=b"missing") is None
