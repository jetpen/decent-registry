from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from decent_registry.cli import _make_datastore_from_args
from decent_registry.durable_store import DEFAULT_MAPSIZE_BYTES, LMDBDatastore


def test_init_creates_lmdb_file(tmp_path: Path) -> None:
    db_path = tmp_path / "store.lmdb"
    store = LMDBDatastore(path=db_path, mapsize_bytes=1024 * 1024)
    store.open()
    try:
        assert db_path.exists(), "LMDB backing file should be created"
    finally:
        store.close()


def test_default_mapsize_is_1tb_when_omitted(tmp_path: Path) -> None:
    db_path = tmp_path / "store-default.lmdb"
    store = LMDBDatastore(path=db_path)
    store.open()
    try:
        assert store._mapsize_bytes == DEFAULT_MAPSIZE_BYTES
    finally:
        store.close()


def test_put_then_get(tmp_path: Path) -> None:
    db_path = tmp_path / "store.lmdb"
    key = b"k1"
    value = b"v1"

    with LMDBDatastore(path=db_path, mapsize_bytes=1024 * 1024) as store:
        store.put(kind="provider", key=key, value=value)
        got = store.get(kind="provider", key=key)
        assert got == value


def test_persistence_across_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "store.lmdb"
    key = b"k1"
    value = b"v1"

    store = LMDBDatastore(path=db_path, mapsize_bytes=1024 * 1024)
    store.open()
    try:
        store.put(kind="provider", key=key, value=value)
        assert store.get(kind="provider", key=key) == value
    finally:
        store.close()

    store2 = LMDBDatastore(path=db_path, mapsize_bytes=1024 * 1024)
    store2.open()
    try:
        assert store2.get(kind="provider", key=key) == value
    finally:
        store2.close()


def test_cli_make_datastore_mapsize_propagates(tmp_path: Path) -> None:
    path = tmp_path / "x.lmdb"

    args = Namespace(datastore_path=path, mapsize=12345)
    store = _make_datastore_from_args(args)
    assert store._mapsize_bytes == 12345

    args2 = Namespace(datastore_path=path, mapsize=None)
    store2 = _make_datastore_from_args(args2)
    assert store2._mapsize_bytes == DEFAULT_MAPSIZE_BYTES
