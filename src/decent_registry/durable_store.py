from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import lmdb  # type: ignore[import-not-found]

DEFAULT_MAPSIZE_BYTES = 1 * 1024**4  # 1TB


class LMDBDatastore:
    """Embedded durable KV store for decent-registry.

    Stores CBOR envelope bytes keyed by the registry lookup key bytes.
    Uses separate LMDB named DBs to isolate provider vs identity keyspaces.

    `path` can be either:
    - a directory (spec-style server default): LMDB will create data.mdb/lock.mdb inside
    - a file path ending in `.lmdb` (legacy-style CLI default): LMDB will use that file
    """

    def __init__(
        self,
        *,
        path: str | Path,
        mapsize_bytes: int = DEFAULT_MAPSIZE_BYTES,
    ):
        self._path = Path(path)
        self._mapsize_bytes = int(mapsize_bytes)

        self._env: lmdb.Environment | None = None
        self._provider_db: Any = None
        self._identity_db: Any = None

    @property
    def path(self) -> Path:
        return self._path

    def open(self) -> None:
        if self._env is not None:
            return

        # Decide whether `path` is a directory (subdir=True) or a database file (subdir=False).
        # - If it exists and is a dir => subdir=True
        # - If it exists and is a file => subdir=False
        # - If it doesn't exist, treat `.lmdb` as a file and anything else as a directory.
        if self._path.exists():
            subdir = self._path.is_dir()
        else:
            subdir = self._path.suffix != ".lmdb"

        if subdir:
            self._path.mkdir(parents=True, exist_ok=True)
        else:
            if self._path.parent:
                self._path.parent.mkdir(parents=True, exist_ok=True)

        # subdir=True => `path` is a directory containing data.mdb.
        # subdir=False => `path` is the lmdb file.
        env = lmdb.open(
            str(self._path),
            map_size=self._mapsize_bytes,
            max_dbs=2,
            subdir=subdir,
            create=True,
        )

        provider_db = env.open_db(b"provider")
        identity_db = env.open_db(b"identity")

        self._env = env
        self._provider_db = provider_db
        self._identity_db = identity_db

    def close(self) -> None:
        if self._env is None:
            return
        self._env.close()
        self._env = None
        self._provider_db = None
        self._identity_db = None

    def __enter__(self) -> "LMDBDatastore":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def put(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
        value: bytes,
    ) -> None:
        self.open()
        assert self._env is not None
        assert self._provider_db is not None
        assert self._identity_db is not None

        db = self._provider_db if kind == "provider" else self._identity_db
        with self._env.begin(write=True, db=db) as txn:
            txn.put(key, value, overwrite=True)

    def get(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
    ) -> bytes | None:
        self.open()
        assert self._env is not None
        assert self._provider_db is not None
        assert self._identity_db is not None

        db = self._provider_db if kind == "provider" else self._identity_db
        with self._env.begin(write=False, db=db) as txn:
            return txn.get(key)
