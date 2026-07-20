from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import lmdb  # type: ignore[import-not-found]

DEFAULT_MAPSIZE_BYTES = 1 * 1024**4  # 1TB


class LMDBDatastore:
    """Embedded durable KV store for decent-registry.

    Stores CBOR envelope bytes keyed by the registry lookup key bytes.
    Uses separate LMDB named DBs to isolate provider vs identity keyspaces.
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

        if self._path.parent:
            self._path.parent.mkdir(parents=True, exist_ok=True)

        # subdir=False => `path` is the lmdb file; LMDB creates sparse backing.
        env = lmdb.open(
            str(self._path),
            map_size=self._mapsize_bytes,
            max_dbs=2,
            subdir=False,
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
