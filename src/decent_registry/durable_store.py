from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import cbor2
import lmdb  # type: ignore[import-not-found]

DEFAULT_MAPSIZE_BYTES = 1 * 1024**4  # 1TB
_ACCEPTED_METADATA_KEYS = {1, 2}


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
        self._accepted_db: Any = None

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
            max_dbs=3,
            subdir=subdir,
            create=True,
        )

        provider_db = env.open_db(b"provider")
        identity_db = env.open_db(b"identity")
        accepted_db = env.open_db(b"accepted")

        self._env = env
        self._provider_db = provider_db
        self._identity_db = identity_db
        self._accepted_db = accepted_db

    def close(self) -> None:
        if self._env is None:
            return
        self._env.close()
        self._env = None
        self._provider_db = None
        self._identity_db = None
        self._accepted_db = None

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

    @staticmethod
    def _metadata_key(*, kind: Literal["provider", "identity"], key: bytes) -> bytes:
        return kind.encode("ascii") + b"\\x00" + bytes(key)

    @staticmethod
    def _extract_seq(value: bytes) -> int | None:
        try:
            envelope = cbor2.loads(value)
            if not isinstance(envelope, dict):
                return None
            if set(envelope) == {1, 2}:
                signed_update_bytes = envelope[1]
            elif set(envelope) == {1, 2, 3}:
                signed_update_bytes = envelope[2]
            else:
                return None
            signed_update = cbor2.loads(signed_update_bytes)
            seq = signed_update[3]
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                return None
            return seq
        except Exception:
            return None

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

    def put_if_newer(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
        value: bytes,
        seq: int,
        state_hash: bytes,
    ) -> bool:
        """Atomically install a strictly newer accepted envelope.

        The accepted metadata and envelope are committed in one LMDB write
        transaction. Existing raw values from older datastore versions are
        compared by decoding their SignedUpdate sequence when possible.
        """
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError("seq must be a non-negative integer")
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes")
        if not isinstance(state_hash, (bytes, bytearray)) or len(state_hash) != 32:
            raise ValueError("state_hash must be exactly 32 bytes")

        self.open()
        assert self._env is not None
        assert self._provider_db is not None
        assert self._identity_db is not None
        assert self._accepted_db is not None

        db = self._provider_db if kind == "provider" else self._identity_db
        metadata_key = self._metadata_key(kind=kind, key=key)
        metadata = cbor2.dumps({1: seq, 2: bytes(state_hash)}, canonical=True)

        with self._env.begin(write=True) as txn:
            current = txn.get(key, db=db)
            current_metadata = txn.get(metadata_key, db=self._accepted_db)
            if current is not None:
                current_seq: int | None = None
                if current_metadata is not None:
                    try:
                        decoded_metadata = cbor2.loads(current_metadata)
                        if (
                            isinstance(decoded_metadata, dict)
                            and set(decoded_metadata) == _ACCEPTED_METADATA_KEYS
                            and isinstance(decoded_metadata[1], int)
                            and not isinstance(decoded_metadata[1], bool)
                        ):
                            current_seq = decoded_metadata[1]
                    except Exception:
                        current_seq = None
                if current_seq is None:
                    current_seq = self._extract_seq(current)
                if current_seq is None or seq <= current_seq:
                    return False
            elif current_metadata is not None:
                return False

            txn.put(key, bytes(value), db=db, overwrite=True)
            txn.put(metadata_key, metadata, db=self._accepted_db, overwrite=True)
            return True
