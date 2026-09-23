from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable


@runtime_checkable
class StorageBackend(Protocol):
    def open(self) -> None: ...
    def close(self) -> None: ...

    def put(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
        value: bytes,
    ) -> None: ...

    def get(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
    ) -> bytes | None: ...

    def get_history(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
    ) -> tuple[bytes, ...] | None: ...

    def put_if_newer(
        self,
        *,
        kind: Literal["provider", "identity"],
        key: bytes,
        value: bytes,
        seq: int,
        state_hash: bytes,
        history: tuple[bytes, ...] | None = None,
    ) -> bool: ...
