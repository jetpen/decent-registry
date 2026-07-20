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
