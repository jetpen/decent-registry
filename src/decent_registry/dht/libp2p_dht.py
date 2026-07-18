import json
import sys
import time
from dataclasses import dataclass
from typing import Any

import trio
from multiaddr import Multiaddr

from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.kad_dht.kad_dht import KadDHT, DHTMode
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.tools.anyio_service.context import background_trio_service


@dataclass
class ProviderRecord:
    """Registry application-level provider record (version 1 JSON schema)."""

    object_hash: str
    version: int = 1
    ttl_seconds: int = 172800
    expires_at: int = 0
    providers: list[dict[str, Any]] | None = None

    def to_bytes(self) -> bytes:
        d: dict[str, Any] = {
            "version": self.version,
            "object_hash": self.object_hash,
            "ttl_seconds": self.ttl_seconds,
            "expires_at": self.expires_at,
        }
        if self.providers is not None:
            d["providers"] = self.providers
        return json.dumps(d, sort_keys=True).encode("utf-8")

    @staticmethod
    def from_bytes(raw: bytes) -> "ProviderRecord":
        d = json.loads(raw.decode("utf-8"))
        return ProviderRecord(
            object_hash=d["object_hash"],
            version=d.get("version", 1),
            ttl_seconds=d.get("ttl_seconds", 0),
            expires_at=d.get("expires_at", 0),
            providers=d.get("providers"),
        )


class Libp2pKadDHT:
    """Thin adapter over libp2p Python Kad-DHT.

    Uses a namespaced Kad-DHT key to avoid collisions with other app data:
    `'/decent-registry/provider/{object_hash}'`.

    `libp2p.kad_dht` uses a trio-based service runtime; this adapter exposes
    async methods usable with pytest-trio.
    """

    def __init__(self, listen: str = "/ip4/127.0.0.1/tcp/0"):
        self._key_pair = create_new_key_pair()
        self._listen = Multiaddr(listen)
        self._host = new_host(key_pair=self._key_pair, enable_tcp=True)

        self._host_ctx: Any | None = None
        self._dht_ctx: Any | None = None
        self._dht: KadDHT | None = None

    @property
    def host(self):
        return self._host

    @property
    def dht(self) -> KadDHT:
        assert self._dht is not None
        return self._dht

    async def __aenter__(self) -> "Libp2pKadDHT":
        self._host_ctx = self._host.run(listen_addrs=[self._listen])
        try:
            await self._host_ctx.__aenter__()
        except Exception:
            self._host_ctx = None
            raise

        # Construct Kad-DHT once the swarm is running
        self._dht = KadDHT(
            self._host,
            DHTMode.SERVER,
            enable_random_walk=False,
            strict_validation=False,
        )
        self._dht_ctx = background_trio_service(self._dht)
        try:
            await self._dht_ctx.__aenter__()
        except Exception:
            # Ensure host context is cleaned up if DHT startup fails.
            if self._host_ctx is not None:
                await self._host_ctx.__aexit__(*sys.exc_info())
            self._dht_ctx = None
            self._host_ctx = None
            raise

        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._dht_ctx is not None:
            await self._dht_ctx.__aexit__(exc_type, exc, tb)
        if self._host_ctx is not None:
            await self._host_ctx.__aexit__(exc_type, exc, tb)

    def get_listen_multiaddr(self) -> str:
        addrs = [str(a) for a in self._host.get_addrs()]
        # pick first tcp addr
        for a in addrs:
            if "/tcp/" in a:
                return a
        raise RuntimeError("no tcp addr")

    async def bootstrap(self, remote_tcp_multiaddr: str) -> None:
        # Kad-DHT uses peer routing; host.connect expects a /p2p/<peerid> multiaddr.
        # remote_tcp_multiaddr may already contain /p2p/. Callers must provide an
        # identify-style destination (with /p2p/<peerid>) for routing.
        if "/p2p/" not in remote_tcp_multiaddr:
            raise ValueError(
                "bootstrap requires destination with /p2p/<peerid> (pass identify-style multiaddr)"
            )

        peer_info = info_from_p2p_addr(Multiaddr(remote_tcp_multiaddr))
        await self._host.connect(peer_info)

    def _kad_key(self, object_hash: str) -> str:
        return f"/decent-registry/provider/{object_hash}"

    async def put_provider_record(self, record: ProviderRecord) -> None:
        assert self._dht is not None
        await self._dht.put_value(self._kad_key(record.object_hash), record.to_bytes())

    async def get_provider_record(
        self, object_hash: str, quorum: int = 0
    ) -> ProviderRecord | None:
        assert self._dht is not None
        raw = await self._dht.get_value(
            self._kad_key(object_hash), quorum=quorum
        )
        if raw is None:
            return None

        record = ProviderRecord.from_bytes(raw)
        expires_at = record.expires_at or 0
        if expires_at > 0 and time.time() > expires_at:
            return None
        return record
