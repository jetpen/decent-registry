import json

import pytest
import trio

from libp2p.peer.peerinfo import info_from_p2p_addr
from multiaddr import Multiaddr

from decent_registry.dht.libp2p_dht import Libp2pKadDHT, ProviderRecord


@pytest.mark.trio
async def test_kad_dht_put_get_two_nodes():
    obj_hash = "d" * 64
    record = ProviderRecord(
        object_hash=obj_hash,
        ttl_seconds=10,
        expires_at=0,
        providers=[
            {
                "provider_id": "p1",
                "endpoints": ["tcp://127.0.0.1:1"],
                "last_seen": 0,
            }
        ],
    )

    dht1 = Libp2pKadDHT()
    dht2 = Libp2pKadDHT()

    async with dht1, dht2:
        # Build a /p2p/ destination for dht2 to connect to dht1.
        dht1_peer_id = dht1.host.get_id().to_string()
        dht1_tcp = dht1.get_listen_multiaddr()
        dest = (
            dht1_tcp
            if "/p2p/" in dht1_tcp
            else f"{dht1_tcp}/p2p/{dht1_peer_id}"
        )

        peer_info = info_from_p2p_addr(Multiaddr(dest))
        await dht2.host.connect(peer_info)

        await dht1.put_provider_record(record)

        got = None
        for _ in range(20):
            got = await dht2.get_provider_record(obj_hash)
            if got is not None:
                break
            await trio.sleep(0.3)

        assert got is not None
        assert got.object_hash == obj_hash
        assert got.providers == record.providers
