import pytest
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.signed_envelope import encode_signed_envelope
from decent_registry.verification import make_signed_update_signature


@pytest.mark.trio
async def test_genuine_serving_peer_is_referred_and_can_join_routing_table():
    dht_a = Libp2pKadDHT()
    dht_b = Libp2pKadDHT()
    dht_c = Libp2pKadDHT()
    dht_d = Libp2pKadDHT()

    async with dht_a, dht_b, dht_c, dht_d:
        b_peer_id = dht_b.host.get_id()
        b_addr = dht_b.get_listen_multiaddr()
        b_dest = (
            b_addr if "/p2p/" in b_addr else f"{b_addr}/p2p/{b_peer_id.to_string()}"
        )
        await dht_a.bootstrap(b_dest)
        assert b_peer_id in dht_a.dht.routing_table.find_local_closest_peers(
            b_peer_id.to_bytes()
        )

        a_peer_id = dht_a.host.get_id()
        a_addr = dht_a.get_listen_multiaddr()
        a_dest = (
            a_addr if "/p2p/" in a_addr else f"{a_addr}/p2p/{a_peer_id.to_string()}"
        )
        await dht_c.bootstrap(a_dest)

        # C only connected to A. Learning B's address confirms A returned B as
        # a FIND_NODE referral; C then proves B directly with a fresh lookup.
        assert dht_c.host.get_peerstore().addrs(b_peer_id)
        await dht_c.dht.peer_routing.find_closest_peers_network(
            b_peer_id.to_bytes(), count=2
        )
        assert b_peer_id in dht_c.dht.routing_table.find_local_closest_peers(
            b_peer_id.to_bytes()
        )

        c_peer_id = dht_c.host.get_id()
        c_addr = dht_c.get_listen_multiaddr()
        c_dest = (
            c_addr if "/p2p/" in c_addr else f"{c_addr}/p2p/{c_peer_id.to_string()}"
        )
        await dht_d.bootstrap(c_dest)
        assert dht_d.host.get_peerstore().addrs(b_peer_id)


@pytest.mark.trio
async def test_kad_dht_put_get_two_nodes():
    obj_hash = "d" * 64
    provider_url = "https://example.com/object.bin"

    # Endpoints are lexicographically sorted before signing.
    endpoints_unsorted = ["/ip4/127.0.0.1/tcp/2", "/ip4/127.0.0.1/tcp/1"]
    endpoints_sorted = sorted(endpoints_unsorted)

    owner_kp = create_new_key_pair()
    owner_priv = owner_kp.private_key
    owner_pub_bytes = owner_kp.public_key.to_bytes()

    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=3,
        object_hash=obj_hash,
        provider_urls=[provider_url],
        endpoints=endpoints_unsorted,
    )
    signed_update_bytes = encode_signed_update(
        record_fields={1: owner_pub_bytes},
        payload=payload_dict,
        seq=1,
    )
    signature = make_signed_update_signature(
        signed_update_bytes_canonical=signed_update_bytes,
        owner_private_key=owner_priv,
    )
    envelope_cbor = encode_signed_envelope(
        signed_update_bytes=signed_update_bytes,
        signature=signature,
    )

    dht1 = Libp2pKadDHT()
    dht2 = Libp2pKadDHT()

    async with dht1, dht2:
        dht1_peer_id = dht1.host.get_id().to_string()
        dht1_tcp = dht1.get_listen_multiaddr()
        dest = dht1_tcp if "/p2p/" in dht1_tcp else f"{dht1_tcp}/p2p/{dht1_peer_id}"
        await dht2.bootstrap(dest)

        await dht1.put_signed_provider_record(obj_hash, envelope_cbor)

        got = await dht2.get_signed_provider_record(obj_hash)
        assert got is not None
        assert got.object_hash == obj_hash
        assert got.provider_urls == [provider_url]
        assert got.endpoints == endpoints_sorted
