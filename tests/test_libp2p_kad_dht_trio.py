import pytest
import trio

from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.peer.peerinfo import info_from_p2p_addr
from multiaddr import Multiaddr

from decent_registry.encoding import encode_signed_update
from decent_registry.provider_schema import build_provider_payload_dict
from decent_registry.signed_envelope import encode_signed_envelope
from decent_registry.verification import make_signed_update_signature
from decent_registry.dht.libp2p_dht import Libp2pKadDHT


@pytest.mark.trio
async def test_kad_dht_put_get_two_nodes():
    obj_hash = "d" * 64
    provider_id = "p1"

    # Endpoints are lexicographically sorted before signing.
    endpoints_unsorted = ["/ip4/127.0.0.1/tcp/2", "/ip4/127.0.0.1/tcp/1"]
    endpoints_sorted = sorted(endpoints_unsorted)

    owner_kp = create_new_key_pair()
    owner_priv = owner_kp.private_key
    owner_pub_bytes = owner_kp.public_key.to_bytes()

    payload_dict = build_provider_payload_dict(
        alg="Ed25519",
        version=1,
        object_hash=obj_hash,
        provider_id=provider_id,
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
        dest = (
            dht1_tcp
            if "/p2p/" in dht1_tcp
            else f"{dht1_tcp}/p2p/{dht1_peer_id}"
        )
        peer_info = info_from_p2p_addr(Multiaddr(dest))
        await dht2.host.connect(peer_info)

        await dht1.put_signed_provider_record(obj_hash, envelope_cbor)

        got = await dht2.get_signed_provider_record(obj_hash)
        assert got is not None
        assert got.object_hash == obj_hash
        assert got.provider_id == provider_id
        assert got.endpoints == endpoints_sorted
