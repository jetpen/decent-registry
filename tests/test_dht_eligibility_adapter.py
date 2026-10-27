from typing import Any

import pytest
import trio
import varint
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.kad_dht.common import PROTOCOL_ID
from libp2p.kad_dht.kad_dht import DHTMode, KadDHT
from libp2p.kad_dht.pb.kademlia_pb2 import Message
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.peerstore import PeerStore
from libp2p.protocol_muxer.multiselect import Multiselect
from multiaddr import Multiaddr


class FakeHost:
    def __init__(self):
        self.key = create_new_key_pair().private_key
        self.peer_id = ID.from_pubkey(self.key.get_public_key())
        self.store = PeerStore()
        self.multiselect = Multiselect()
        self.handlers = self.multiselect.handlers
        self.next_stream: Any = None

    def get_id(self):
        return self.peer_id

    def get_private_key(self):
        return self.key

    def get_peerstore(self):
        return self.store

    def get_addrs(self):
        return [Multiaddr("/ip4/127.0.0.1/tcp/43210")]

    def get_connected_peers(self):
        return []

    def set_stream_handler(self, protocol, handler):
        self.multiselect.add_handler(protocol, handler)

    def remove_stream_handler(self, protocol):
        self.multiselect.remove_handler(protocol)

    async def new_stream(self, peer, protocols):
        return self.next_stream


@pytest.mark.trio
async def test_client_dht_mode_does_not_register_inbound_handler():
    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.CLIENT, enable_random_walk=False)
    install_dht_serving_eligibility(host, dht, DHTMode.CLIENT)
    assert PROTOCOL_ID not in host.handlers
    assert PROTOCOL_ID not in host.multiselect.get_protocols()


@pytest.mark.trio
async def test_mode_switch_reinstalls_only_server_handler_and_closes_late_client_stream():
    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.SERVER, enable_random_walk=False)
    install_dht_serving_eligibility(host, dht, DHTMode.SERVER)
    server_handler = host.handlers[PROTOCOL_ID]
    await dht.switch_mode(DHTMode.CLIENT)
    assert PROTOCOL_ID not in host.handlers
    assert PROTOCOL_ID not in host.multiselect.get_protocols()
    stream = FakeStream(b"")
    await server_handler(stream)
    assert stream.closed
    await dht.switch_mode(DHTMode.SERVER)
    assert PROTOCOL_ID in host.handlers
    assert PROTOCOL_ID in host.multiselect.get_protocols()


@pytest.mark.trio
@pytest.mark.parametrize(
    "incoming",
    [
        b"",
        bytes([0x80]) * 10,
        lambda: _framed_message_with_invalid_sender_record(),
    ],
)
async def test_inbound_eof_malformed_and_rejected_sender_never_admit(incoming):
    from types import SimpleNamespace

    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    class InboundStream(FakeStream):
        def __init__(self, peer_id, data):
            super().__init__(data)
            self.muxed_conn = SimpleNamespace(peer_id=peer_id)

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.SERVER, enable_random_walk=False)
    eligibility = install_dht_serving_eligibility(host, dht, DHTMode.SERVER)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    payload = incoming() if callable(incoming) else incoming

    await host.handlers[PROTOCOL_ID](InboundStream(peer, payload))

    assert not eligibility.is_eligible(peer)
    assert peer not in dht.routing_table.find_local_closest_peers(b"target")


def _framed_message_with_invalid_sender_record():
    request = Message(type=Message.FIND_NODE, key=b"target", senderRecord=b"bad")
    payload = request.SerializeToString()
    return varint.encode(len(payload)) + payload


@pytest.mark.trio
async def test_cancelled_inbound_dht_handler_closes_its_stream():
    from types import SimpleNamespace

    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    class BlockingStream(FakeStream):
        def __init__(self, peer_id):
            super().__init__(b"")
            self.muxed_conn = SimpleNamespace(peer_id=peer_id)
            self.read_started = trio.Event()

        async def read(self, n=None) -> bytes:
            self.read_started.set()
            await trio.sleep_forever()
            raise AssertionError("unreachable")

        async def close(self):
            await trio.lowlevel.checkpoint()
            self.closed = True

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.SERVER, enable_random_walk=False)
    install_dht_serving_eligibility(host, dht, DHTMode.SERVER)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    stream = BlockingStream(peer)

    async with trio.open_nursery() as nursery:
        nursery.start_soon(host.handlers[PROTOCOL_ID], stream)
        await stream.read_started.wait()
        nursery.cancel_scope.cancel()

    assert stream.closed


@pytest.mark.trio
async def test_cancelled_outbound_find_node_shields_stream_cleanup():
    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    class BlockingStream(FakeStream):
        def __init__(self):
            super().__init__(b"")
            self.read_started = trio.Event()

        async def read(self, n=None) -> bytes:
            self.read_started.set()
            await trio.sleep_forever()
            raise AssertionError("unreachable")

        async def close(self):
            await trio.lowlevel.checkpoint()
            self.closed = True

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.CLIENT, enable_random_walk=False)
    eligibility = install_dht_serving_eligibility(host, dht, DHTMode.CLIENT)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    host.store.add_addrs(peer, [Multiaddr("/ip4/127.0.0.1/tcp/43211")], 60)
    raw_stream = BlockingStream()
    host.next_stream = raw_stream

    async with trio.open_nursery() as nursery:
        nursery.start_soon(dht.peer_routing._query_peer_for_closest, peer, b"target")
        await raw_stream.read_started.wait()
        nursery.cancel_scope.cancel()

    assert raw_stream.closed
    assert not eligibility.is_eligible(peer)


@pytest.mark.trio
async def test_registry_wraps_only_dht_streams_and_bounds_inbound_frames():
    from decent_registry.dht.serving_eligibility import (
        BoundedDHTStream,
        BoundedInboundDHTStream,
        install_dht_serving_eligibility,
    )

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.CLIENT, enable_random_walk=False)
    install_dht_serving_eligibility(host, dht, DHTMode.CLIENT)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    raw = FakeStream(b"")
    host.next_stream = raw
    dht_stream = await host.new_stream(peer, [PROTOCOL_ID])
    assert isinstance(dht_stream, BoundedDHTStream)
    host.next_stream = raw
    other_stream = await host.new_stream(peer, ["/other/protocol"])
    assert other_stream is raw

    raw = FakeStream(b"")
    inbound = BoundedInboundDHTStream(raw, max_bytes=8)
    with pytest.raises(ValueError, match="oversize"):
        await inbound.read(9)
    assert raw.read_calls == []

    raw = FakeStream(varint.encode(9) + b"x" * 9)
    inbound = BoundedInboundDHTStream(raw, max_bytes=8)
    with pytest.raises(ValueError, match="oversize"):
        await inbound.read(1)
    assert raw.read_calls == [1]


def test_dht_adapter_frame_parser_rejects_oversized_and_truncated_frames():
    from decent_registry.dht.serving_eligibility import _read_bounded_dht_frame

    assert _read_bounded_dht_frame(varint.encode(1) + b"\x08") == b"\x08"
    with pytest.raises(ValueError, match="oversize"):
        _read_bounded_dht_frame(varint.encode(9) + b"123456789", max_bytes=8)
    with pytest.raises(ValueError, match="truncated"):
        _read_bounded_dht_frame(varint.encode(2) + b"1")
    with pytest.raises(ValueError, match="non-canonical"):
        _read_bounded_dht_frame(bytes([0x81, 0x00]) + b"x")


def test_dht_frame_response_must_match_request_type():
    from decent_registry.dht.serving_eligibility import _validate_dht_response

    request = Message(type=Message.FIND_NODE)
    response = Message(type=Message.PING, key=b"x")
    with pytest.raises(ValueError, match="response type"):
        _validate_dht_response(request, response)


def test_dht_response_rejects_mismatched_keys_and_invalid_referrals():
    from decent_registry.dht.serving_eligibility import _validate_dht_response

    get_request = Message(type=Message.GET_VALUE, key=b"requested")
    wrong_key_response = Message(type=Message.GET_VALUE, key=b"other")
    with pytest.raises(ValueError, match="response key"):
        _validate_dht_response(get_request, wrong_key_response)

    find_request = Message(type=Message.FIND_NODE, key=b"target")
    malformed_peer_response = Message(type=Message.FIND_NODE)
    malformed_peer_response.closerPeers.add().id = b"not-a-multihash"
    with pytest.raises(ValueError):
        _validate_dht_response(find_request, malformed_peer_response)


class FakeStream:
    def __init__(self, incoming: bytes):
        self.incoming = incoming
        self.read_calls = []
        self.writes = []
        self.closed = False

    async def read(self, n=None):
        self.read_calls.append(n)
        if n is None:
            n = len(self.incoming)
        chunk, self.incoming = self.incoming[:n], self.incoming[n:]
        return chunk

    async def write(self, data):
        self.writes.append(data)

    async def close(self):
        self.closed = True


@pytest.mark.trio
async def test_only_complete_matching_bounded_response_refreshes_eligibility():
    from decent_registry.dht.serving_eligibility import BoundedDHTStream

    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    request = Message(type=Message.FIND_NODE, key=b"k").SerializeToString()
    response = Message(type=Message.FIND_NODE, key=b"k").SerializeToString()
    proofs = []

    async def prove(peer_id):
        proofs.append(peer_id)

    stream = FakeStream(varint.encode(len(response)) + response[:-1])
    bounded = BoundedDHTStream(stream, peer, prove, max_bytes=64)
    await bounded.write(varint.encode(len(request)) + request)
    await bounded.read(1)
    await bounded.read(len(response))
    assert proofs == []

    stream = FakeStream(varint.encode(len(response)) + response)
    bounded = BoundedDHTStream(stream, peer, prove, max_bytes=64)
    await bounded.write(varint.encode(len(request)) + request)
    await bounded.read(1)
    await bounded.read(len(response))
    assert proofs == [peer]

    proofs.clear()
    mismatched = Message(type=Message.PING, key=b"k").SerializeToString()
    stream = FakeStream(varint.encode(len(mismatched)) + mismatched)
    bounded = BoundedDHTStream(stream, peer, prove, max_bytes=64)
    await bounded.write(varint.encode(len(request)) + request)
    await bounded.read(1)
    with pytest.raises(ValueError, match="invalid DHT response"):
        await bounded.read(len(mismatched))
    assert proofs == []

    invalid_type = bytes([8, 99])
    stream = FakeStream(varint.encode(len(invalid_type)) + invalid_type)
    bounded = BoundedDHTStream(stream, peer, prove, max_bytes=64)
    await bounded.write(varint.encode(len(request)) + request)
    await bounded.read(1)
    with pytest.raises(ValueError, match="invalid DHT response"):
        await bounded.read(len(invalid_type))
    assert proofs == []


@pytest.mark.trio
async def test_timed_out_dht_response_does_not_refresh_eligibility():
    from decent_registry.dht.serving_eligibility import BoundedDHTStream

    class SlowStream(FakeStream):
        async def read(self, n=None):
            await trio.sleep(1)
            return await super().read(n)

    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    request = Message(type=Message.FIND_NODE, key=b"k").SerializeToString()
    proofs = []

    async def prove(peer_id):
        proofs.append(peer_id)

    stream = SlowStream(bytes([1]))
    bounded = BoundedDHTStream(
        stream, peer, prove, max_bytes=64, frame_timeout_seconds=0.01
    )
    await bounded.write(varint.encode(len(request)) + request)
    with pytest.raises(trio.TooSlowError):
        await bounded.read(1)
    assert proofs == []


@pytest.mark.trio
async def test_oversized_dht_response_is_rejected_before_body_read():
    from decent_registry.dht.serving_eligibility import BoundedDHTStream

    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    request = Message(type=Message.FIND_NODE, key=b"k").SerializeToString()
    stream = FakeStream(varint.encode(9) + b"x" * 9)
    bounded = BoundedDHTStream(stream, peer, max_bytes=8)
    await bounded.write(varint.encode(len(request)) + request)
    with pytest.raises(ValueError, match="oversize"):
        await bounded.read(1)
    assert len(stream.read_calls) == 1
    assert stream.read_calls == [1]


@pytest.mark.trio
async def test_routing_table_admission_and_referrals_expire_after_five_minutes():
    from decent_registry.dht.serving_eligibility import RoutingEligibility

    class Table:
        def __init__(self):
            self.peers = set()

        async def add_peer(self, peer):
            self.peers.add(peer)
            return True

        def find_local_closest_peers(self, key, count=20):
            return list(self.peers)[:count]

        def remove_peer(self, peer):
            self.peers.discard(peer)
            return True

        def size(self):
            return len(self.peers)

    now = [0.0]
    table = Table()
    eligibility = RoutingEligibility(table, clock=lambda: now[0])
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    assert await table.add_peer(peer) is False
    await eligibility.record_valid_response(peer)
    assert await table.add_peer(peer) is True
    assert table.find_local_closest_peers(b"key") == [peer]
    now[0] = 299
    await eligibility.record_valid_response(peer)
    now[0] = 300
    assert table.find_local_closest_peers(b"key") == [peer]
    now[0] = 599
    assert table.find_local_closest_peers(b"key") == []
    assert peer not in table.peers


@pytest.mark.trio
async def test_routing_eligibility_forwards_libp2p_mode_override_keyword():
    from decent_registry.dht.serving_eligibility import RoutingEligibility

    class Table:
        def __init__(self):
            self.peers = set()
            self.mode_overrides = []

        async def add_peer(self, peer, *, skip_server_mode_check=False):
            self.mode_overrides.append(skip_server_mode_check)
            self.peers.add(peer)
            return True

        def find_local_closest_peers(self, key, count=20):
            return list(self.peers)[:count]

        def remove_peer(self, peer):
            self.peers.discard(peer)
            return True

        def size(self):
            return len(self.peers)

    table = Table()
    eligibility = RoutingEligibility(table)
    unverified_peer = ID.from_pubkey(
        create_new_key_pair().private_key.get_public_key()
    )
    assert await table.add_peer(
        unverified_peer, skip_server_mode_check=True
    ) is False
    assert table.mode_overrides == []
    assert unverified_peer not in table.peers

    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    await eligibility.record_valid_response(peer)
    assert table.mode_overrides == [False]

    assert await table.add_peer(peer, skip_server_mode_check=True) is True
    assert table.mode_overrides == [False, True]


@pytest.mark.trio
async def test_routing_eligibility_preserves_default_add_peer_signature():
    from decent_registry.dht.serving_eligibility import RoutingEligibility

    class Table:
        def __init__(self):
            self.peers = set()

        async def add_peer(self, peer):
            self.peers.add(peer)
            return True

        def find_local_closest_peers(self, key, count=20):
            return list(self.peers)[:count]

        def remove_peer(self, peer):
            self.peers.discard(peer)
            return True

        def size(self):
            return len(self.peers)

    table = Table()
    eligibility = RoutingEligibility(table)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    await eligibility.record_valid_response(peer)

    assert await table.add_peer(peer) is True


@pytest.mark.trio
async def test_dht_stream_open_timeout_prevents_unbounded_dial(monkeypatch):
    from decent_registry.dht import serving_eligibility
    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    class SlowHost(FakeHost):
        async def new_stream(self, peer, protocols):
            await trio.sleep(1)
            return FakeStream(b"")

    monkeypatch.setattr(serving_eligibility, "MAX_DHT_FRAME_TIME_SECONDS", 0.01)
    host = SlowHost()
    dht = KadDHT(host, mode=DHTMode.CLIENT, enable_random_walk=False)
    install_dht_serving_eligibility(host, dht, DHTMode.CLIENT)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())

    with pytest.raises(trio.TooSlowError):
        await host.new_stream(peer, [PROTOCOL_ID])


@pytest.mark.trio
async def test_preexisting_and_failed_find_node_peers_are_not_admitted():
    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    class FailingHost(FakeHost):
        async def new_stream(self, peer, protocols):
            raise OSError("simulated outbound failure")

    host = FailingHost()
    dht = KadDHT(host, mode=DHTMode.CLIENT, enable_random_walk=False)
    peer = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    addr = Multiaddr("/ip4/127.0.0.1/tcp/43211")
    await dht.routing_table.add_peer(PeerInfo(peer, [addr]))
    host.store.add_addrs(peer, [addr], 60)
    assert peer in dht.routing_table.find_local_closest_peers(b"target")

    eligibility = install_dht_serving_eligibility(host, dht, DHTMode.CLIENT)
    assert peer not in dht.routing_table.find_local_closest_peers(b"target")

    await dht.peer_routing.find_closest_peers_network(b"target", count=1)

    assert not eligibility.is_eligible(peer)
    assert peer not in dht.routing_table.find_local_closest_peers(b"target")


@pytest.mark.trio
async def test_valid_find_node_response_qualifies_only_the_responder():
    from decent_registry.dht.serving_eligibility import install_dht_serving_eligibility

    host = FakeHost()
    dht = KadDHT(host, mode=DHTMode.CLIENT, enable_random_walk=False)
    eligibility = install_dht_serving_eligibility(host, dht, DHTMode.CLIENT)
    responder = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    referred = ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
    host.store.add_addrs(responder, [Multiaddr("/ip4/127.0.0.1/tcp/43211")], 60)

    response = Message(type=Message.FIND_NODE)
    response.closerPeers.add().id = referred.to_bytes()
    response_bytes = response.SerializeToString()
    host.next_stream = FakeStream(varint.encode(len(response_bytes)) + response_bytes)

    await dht.peer_routing._query_peer_for_closest(responder, b"target")

    assert eligibility.is_eligible(responder)
    assert not eligibility.is_eligible(referred)
    assert not await dht.routing_table.add_peer(PeerInfo(referred, []))


@pytest.mark.trio
async def test_eligibility_cache_is_bounded_and_evicts_oldest(monkeypatch):
    from decent_registry.dht import serving_eligibility

    class Table:
        def __init__(self):
            self.peers = set()

        async def add_peer(self, peer):
            self.peers.add(peer)
            return True

        def find_local_closest_peers(self, key, count=20):
            return list(self.peers)[:count]

        def remove_peer(self, peer):
            self.peers.discard(peer)
            return True

        def size(self):
            return len(self.peers)

    monkeypatch.setattr(serving_eligibility, "MAX_ELIGIBLE_PEERS", 2)
    table = Table()
    eligibility = serving_eligibility.RoutingEligibility(table, clock=lambda: 0.0)
    peers = [
        ID.from_pubkey(create_new_key_pair().private_key.get_public_key())
        for _ in range(3)
    ]
    for peer in peers:
        await eligibility.record_valid_response(peer)

    assert not eligibility.is_eligible(peers[0])
    assert eligibility.is_eligible(peers[1])
    assert eligibility.is_eligible(peers[2])
    assert peers[0] not in table.peers
