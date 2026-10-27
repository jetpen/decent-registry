"""Bounded Kademlia streams and fresh-serving routing eligibility.

This adapter is intentionally coupled to the pinned py-libp2p 0.8.1 stream
framing and routing-table seams. Keep the tests in
``tests/test_dht_eligibility_adapter.py`` in sync with dependency changes.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import multihash
import trio
import varint
from google.protobuf.message import DecodeError
from libp2p.kad_dht.common import PROTOCOL_ID
from libp2p.kad_dht.kad_dht import DHTMode
from libp2p.kad_dht.pb.kademlia_pb2 import Message
from libp2p.kad_dht.peer_routing import maybe_consume_signed_record
from libp2p.peer.id import ID
from multiaddr import Multiaddr

MAX_DHT_MESSAGE_SIZE = 1024 * 1024
MAX_DHT_FRAME_TIME_SECONDS = 15.0
MAX_ELIGIBLE_PEERS = 1024
SERVING_PROOF_TTL_SECONDS = 5 * 60


async def _discard_proof(_: ID) -> None:
    return None


async def _close_stream_shielded(stream: Any) -> None:
    with trio.CancelScope(shield=True):
        await stream.close()


def _decode_varint_prefix(data: bytes) -> tuple[int, int] | None:
    """Return (length, prefix_bytes), None for an incomplete prefix."""
    value = 0
    shift = 0
    for index, byte in enumerate(data[:10]):
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index + 1
        shift += 7
    if len(data) >= 10:
        raise ValueError("malformed DHT varint length")
    return None


def _read_bounded_dht_frame(
    frame: bytes, *, max_bytes: int = MAX_DHT_MESSAGE_SIZE
) -> bytes:
    """Decode one complete varint-framed DHT payload without accepting tails."""
    decoded = _decode_varint_prefix(frame)
    if decoded is None:
        raise ValueError("truncated DHT frame length")
    length, prefix_size = decoded
    if varint.encode(length) != frame[:prefix_size]:
        raise ValueError("non-canonical DHT frame length")
    if length > max_bytes:
        raise ValueError("oversize DHT frame")
    payload = frame[prefix_size:]
    if len(payload) < length:
        raise ValueError("truncated DHT frame payload")
    if len(payload) != length:
        raise ValueError("trailing bytes after DHT frame")
    return payload


def _validate_dht_response(request: Message, response: Message) -> None:
    # This generated protobuf uses implicit presence for its enum field. An
    # empty payload therefore defaults to PUT_VALUE; it cannot prove a typed
    # response and is deliberately not eligibility evidence.
    if response.ByteSize() == 0:
        raise ValueError("DHT response type is missing")
    if request.type != response.type:
        raise ValueError("DHT response type does not match request type")
    if request.type == Message.PING:
        raise ValueError("DHT PING is not serving proof for this implementation")
    if request.type == Message.PUT_VALUE:
        if not request.HasField("record") or response.key != request.record.key:
            raise ValueError(
                "DHT PUT_VALUE response did not acknowledge the record key"
            )
    elif (
        request.type
        in (
            Message.GET_VALUE,
            Message.ADD_PROVIDER,
            Message.GET_PROVIDERS,
        )
        and response.key != request.key
    ):
        raise ValueError("DHT response key does not match request key")
    if (
        request.type == Message.GET_VALUE
        and response.HasField("record")
        and response.record.key != request.key
    ):
        raise ValueError("DHT value record key does not match request key")
    for field_name in ("closerPeers", "providerPeers"):
        for peer in getattr(response, field_name):
            multihash.decode(peer.id)
            for address in peer.addrs:
                Multiaddr(address)


def _contains_type_field(payload: bytes) -> bool:
    """Check that protobuf field 1 (Kademlia Message.type) was on the wire."""
    valid_types = {
        Message.PUT_VALUE,
        Message.GET_VALUE,
        Message.ADD_PROVIDER,
        Message.GET_PROVIDERS,
        Message.FIND_NODE,
        Message.PING,
    }
    offset = 0
    while offset < len(payload):
        tag = _decode_varint_prefix(payload[offset:])
        if tag is None:
            return False
        key, key_size = tag
        field_number, wire_type = key >> 3, key & 7
        offset += key_size
        if field_number == 1 and wire_type == 0:
            value = _decode_varint_prefix(payload[offset:])
            return value is not None and value[0] in valid_types
        if wire_type == 0:
            value = _decode_varint_prefix(payload[offset:])
            if value is None:
                return False
            offset += value[1]
        elif wire_type == 1:
            offset += 8
        elif wire_type == 2:
            length = _decode_varint_prefix(payload[offset:])
            if length is None:
                return False
            offset += length[1] + length[0]
        elif wire_type == 5:
            offset += 4
        else:
            return False
        if offset > len(payload):
            return False
    return False


class _FrameDeadline:
    def __init__(self, timeout_seconds: float, timeout_message: str) -> None:
        self._timeout_seconds = timeout_seconds
        self._timeout_message = timeout_message
        self._deadline: float | None = None

    async def run(self, operation: Callable[..., Awaitable[Any]], *args: Any) -> Any:
        if self._deadline is None:
            self._deadline = trio.current_time() + self._timeout_seconds
        remaining = self._deadline - trio.current_time()
        if remaining <= 0:
            raise TimeoutError(self._timeout_message)
        with trio.fail_after(remaining):
            return await operation(*args)


class BoundedDHTStream:
    """Proxy a libp2p stream, bounding frame reads and observing valid replies."""

    def __init__(
        self,
        stream: Any,
        peer_id: ID,
        on_valid_response: Callable[[ID], Awaitable[None]] = _discard_proof,
        *,
        validate_response: Callable[[ID, Message], bool] | None = None,
        max_bytes: int = MAX_DHT_MESSAGE_SIZE,
        frame_timeout_seconds: float = MAX_DHT_FRAME_TIME_SECONDS,
    ) -> None:
        self._stream = stream
        self._peer_id = peer_id
        self._on_valid_response = on_valid_response
        self._validate_response = validate_response
        self._max_bytes = max_bytes
        self._frame_timeout_seconds = frame_timeout_seconds
        self._request = bytearray()
        self._request_message: Message | None = None
        self._response_prefix = bytearray()
        self._response_length: int | None = None
        self._response_payload = bytearray()
        self._proof_recorded = False
        self._tracking = True
        self._read_deadline: float | None = None
        self._write_deadline: float | None = None
        self._written_bytes = 0

    async def close(self) -> None:
        await _close_stream_shielded(self._stream)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    async def _read_with_deadline(self, n: int) -> bytes:
        if self._read_deadline is None:
            self._read_deadline = trio.current_time() + self._frame_timeout_seconds
        remaining = self._read_deadline - trio.current_time()
        if remaining <= 0:
            raise TimeoutError("DHT response frame timed out")
        with trio.fail_after(remaining):
            return await self._stream.read(n)

    async def _write_with_deadline(self, data: bytes) -> None:
        if self._write_deadline is None:
            self._write_deadline = trio.current_time() + self._frame_timeout_seconds
        remaining = self._write_deadline - trio.current_time()
        if remaining <= 0:
            raise TimeoutError("DHT request frame write timed out")
        with trio.fail_after(remaining):
            await self._stream.write(data)

    async def write(self, data: bytes) -> None:
        self._written_bytes += len(data)
        if self._written_bytes > self._max_bytes + 10:
            raise ValueError("oversize outbound DHT frame")
        if self._tracking:
            if len(self._request) + len(data) > self._max_bytes + 10:
                raise ValueError("oversize outbound DHT frame")
            self._request.extend(data)
            self._observe_request()
        await self._write_with_deadline(data)

    def _observe_request(self) -> None:
        decoded = _decode_varint_prefix(bytes(self._request))
        if decoded is None:
            return
        length, prefix_size = decoded
        if varint.encode(length) != bytes(self._request[:prefix_size]):
            raise ValueError("non-canonical outbound DHT frame length")
        # Older libp2p routing-table implementations can open a legacy,
        # non-varint PING stream. It is not evidence of Kademlia serving and
        # remains pass-through only.
        if length == 0:
            self._tracking = False
            return
        if length > self._max_bytes:
            raise ValueError("oversize outbound DHT frame")
        if len(self._request) < prefix_size + length:
            return
        if len(self._request) != prefix_size + length:
            self._tracking = False
            return
        request = Message()
        try:
            request.ParseFromString(bytes(self._request[prefix_size:]))
        except DecodeError:
            self._tracking = False
            return
        request_payload = bytes(self._request[prefix_size : prefix_size + length])
        if request.ByteSize() and _contains_type_field(request_payload):
            self._request_message = request
        else:
            self._tracking = False

    async def read(self, n: int | None = None) -> bytes:
        if n is not None and n < 0:
            raise ValueError("negative DHT stream read length")
        if n is not None and n > self._max_bytes:
            raise ValueError("oversize DHT frame read")
        requested = self._max_bytes + 1 if n is None else n
        chunk = await self._read_with_deadline(requested)
        if len(chunk) > self._max_bytes + 1:
            raise ValueError("oversize DHT frame read")
        if self._tracking and self._request_message is not None and chunk:
            await self._observe_response(chunk)
        return chunk

    async def _observe_response(self, chunk: bytes) -> None:
        if self._response_length is None:
            self._response_prefix.extend(chunk)
            decoded = _decode_varint_prefix(bytes(self._response_prefix))
            if decoded is None:
                if len(self._response_prefix) > 10:
                    raise ValueError("malformed DHT response length")
                return
            length, prefix_size = decoded
            if varint.encode(length) != bytes(self._response_prefix[:prefix_size]):
                raise ValueError("non-canonical DHT response length")
            if length > self._max_bytes:
                raise ValueError("oversize DHT response")
            self._response_length = length
            remainder = bytes(self._response_prefix[prefix_size:])
            self._response_prefix.clear()
            if remainder:
                self._response_payload.extend(remainder)
        else:
            self._response_payload.extend(chunk)
        assert self._response_length is not None
        if len(self._response_payload) > self._response_length:
            raise ValueError("DHT response exceeds declared frame length")
        if len(self._response_payload) != self._response_length or self._proof_recorded:
            return
        response = Message()
        try:
            response_payload = bytes(self._response_payload)
            if not _contains_type_field(response_payload):
                raise ValueError("DHT response omitted its message type")
            response.ParseFromString(response_payload)
            assert self._request_message is not None
            _validate_dht_response(self._request_message, response)
            if self._validate_response is not None and not self._validate_response(
                self._peer_id, response
            ):
                raise ValueError("DHT response failed signed-record validation")
        except Exception as exc:
            raise ValueError("invalid DHT response frame") from exc
        self._proof_recorded = True
        await self._on_valid_response(self._peer_id)


class BoundedInboundDHTStream:
    """Proxy a server-side stream and refuse a frame before its body is read."""

    def __init__(
        self,
        stream: Any,
        *,
        max_bytes: int = MAX_DHT_MESSAGE_SIZE,
        frame_timeout_seconds: float = MAX_DHT_FRAME_TIME_SECONDS,
    ) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._frame_timeout_seconds = frame_timeout_seconds
        self._prefix = bytearray()
        self._length: int | None = None
        self._payload_read = 0
        self._read_deadline: float | None = None
        self._write_deadline: float | None = None
        self._written_bytes = 0

    async def close(self) -> None:
        await _close_stream_shielded(self._stream)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    async def _read_with_deadline(self, n: int) -> bytes:
        if self._read_deadline is None:
            self._read_deadline = trio.current_time() + self._frame_timeout_seconds
        remaining = self._read_deadline - trio.current_time()
        if remaining <= 0:
            raise TimeoutError("inbound DHT request frame timed out")
        with trio.fail_after(remaining):
            return await self._stream.read(n)

    async def _write_with_deadline(self, data: bytes) -> None:
        if self._write_deadline is None:
            self._write_deadline = trio.current_time() + self._frame_timeout_seconds
        remaining = self._write_deadline - trio.current_time()
        if remaining <= 0:
            raise TimeoutError("inbound DHT response write timed out")
        with trio.fail_after(remaining):
            await self._stream.write(data)

    async def write(self, data: bytes) -> None:
        self._written_bytes += len(data)
        if self._written_bytes > self._max_bytes + 10:
            raise ValueError("oversize inbound DHT response")
        await self._write_with_deadline(data)

    async def read(self, n: int | None = None) -> bytes:
        if n is not None and n < 0:
            raise ValueError("negative inbound DHT stream read length")
        if n is not None and n > self._max_bytes:
            raise ValueError("oversize inbound DHT frame")
        requested = self._max_bytes + 11 if n is None else n
        chunk = await self._read_with_deadline(requested)
        if len(chunk) > self._max_bytes + 10:
            raise ValueError("oversize inbound DHT frame")
        if self._length is None:
            self._prefix.extend(chunk)
            decoded = _decode_varint_prefix(bytes(self._prefix))
            if decoded is None:
                if len(self._prefix) >= 10:
                    raise ValueError("malformed inbound DHT frame length")
                return chunk
            length, prefix_size = decoded
            if length > self._max_bytes:
                raise ValueError("oversize inbound DHT frame")
            if varint.encode(length) != bytes(self._prefix[:prefix_size]):
                raise ValueError("non-canonical inbound DHT frame length")
            self._length = length
            self._payload_read = len(self._prefix) - prefix_size
        else:
            self._payload_read += len(chunk)
        if self._length is not None and self._payload_read > self._length:
            raise ValueError("inbound DHT frame exceeds declared length")
        return chunk


class RoutingEligibility:
    """Gate routing-table admission and referrals on fresh response proof."""

    def __init__(
        self, routing_table: Any, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._table = routing_table
        self._clock = clock
        self._expires: dict[ID, float] = {}
        self._add = routing_table.add_peer
        self._find = routing_table.find_local_closest_peers
        self._remove = routing_table.remove_peer
        routing_table.add_peer = self._guarded_add
        routing_table.find_local_closest_peers = self._guarded_find
        for bucket in getattr(routing_table, "buckets", ()):
            for peer_id in tuple(bucket.peer_ids()):
                self._remove(peer_id)

    @staticmethod
    def _peer_id(peer: Any) -> ID:
        return getattr(peer, "peer_id", peer)

    def is_eligible(self, peer_id: ID) -> bool:
        expiry = self._expires.get(peer_id)
        if expiry is None:
            return False
        if self._clock() >= expiry:
            self._expires.pop(peer_id, None)
            self._remove(peer_id)
            return False
        return True

    async def record_valid_response(self, peer_id: ID) -> None:
        if peer_id not in self._expires and len(self._expires) >= MAX_ELIGIBLE_PEERS:
            oldest_peer = min(self._expires, key=self._expires.__getitem__)
            self._expires.pop(oldest_peer, None)
            self._remove(oldest_peer)
        self._expires[peer_id] = self._clock() + SERVING_PROOF_TTL_SECONDS
        await self._add(peer_id)

    def clear(self) -> None:
        for peer_id in tuple(self._expires):
            self._remove(peer_id)
        self._expires.clear()

    async def _guarded_add(
        self, peer: Any, *, skip_server_mode_check: bool = False
    ) -> bool:
        peer_id = self._peer_id(peer)
        if not self.is_eligible(peer_id):
            return False
        if skip_server_mode_check:
            return await self._add(peer, skip_server_mode_check=True)
        return await self._add(peer)

    def _guarded_find(self, key: bytes, count: int = 20) -> list[ID]:
        all_peers = self._find(key, max(count, self._table.size()))
        eligible: list[ID] = []
        for peer_id in all_peers:
            if self.is_eligible(peer_id):
                eligible.append(peer_id)
        return eligible[:count]


def install_dht_serving_eligibility(
    host: Any,
    dht: Any,
    mode: DHTMode,
    *,
    on_mode_changed: Callable[[DHTMode], None] | None = None,
) -> RoutingEligibility:
    """Install the Registry-owned frame and routing gates on one DHT instance."""
    if dht.mode != mode:
        raise ValueError("DHT mode changed before serving eligibility installation")
    eligibility = RoutingEligibility(dht.routing_table)
    original_new_stream = host.new_stream

    def validate_response(peer_id: ID, response: Message) -> bool:
        if not maybe_consume_signed_record(response, host, peer_id):
            return False
        for field_name in ("closerPeers", "providerPeers"):
            for peer_data in getattr(response, field_name, ()):
                if not maybe_consume_signed_record(peer_data, host):
                    return False
        return True

    async def bounded_new_stream(peer_id: ID, protocol_ids: Sequence[Any]) -> Any:
        if PROTOCOL_ID not in protocol_ids:
            return await original_new_stream(peer_id, protocol_ids)
        with trio.fail_after(MAX_DHT_FRAME_TIME_SECONDS):
            stream = await original_new_stream(peer_id, protocol_ids)
        return BoundedDHTStream(
            stream,
            peer_id,
            eligibility.record_valid_response,
            validate_response=validate_response,
        )

    host.new_stream = bounded_new_stream

    async def inbound_handler(stream: Any) -> None:
        if dht.mode == DHTMode.CLIENT:
            await _close_stream_shielded(stream)
            return
        bounded_stream = BoundedInboundDHTStream(stream)
        try:
            await dht.handle_stream(bounded_stream)
        finally:
            await bounded_stream.close()

    def register_handler() -> None:
        if dht.mode == DHTMode.CLIENT:
            host.remove_stream_handler(PROTOCOL_ID)
        else:
            host.set_stream_handler(PROTOCOL_ID, inbound_handler)

    register_handler()
    original_switch_mode = dht.switch_mode

    async def switch_mode(new_mode: DHTMode) -> DHTMode:
        result = await original_switch_mode(new_mode)
        eligibility.clear()
        register_handler()
        if on_mode_changed is not None:
            on_mode_changed(result)
        return result

    dht.switch_mode = switch_mode
    return eligibility
