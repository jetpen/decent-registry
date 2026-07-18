import socket
import time

from decent_registry.dht.protocol import DHTNode


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_ping_pong_round_trip():
    port = _free_port()
    node = DHTNode("127.0.0.1", port, k=5)
    node.start()
    try:
        # Give listener thread time to accept.
        time.sleep(0.1)
        resp = node.send_direct(f"tcp://127.0.0.1:{port}", {"type": "PING", "id": "req-1"})
        assert resp is not None
        assert resp.get("type") == "PONG"
        assert resp.get("id") == "req-1"
        assert resp.get("responder_id") == node.node_id
    finally:
        node.stop()
