import socket
import threading
import uuid
import time
import logging
from .routing import RoutingTable
from .storage import Storage

logger = logging.getLogger("dht.node")

# Framing methods instead of circular relative imports
import json
import struct

def send_msg(sock: socket.socket, msg_dict: dict):
    payload = json.dumps(msg_dict).encode("utf-8")
    header = struct.pack(">I", len(payload))
    sock.sendall(header + payload)

def read_exact(sock: socket.socket, length: int) -> bytes | None:
    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

def rcv_msg(sock: socket.socket) -> dict | None:
    header = read_exact(sock, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    payload_bytes = read_exact(sock, length)
    if not payload_bytes:
        return None
    return json.loads(payload_bytes.decode("utf-8"))

class DHTNode:
    def __init__(self, host: str, port: int, node_id: str = None, k: int = 20):
        self.host = host
        self.port = port
        if node_id is None:
            # Generate random 256-bit (64 hex characters) identifier
            self.node_id = uuid.uuid4().hex + uuid.uuid4().hex
        else:
            self.node_id = node_id
        
        self.k = k
        self.routing_table = RoutingTable(self.node_id, k=k)
        self.storage = Storage()
        self._server_sock = None
        self._is_running = False
        self._listener_thread = None

    @property
    def my_node_info(self) -> dict:
        return {
            "node_id": self.node_id,
            "endpoints": [f"tcp://{self.host}:{self.port}"]
        }

    def start(self):
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(128)
        self._is_running = True
        logger.info(f"DHTNode {self.node_id} listening on {self.host}:{self.port}")
        self._listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listener_thread.start()

    def stop(self):
        self._is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._listener_thread:
            self._listener_thread.join(timeout=2.0)

    def _listen_loop(self):
        while self._is_running:
            try:
                sock, addr = self._server_sock.accept()
                threading.Thread(target=self._handle_client, args=(sock,), daemon=True).start()
            except Exception:
                if not self._is_running:
                    break
                time.sleep(0.1)

    def _handle_client(self, sock: socket.socket):
        with sock:
            sock.settimeout(10.0)
            while self._is_running:
                try:
                    msg = rcv_msg(sock)
                    if not msg:
                        break
                    resp = self._dispatch_message(msg)
                    if resp:
                        send_msg(sock, resp)
                except Exception as e:
                    logger.warning(f"Error handling message on {self.node_id}: {e}")
                    break

    def _dispatch_message(self, msg: dict) -> dict | None:
        m_type = msg.get("type")
        msg_id = msg.get("id", "")
        
        # In custom Kademlia, we record the sender's existence in routing table on receipt of any valid message
        sender_id = msg.get("sender_id") or msg.get("responder_id")
        sender_endpoints = msg.get("sender_endpoints") or []
        if sender_id and sender_endpoints:
            self.routing_table.add_node({"node_id": sender_id, "endpoints": sender_endpoints})

        if m_type == "PING":
            return {
                "type": "PONG",
                "id": msg_id,
                "responder_id": self.node_id,
                "responder_endpoints": [f"tcp://{self.host}:{self.port}"],
                "ts": int(time.time())
            }
        
        elif m_type == "FIND_NODE":
            target_key = msg.get("target_key", "")
            req_k = msg.get("k", self.k)
            closer = self.routing_table.get_closest_nodes(target_key, count=req_k)
            return {
                "type": "FIND_NODE_REPLY",
                "id": msg_id,
                "responder_id": self.node_id,
                "closer_nodes": closer
            }
        
        elif m_type == "PUT_VALUE":
            target_key = msg.get("target_key", "")
            record = msg.get("value_record")
            if not record or not self._validate_record(target_key, record):
                return {
                    "type": "ERROR",
                    "id": msg_id,
                    "error": "Invalid value record schemas or expired"
                }
            self.storage.put(target_key, record)
            return {
                "type": "PUT_VALUE_REPLY",
                "id": msg_id,
                "responder_id": self.node_id,
                "status": "ok"
            }
        
        elif m_type == "GET_VALUE":
            target_key = msg.get("target_key", "")
            req_k = msg.get("k", self.k)
            record = self.storage.get(target_key)
            if record:
                return {
                    "type": "GET_VALUE_REPLY",
                    "id": msg_id,
                    "responder_id": self.node_id,
                    "found": True,
                    "value_record": record
                }
            else:
                closer = self.routing_table.get_closest_nodes(target_key, count=req_k)
                return {
                    "type": "GET_VALUE_REPLY",
                    "id": msg_id,
                    "responder_id": self.node_id,
                    "found": False,
                    "closer_nodes": closer
                }
        
        return {
            "type": "ERROR",
            "id": msg_id,
            "error": f"Unknown message type: {m_type}"
        }

    def _validate_record(self, key: str, record: dict) -> bool:
        if record.get("version") != 1:
            return False
        if record.get("object_hash") != key:
            return False
        expires_at = record.get("expires_at", 0)
        if time.time() > expires_at:
            return False
        
        # Check providers list structures
        providers = record.get("providers", [])
        if not isinstance(providers, list):
            return False
        for p in providers:
            if not isinstance(p, dict):
                return False
            if "provider_id" not in p or not isinstance(p.get("endpoints"), list):
                return False
            if len(p["endpoints"]) == 0:
                return False
        return True

    def send_direct(self, endpoint: str, msg: dict, timeout: float = 5.0) -> dict | None:
        """Helper to send a message to a direct endpoint and return response."""
        # endpoints are TCP strings: tcp://host:port
        if not endpoint.startswith("tcp://"):
            return None
        parts = endpoint[6:].split(":")
        if len(parts) != 2:
            return None
        host, port = parts[0], int(parts[1])
        
        # Enrich request with sender details
        msg["sender_id"] = self.node_id
        msg["sender_endpoints"] = [f"tcp://{self.host}:{self.port}"]
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                send_msg(sock, msg)
                return rcv_msg(sock)
        except Exception:
            return None
