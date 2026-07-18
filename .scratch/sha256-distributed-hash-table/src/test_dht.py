import unittest
import time
import logging
from .routing import xor_distance, common_prefix_length, RoutingTable
from .storage import Storage
from .protocol import DHTNode
from .dht import DHTClient

logging.basicConfig(level=logging.INFO)

class TestDHT(unittest.TestCase):
    def test_routing_xor_distance(self):
        distance = xor_distance("00", "0f")
        self.assertEqual(distance, 15)
        
        cpl = common_prefix_length("00", "0f")
        # 00 = 0000 0000, 0f = 0000 1111 => 4 bits prefix matching
        # hex is 256 bits (64 chars)
        # leading chars match => leading zeros in XOR
        # 64 chars. 62 match (all 0), 1 doesn't (last is '0' vs 'f' in byte representation / half-byte)
        # hex strings compared are expected to be full-length hash representations
        node1 = "0" * 64
        node2 = "0" * 63 + "f"
        # 63 chars value "0" matches => 63 * 4 = 252 common bits. The last char "0" (0000) vs "f" (1111) matches 0 bits.
        self.assertEqual(common_prefix_length(node1, node2), 252)

    def test_storage_ttl(self):
        store = Storage()
        record = {
            "version": 1,
            "object_hash": "a" * 64,
            "ttl_seconds": 1,
            "expires_at": time.time() + 0.2,
            "providers": [
                {"provider_id": "p1", "endpoints": ["tcp://1:2"], "last_seen": int(time.time())}
            ]
        }
        store.put("a" * 64, record)
        self.assertIsNotNone(store.get("a" * 64))
        
        # wait for expiration
        time.sleep(0.3)
        self.assertIsNone(store.get("a" * 64))

    def test_multi_node_lookups(self):
        # We start 3 nodes on random ports
        nodes = []
        clients = []
        
        for idx in range(3):
            # Port 19100 + idx
            n = DHTNode("127.0.0.1", 19100 + idx, k=5)
            n.start()
            nodes.append(n)
            clients.append(DHTClient(n, alpha=2))
        
        try:
            # Let nodes initialize and start their listeners
            time.sleep(0.5)
            
            # Bootstrap node 1 and 2 to node 0
            boot1 = clients[1].bootstrap(["tcp://127.0.0.1:19100"])
            boot2 = clients[2].bootstrap(["tcp://127.0.0.1:19100"])
            
            self.assertTrue(boot1)
            self.assertTrue(boot2)
            
            # We now store a value on node 2 for some target key
            target_key = "f" * 64
            record = {
                "version": 1,
                "object_hash": target_key,
                "ttl_seconds": 100,
                "expires_at": time.time() + 100,
                "providers": [
                    {"provider_id": nodes[2].node_id, "endpoints": ["tcp://127.0.0.1:19102"], "last_seen": int(time.time())}
                ]
            }
            
            # Store payload via client 2 (will store either locally or on node 0/1 depending on XOR distance closeness)
            stores = clients[2].store_value(target_key, record)
            self.assertGreaterEqual(stores, 1)
            
            # Let's verify target is discoverable by client 0 (who wasn't directly told about the store)
            found_record, closer_nodes = clients[0].iterative_find_value(target_key)
            self.assertIsNotNone(found_record)
            self.assertEqual(found_record["object_hash"], target_key)
            self.assertEqual(found_record["providers"][0]["provider_id"], nodes[2].node_id)
            
        finally:
            for n in nodes:
                n.stop()

if __name__ == "__main__":
    unittest.main()
