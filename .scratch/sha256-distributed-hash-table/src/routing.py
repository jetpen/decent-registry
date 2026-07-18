# XOR math helper
def xor_distance(hex1: str, hex2: str) -> int:
    """Computes XOR distance between two hex-encoded 256-bit identifiers."""
    return int(hex1, 16) ^ int(hex2, 16)

def common_prefix_length(hex1: str, hex2: str) -> int:
    """Computes the number of leading common bits between two hex identifiers."""
    i1 = int(hex1, 16)
    i2 = int(hex2, 16)
    xor_val = i1 ^ i2
    if xor_val == 0:
        return 256
    # Fast bit length check
    return 256 - xor_val.bit_length()

import struct

class KBucket:
    def __init__(self, k: int = 20):
        self.k = k
        # List of dicts: {"node_id": str, "endpoints": [...]}
        self.nodes = []

    def add_node(self, node: dict) -> bool:
        node_id = node["node_id"]
        # If already exists, update and move to end (recently used)
        for i, existing in enumerate(self.nodes):
            if existing["node_id"] == node_id:
                self.nodes.pop(i)
                self.nodes.append(node)
                return True
        # If not full, append
        if len(self.nodes) < self.k:
            self.nodes.append(node)
            return True
        # Bucket full; return False (in Kademlia, would trigger ping check of oldest, but keeping simple)
        return False

    def remove_node(self, node_id: str):
        self.nodes = [n for n in self.nodes if n["node_id"] != node_id]

class RoutingTable:
    def __init__(self, host_node_id: str, k: int = 20):
        self.host_node_id = host_node_id
        self.k = k
        # We model routing table as 256 physical buckets (one for each potential CPL)
        self.buckets = [KBucket(k) for _ in range(256)]

    def add_node(self, node: dict) -> bool:
        node_id = node["node_id"]
        if node_id == self.host_node_id:
            return False
        cpl = common_prefix_length(self.host_node_id, node_id)
        # fallback for identical (but already filtered out above)
        if cpl >= 256:
            cpl = 255
        return self.buckets[cpl].add_node(node)

    def get_closest_nodes(self, target_key: str, count: int) -> list[dict]:
        """Returns up to `count` closest nodes to the target_key, sorted by XOR distance."""
        all_nodes = []
        for b in self.buckets:
            all_nodes.extend(b.nodes)
        
        # Sort by XOR distance from target_key
        target_val = int(target_key, 16)
        all_nodes.sort(key=lambda n: int(n["node_id"], 16) ^ target_val)
        return all_nodes[:count]

    def remove_node(self, node_id: str):
        cpl = common_prefix_length(self.host_node_id, node_id)
        if cpl >= 256:
            cpl = 255
        self.buckets[cpl].remove_node(node_id)
