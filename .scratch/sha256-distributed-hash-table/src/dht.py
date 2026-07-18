import uuid
import time
import logging
from .protocol import DHTNode

logger = logging.getLogger("dht.orchestration")

class DHTClient:
    def __init__(self, node: DHTNode, alpha: int = 3):
        self.node = node
        self.alpha = alpha

    def bootstrap(self, bootstrap_endpoints: list[str]) -> bool:
        """Joins the network by querying bootstrap seed nodes for local node id."""
        success = False
        for ep in bootstrap_endpoints:
            # ping bootstrap seeds to register ourselves and populate table
            pong = self.node.send_direct(ep, {"type": "PING", "id": uuid.uuid4().hex})
            if pong:
                success = True
                # Add node to our table
                resp_id = pong.get("responder_id")
                resp_endpoints = pong.get("responder_endpoints") or [ep]
                if resp_id:
                    self.node.routing_table.add_node({"node_id": resp_id, "endpoints": resp_endpoints})
        
        if success:
            # Run iterative lookup of our own node identity to populate/refresh our buckets
            self.iterative_find_node(self.node.node_id)
        return success

    def iterative_find_node(self, target_key: str) -> list[dict]:
        """Locates the closest known nodes to target_key by walking the DHT."""
        shortlist = self.node.routing_table.get_closest_nodes(target_key, count=self.node.k)
        contacted = set()
        
        for _ in range(20): # max round limit
            # filter uncontacted
            candidates = [n for n in shortlist if n["node_id"] not in contacted]
            if not candidates:
                break
            
            # Sort by XOR distance
            target_val = int(target_key, 16)
            candidates.sort(key=lambda n: int(n["node_id"], 16) ^ target_val)
            
            # pick up to alpha
            to_query = candidates[:self.alpha]
            new_nodes_found = []
            
            # query in series/parallel (sequential list query is simple and reliable for standard socket limits)
            for target_node in to_query:
                node_id = target_node["node_id"]
                contacted.add(node_id)
                eps = target_node.get("endpoints", [])
                if not eps:
                    continue
                
                resp = self.node.send_direct(eps[0], {
                    "type": "FIND_NODE",
                    "id": uuid.uuid4().hex,
                    "target_key": target_key,
                    "k": self.node.k
                })
                if resp and resp.get("type") == "FIND_NODE_REPLY":
                    # Add query responder to routing
                    resp_id = resp.get("responder_id")
                    if resp_id:
                        self.node.routing_table.add_node({"node_id": resp_id, "endpoints": eps})
                    
                    # Merge closer_nodes
                    for cn in resp.get("closer_nodes", []):
                        if cn["node_id"] != self.node.node_id:
                            new_nodes_found.append(cn)
            
            if not new_nodes_found:
                # Terminate round if no new contacts
                break
                
            # Merge and sort blacklist
            shortlist_map = {n["node_id"]: n for n in shortlist}
            for n in new_nodes_found:
                shortlist_map[n["node_id"]] = n
                
            shortlist = list(shortlist_map.values())
            shortlist.sort(key=lambda n: int(n["node_id"], 16) ^ target_val)
            shortlist = shortlist[:self.node.k]
            
        return shortlist

    def iterative_find_value(self, target_key: str) -> tuple[dict | None, list[dict]]:
        """Iteratively queries nodes for a value record associated with target_key."""
        shortlist = self.node.routing_table.get_closest_nodes(target_key, count=self.node.k)
        contacted = set()
        
        target_val = int(target_key, 16)
        
        for _ in range(20):
            candidates = [n for n in shortlist if n["node_id"] not in contacted]
            if not candidates:
                break
            
            candidates.sort(key=lambda n: int(n["node_id"], 16) ^ target_val)
            to_query = candidates[:self.alpha]
            new_nodes_found = []
            
            for target_node in to_query:
                node_id = target_node["node_id"]
                contacted.add(node_id)
                eps = target_node.get("endpoints", [])
                if not eps:
                    continue
                
                resp = self.node.send_direct(eps[0], {
                    "type": "GET_VALUE",
                    "id": uuid.uuid4().hex,
                    "target_key": target_key,
                    "k": self.node.k
                })
                if resp and resp.get("type") == "GET_VALUE_REPLY":
                    # Add query responder to routing
                    resp_id = resp.get("responder_id")
                    if resp_id:
                        self.node.routing_table.add_node({"node_id": resp_id, "endpoints": eps})
                    
                    if resp.get("found"):
                        return resp["value_record"], []
                    
                    for cn in resp.get("closer_nodes", []):
                        if cn["node_id"] != self.node.node_id:
                            new_nodes_found.append(cn)
            
            if not new_nodes_found:
                break
                
            shortlist_map = {n["node_id"]: n for n in shortlist}
            for n in new_nodes_found:
                shortlist_map[n["node_id"]] = n
                
            shortlist = list(shortlist_map.values())
            shortlist.sort(key=lambda n: int(n["node_id"], 16) ^ target_val)
            shortlist = shortlist[:self.node.k]
            
        return None, shortlist

    def store_value(self, target_key: str, record: dict) -> int:
        """Stores a record on the k closest nodes to the key. Returns count of successful stores."""
        closest_nodes = self.iterative_find_node(target_key)
        # Also store locally if we are among closest
        target_val = int(target_key, 16)
        all_candidates = list(closest_nodes)
        
        # Include our node in decision
        me = self.node.my_node_info
        all_candidates.append(me)
        all_candidates.sort(key=lambda n: int(n["node_id"], 16) ^ target_val)
        
        store_targets = all_candidates[:self.node.k]
        
        success_count = 0
        for target in store_targets:
            if target["node_id"] == self.node.node_id:
                self.node.storage.put(target_key, record)
                success_count += 1
            else:
                eps = target.get("endpoints", [])
                if not eps:
                    continue
                resp = self.node.send_direct(eps[0], {
                    "type": "PUT_VALUE",
                    "id": uuid.uuid4().hex,
                    "target_key": target_key,
                    "value_record": record
                })
                if resp and resp.get("type") == "PUT_VALUE_REPLY" and resp.get("responder_id") == target["node_id"]:
                    success_count += 1
                    
        return success_count
