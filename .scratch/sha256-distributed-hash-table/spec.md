Status: ready-for-agent

## Problem Statement

Need a decentralized, eventually consistent registry that maps a SHA-256 hash of an object to Internet address(es) where providers can serve that object, without relying on centralized indexing services or non-importable third-party DHT/Kademlia libraries.

## Solution

Implement a Python, Kademlia-style Distributed Hash Table (DHT) subset that routes on XOR distance over a 256-bit keyspace (keys are SHA-256 hex strings). The system stores provider registry records (object-hash → provider list) using TTL-based expiration. Node-to-node communication uses a minimal TCP transport with length-prefixed JSON RPC messages. Lookups are iterative: a client walks the routing table by repeatedly querying α closest known nodes and expanding a shortlist with closer nodes until value is found (or iteration/termination criteria are reached).

## User Stories

1. As a content provider, I want to publish a provider record for an object hash, so that others can discover where to retrieve the object.
2. As a content provider, I want to include one or more reachable provider endpoints for an object hash, so clients can contact me using appropriate transport(s).
3. As a content provider, I want my provider record to automatically expire, so the registry eventually stops returning stale addresses.
4. As a content provider, I want to republish/update my provider record before expiration, so the registry refreshes last-seen information.
5. As a content provider, I want provider entries to deduplicate by provider identity and keep the newest last-seen, so repeated publishes converge.
6. As a node operator, I want to run a DHT node that listens for TCP RPC messages, so the registry network can be deployed without additional infrastructure.
7. As a node operator, I want a node identity (node_id) that can participate in XOR routing, so the DHT can form buckets and return closer nodes.
8. As a node operator, I want the routing table to be populated from peers encountered via RPC traffic, so the node becomes useful after bootstrapping.
9. As a new node, I want to join the network by contacting at least one known bootstrap endpoint, so I can participate in lookups.
10. As a new node, I want to discover/refresh my routing state by performing lookups based on my own node_id, so I fill appropriate buckets.
11. As a network participant, I want to perform an iterative node lookup for a target key, so I can find the closest known nodes relevant to that key.
12. As a network participant, I want an iterative value lookup that returns the provider record when present and unexpired, so I can resolve objects.
13. As a network participant, I want value lookups to fall back to returning closest nodes when the value is not found, so resolution can be retried/continued.
14. As a client, I want the DHT to use XOR distance on SHA-256 key material, so routing behavior is deterministic across nodes.
15. As a client, I want the lookup to query up to α nodes concurrently/in each round, so failures do not permanently stall progress.
16. As a client, I want lookups to terminate when the search stops improving or convergence conditions are reached, so lookups complete with bounded effort.
17. As a client, I want timeouts and malformed-message handling to not crash the node process, so the system remains available under bad peers.
18. As a node, I want to validate received provider records (version/object_hash/expiry structure), so invalid or expired data is rejected.
19. As a node, I want to accept PUT_VALUE only when the record passes validation, so clients can rely on returned values.
20. As a node, I want to treat expired stored records as absent (and prune), so GET_VALUE does not return stale entries.
21. As an application developer, I want a stable JSON message contract for PING/PONG, FIND_NODE, GET_VALUE, and PUT_VALUE, so I can interoperate with the DHT.
22. As an application developer, I want message framing to be length-prefixed, so I can implement the protocol correctly over TCP streams.
23. As an application developer, I want request-response correlation via request id, so I can match responses to outstanding queries.
24. As an application developer, I want consistent response structures for found vs not-found GET_VALUE_REPLY, so clients can implement lookup logic.
25. As a security-conscious operator, I want to at least have a clear extension point for adding provider identity signing later (even if v1 is trust-based), so the system can be hardened.
26. As an operator, I want the system to be eventually consistent via TTL, so correctness is achieved over time rather than requiring strict consensus.
27. As an operator, I want the system to overwrite stored values for the same object hash on PUT_VALUE, so updates are applied deterministically.
28. As a client, I want store_value to place records on the k closest nodes to the target key (including possibly local storage), so replication improves availability.
29. As a client, I want store_value to return a success count, so I can track whether replication succeeded.
30. As a client, I want routing table buckets to enforce a per-bucket capacity (k), so memory stays bounded.
31. As a client, I want routing table node sets to be kept updated via most-recently-used behavior when the same node_id is re-seen, so frequently active peers remain in view.
32. As a test harness, I want to run multi-node smoke tests on localhost using TCP ports, so behavior can be validated without external dependencies.
33. As a tester, I want unit tests to cover routing XOR distance, TTL expiration, and multi-node iterative value discovery, so regressions are caught early.

## Implementation Decisions

- DHT model: Kademlia-style XOR metric DHT subset.
  - Routing key: `object_hash` is SHA-256 of the object, encoded as lowercase hex (64 chars).
  - Distance: `d(x,y) = x XOR y` computed over 256-bit identifiers.
- Node routing structure:
  - Routing table modeled as 256 k-buckets indexed by common prefix length (CPL) between host node_id and remote node_id.
  - Each bucket stores up to k nodes (k default target 20).
  - Bucket insertion updates existing node_id by moving it to most-recently-used position; if full, insertion returns false (prototype simplifies Kademlia eviction/ping behavior).
- Lookup / iterative search:
  - Lookup parameters: replication/closest-set size `k` (default 20) and concurrency/round parallelism `α` (default 3).
  - Iterative walker maintains a shortlist of candidate nodes ordered by XOR distance to the target_key.
  - Each round selects up to α closest uncontacted candidates, queries them, and merges returned `closer_nodes` into the shortlist.
  - Termination criteria (prototype): max round limit (e.g., 20) and early stop when no newly discovered nodes are merged; the conceptual termination also includes “no improvement/convergence” in the design notes.
  - GET_VALUE iterative lookup returns the first found unexpired record; if none is found, returns final shortlist of closest known nodes.
- Value storage model:
  - Storage is an in-memory map keyed by `object_hash` to a provider list record.
  - Expiration is TTL-based; expired entries are pruned on access and treated as not found.
  - Replication target: store_value writes to the k-closest nodes to the target_key (and may store locally if the client node is among those k).
- Provider record schema (prototype-first; version 1; JSON-serializable):

  ```json
  {
    "version": 1,
    "object_hash": "<sha256hex>",
    "ttl_seconds": 172800,
    "expires_at": 1730000000,
    "providers": [
      {
        "provider_id": "<ed25519-public-key-hex>",
        "endpoints": ["tcp://<host>:<port>", "http://<host>:<port>"],
        "last_seen": 1730000000
      }
    ]
  }
  ```

  - `expires_at` is sender-computed as `now + ttl_seconds` (receivers enforce expiry).
  - TTL default target: 48 hours (172800s).
- Provider entry dedup and validation (prototype):
  - Dedup rule: unique by `provider_id` + sorted `endpoints`; in merged duplicates keep the newest `last_seen` (prototype notes).
  - Receiver validation on PUT_VALUE:
    - `version == 1`
    - `object_hash` equals the PUT_VALUE `target_key`
    - record is not expired (`now <= expires_at`)
    - `providers` is a list; each provider entry is a dict with non-empty `provider_id` and `endpoints` list with at least 1 endpoint.
- RPC / wire protocol contract:
  - Transport: TCP.
  - Framing: 4-byte big-endian unsigned length prefix followed by UTF-8 JSON payload.
  - All messages: JSON object containing at least `type` and request `id`.
  - Correlation: server echoes request `id` in response.
  - Message families:
    - `PING` → `PONG`
    - `FIND_NODE` → `FIND_NODE_REPLY` (returns `closer_nodes`)
    - `PUT_VALUE` → `PUT_VALUE_REPLY`
    - `GET_VALUE` → `GET_VALUE_REPLY` (found/value_record or closer_nodes)
  - Errors: `ERROR` with `{type: "ERROR", id: <request id>, error: <string>}`.
- Bootstrap/join:
  - Joining node is provided a seed list of bootstrap endpoints.
  - On bootstrap, node sends PING to bootstrap endpoints to register/confirm connectivity and to learn at least one responder node.
  - After success, node populates/refreshes routing by running iterative_find_node on its own node_id.

## Testing Decisions

- Primary test seam (external behavior): multi-node TCP integration.
  - Use the `DHTNode`/`DHTClient` lifecycle as black-box interfaces:
    - start multiple DHT nodes on localhost ports
    - bootstrap nodes by dialing a seed node
    - store a provider record for a target_key via store_value
    - verify iterative_find_value on another node discovers the unexpired provider record
    - verify TTL expiration behavior via existing TTL-focused tests
  - Rationale: exercises end-to-end message framing, request/response handling, routing table population from RPC, lookup iteration, and storage TTL pruning.
- Also retain existing unit coverage:
  - routing XOR distance and common prefix length logic
  - Storage TTL semantics (get returns None after expiration)
  - iterative lookup behavior across multi-node network (covers routing and protocol integration).
- Prior art:
  - existing test suite in `src/test_dht.py` provides the baseline for the multi-node lifecycle.

## Out of Scope

- Cryptographic signing/authentication of provider records in v1 (trust-based acceptance only).
- UDP transport, NAT traversal mechanisms, or discovery beyond explicit TCP seed endpoints.
- Production-grade churn resilience and proactive re-replication beyond TTL semantics.
- Full Kademlia eviction/ping behavior and strict bucket management fidelity (prototype simplifies bucket-full handling).
- Advanced security hardening for malformed/malicious inputs beyond minimal validation and ERROR responses.
- Persistent storage across restarts (prototype uses in-memory storage only).

## Further Notes

- The prototype is eventually consistent via TTL expiration; correctness is “best-effort” until republishing/refresh keeps values unexpired.
- Next hardening steps are clear extension points: provider record signing/verification, stricter message validation, and improved lookup termination/convergence behavior under churn.
