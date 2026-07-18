# 04 — Python DHT Prototype (Kademlia XOR subset)

Type: prototype
Status: resolved

Implement the minimal Python DHT prototype implied by tickets 01-03.

## Answer
The minimal Python DHT prototype has been implemented under `.scratch/sha256-distributed-hash-table/src/`.

### 1. XOR math and Distance helper
- `xor_distance(id1, id2)`: Bitwise XOR of two hex node identifiers parsed as integers. Returns integer distance.

### 2. Node identity and Storage (`.scratch/sha256-distributed-hash-table/src/storage.py`)
- Nodes generate a 256-bit identifier (64 hex characters) and start a local TCP-based listener.
- Storage holds stored DHT records in-memory, keyed by `object_hash`. Expired records (where `expires_at < current_time`) are dynamically pruned on access and treated as "not found".

### 3. Routing Table (`.scratch/sha256-distributed-hash-table/src/routing.py`)
- Standard Kademlia split buckets: organizes known nodes into k-buckets depending on their common prefix length (CPL) with the host node ID.
- Up to `k = 20` nodes are held per bucket. Eviction and sorting priorities apply XOR distance ordering relative to the target or host keys.

### 4. Framing, Server, and protocol handles (`.scratch/sha256-distributed-hash-table/src/protocol.py`)
- Envelope framing: 4-byte big-endian unsigned length `N` preceding the JSON body over plain TCP.
- Message handlers implement `PING` (corresponds to verification), `FIND_NODE`, `PUT_VALUE` (verifies version, `expires_at`, types), and `GET_VALUE` (returns the record if present and not expired, or alternative `closer_nodes`).

### 5. Iterative Lookups and Core Client logic (`.scratch/sha256-distributed-hash-table/src/dht.py`)
- `iterative_find_node`:Progressively walks buckets toward destination target keys using concurrent parallel requests (capped by `α = 3`).
- `iterative_find_value`: Runs lookup walker, returning the first non-expired record found or the best-effort closest nodes.
- Orchestrates peer-discovery / bootstrapping by looking up its own host node ID after connecting to the initial configurability seed endpoints.

### 6. Validation tests (`.scratch/sha256-distributed-hash-table/src/test_dht.py`)
- Completed verification test suite demonstrating single-node local validation, multi-node network bootstrapping over localhost, multi-hop iterative values discovery, and correctness of record TTL expirations.

## Comments
Code fully implemented and locally verified. See files in `.scratch/sha256-distributed-hash-table/src/`.
