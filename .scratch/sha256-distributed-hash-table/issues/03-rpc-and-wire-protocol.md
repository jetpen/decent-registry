# 03 — RPC / Wire Protocol Definition

Type: research
Status: resolved

Define the minimal RPC/wire protocol messages and lookup/storage semantics needed for the Python Kademlia-style registry.

## Answer
Prototype-first: TCP transport + length-prefixed JSON messages.

### 1. Transport / framing
- Transport: TCP.
- Message envelope: 4-byte big-endian unsigned length `N`, followed by `N` bytes of UTF-8 JSON payload.
- Each TCP connection handles multiple request/response messages.

### 2. Message format
All messages are JSON objects with at least:
- `type`: message family string
- `id`: request UUID (string) to correlate responses

Errors are returned as:
- `{ "type": "ERROR", "id": <request id>, "error": "<string>" }`

### 3. Message families
#### a) `PING`
- Request: `{ "type": "PING", "id": "...", "sender_id": "<node-id-hex>" }`
- Response: `{ "type": "PONG", "id": "...", "responder_id": "<node-id-hex>", "ts": <unix_ts> }`

#### b) `FIND_NODE`
- Request:
  - `{ "type": "FIND_NODE", "id": "...", "target_key": "<sha256hex>", "k": <int> }`
- Response:
  - `{ "type": "FIND_NODE_REPLY", "id": "...", "closer_nodes": [ {"node_id": "<hex>", "endpoints": ["tcp://h:p", "http://h:p"]}, ... ] }`

`closer_nodes` must be the k nodes with smallest XOR distance to `target_key` among the responder’s routing table/known candidates (implementation-defined selection, but must be consistent with XOR ordering).

#### c) `PUT_VALUE` (STORE)
- Request:
  - `{ "type": "PUT_VALUE", "id": "...", "target_key": "<sha256hex>", "value_record": { ... } }`
- Response:
  - `{ "type": "PUT_VALUE_REPLY", "id": "...", "status": "ok" }`

Target node validates basic schema constraints (ticket 02 validation rules) and stores the record keyed by `target_key`.

#### d) `GET_VALUE` (FIND_VALUE)
- Request:
  - `{ "type": "GET_VALUE", "id": "...", "target_key": "<sha256hex>", "k": <int> }`
- Response (two cases):
  1) Found (not expired):
     - `{ "type": "GET_VALUE_REPLY", "id": "...", "found": true, "value_record": { ... } }`
  2) Not found:
     - `{ "type": "GET_VALUE_REPLY", "id": "...", "found": false, "closer_nodes": [ ... ] }`

If record is expired, treat as not found.

#### e) Bootstrap / join
Two prototype options (wire-level or documented):
- Document a bootstrap workflow: the joining node starts by dialing a configured seed list of endpoints, then populates routing buckets via `FIND_NODE` lookups.
- Optionally add a `BOOTSTRAP` message later; not required for v1.

### 4. Iterative lookup semantics
Inputs (local):
- `target_key`
- `k` (replication/closest-set size; prototype default: 20)
- `α` (concurrency; prototype default: 3)

Algorithm (prototype termination):
1. Maintain `shortlist` = initial known nodes ordered by XOR distance to `target_key`.
2. Repeat for up to a max round count (e.g., 20):
   - Choose up to `α` nodes from `shortlist` with smallest XOR distance.
   - In parallel, send `GET_VALUE` to them.
   - If any response returns `found=true`, return the `value_record`.
   - Otherwise, for each response with `closer_nodes`, merge those nodes into `shortlist` (dedup by `node_id`, keep endpoint sets unioned).
   - Track whether the best XOR distance improved compared to the previous round.
3. Terminate when:
- no improvement in best XOR distance for one full round, OR
- `shortlist` has converged to the k closest nodes you’ve seen.
4. If no value was found, return the final k closest nodes as best-effort output.

### 5. Error handling
- Malformed/invalid JSON or invalid message shape: respond with `ERROR` and close the connection.
- Timeouts/retries: treat as failure; do not abort the whole lookup.

## Comments
Wire protocol kept minimal for a prototype. Later tickets can add UDP, NAT traversal, authentication/signing, and record validation hardening.
