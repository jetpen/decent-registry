# 01 — Distributed Registry Overview

Type: research
Status: resolved

What is the overall architecture for a distributed hash table that acts as a registry, mapping SHA-256 hashes to Internet addresses of objects? Key sub-questions:
- Which DHT protocol(s) are suitable (e.g., Kademlia, Chord, etc.) for hash→key lookups?
- How are object addresses stored at the responsible nodes (replication, TTLs, multi-address support)?
- Bootstrap/peer discovery: how new nodes find the network and start answering lookups.
- Updates, failures, and churn handling: how the registry remains consistent enough for practical resolution.

## Answer
Python implementation constraint: in this environment, the common Python DHT/Kademlia module names were not importable (`kademlia`, `pydht`, `libp2p`, `pylibp2p`, `kad`, `pylibp2p`). Therefore the architecture is a custom Python implementation of a Kademlia-style DHT subset, driven by Kademlia protocol mechanics and practical parameter defaults.

Recommended design: Kademlia-style XOR routing over SHA-256 key material, with value records implementing a provider registry.

1. Routing / keyspace
- Use XOR distance between identifiers.
- Kademlia uses an XOR-based metric: `d(x,y) = x XOR y` over the keyspace, and lookups converge in logarithmically many steps by querying increasingly closer nodes.
- Use SHA-256 for the key material you route on (so the registry key is the SHA-256 hash of the object). Keyspace size is 256 bits.

2. Lookup operation model
- Iterative lookup: an initiating node performs the lookup by contacting a sequence of “closer” nodes; termination happens when sufficient closest responses are obtained.
- Concurrency/parallelism knob (`α`) controls the number of parallel in-flight RPCs during a lookup.
- Kademlia’s original design uses parallel/asynchronous queries to tolerate node failures without user-facing timeout amplification.

3. Value storage model for a registry
- Store `(object-hash → value-record)` mappings.
- For “object address” resolution, define the value-record as a list of providers that can serve the object identified by that hash.
- Providers are represented by provider identity + one or more network address endpoints usable by clients to contact the provider.

4. Replication / durability
- Responsibility for a key is the “k closest peers” under the XOR metric.
- Practical defaults from libp2p kad deployments: replication parameter `k` recommended default is 20.
- Replication across the k-closest region provides resilience under churn and partial failures.

5. Record lifecycle (TTL and republishing)
- Use TTL-based record expiration.
- Practical defaults (libp2p kad + related operational parameter guides): value record TTL is often 48 hours, with periodic re-publication/re-replication so records do not silently disappear.

6. Bootstrap / network joining
- A joining node must be able to contact at least one existing node participating in the DHT swarm.
- Use an explicit bootstrap list (seed nodes) or dedicated bootstrapper nodes that are publicly reachable.

7. Consistency properties
- The registry is eventually consistent.
- Lookups return best-effort “closest peers” and may return stale providers until TTL/republishing refreshes records.

Follow-up uncertainties this effort must resolve next:
- Exact provider/value-record schema (fields, versioning, address representation, dedup rules).
- Validation/signing strategy for provider entries (to mitigate malicious/stale addresses).
- Handling mutable address updates under TTL + republishing.
- Concrete selection of (`k`, `α`, termination/resiliency thresholds, TTL/republish intervals) for the desired churn tolerance and lookup latency.

## Comments
- Ticket 01 sets the DHT architecture for the chosen Python stack; subsequent tickets must remove libp2p/multiaddr-specific assumptions.
