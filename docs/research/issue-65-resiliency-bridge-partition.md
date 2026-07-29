# Issue #65 — Resiliency across libp2p Kad-DHT partitions / bridge behavior

## Question
Two otherwise-isolated libp2p/Kad-DHT networks exist:
- Network1: seed1a + node1b
- Network2: seed2a + node2b

A client/bridge node bootstraps using both seeds (seed1a and seed2a). Does that establish a durable “bridge” such that information/federation can be synchronized across both networks even after the bridge disconnects? Further: can routing-table / peer-contact information propagate across the bridge so that, after the bridge disconnects, the two networks remain interconnected?

## Relevant code facts (repo)
### Bridge / bootstrap behavior
In `src/decent_registry/dht/libp2p_dht.py`, the bridge node’s joining mechanism is:
- `bootstrap(remote_tcp_multiaddr)` requires an identify-style destination containing `/p2p/<peerid>`
- implementation: `await self._host.connect(peer_info)`

Therefore, bridging depends on the existence of dial/connect paths to peers on both sides while the bridge process is running.

### Registry storage namespaces
The DHT keyspace used for stored signed records is namespaced:
- providers: `/decent-registry/provider/{object_hash}`
- identities: `/decent-registry/identity/{object_key_hex}`

Implemented via `_kad_key(object_hash, kind)` in `Libp2pKadDHT`.

### put / get paths
- `put_signed_provider_record()`:
  - reads existing value with `await self.dht.get_value(kad_key, quorum=0)`
  - enforces signature validity + seq monotonicity via `RecordValidator.validate_provider_overwrite(...)`
  - writes via `await self.dht.put_value(kad_key, envelope_cbor)`
- `get_signed_provider_record()`:
  - queries via `await self.dht.get_value(kad_key, quorum=quorum)`
  - if DHT value is missing and durable store exists, falls back to local LMDB cache

## Implemented experiment
### Goal
Empirically test the “bridge enables cross-network availability after disconnect” hypothesis.

### Experiment topology (local)
Created 5 in-process Kad-DHT nodes bound to localhost ephemeral ports:
- seed1a, node1b on network1 (bootstrapped via seed1a)
- seed2a, node2b on network2 (bootstrapped via seed2a)
- bridge bootstrapped to both seed1a and seed2a simultaneously

### Procedure
1. Bootstrap `node1b` only to `seed1a`.
2. Bootstrap `node2b` only to `seed2a`.
3. Bring up `bridge`, bootstrap it to both `seed1a` and `seed2a`.
4. While `bridge` is running:
   - `bridge` performs `put provider` for `obj_hash1`.
   - `node1b` and `node2b` attempt `get provider` for `obj_hash1`.
5. Stop `bridge` (disconnect/offline).
6. After bridge is stopped:
   - `node1b` performs `put provider` for `obj_hash2`.
   - `node2b` attempts `get provider` for `obj_hash2`.

### Test harness
Runner script committed in this repo:
- `scripts/bridge_partition_resiliency_experiment.py`
- commit: `8db37eb` (“test/exp: bridge partition resiliency experiment script (#65)”) 

## Findings (observed evidence)
### Output summary from the implemented runner (single run)
The runner printed:

- During bridge is online, after `bridge` puts `obj_hash1`:
  - `bridge_found: True`
  - `node1b_found: False`
  - `node2b_found: False`

- After bridge disconnect (bridge process stopped):
  - `node2b_obj_hash2_found: False`

### Direct implication
In this local topology model, connecting a bridge node to both seeds was not sufficient to make values placed while the bridge was online become retrievable by nodes on the other side, and after the bridge disconnects, cross-network availability did not persist.

## Limitations
- This is **not** a true transport-level network partition.
  - All peers were on `127.0.0.1` and could be dually dialed if routing/peerstore state permitted.
  - The isolation is primarily topological (what each node bootstraps to initially), not enforced by firewall/NAT rules.
- libp2p/Kademlia routing/table convergence dynamics were not exhaustively tuned/controlled.
- Durable store replication behavior across partitions was not conclusively characterized here (the experiment was intended as a resiliency probe, not a full quorum/replication study).

## Conclusion (current evidence)
- The “routing-table / peer-contact propagation yields permanent interconnection after bridge disconnect” claim is not supported by the observed behavior in this repo’s current local Kad-DHT setup.
- Cross-network federation (in the sense of post-disconnect mutual retrievability) did not occur under the tested conditions.

## Next steps (to strengthen the evidence)
1. Repeat the same experiment under **real network partition** conditions (separate subnets / firewall rules) to prevent any accidental direct dialability.
2. Add additional probes:
   - check whether `node1b` can eventually discover records placed by `bridge` (time-to-availability)
   - check whether `node2b` can discover records after longer bridge uptime (routing convergence window)
3. If available in the libp2p runtime used by this repo, vary DHT maintenance parameters and/or random walk settings to evaluate whether replication/lookup stabilization changes the result.
