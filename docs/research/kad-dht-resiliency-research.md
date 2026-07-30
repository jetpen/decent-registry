# Resiliency across libp2p / Kad-DHT partitions and multi-seed bridge behavior

## Question (general)
Consider two otherwise-isolated libp2p/Kad-DHT networks:
- Network1: seed1a + node1b
- Network2: seed2a + node2b

A client node may bootstrap/connect to multiple seeds (e.g., one seed in each network) and then:
1) perform PUTs of signed registry records
2) optionally remain online while doing so

What resiliency properties follow under partition / intermittent connectivity?
- Cross-network *data availability*: can nodes on both sides retrieve values placed by the multi-seed client?
- Cross-network *persistence after disconnect*: does availability persist after the multi-seed client disconnects?
- Cross-network *routing/peer-contact propagation*: can routing-table/peer-contact state remain sufficient to keep networks interconnected after disconnect?

## Evidence log (amendable)
This document is expected to be appended by subsequent resiliency research tickets.

## Open questions / additions
- How does record placement differ when the multi-seed client performs PUTs vs when it only performs GETs?
- Does libp2p Kad-DHT replicate PUTs across a unified overlay, or does placement remain constrained to the portion of the overlay the node effectively participates in?
- Does durable store configuration (LMDB) change observed cross-network resiliency? When DHT retrieval fails, does fallback to local durable store mask cross-network availability failures?

- [#67 - RESOLVED] Default client-side GET does not scan/try alternate bootstrapped seeds as fallback during the same lookup. GET behavior is driven by the libp2p/Kad-DHT routing-table lookup for the key (closest-peer lookup / routing-table contents), so a record may be unreachable even when the client is connected to multiple seeds. A subsequent GET can succeed after bootstrapping to the “correct” network (routing table updates), but fallback-to-other-seed is not automatic.

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

## Implemented experiment (previous evidence)
### Goal
Empirically test cross-network data availability and post-disconnect persistence when a node connected to multiple seeds performs PUTs.

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
- commit: `8db37eb` (“test/exp: bridge partition resiliency experiment script”) 

## Findings (observed evidence)
### Output summary from the implemented runner (single run) (bridge PUT)
The original runner printed:

- During bridge is online, after `bridge` puts `obj_hash1`:
  - `bridge_found: True`
  - `node1b_found: False`
  - `node2b_found: False`

- After bridge disconnect (bridge process stopped):
  - `node2b_obj_hash2_found: False`

### Direct implication (from previous evidence)
In this local topology model, connecting a bridge node to both seeds was not sufficient to make values placed while the bridge was online become retrievable by nodes on the other side, and after the bridge disconnects, cross-network availability did not persist.

### Additional evidence: PUT placement when a multi-seed client does the PUT
New local experiment (scenario-matrix) executed via:
- `scripts/put_multiseed_client_put_placement_experiment.py`

Matrix:
- Scenario A (control): client bootstraps to `seed1a` only, then PUTs `obj_hash_a`.
- Scenario B (test): client bootstraps to `seed1a` AND `seed2a` simultaneously, then PUTs `obj_hash_b`.
- After each client disconnect, probes are re-run.

Observed single-run results (from the script output):
- `scenario_A_put_via_client_seed1_only`:
  - `node1b_found: False`
  - `node2b_found: False`
- `scenario_B_put_via_client_seed1_and_seed2`:
  - `node1b_found: False`
  - `node2b_found: True`
  - `node2b_first_found_after_s: ~9.83`
- `persistence_after_disconnect`:
  - `node2b_get_obj_hash_a: False`
  - `node2b_get_obj_hash_b: True`

### Interpretation for the #66 question
In this run, a multi-seed client’s PUT was not simultaneously available across both networks.
- The PUT made `obj_hash_b` retrievable in Network2 (`node2b_found=True`) but not Network1 (`node1b_found=False`).
- After the multi-seed client disconnected, Network2 still retrieved the record while Network1 did not.

Therefore, the PUT appears to be effectively placed/accepted into one overlay partition (not both) under the tested conditions.

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

### Additional evidence: Client-side GET fallback across seeds (#67)
New local experiments executed (same local topology model: Network1 = seed1a + node1b, Network2 = seed2a + node2b):

1) `scripts/get_multiseed_client_get_fallback_experiment.py`

Question tested: client bootstraps to one seed vs both seeds, then performs GET for a record that was PUT into Network2 (via node2b).

Recorded results (3 independent reruns; all consistent):
- Sanity (record landed):
  - node2b GET for `obj_hash_b`: `found=true` (first_found_after_s: mean ≈ 0.00188s, range [0.00178s, 0.00203s])
  - node1b GET for `obj_hash_b`: `found=false`
- Scenario A (client bootstraps to Network1 only; GET):
  - `found=false` (3/3)
- Scenario B (client bootstraps to both seeds; GET):
  - `found=false` (3/3)
- Scenario C (client bootstraps to Network1 only; GET fails; then bootstrap Network2 and retry GET):
  - first GET after seed1: `found=false` (3/3)
  - second GET after bootstrapping seed2: `found=true` (first_found_after_s: mean ≈ 0.3166s, range [0.3150s, 0.3177s])

Interpretation:
- Being connected/bootstrapped to multiple seeds does not force the GET to “try the other network” when the first routing-table lookup misses.
- Successful retrieval after bootstrapping seed2 reflects routing-table / peer-contact convergence rather than an explicit alternate-seed fallback inside the GET call.

2) `scripts/get_multiseed_client_put_then_get_experiment.py`

Setup: same record PUT performed by a multi-seed client; probes check whether other nodes observe the record and whether the client can GET after disconnecting seeds.

Observed results (3 independent reruns; all consistent):
- PUT landing probe:
  - node1b GET: `found=false` (3/3)
  - node2b GET: `found=false` (3/3)
- Client GET:
  - GET while connected to seed1 + seed2: `found=true` (first_found_after_s: mean ≈ 0.00189s, range [0.00182s, 0.00194s]) (3/3)
  - after disconnecting seed2: `found=true` (first_found_after_s: mean ≈ 0.00192s, range [0.00173s, 0.00213s]) (3/3)
  - after disconnecting both seeds: `found=true` (first_found_after_s: mean ≈ 0.00174s, range [0.00168s, 0.00178s]) (3/3)

Interpretation:
- In this repo’s current local Kad-DHT setup, client-performed PUTs may be sufficient for the client itself (client is within the responsible/serving set / local lookup path), while other nodes on the overlays may not observe the record. This can mask cross-network lookup behavior via self-contained availability.
