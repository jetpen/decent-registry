# sha256-distributed-hash-table — Wayfinding Map

## Fog
- Need to design a distributed hash table (DHT) that functions as a registry.
- Given a SHA-256 hash of an object, resolve to the Internet address(es) where that object can be found.
- Repo lacks existing domain vocabulary/ADR context (no CONTEXT.md / CONTEXT-MAP.md).

## Decisions-so-far
- Architecture: custom Python implementation of a Kademlia-style XOR DHT subset (custom transport/logic required because common Python DHT/Kademlia module names were not importable in this environment).
- Keying: route on XOR distance between identifiers; registry key is SHA-256 hex of the object.
- DHT value model: `(object_hash -> provider list)` value record.
- Provider value record schema (ticket 02): JSON schema with `version`, `object_hash`, `ttl_seconds`, `expires_at`, `providers[]` (`provider_id` as Ed25519 public key hex, `endpoints[]`, `last_seen`). Prototype validation rules and dedup rules specified.
- Wire/RPC protocol (ticket 03): TCP with length-prefixed JSON envelope; `FIND_NODE`, `PUT_VALUE`, `GET_VALUE` (+ `PING`/`PONG`), plus iterative lookup semantics and termination criteria.
- Parameter targets to calibrate the prototype: recommended defaults from kad-style deployments include `k ≈ 20`, value record TTL ≈ 48h, and concurrency `α ≈ 3`.

Next: none — tickets 05–08 are complete (packaging, node CLI, registry CLI, and CLI put/get end-to-end verification).

- Cleanup: removed duplicate prototype source under `.scratch/sha256-distributed-hash-table/src/`; canonical implementation lives under `src/decent_registry/dht/`.

- Ticket 05 update: prototype packaged as `decent_registry.dht.*` importable modules; `pytest` passes (3 tests).
- Ticket 06 update: implemented `decent-registry node` CLI with `--bootstrap` and bounded `--run-seconds` mode; bootstrap failure exit code verified; `PING`/`PONG` validated. Full `pytest -q` passes (5 tests).
- Ticket 07 update: implemented `decent-registry put`/`get` registry CLI; unit+subprocess tests verify put→get and TTL expiry (now `7 passed`).
- Ticket 08 update: end-to-end CLI integration verification implemented (now `7 passed`).

Ticket pointers:
- Ticket 01: `.scratch/sha256-distributed-hash-table/issues/01-distributed-registry-overview.md`
- Ticket 02: `.scratch/sha256-distributed-hash-table/issues/02-provider-record-schema.md`
- Ticket 03: `.scratch/sha256-distributed-hash-table/issues/03-rpc-and-wire-protocol.md`
- Ticket 05: `.scratch/sha256-distributed-hash-table/issues/05-package-and-productionize-python-dht-prototype.md`
- Ticket 06: `.scratch/sha256-distributed-hash-table/issues/06-node-cli-start-listener-via-bootstrap.md`
- Ticket 07: `.scratch/sha256-distributed-hash-table/issues/07-registry-cli-put-get-provider-record.md`
- Ticket 08: `.scratch/sha256-distributed-hash-table/issues/08-cli-driven-end-to-end-integration-verification.md`
