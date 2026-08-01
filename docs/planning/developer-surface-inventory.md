# Developer Surface Inventory

**Status:** research inventory
**Issue:** #76
**Branch:** `research/developer-surface-inventory`
**Baseline:** `7937c47`

## Scope and reading guide

This inventory separates surfaces that are implemented from research proposals and known
limitations. Repository paths are the primary citations; canonical user-facing material
is listed in [README.md](../../README.md) and the protocol documentation.

The project exposes a Python package, a command-line client/node launcher, signed-record
formats, persistent storage, and a libp2p Kad-DHT integration. The inventory is intended
to help a developer find the right entry point before changing or integrating the system.

## Quick surface map

| Area | Implemented entry point | Primary source |
| --- | --- | --- |
| CLI | `decent-registry` commands | [cli.py](../../src/decent_registry/cli.py) |
| Configuration | configuration loading and settings | [config.py](../../src/decent_registry/config.py) |
| Registry orchestration | service operations | [registry_service.py](../../src/decent_registry/registry_service.py) |
| Record validation | signed-update and record checks | [record_validator.py](../../src/decent_registry/record_validator.py) |
| Cryptographic verification | signatures and envelopes | [verification.py](../../src/decent_registry/verification.py) |
| Signed wire form | envelope construction and parsing | [signed_envelope.py](../../src/decent_registry/signed_envelope.py) |
| Envelope construction | record-to-envelope helpers | [envelope_builder.py](../../src/decent_registry/envelope_builder.py) |
| Encoding | canonical serialization helpers | [encoding.py](../../src/decent_registry/encoding.py) |
| Keys and crypto | Ed25519 utilities | [crypto_utils.py](../../src/decent_registry/crypto_utils.py) |
| Provider records | provider schema and URL data | [provider_schema.py](../../src/decent_registry/provider_schema.py) |
| Storage | backend abstraction and LMDB implementation | [storage_backend.py](../../src/decent_registry/storage_backend.py) |
| Durable storage | persistent store implementation | [durable_store.py](../../src/decent_registry/durable_store.py) |
| DHT | libp2p Kad-DHT node and operations | [libp2p_dht.py](../../src/decent_registry/dht/libp2p_dht.py) |

## CLI surface (implemented)

The executable is documented in [README.md](../../README.md) and implemented in
[cli.py](../../src/decent_registry/cli.py).

### Key generation

- `decent-registry keygen` creates client key material for signing operations.
- Key-generation and configuration usage is explained in
  [client-keygen-cli-config.md](../client-keygen-cli-config.md).

### Node operation

- `decent-registry node` starts the registry node.
- `-v` / `--verbose` enables verbose node output.
- `--host` selects the node host.
- `--port` selects the node port.
- `--config` supplies configuration.
- `--bootstrap` supplies bootstrap connectivity.
- `--run-seconds` bounds a node run for scripted or local operation.
- Single-node setup is documented in [single-node-server-setup.md](../single-node-server-setup.md).
- Multi-node operation is documented in [multi-node-cluster-setup.md](../multi-node-cluster-setup.md).

### Provider records

- `decent-registry put provider` writes a provider record.
- `decent-registry get provider` reads a provider record.
- Provider examples and payload expectations are in
  [provider-put-get-examples.md](../provider-put-get-examples.md).

### Identity records

- `decent-registry put identity` writes an identity record.
- `decent-registry get identity` reads an identity record.
- Identity examples and payload expectations are in
  [identity-put-get-examples.md](../identity-put-get-examples.md).

## Package and protocol surface (implemented)

### Domain vocabulary

The protocol concepts are defined in [protocol-concepts.md](../protocol-concepts.md).

- `SignedUpdate` is the update being authorized.
- `SignedEnvelope` is the signed, transported record form.
- An Identity Record describes an owner identity.
- A Provider Record describes provider data and endpoints.
- `Owner Name` and `Owner Public Key` identify and bind the signer.
- `Object Key` identifies an identity object; `Object Hash` identifies a provider object.
- `Seq` provides update ordering.
- `Owner Binding` connects an object to its authorized owner.
- `Canonical CBOR` is the deterministic envelope encoding.
- `Ed25519` is the signature system.

### Service and validation

- [registry_service.py](../../src/decent_registry/registry_service.py) is the service-level
  orchestration surface for registry operations.
- [record_validator.py](../../src/decent_registry/record_validator.py) validates record
  structure and update rules.
- Implemented validation requires strict `Seq` increases for accepted updates.
- Implemented validation enforces owner binding.
- Provider URLs are validated and multiaddr endpoints are sorted as part of the provider
  record behavior.

### Encoding, envelopes, and cryptography

- [encoding.py](../../src/decent_registry/encoding.py) owns encoding helpers used by the
  protocol surface.
- [signed_envelope.py](../../src/decent_registry/signed_envelope.py) represents the signed
  envelope form.
- [envelope_builder.py](../../src/decent_registry/envelope_builder.py) builds envelopes.
- [verification.py](../../src/decent_registry/verification.py) verifies signatures and
  envelope authenticity.
- [crypto_utils.py](../../src/decent_registry/crypto_utils.py) provides Ed25519-related
  cryptographic utilities.
- Signed envelopes use canonical CBOR so signing and verification have a stable byte form.

### Schemas and persistence

- [provider_schema.py](../../src/decent_registry/provider_schema.py) defines provider record
  data and endpoint-related validation.
- [storage_backend.py](../../src/decent_registry/storage_backend.py) defines the storage
  backend surface.
- [durable_store.py](../../src/decent_registry/durable_store.py) implements durable storage.
- The implemented durable backend is LMDB.
- [config.py](../../src/decent_registry/config.py) supplies configuration integration for
  the runtime and storage-facing components.

## DHT surface (implemented)

The node and Kad-DHT integration are implemented in
[libp2p_dht.py](../../src/decent_registry/dht/libp2p_dht.py).

- The implementation provides a libp2p Kad-DHT node.
- The implementation supports DHT `put` and `get` operations.
- Provider namespace: `/decent-registry/provider/{object_hash}`.
- Identity namespace: `/decent-registry/identity/{object_key_hex}`.
- A provider key uses the provider `object_hash`.
- An identity key is `sha256(owner_name_bytes)`.
- Namespace and URL research is recorded in
  [registry-url-format.md](../research/registry-url-format.md).

## Configuration and operational documentation

- Runtime configuration is surfaced by [config.py](../../src/decent_registry/config.py).
- CLI configuration and key material are covered by
  [client-keygen-cli-config.md](../client-keygen-cli-config.md).
- A local node workflow is covered by [single-node-server-setup.md](../single-node-server-setup.md).
- Cluster/bootstrap operation is covered by [multi-node-cluster-setup.md](../multi-node-cluster-setup.md).
- Read/write examples are separated into provider and identity guides.
- The repository's current test command is `.venv/bin/pytest -q`.
- The parent-session verification result was `56 passed, 1 skipped`.

## Canonical documentation index

- [README.md](../../README.md): project orientation and implemented command usage.
- [protocol-concepts.md](../protocol-concepts.md): domain and protocol vocabulary.
- [single-node-server-setup.md](../single-node-server-setup.md): one-node operation.
- [multi-node-cluster-setup.md](../multi-node-cluster-setup.md): multi-node operation.
- [client-keygen-cli-config.md](../client-keygen-cli-config.md): keygen and client settings.
- [provider-put-get-examples.md](../provider-put-get-examples.md): provider read/write examples.
- [identity-put-get-examples.md](../identity-put-get-examples.md): identity read/write examples.

## Research and proposed surfaces (not implemented here)

The following items are proposals or research notes, not claims about shipped interfaces.

- The `kad:` grammar and route ideas are researched in
  [registry-url-format.md](../research/registry-url-format.md).
- Chromium extension architecture is researched in
  [browser-extension-dht-url-rendering.md](../research/browser-extension-dht-url-rendering.md).
- Identity aliases are a proposed lookup concept.
- Reverse lookup by owner public key is a proposed lookup concept.
- An HTTP gateway is a proposed integration surface.
- A native-messaging bridge is a proposed integration surface.
- Bootstrap peer-identity caveats remain limitations called out by the research docs.
- These proposals should not be treated as existing HTTP endpoints, browser APIs, or SDKs.

## Integration checklist

1. Choose `keygen` and the CLI examples for a client-facing workflow.
2. Choose `registry_service.py` when integrating registry operations in Python.
3. Use the envelope builder and canonical encoding path for signed updates.
4. Use verification and record validation rather than duplicating signature or sequence rules.
5. Use provider and identity schemas for their respective record families.
6. Use the storage backend abstraction rather than coupling callers to LMDB.
7. Use the DHT module for implemented libp2p Kad-DHT operations.
8. Treat the namespace strings as protocol surface and preserve the object-key rules.
9. Consult the canonical docs before relying on research-only URL or browser proposals.
10. Run `.venv/bin/pytest -q` after changes; the recorded baseline is 56 passed and 1 skipped.

## Boundaries and limitations

- This inventory records existing repository surfaces; it does not add an API guarantee.
- No HTTP gateway is listed as implemented because the cited research describes it as proposed.
- No browser extension is listed as implemented because its architecture is research-only.
- Alias and reverse-owner lookup are not presented as shipped operations.
- Bootstrap caveats should be checked against the setup and research docs before deployment.
- CLI flags and commands are cited to [cli.py](../../src/decent_registry/cli.py); README examples
  remain the canonical usage narrative.
- Protocol behavior is cited to the package modules and [protocol-concepts.md](../protocol-concepts.md).

## Maintenance notes

Update this inventory when a new CLI command, package module, namespace, or canonical guide
becomes an implemented developer surface. Keep proposed work in the research section until
its implementation and canonical documentation exist. Preserve repository-path citations so
future readers can verify each claim directly.
