# Vision and ecosystem

## Purpose

`decent-registry` is a peer-to-peer registry for publishing and resolving signed Identity Records and Provider Records over libp2p Kad-DHT. It is intended as a foundation for applications that need verifiable information without requiring one organization to coordinate every registry operation.

This document separates current behavior from research, proposed designs, and long-term Ecosystem Goals. It does not claim that the current prototype is unstoppable, ungovernable, censorship-proof, private by default, or available in every deployment.

## The architectural choice

The project uses peer-to-peer libp2p Kad-DHT, signed records, and end-to-end verification. It does not use a blockchain, native token, or consensus layer.

This is a deliberate project position rather than a universal claim about every blockchain or Web 3.0 system. The choice prioritizes:

- self-hostable infrastructure;
- verifiable records whose signatures can be checked by clients;
- independent node operation; and
- lower participation barriers for operators who do not need to join a token or consensus system.

The project uses “decentralized” operationally. A system is decentralized in this context when:

- no single organization is required to coordinate or control the Registry;
- independent parties can operate nodes; and
- clients can verify records end-to-end without trusting a single operator.

This definition does not promise censorship resistance, privacy, anonymity, availability, or freedom from governance. Those properties depend on deployment, threat model, operational practice, and future implementation work.

## Implemented and code-backed

The following capabilities are implemented in the repository:

- The CLI exposes `keygen`, `node`, `put`, and `get` operations in [`src/decent_registry/cli.py`](../src/decent_registry/cli.py).
- `SignedUpdate` and `SignedEnvelope` provide signed record structures. Canonical serialization and envelope construction are implemented in [`encoding.py`](../src/decent_registry/encoding.py), [`signed_envelope.py`](../src/decent_registry/signed_envelope.py), and [`envelope_builder.py`](../src/decent_registry/envelope_builder.py).
- Ed25519 key and signature operations are implemented in [`crypto_utils.py`](../src/decent_registry/crypto_utils.py) and [`verification.py`](../src/decent_registry/verification.py).
- Record validation enforces strict `Seq` increases and `Owner Binding` in [`record_validator.py`](../src/decent_registry/record_validator.py) and [`verification.py`](../src/decent_registry/verification.py).
- Provider and Identity Record schemas and registry orchestration are implemented in [`provider_schema.py`](../src/decent_registry/provider_schema.py) and [`registry_service.py`](../src/decent_registry/registry_service.py).
- The storage abstraction and LMDB durable store are implemented in [`storage_backend.py`](../src/decent_registry/storage_backend.py) and [`durable_store.py`](../src/decent_registry/durable_store.py).
- The libp2p Kad-DHT adapter implements the Registry node and record `put`/`get` behavior in [`dht/libp2p_dht.py`](../src/decent_registry/dht/libp2p_dht.py).
- Configuration loading and CLI overrides are implemented in [`config.py`](../src/decent_registry/config.py).

These are repository behaviors, not claims of production readiness, global availability, permanent storage, or resistance to every attack or failure mode. The canonical operational documentation is linked from the [protocol concepts](protocol-concepts.md), [single-node setup](single-node-server-setup.md), [multi-node setup](multi-node-cluster-setup.md), [client key and configuration](client-keygen-cli-config.md), [Provider Record examples](provider-put-get-examples.md), and [Identity Record examples](identity-put-get-examples.md).

### Private-key secrecy

Private keys are never registry content. They must remain in local, secure, or hardware-backed key stores and must never be displayed, logged, transmitted as registry data, or included in documentation examples. Registry records contain public verification material and signatures, not private-key material.

## Documented or researched but unimplemented

The following items have research or design documentation but are not shipped interfaces:

- The `kad:` URL grammar and route concepts in [`research/registry-url-format.md`](research/registry-url-format.md).
- Chromium extension DHT URL resolution and rendering in [`research/browser-extension-dht-url-rendering.md`](research/browser-extension-dht-url-rendering.md).
- Lost-key recovery mechanisms, including passkeys, guardians, and one-time recovery material, in [`research/identity-recovery-research.md`](research/identity-recovery-research.md).
- Explicit 2-of-3 signer-set authorization and key replacement in [`research/2-of-3-multisig-key-recovery.md`](research/2-of-3-multisig-key-recovery.md).
- The DHT resiliency experiments and conclusions in [`research/kad-dht-resiliency-research.md`](research/kad-dht-resiliency-research.md).

These materials must not be described as existing URL handlers, browser APIs, HTTP endpoints, SDKs, recovery protocols, or multisignature support. The current CLI does not provide identity graphs, recovery, or multisignature bundles.

## Proposed designs

Identity, Storage, and Social are Companion Service concepts, not implemented services:

- An **Identity Graph** could represent an owner’s primary identity, aliases, and public keys as related registry records. It must publish only public verification material; private keys remain local.
- A **Storage Service** could retain content independently while using Registry records for signed metadata, content references, or discovery. It would be distinct from the current LMDB datastore and DHT record replication.
- A **Social Graph** could represent an owner’s relationships to other users as related records, providing a foundation for future messaging, collaboration, and social networking applications.
- Higher-level applications could combine Registry, Identity, Storage, and Social conventions without those conventions defining application-specific protocols.

These are proposed integration boundaries. No production wire protocols, identity graph implementation, general-purpose storage service, or social service are defined or shipped here.

## Long-term vision and Ecosystem Goals

The long-term vision is to give people more control over the services and records they rely on while making verifiable peer-to-peer infrastructure easier to operate and integrate.

The project’s Ecosystem Goals include:

- increasing user control and privacy over identity and service relationships;
- reducing unnecessary centralization;
- allowing independently operated infrastructure;
- enabling clients to verify signed information without trusting a single operator; and
- improving resilience to service withdrawal or censorship through independent operation and replication.

These are goals, not current capability guarantees. Their realization depends on future protocol design, implementations, deployment choices, key-management practices, and applications.

## Claim policy

Every substantive claim in this document belongs to one of four Claim Classes:

1. **Implemented and code-backed** — verified against repository code and tests.
2. **Documented or researched but unimplemented** — supported by repository documentation or research but not exposed as a shipped interface.
3. **Proposed design** — a possible future design or integration boundary, not an implementation guarantee.
4. **Long-term vision** — an Ecosystem Goal or aspiration, explicitly not a current capability.

Claims should remain in clearly labeled sections. Current implementation, research, proposed designs, and aspirations must not be blended into an unlabeled guarantee.

## Further reading

- [Developer surface inventory](planning/developer-surface-inventory.md)
- [Documentation information architecture](planning/documentation-information-architecture.md)
- [Vision narrative and claims policy](planning/vision-narrative-and-claims-policy.md)
- [Companion service concepts](planning/companion-service-concepts.md)
- [End-user scenario catalog](planning/end-user-scenario-catalog.md)
- [Developer application guide specification](planning/developer-application-guide-spec.md)

The root [README documentation index](../README.md#documentation) links this document alongside the canonical operator and integrator guides.

## Verification

The documentation-only change was verified with `.venv/bin/pytest -q`: 56 passed, 1 skipped.

