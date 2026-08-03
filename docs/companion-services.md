# Companion services

## Purpose and status

This document describes proposed Companion Service conventions around the implemented Registry. It defines user-facing roles, boundaries, relationships, and value. It does not define production wire protocols, schemas, endpoints, APIs, or implementations for companion services.

The Registry is the only implemented service described here. Identity, Storage, and Social are proposed conventions that build on Registry records. Identity recovery and multisignature authorization are researched but unimplemented.

## Claim classes

The document uses the four Claim Classes defined in [`CONTEXT.md`](../CONTEXT.md):

1. **Implemented and code-backed** — verified against repository code and tests.
2. **Documented or researched but unimplemented** — supported by repository documentation or research but not exposed as a shipped interface.
3. **Proposed design** — a possible future convention or integration boundary, not an implementation guarantee.
4. **Long-term vision** — an Ecosystem Goal, explicitly not a current capability.

The status of each service is stated in its section. Proposed concepts must not be read as current interfaces.

## Registry — implemented foundation

**Claim class: Implemented and code-backed.**

The Registry publishes and resolves signed Identity Records and Provider Records over libp2p Kad-DHT. Its implemented surfaces include:

- CLI `keygen`, `node`, `put`, and `get` operations in [`src/decent_registry/cli.py`](../src/decent_registry/cli.py);
- `SignedUpdate`, `SignedEnvelope`, Canonical CBOR, and envelope construction in [`encoding.py`](../src/decent_registry/encoding.py), [`signed_envelope.py`](../src/decent_registry/signed_envelope.py), and [`envelope_builder.py`](../src/decent_registry/envelope_builder.py);
- Ed25519 signing and verification in [`crypto_utils.py`](../src/decent_registry/crypto_utils.py) and [`verification.py`](../src/decent_registry/verification.py);
- `Seq` and `Owner Binding` validation in [`record_validator.py`](../src/decent_registry/record_validator.py) and [`verification.py`](../src/decent_registry/verification.py);
- Identity Record and Provider Record schemas in [`provider_schema.py`](../src/decent_registry/provider_schema.py) and [`registry_service.py`](../src/decent_registry/registry_service.py);
- LMDB durable storage through [`durable_store.py`](../src/decent_registry/durable_store.py) and [`storage_backend.py`](../src/decent_registry/storage_backend.py); and
- libp2p Kad-DHT node, namespace, `put`, and `get` behavior in [`dht/libp2p_dht.py`](../src/decent_registry/dht/libp2p_dht.py).

The Registry does not own user accounts, store arbitrary application content, define social relationships, or guarantee permanent availability. The canonical operational guides are linked from the root [`README.md`](../README.md), including [protocol concepts](protocol-concepts.md), [single-node setup](single-node-server-setup.md), [multi-node setup](multi-node-cluster-setup.md), [client key configuration](client-keygen-cli-config.md), and the [Provider Record](provider-put-get-examples.md) and [Identity Record](identity-put-get-examples.md) examples.

## Identity convention — proposed

**Claim class: Proposed design.**

The Identity convention establishes how an owner’s name, aliases, and public key set can be represented as an Identity Graph: a set of related Identity Records.

Registry records may contain:

- an Owner Name;
- aliases and related-record references;
- one or more Owner Public Keys; and
- other public verification material needed to resolve relationships.

Private keys are never registry content. They must remain in local, secure, or hardware-backed key stores and must never be displayed, logged, transmitted as registry data, or included in documentation examples. A registry record may refer to local key-management or recovery processes, but it must not publish secret key material.

The current implementation supports the basic single-key Identity Record path. Identity Graphs, alias resolution, recovery, and key rotation are not current Registry operations.

### Recovery and multisignature research

**Claim class: Documented or researched but unimplemented.**

The following research informs possible future Identity conventions:

- [`docs/research/identity-recovery-research.md`](research/identity-recovery-research.md) evaluates passkeys, guardian recovery, one-time recovery material, and other methods. It requires future validator and protocol work.
- [`docs/research/2-of-3-multisig-key-recovery.md`](research/2-of-3-multisig-key-recovery.md) evaluates an explicit 2-of-3 Signer Set and key-replacement transitions.

Neither recovery nor multisignature support exists in the current CLI, Python API, or validator. These research documents must not be presented as implementation documentation.

## Storage convention — proposed

**Claim class: Proposed design.**

A Storage Service could provide durable and potentially content-addressable data retention and retrieval. Registry records could publish signed content metadata, content references, ownership references, or discovery information while a separate storage substrate retains the actual content.

This concept is distinct from the implemented LMDB datastore and DHT replication, which support Registry node state and record lookup. No general-purpose Storage Service, content lifecycle, availability guarantee, confidentiality model, or production protocol is implemented or defined here.

A future application might use a Provider Record or an Identity Graph to identify a content provider or owner, but the Storage convention does not define how applications upload, retrieve, delete, replicate, encrypt, or moderate content.

## Social convention — proposed

**Claim class: Proposed design.**

The Social convention establishes how an owner’s Social Graph can be represented as related registry records. A Social Graph records an owner’s relationships to other users and can provide a foundation for future messaging, collaborative, and social networking applications.

Relationship records could reference Identity Records and other owners. Owners control relationships they publish, but published relationships are not private by default. Consent, revocation, visibility, moderation, graph consistency, and application semantics remain future design questions.

No social graph protocol or social application is implemented. This document does not define messaging formats, collaboration protocols, feeds, moderation systems, or user interfaces.

## Relationships and composition

The concepts form a layered model:

- **Registry → Identity:** the implemented Registry provides signed record storage and resolution; Identity conventions use related records for names, aliases, and public keys.
- **Identity → Social:** Social relationship records can reference Identity Records and owners, allowing applications to resolve a Social Graph through the Registry.
- **Registry → Storage:** Storage may use Registry records for signed metadata, content references, and discovery while retaining content independently.
- **Registry → Applications:** applications can combine Registry, Identity, Storage, and Social conventions. The conventions do not define application-specific messaging, collaboration, or user-interface protocols.

A future messaging or collaborative application could use Identity Graphs for owner and key references, a Storage Service for content, and Social Graphs for relationship-aware discovery. That composition is a proposed application boundary, not a current integrated service.

## User-facing value and limitations

- **Registry:** enables users to publish and resolve signed, verifiable records without requiring one central operator. This does not guarantee availability or endpoint reachability.
- **Identity:** could enable a verifiable public identity of names, aliases, and public keys. Public records do not provide privacy by themselves, and current implementation does not support the proposed graph or recovery conventions.
- **Storage:** could enable durable and content-addressable retention independent of one node. No storage protocol, confidentiality guarantee, or availability guarantee exists today.
- **Social:** could enable verifiable relationship graphs as a foundation for messaging and collaboration applications. Relationship publication is not private by default, and no social protocol exists today.

Sovereignty, privacy, anti-centralization, and anti-censorship remain Ecosystem Goals rather than automatic properties of these proposed conventions. Deployment, threat model, key management, application design, and future implementation determine their actual properties.

## Canonical documentation and boundaries

- [Vision and ecosystem](vision-and-ecosystem.md) defines the project framing and claim policy.
- [Companion service concepts planning decision](planning/companion-service-concepts.md) defines the approved service boundaries and relationships.
- [Vision narrative and claims policy](planning/vision-narrative-and-claims-policy.md) defines the four Claim Classes.
- [Protocol concepts](protocol-concepts.md) defines implemented record and transport vocabulary.
- [Developer surface inventory](planning/developer-surface-inventory.md) distinguishes implemented surfaces from research-only proposals.
- [End-user scenario catalog](planning/end-user-scenario-catalog.md) defines future scenarios using the four Claim Classes.
- [Developer application guide specification](planning/developer-application-guide-spec.md) defines how developers will be guided without implying companion-service support.

Canonical setup, configuration, and Provider/Identity Record examples remain the source for operational instructions. This document does not duplicate them.

## Private-key secrecy

Private keys must never be displayed, logged, transmitted, stored as registry content, or included in example bundles. Only public verification material and signatures may be exchanged through registry-oriented workflows.

## Verification

The documentation-only change is verified with `.venv/bin/pytest -q`: 56 passed, 1 skipped.

