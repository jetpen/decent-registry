# Companion service concepts

**Status:** planning decision
**Issue:** #74
**Map:** [Documentation ecosystem vision and application guide for decentralized services](https://github.com/jetpen/decent-registry/issues/71)

## Scope and claim class

This document defines user-facing concepts and boundaries only. It does not define production wire protocols, schemas, endpoints, or implementations for companion services.

The registry is **implemented and code-backed**. Identity, storage, and social services are **proposed designs** that build on registry records where appropriate. Identity recovery and multisignature material cited below is **researched but unimplemented**.

## Service definitions and boundaries

### Registry

- **Role:** Publishes and resolves signed, verifiable records.
- **Status:** Implemented foundation in `decent-registry`.
- **Boundary:** It does not own user accounts, store arbitrary application content, define social relationships, or guarantee permanent availability.
- **Evidence:** The implemented CLI, record, storage, and DHT surfaces are inventoried in [`docs/planning/developer-surface-inventory.md`](developer-surface-inventory.md).

### Identity service

- **Role:** Establishes a convention for storing an owner’s name, aliases, and public key set as a graph of related registry records.
- **Status:** Proposed service convention, building on the implemented Identity Record.
- **Published material:** Registry records contain public verification material only: Owner Name, Owner Public Key values, aliases, and relationships among those records.
- **Private-key boundary:** No convention in this document stores private-key bytes in registry records. Private keys remain in local, secure, or hardware-backed key stores. Registry records may identify public keys or refer to local key-management and recovery processes, but they must not publish secret key material.
- **Recovery and rotation:** Passkeys, guardian recovery, one-time recovery material, and 2-of-3 signer-set replacement are researched designs requiring future validator and protocol work; they are not current identity-service capabilities. See [`identity-recovery-research.md`](../research/identity-recovery-research.md) and [`2-of-3-multisig-key-recovery.md`](../research/2-of-3-multisig-key-recovery.md).

### Storage service

- **Role:** Provides durable and potentially content-addressable data retention and retrieval.
- **Status:** Proposed service.
- **Boundary:** It may use registry records for content addressing, signed metadata, ownership references, or discovery, while retaining actual content in its own storage substrate.
- **Distinction from current implementation:** The existing LMDB datastore and DHT replication support registry node state and record lookup. They do not constitute the proposed general-purpose storage service.

### Social service

- **Role:** Establishes a convention for storing an owner’s social graph—the owner’s relationships to other users—as related registry records.
- **Status:** Proposed service convention.
- **Foundation:** The social graph is foundational for higher-level social networking applications, including messaging, collaborative services, and other applications.
- **Boundary:** This concept does not define those applications or their production protocols. It defines how relationship records can reference identity records and owners.

## Relationships and composition

The services form a layered conceptual model:

- **Registry → Identity:** The registry is the implemented foundation; identity conventions use related signed records for names, aliases, and public keys.
- **Identity → Social:** Social relationship records reference identity records and owners, allowing a social graph to be resolved and verified through the registry.
- **Registry → Storage:** Storage may use registry records for signed content metadata, content references, and discovery while retaining content independently.
- **Registry → Applications:** Applications consume registry, identity, storage, and social conventions. The conventions do not define application-specific messaging, collaboration, or user-interface protocols.

Identity is the base layer for other proposed services because storage and social content needs to identify owners and keys. Storage is conceptually parallel to identity and social: it may serve them and use registry metadata without being part of the identity or social convention.

## User-facing value

- **Registry:** Enables users to publish and resolve signed, verifiable records without requiring one central operator.
- **Identity:** Enables users to maintain a verifiable public identity of names, aliases, and public keys, with future conventions for key recovery and replacement.
- **Storage:** Enables durable and content-addressable data retention and retrieval that is not dependent on a single node.
- **Social:** Enables owners to publish verifiable relationship graphs, forming a foundation for interoperable messaging, collaboration, and higher-level social applications.

These value statements describe intended capabilities and do not guarantee availability, privacy, anonymity, censorship resistance, or interoperability in every deployment.

## Composition examples

- **Identity:** Related registry records link an Owner Name, aliases, and public keys. Private keys remain in local or secure key stores.
- **Storage:** A registry record publishes signed content metadata or a content reference; storage nodes retain and serve the actual content through a separately defined storage system.
- **Social:** Relationship records reference Identity Records and other owners, forming a verifiable social graph that applications can query and interpret.
- **Applications:** Messaging and collaboration applications consume identity, storage, and social conventions without those conventions defining the applications’ protocols.

## Documentation rules

- Cite implemented claims with repository paths and preserve the distinction between the registry and proposed companion services.
- Label identity, storage, and social conventions as proposed unless implementation evidence exists.
- Label recovery and multisignature research as researched but unimplemented.
- State the private-key boundary in every identity-oriented document: only public verification material belongs in registry records.
- State relevant limitations alongside claims rather than hiding them in a distant disclaimer.
- Reuse the canonical protocol, setup, configuration, and put/get guides instead of duplicating their operational content.
- Use the vocabulary defined in [`CONTEXT.md`](../../CONTEXT.md), including `SignedUpdate`, `SignedEnvelope`, `Identity Record`, `Provider Record`, `Owner Name`, `Owner Public Key`, `Object Key`, `Object Hash`, `Seq`, `Owner Binding`, `Canonical CBOR`, and `Ed25519`.
- Follow the four claim classes established in [`vision-narrative-and-claims-policy.md`](vision-narrative-and-claims-policy.md).

## Resolution audit trail

The interactive grilling confirmed:

1. **Boundaries:** Registry publishes and resolves signed records; Identity defines related-record conventions for names, aliases, and public keys; Storage retains content on a separate substrate; Social defines related-record conventions for owners’ social graphs.
2. **Private-key clarification:** The identity convention stores only public keys and other public verification material in registry records. Private keys remain local, secure, or hardware-backed and are never stored as registry content.
3. **Relationships:** Registry is foundational; Identity builds on Registry; Social builds on Identity and Registry; Storage operates in parallel and may use Registry metadata.
4. **User-facing value:** Each service has the value statement above, without guarantees beyond the stated implementation status.
5. **Composition:** The artifact includes identity, storage, social, and application composition examples.

This artifact resolves #74. It does not resolve end-user scenario selection (#75) or developer-guide structure (#77).

## Verification

The repository test baseline is `.venv/bin/pytest -q`: 56 passed, 1 skipped. This planning artifact makes no code or test changes.

## Source inputs

- [`documentation-information-architecture.md`](documentation-information-architecture.md)
- [`vision-narrative-and-claims-policy.md`](vision-narrative-and-claims-policy.md)
- [`developer-surface-inventory.md`](developer-surface-inventory.md)
- [`CONTEXT.md`](../../CONTEXT.md)
- [`README.md`](../../README.md)
- [`identity-recovery-research.md`](../research/identity-recovery-research.md)
- [`2-of-3-multisig-key-recovery.md`](../research/2-of-3-multisig-key-recovery.md)
- [`src/decent_registry/`](../../src/decent_registry/)

