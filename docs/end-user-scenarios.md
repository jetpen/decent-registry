# End-user scenarios

## How to read these scenarios

Each scenario states its Claim Class, actors, motivation, numbered user flow, services involved, sovereignty and privacy properties, current-versus-future status, and limitations.

The Claim Classes are:

- **Implemented and code-backed** — verified against repository code and tests.
- **Documented or researched but unimplemented** — supported by repository documentation or research but not a shipped interface.
- **Proposed design** — a possible future convention or integration boundary.
- **Long-term vision** — an Ecosystem Goal, not a current capability.

Current implementation details are linked to the canonical protocol, setup, configuration, and Provider/Identity Record guides. Proposed services and research must not be read as current interfaces.

## 1. Publish and resolve a signed Provider Record

**Claim Class:** Implemented and code-backed.

**Actors:** A service provider and a client.

**Motivation:** Make provider information and endpoints discoverable and verifiable.

**User flow:**

1. The provider prepares a Provider Record containing its provider URL and endpoint information.
2. The provider uses its local Ed25519 private key to sign a `SignedUpdate`.
3. The Registry stores the resulting `SignedEnvelope` under the Provider Record lookup key.
4. A client resolves the record through the Registry.
5. The client verifies the signature and reads the normalized endpoint list.

**Services involved:** The implemented Registry.

**Sovereignty and privacy properties:** The record is cryptographically verifiable and the signing key remains under the provider’s control. A public Provider Record is not private by default.

**Current-versus-future status:** Implemented through the CLI, Python service, provider schema, Canonical CBOR, and DHT surfaces. See [Provider Record put/get examples](provider-put-get-examples.md) and [protocol concepts](protocol-concepts.md).

**Limitations:** A valid record does not guarantee provider availability, endpoint reachability, privacy, global replication, or resistance to every attack.

## 2. Create and update a signed Identity Record

**Claim Class:** Implemented and code-backed.

**Actors:** An identity owner and a client.

**Motivation:** Establish a verifiable public association between an Owner Name and Owner Public Key.

**User flow:**

1. The owner generates or selects an Ed25519 key using the documented local key-management procedure.
2. The owner creates an Identity Record containing the Owner Name and Owner Public Key.
3. The owner signs the `SignedUpdate` locally; the private key is never included in the registry record.
4. The owner publishes the resulting `SignedEnvelope` through the Registry.
5. The owner later creates a supported update with a strictly higher `Seq`.
6. The Registry verifies the signature, key derivation, owner binding, and sequence ordering before accepting the update.

**Services involved:** The implemented Registry and its basic Identity Record structure.

**Sovereignty and privacy properties:** Ownership is verified by signature, while private keys remain in local or hardware-backed storage. Published identity fields are visible to readers.

**Current-versus-future status:** The Identity Record and current single-key signing path are implemented. See [Identity Record put/get examples](identity-put-get-examples.md) and [client key configuration](client-keygen-cli-config.md).

**Limitations:** Current owner binding and validation do not provide the proposed identity graph, recovery, or multisignature workflows. Loss of the current private key prevents ordinary updates.

## 3. Establish an Identity Graph

**Claim Class:** Proposed design.

**Actors:** An identity owner, applications, and clients resolving identity records.

**Motivation:** Represent one owner’s primary identity, aliases, public keys, and future recovery references as related registry records.

**User flow:**

1. The owner publishes a primary Identity Record.
2. The owner publishes alias records linked to that primary record.
3. The primary record identifies the owner’s public verification keys and any future recovery references.
4. An application resolves the related records and presents the resulting Identity Graph.
5. The owner updates the graph by publishing new signed records under the future identity convention.

**Services involved:** The Registry and the proposed Identity convention.

**Sovereignty and privacy properties:** The owner chooses which names, aliases, keys, and relationships to publish. Public records are visible to readers and therefore do not provide privacy by themselves. Private keys remain local and are never registry content.

**Current-versus-future status:** The graph convention and recovery references are proposed. The repository implements only the basic Identity Record path.

**Limitations:** Alias resolution, primary-record linking, recovery validation, key rotation, and graph consistency require future protocol and validator work.

## 4. Store and retrieve content through a proposed Storage Service

**Claim Class:** Proposed design.

**Actors:** A content creator, a content consumer, a storage operator, and an application.

**Motivation:** Retain and retrieve content independently of a single node while using Registry records for signed metadata or discovery.

**User flow:**

1. The creator prepares content and derives or receives a content reference.
2. The creator optionally signs metadata using an Identity convention.
3. The creator submits the content to a Storage Service.
4. The creator publishes or resolves Registry metadata describing the content or its provider.
5. A consumer resolves the metadata, retrieves the content from storage, and verifies the content or its signed metadata.

**Services involved:** The Registry, a proposed Storage Service, and an application.

**Sovereignty and privacy properties:** Signed metadata can establish integrity and attribution. Confidentiality, deletion, availability, and operator trust require separate storage and application policies.

**Current-versus-future status:** Proposed. The current LMDB datastore and DHT record replication are not a general-purpose Storage Service.

**Limitations:** No Storage Service protocol, availability guarantee, content lifecycle, or confidentiality model is defined by this project.

## 5. Publish and resolve an owner’s Social Graph

**Claim Class:** Proposed design.

**Actors:** Two or more owners and applications.

**Motivation:** Represent relationships between users as verifiable records that higher-level applications can consume.

**User flow:**

1. An owner publishes a relationship record referencing their Identity Record and another owner.
2. The other owner may publish an independent reciprocal relationship record.
3. Applications resolve the related Identity Records and relationship records.
4. The application interprets the Social Graph according to its own user and privacy policies.
5. A future application uses the graph for discovery, messaging, collaboration, or another social feature.

**Services involved:** The Registry, the Identity convention, the proposed Social convention, and applications.

**Sovereignty and privacy properties:** Owners control relationships they publish. Publication is not private by default; relationship semantics, consent, and visibility require application-level policy.

**Current-versus-future status:** Proposed. No Social Graph protocol or social application is implemented.

**Limitations:** Relationship consent, revocation, privacy, moderation, graph consistency, and application semantics remain unspecified.

## 6. Perform 2-of-3 multisignature Identity Record signing and updating

**Claim Class:** Documented or researched but unimplemented.

**Actors:** Three key holders (K1, K2, and K3), an initiating owner or application, and the Registry.

**Motivation:** Require collective authorization and permit replacement of one lost or compromised signer while two trustworthy signers remain.

**User flow:**

1. The owner or application drafts a bundle of Identity Record updates, including the complete intended state transition.
2. The unsigned bundle is passed among the designated private-key holders.
3. Each holder reviews the same canonical bundle and signs locally. Private keys never leave local or hardware-backed secure storage.
4. Signatures are collected until two distinct valid signatures are present.
5. A partial bundle with fewer than two valid signatures is rejected and cannot be submitted as an authorized update.
6. The final bundle of signed records is submitted to the Registry.
7. A future validator verifies signer-set membership, target and predecessor-state binding, and sequence and epoch advancement.
8. If one signer is lost or compromised, the two remaining signers authorize a complete replacement signer set in one state transition.

**Services involved:** The Registry and a proposed Identity authorization convention.

**Sovereignty and privacy properties:** A single lost key does not necessarily prevent updates, and collective authorization reduces dependence on one signer. Private-key secrecy remains absolute; only public verification material and signatures are exchanged.

**Current-versus-future status:** The workflow is researched and unimplemented. The current CLI, Python API, and validator do not support multisignature bundles.

**Limitations:** Two lost or compromised signers cannot be recovered through ordinary 2-of-3 authorization. Bundle transport, signer identity, canonical format, replay protection, recovery policy, and application tooling require future design and implementation. See [2-of-3 multisig key recovery research](research/2-of-3-multisig-key-recovery.md).

## 7. Build a cross-domain application

**Claim Class:** Proposed design.

**Actors:** An application developer and application users.

**Motivation:** Combine Registry, Identity, Storage, and Social conventions into a higher-level messaging, collaboration, or other application.

**User flow:**

1. The developer uses Registry records for verifiable metadata.
2. The application uses Identity conventions for owner and key references.
3. The application integrates a Storage Service for content.
4. The application consumes Social Graph records for discovery or relationship-aware behavior.
5. The application defines its own interaction, privacy, consent, moderation, and security behavior.

**Services involved:** The Registry, Identity, Storage, Social, and the application.

**Sovereignty and privacy properties:** The application can avoid dependence on one Registry operator, but privacy and user control depend on the application’s design and deployment.

**Current-versus-future status:** Proposed. The Companion Services and application protocols are not implemented.

**Limitations:** Storage, social, identity-graph, and authorization conventions must be specified before a runnable cross-domain application can be claimed.

## Canonical documentation

- [Vision and ecosystem](vision-and-ecosystem.md) explains project framing and claim policy.
- [Companion services](companion-services.md) explains proposed service boundaries and relationships.
- [Protocol concepts](protocol-concepts.md) defines implemented record and transport vocabulary.
- [Single-node setup](single-node-server-setup.md) and [multi-node setup](multi-node-cluster-setup.md) explain operational setup.
- [Client key configuration](client-keygen-cli-config.md) explains local key generation and configuration.
- [Provider Record examples](provider-put-get-examples.md) and [Identity Record examples](identity-put-get-examples.md) show current CLI workflows.

The [end-user scenario catalog planning artifact](planning/end-user-scenario-catalog.md) records the scenario decisions and claim boundaries. The [developer-surface inventory](planning/developer-surface-inventory.md) separates implemented surfaces from research proposals.

## Private-key secrecy

Private keys must never be displayed, logged, transmitted as Registry content, or included in example bundles. They remain in local, secure, or hardware-backed key stores. Only public verification material and signatures may be exchanged through registry-oriented workflows.

## Verification

The documentation-only change was verified with `.venv/bin/pytest -q`: 56 passed, 1 skipped.

