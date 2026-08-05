# End-user scenario catalog and format

**Status:** planning decision
**Issue:** #75
**Map:** [Documentation ecosystem vision and application guide for decentralized services](https://github.com/jetpen/decent-registry/issues/71)

## Decision summary

The scenario documentation will cover nine scenario groups. Every scenario uses the same template and one of the four claim classes established by [Vision narrative and claims policy](vision-narrative-and-claims-policy.md): implemented and code-backed; documented or researched but unimplemented; proposed design; or long-term vision.

## Scenario template

Each scenario uses these fields:

- **Title** — concise scenario name.
- **Status class** — one of the four claim classes.
- **Actors** — people, applications, operators, or services involved.
- **Motivation** — the user need or goal.
- **Numbered user flow** — observable step-by-step actions.
- **Services involved** — registry, identity, storage, social, and any application layer.
- **Sovereignty and privacy properties** — what the scenario enables or leaves under user control; never state these as automatic guarantees.
- **Current-versus-future status** — explicit implementation boundary.
- **Limitations** — operational, security, availability, privacy, and protocol constraints.

## Scenario catalog

### 1. Publish and resolve a signed Provider Record

- **Status class:** Implemented and code-backed.
- **Actors:** Service provider and client.
- **Motivation:** Make provider information and endpoints discoverable and verifiable.
- **Flow:** The provider prepares a Provider Record, signs a `SignedUpdate`, stores the resulting `SignedEnvelope` through the implemented registry path, and the client resolves the record, verifies it, and reads the normalized endpoints.
- **Services involved:** Registry.
- **Sovereignty and privacy properties:** The record is cryptographically verifiable and the signing key remains under the provider’s control.
- **Current-versus-future status:** Implemented through the CLI, Python service, provider schema, canonical CBOR, and DHT surfaces documented in the canonical provider guide.
- **Limitations:** A valid record does not guarantee provider availability, endpoint reachability, privacy, or global replication.

### 2. Create and update a signed Identity Record

- **Status class:** Implemented and code-backed.
- **Actors:** Identity owner and client.
- **Motivation:** Establish a verifiable public association between an Owner Name and Owner Public Key.
- **Flow:** The owner generates or selects key material, creates an Identity Record, signs the `SignedUpdate`, publishes it, then creates a later update with a strictly higher `Seq` when changing supported record data.
- **Services involved:** Registry; the basic Identity Record structure.
- **Sovereignty and privacy properties:** Ownership is verified by signature; private keys remain local and are not registry content.
- **Current-versus-future status:** The Identity Record and current single-key signing path are implemented.
- **Limitations:** Current owner binding and validator rules do not provide the proposed identity graph, recovery, or multisignature workflows. Loss of the current private key prevents ordinary updates.

### 3. Establish an identity graph

- **Status class:** Proposed design.
- **Actors:** Identity owner, applications, and clients resolving identity records.
- **Motivation:** Represent one owner’s primary identity, aliases, public keys, and future recovery references as related registry records.
- **Flow:** The owner publishes a primary Identity Record, publishes alias records linked to it, associates public verification keys and recovery references with the primary, and applications resolve the graph from the registry.
- **Services involved:** Registry and proposed Identity service convention.
- **Sovereignty and privacy properties:** The owner controls which names, aliases, keys, and relationships are published; public records are visible to readers and therefore do not provide privacy by themselves.
- **Current-versus-future status:** The graph convention and recovery references are proposed. The current repository implements only the basic Identity Record path.
- **Limitations:** Alias resolution, primary-record linking, recovery validation, and key rotation require future protocol and validator work.

### 4. Store and retrieve content through a proposed Storage service

- **Status class:** Proposed design.
- **Actors:** Content creator, content consumer, and storage operator.
- **Motivation:** Retain and retrieve content independently of a single node while using registry records for signed metadata or discovery.
- **Flow:** The creator prepares content, derives a content address, optionally signs metadata using an identity, submits content to a storage service, publishes or resolves its registry metadata, and the consumer retrieves and verifies the content.
- **Services involved:** Registry, proposed Storage service, and an application.
- **Sovereignty and privacy properties:** Signed metadata can establish integrity and attribution; confidentiality, deletion, availability, and operator trust require separate storage and application policies.
- **Current-versus-future status:** Proposed. The current LMDB datastore and DHT record replication are not a general-purpose Storage service.
- **Limitations:** No storage-service protocol, availability guarantee, content lifecycle, or confidentiality model is defined by this map.

### 5. Publish and resolve an owner’s social graph

- **Status class:** Proposed design.
- **Actors:** Two or more owners and applications.
- **Motivation:** Represent relationships between users as verifiable records that higher-level applications can consume.
- **Flow:** An owner publishes a relationship record referencing their Identity Record and another owner, the other owner may publish an independent reciprocal relationship, and applications resolve and interpret the graph.
- **Services involved:** Registry, Identity service convention, proposed Social service convention, and applications.
- **Sovereignty and privacy properties:** Owners control relationships they publish; publication is not private, and relationship semantics and visibility require application-level policy.
- **Current-versus-future status:** Proposed. No social graph protocol or social application is implemented.
- **Limitations:** Relationship consent, revocation, privacy, moderation, graph consistency, and application semantics remain unspecified.

### 6. Perform 2-of-3 multisignature Identity Record signing and updating

- **Status class:** Documented or researched but unimplemented.
- **Actors:** Three key holders (K1, K2, K3), an initiating owner or application, and the registry.
- **Motivation:** Require collective authorization and permit replacement of one lost or compromised signer while two trustworthy signers remain.
- **Flow:**
  1. The owner or application drafts a bundle of Identity Record updates, including the complete intended state transition.
  2. The unsigned bundle is passed among the designated private-key holders.
  3. Each holder reviews the same canonical bundle and signs locally; private keys never leave local or hardware-backed secure storage.
  4. Signatures are collected until two distinct valid signatures are present.
  5. A partial bundle with fewer than two valid signatures is rejected and cannot be submitted as an authorized update.
  6. The final bundle of signed records is submitted to the registry.
  7. The validator verifies that both signers belong to the current signer set, that the target and predecessor state are bound, and that the sequence and epoch advance correctly.
  8. For a lost or compromised signer, the two remaining signers authorize a complete replacement signer set in one state transition.
- **Services involved:** Registry and proposed Identity authorization convention.
- **Sovereignty and privacy properties:** A single lost key does not necessarily prevent updates; collective authorization reduces dependence on one signer. Private-key secrecy remains absolute.
- **Current-versus-future status:** The local Python bundle workflow is implemented and code-backed for drafting, local signing, proof merging, and threshold finalization. CLI commands, Registry put/get integration, and DHT submission remain future work.
- **Limitations:** Two lost or compromised signers cannot be recovered through ordinary 2-of-3 authorization. CLI transport, recovery policy, application tooling, and production Registry integration require future design and implementation.

### 7. Build a cross-domain application

- **Status class:** Proposed design.
- **Actors:** Application developer and application users.
- **Motivation:** Combine registry, identity, storage, and social conventions into a higher-level messaging, collaboration, or other application.
- **Flow:** The developer uses registry records for verifiable metadata, uses identity conventions for owner and key references, integrates a storage service for content, consumes social graph records for discovery or relationships, and defines application-specific interaction and privacy behavior.
- **Services involved:** Registry, Identity, Storage, Social, and the application.
- **Sovereignty and privacy properties:** The application can avoid dependence on one registry operator, but privacy and user control depend on its own design and deployment.
- **Current-versus-future status:** Proposed. The companion services and application protocols are not implemented.
- **Limitations:** Storage, social, identity-graph, and authorization conventions must be specified before a runnable cross-domain application can be claimed.

### 8. Re-host a censored document under a stable content hash

- **Status class:** Implemented and code-backed.
- **Actors:** Content owner, public cloud hosting provider, hostile actor (such as a state authority) pressuring the host, and end-user clients.
- **Motivation:** Demonstrate censorship resistance through content addressing: the document’s Object Hash is stable across hosting locations, so the owner can re-host the identical bytes after a takedown and repoint the signed Provider Record.
- **Flow:** The owner computes the Object Hash of the document (`H`), hosts it at `URL_A`, and publishes a signed Provider Record (`seq = 1`). Clients resolve, verify, download, and compare the downloaded bytes with the Object Hash. The host is pressured into a takedown; the registry pointer is unaffected. The owner re-hosts the identical bytes at `URL_B` and publishes `seq = 2` under the same owner key. Clients resolve the same key to the new URL and verify the Object Hash.
- **Services involved:** Registry; external public web hosting.
- **Sovereignty and privacy properties:** Availability is decoupled from any single host; only the owner’s key can repoint the record; clients verify content against the Object Hash; the Registry stores pointers, not content. Public records are not private by default.
- **Current-versus-future status:** Implemented and code-backed for signed Provider Records, put/get, sequence monotonicity, and owner-collision rejection; see the [single-node setup](../single-node-server-setup.md) and [multi-node setup](../multi-node-cluster-setup.md) guides; exercised end to end by the gated acceptance test `tests/test_acceptance_object_url.py`. The hosting, takedown, and re-hosting steps are illustrative narratives over these existing interfaces.
- **Limitations:** No host-retention guarantees; clients must verify the Object Hash; the owner must retain the signing key; old URLs are overwritten, not retained as history; stale pointers may persist during propagation.

### 9. Publish and resolve a web-page `kad:` link through a Chromium extension

- **Status class:** Documented or researched but unimplemented.
- **Actors:** A content publisher, an end user, a Chromium browser with the proposed extension, Registry nodes, and a host provider.
- **Motivation:** Publish a stable Object Hash reference in a web page while allowing the target object to move between providers.
- **Flow:** The publisher embeds `kad:<bootstrap-multiaddr>//provider/by-hash/<object-hash>`. The extension parses the URL, uses a proposed local bridge to resolve the Provider Record from the Registry, verifies the signed record, and navigates to its validated `provider_url`. After a host takedown, the owner re-hosts the identical bytes and publishes a higher-`Seq` Provider Record, so the same `kad:` link resolves to the new provider URL.
- **Services involved:** Web page, proposed Chromium extension, proposed local resolution bridge, Registry, and external HTTP(S) hosting.
- **Sovereignty and privacy properties:** The publisher chooses the Registry bootstrap multiaddr, while the owner controls authorized Provider Record updates. Object addressing decouples discovery from a single host, but public records and resolution requests may be observable and provide no anonymity or private-by-default publication.
- **Current-versus-future status:** Provider Record put/get mechanics are implemented; the web-page link convention, Chromium extension, local bridge, and end-to-end browser flow are documented or researched but unimplemented. The current Registry node is libp2p-only and does not provide the proposed HTTP-compatible resolution surface.
- **Limitations:** No extension or local bridge is shipped. A browser cannot be assumed to understand `kad:` without the proposed integration. The Registry cannot guarantee provider availability, host persistence, re-hosting success, or censorship resistance. Clients must verify downloaded bytes against the Object Hash.

## Documentation rules

- Use the four claim classes consistently.
- Cite implemented claims with repository paths and canonical guides.
- Link researched claims to their research files and label them unimplemented.
- Label companion-service and cross-domain content as proposed unless implementation evidence exists.
- State limitations next to the relevant claims.
- Never imply that current CLI support includes identity graphs, recovery, multisignature bundles, storage services, social graphs, or cross-domain applications.
- Preserve the private-key secrecy rule: private keys are never displayed, logged, transmitted as registry content, or included in bundles; only signatures and public verification material are exchanged.
- Use the vocabulary defined in [`CONTEXT.md`](../../CONTEXT.md).

## Resolution audit trail

The interactive grilling confirmed:

1. Scenario scope covers Registry, Identity, Storage, Social, a cross-domain application, and a dedicated 2-of-3 multisignature Identity Record scenario.
2. Every scenario uses the confirmed template fields above.
3. The multisignature scenario uses the bundle flow: draft, circulate, local signing, collect two distinct signatures, reject partial bundles, and submit the final bundle.
4. The multisignature flow is researched but unimplemented and must not imply current CLI support.
5. Issue #83 extended the catalog with an eighth scenario: Re-host a censored document under a stable content hash.
6. Issue #84 extended the catalog with a ninth scenario: Publish and resolve a web-page `kad:` link through a Chromium extension.

This artifact resolves #75. It does not resolve developer-guide structure (#77).

## Verification

The repository test baseline is `.venv/bin/pytest -q`: 56 passed, 1 skipped. This planning artifact makes no code or test changes.

## Source inputs

- [`documentation-information-architecture.md`](documentation-information-architecture.md)
- [`vision-narrative-and-claims-policy.md`](vision-narrative-and-claims-policy.md)
- [`companion-service-concepts.md`](companion-service-concepts.md)
- [`developer-surface-inventory.md`](developer-surface-inventory.md)
- [`2-of-3-multisig-key-recovery.md`](../research/2-of-3-multisig-key-recovery.md)
- [`CONTEXT.md`](../../CONTEXT.md)
- [`README.md`](../../README.md)
- [`src/decent_registry/`](../../src/decent_registry/)

