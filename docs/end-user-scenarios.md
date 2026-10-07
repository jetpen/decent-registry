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

**Current-versus-future status:** Implemented through the CLI, Python service, provider schema, Canonical CBOR, and DHT surfaces. The Provider Record stores one or more validated `provider_urls` plus a separate list of multiaddr `endpoints`; neither field promises reachability. See [Provider Record put/get examples](provider-put-get-examples.md) and [protocol concepts](protocol-concepts.md).

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

**Current-versus-future status:** Legacy single-key Identity Records and version-1 explicit-Ed25519 multisignature Identity Records are implemented. See [Identity Record put/get examples](identity-put-get-examples.md), [client key configuration](client-keygen-cli-config.md), and [Multisignature Records and Migration](multisignature-records.md).

**Limitations:** Identity Graphs and separate recovery policies remain future work. A legacy record still depends on its Owner Public Key until it is explicitly upgraded to a multisignature state.

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

**Claim Class:** Implemented and code-backed.

**Actors:** Three key holders (K1, K2, and K3), an initiating owner or application, and the Registry.

**Motivation:** Require collective authorization and permit replacement of one lost or compromised signer while two trustworthy signers remain.

**User flow:**

1. The owner or application drafts a bundle of Identity Record updates, including the complete intended state transition.
2. The unsigned bundle is passed among the designated private-key holders.
3. Each holder reviews the same canonical bundle and signs locally. Private keys never leave local or hardware-backed secure storage.
4. Signatures are collected until two distinct valid signatures are present.
5. A partial bundle with fewer than two valid signatures is rejected and cannot be submitted as an authorized update.
6. The final bundle of signed records is submitted to the Registry.
7. The Registry verifies Signer Set membership, target and predecessor-state binding, record kind, lookup key, `Seq`, and epoch advancement before accepting the finalized SignedEnvelope.
8. If one signer is lost or compromised, the remaining threshold authorizes a complete replacement Signer Set in one state transition, provided the current Signer Set can still meet its threshold.

**Services involved:** The Registry and a proposed Identity authorization convention.

**Sovereignty and privacy properties:** A single lost key does not necessarily prevent updates, and collective authorization reduces dependence on one signer. Private-key secrecy remains absolute; only public verification material and signatures are exchanged.

**Current-versus-future status:** The canonical version-1 wire format, local CLI Bundle workflow, finalized Identity and Provider Record submission, resolution metadata, explicit legacy upgrade, signer replacement, and Registry-side Identity owner-key rotation acceptance are implemented. Wallet private-key rotation dispatch, consent, and publication confirmation remain unimplemented; Registry acceptance alone is not wallet confirmation. See [Multisignature Records and Migration](multisignature-records.md).

**Limitations:** Two lost or compromised signers cannot be recovered through ordinary 2-of-3 authorization. Separate recovery policy, FROST, deployment, availability, privacy, and application tooling remain future work. See [2-of-3 multisig key recovery research](research/2-of-3-multisig-key-recovery.md).

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

## 8. Re-host a censored document under a stable content hash

**Claim Class:** Implemented and code-backed.

**Actors:** A content owner, a public cloud hosting provider, a hostile actor such as a state authority pressuring the host, and end-user clients.

**Motivation:** Demonstrate censorship resistance through content addressing. A document’s identity is its Object Hash, independent of hosting location. If a host is pressured to remove the file, the owner can re-host the identical bytes elsewhere and advertise another locator; clients can discover the new source under the same lookup key and verify the bytes are unchanged.

**User flow:**

1. The owner computes the Object Hash `H` of a document. `H` identifies the content regardless of hosting location.
2. The owner uploads the document to public cloud infrastructure and obtains `URL_A`.
3. The owner publishes a signed Provider Record for Object Hash `H` advertising `URL_A` plus any other available provider URI locators, along with provider `endpoints` and an Ed25519 signature at `seq = 1`, following [Publish and resolve a signed Provider Record](#1-publish-and-resolve-a-signed-provider-record), the [Provider Record examples](provider-put-get-examples.md) flow, and the [Client key configuration](client-keygen-cli-config.md) guidance.
4. A client resolves the record with `get provider --object-hash H`, verifies the signature, selects a supported locator such as `URL_A`, and confirms downloaded bytes match `H`.
5. A hostile actor pressures the cloud provider, and `URL_A` stops serving the file.
6. The Registry entry is unaffected: the DHT stores signed locators, not the file content. Censoring one hosting provider does not remove the Provider Record or its other locators.
7. The owner may re-host the identical bytes at `URL_B` and publish a higher-Seq Provider Record with `URL_B` in its `provider_urls` list, optionally retaining other valid locators. The Object Hash remains `H`.
8. A client resolves the same key, selects an available supported locator from the updated `provider_urls`, and verifies downloaded bytes against `H`.


**Services involved:** The implemented Registry (`put provider`/`get provider`, canonical CBOR signed envelopes, and local Ed25519 signing) plus ordinary public web hosting external to the Registry.

**Sovereignty and privacy properties:** Content addressing decouples a document’s identity from a single host. Multiple URI locators can aid discovery, but do not guarantee availability, independence, or censorship resistance; owners control updates with their signing key and clients verify bytes against the Object Hash. The Registry stores signed pointers rather than file content. A public record is not private by default.

**Current-versus-future status:** Implemented and code-backed for signed Provider Records, `put provider`/`get provider`, sequence monotonicity, and owner-collision rejection — see [Protocol concepts](protocol-concepts.md) and [Provider Record examples](provider-put-get-examples.md). See the [single-node setup](single-node-server-setup.md) and [multi-node setup](multi-node-cluster-setup.md) guides for running the Registry backbone. The provider put/get path is also exercised end to end by the gated acceptance test `tests/test_acceptance_object_url.py`, run with `DECENT_REGISTRY_RUN_ACCEPTANCE=1`. The hosting, takedown, and re-hosting steps are illustrative narratives over these existing interfaces.

**Limitations:** The Registry cannot force a host to retain content or restore a removed locator. Clients must compute the Object Hash of downloaded bytes and compare it with the record to detect mismatches. The owner must retain the signing key to publish updated provider URIs. The record is a live locator list, not guaranteed history; stale pointers may persist during propagation. Multiple advertised locators do not themselves prove availability or independence—clients should choose an available supported source and verify its content.

## 9. Publish and resolve a web-page `kad:` link through a Chromium extension

**Claim Class:** Documented or researched but unimplemented.

**Actors:** A content publisher embedding a link in a web page, an end user, a Chromium browser with the proposed extension installed, Registry nodes, and a host provider serving the target object.

**Motivation:** Let a web page publish a stable content-addressed link whose target can be discovered even when its host changes. The Registry publishes provider URI locators under an Object Hash; the proposed browser client chooses an HTTP(S) locator it can open.

**User flow:**

1. A publisher embeds a link such as `kad:<bootstrap-multiaddr>//provider/by-hash/<object-hash>` in a web page. The URL contains the Registry bootstrap multiaddr and the target object’s SHA-256 Object Hash.
2. An end user browses that page in Chromium with the proposed extension installed and activates the `kad:` link.
3. The extension intercepts the link activation and parses the custom URL using the grammar in [Registry service URL format](research/registry-url-format.md). The multiaddr is a bootstrap multiaddr containing `/p2p/<peerid>`; it is not an HTTP authority component.
4. Through the proposed local HTTP gateway or native-messaging bridge, the extension connects to the Registry using the bootstrap multiaddr and requests the Provider Record for the Object Hash. The browser-extension architecture and its limitations are described in [Chromium extension DHT URL resolution research](research/browser-extension-dht-url-rendering.md).
5. The Registry returns the signed Provider Record, including its validated `provider_urls` and separate multiaddr `endpoints`. The extension or bridge verifies the `SignedEnvelope` and Provider Record. For browser navigation, the client selects a supported HTTP(S) locator; non-HTTP schemes require a suitable external handler and are not opened by the extension.
6. The extension selects a supported HTTP(S) URI from `provider_urls` and navigates to it, causing Chromium to perform the ordinary GET and render the target object.
7. The client may recompute the SHA-256 digest of downloaded bytes and compare it with the Object Hash to detect a mismatched or forged copy.
8. If a host is pressured to remove the object, the owner can re-host the identical bytes elsewhere and publish an updated `provider_urls` list for the same Object Hash; the original `kad:` link remains unchanged, and clients can verify the retrieved bytes against that hash.

**Services involved:** A web page, the proposed Chromium extension and local bridge, the implemented Registry Provider Record path, and external provider transports. The proposed extension opens only HTTP(S) locators.

**Sovereignty and privacy properties:** A publisher can choose the bootstrap Registry multiaddr embedded in a link, and a content owner controls authorized Provider Record updates through the signing key and `Seq` rules. Content addressing decouples the Object Hash from one host and can make re-hosting fluid. Provider Records and link-resolution requests are public or observable according to deployment; this scenario provides no anonymity or private-by-default publication. Decentralized operation does not by itself guarantee censorship resistance, availability, or host persistence.

**Current-versus-future status:** The Provider Record put/get mechanics are implemented through the [Provider Record examples](provider-put-get-examples.md), [protocol concepts](protocol-concepts.md), [multi-node setup](multi-node-cluster-setup.md), and [client key configuration](client-keygen-cli-config.md) guides. The gated `tests/test_acceptance_object_url.py` acceptance test provides supporting evidence for those mechanics when run with `DECENT_REGISTRY_RUN_ACCEPTANCE=1`. The web-page `kad:` link convention, Chromium extension, local bridge, and end-to-end browser flow are documented or researched but unimplemented. The current Registry node is libp2p-only; the HTTP-compatible resolution surface described in the research is a future implementation boundary.

**Limitations:** No Chromium extension or local bridge is shipped. A web page cannot assume that browsers understand `kad:` without the proposed integration. The Registry cannot force providers to retain content, guarantee multiple locators are independently operated, or prevent censorship of every Registry node or provider. At least one reachable source and a usable Registry path are required. Clients must verify downloaded bytes against the Object Hash. Provider Records
are live locator lists, not guaranteed history; public records are not private
by default.

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

The documentation-only changes were verified with `.venv/bin/pytest -q`: 115 passed, 1 skipped. The gated downloadable-object acceptance test (`tests/test_acceptance_object_url.py`, run with `DECENT_REGISTRY_RUN_ACCEPTANCE=1`) provides supporting evidence for the code-backed provider put/get mechanics.

