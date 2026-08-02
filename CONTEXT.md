# Decent Registry

A decentralized registry that stores and resolves signed identity and provider records over libp2p Kad-DHT.

## Language

**SignedUpdate**: A canonical, signed record that contains `record_fields`, a `payload`, and a monotonic `seq`. The SignedUpdate is the data structure bound to the Ed25519 signature.
_Avoid_: Update, signed record payload

**SignedEnvelope**: The canonical CBOR wrapper that contains SignedUpdate bytes together with an Ed25519 signature. The SignedEnvelope is what is stored and transported as the DHT value.
_Avoid_: Envelope, signed value

**Identity Record**: A record type where `record_fields` bind an owner name to an Ed25519 public key. The DHT record key is derived from the owner name bytes.
_Avoid_: User record, identity claim

**Provider Record**: A record type where the SignedUpdate binds an `object_hash` to a provider URL and a sorted list of multiaddr endpoints.
_Avoid_: Object record, provider claim

**Owner Name**: The byte-string identity input that defines an Identity Record’s derived DHT record key.
_Avoid_: Username, account name

**Owner Public Key**: The Ed25519 public key bytes that the registry uses to verify signatures for a record key (and to enforce owner-binding on overwrite).
_Avoid_: Identity key, public address

**Object Key**: The DHT lookup key for an Identity Record derived from the owner name bytes.
_Avoid_: Identifier

**Object Hash**: The SHA-256 hex digest used as the DHT record key input for Provider Records and as a signed field inside the Provider Record payload.
_Avoid_: Hash

**Seq**: A non-negative integer that orders overwrites for a given record key. Later overwrites must have strictly larger Seq.
_Avoid_: Version, nonce

**Owner Binding**: The rule that the first accepted SignedUpdate for a record key commits that record key to a specific Owner Public Key; later overwrites must use the same Owner Public Key.
_Avoid_: Ownership, key binding

**Canonical CBOR**: Deterministic CBOR encoding required so the bytes that are signed/verified are reproducible.
_Avoid_: CBOR

**Ed25519**: The signature scheme used to sign and verify SignedUpdate digest input.
_Avoid_: EdDSA, Curve25519

**Registry**: The implemented service that stores and resolves signed Identity Records and Provider Records over libp2p Kad-DHT.
_Avoid_: central registry

**Companion Service**: A proposed ecosystem service concept that builds on or extends the Registry; Identity, Storage, and Social are companion-service concepts.
_Avoid_: companion protocol

**Identity Graph**: A set of related Identity Records representing one owner's primary identity, aliases, and public keys.
_Avoid_: identity profile

**Social Graph**: A set of relationship records linking an owner to other users, foundational to future messaging, collaboration, and social applications.
_Avoid_: friends list

**Storage Service**: A proposed convention for durable, content-addressable data retention, distinct from the Registry's LMDB datastore and DHT record replication.
_Avoid_: object store

**Signer Set**: The distinct public keys authorized to sign updates under a threshold policy, together with the associated threshold and epoch.
_Avoid_: keyring

**Multisignature Bundle**: A bundle of record updates circulated among private-key holders for local signing and submitted to the Registry only after the required number of distinct signatures is collected.
_Avoid_: transaction, batch

**Recovery Policy**: A separately enrolled authorization path, distinct from ordinary threshold authorization, for identity control after lost or compromised keys.
_Avoid_: emergency override

**Claim Class**: The mandatory classification of a documentation claim as implemented and code-backed, documented or researched but unimplemented, proposed design, or long-term vision.
_Avoid_: status label

**Ecosystem Goal**: A stated objective such as sovereignty, privacy, anti-centralization, or anti-censorship; an aim, not a current guarantee.
_Avoid_: capability guarantee

**Decentralized**: The operational property that no single organization is required to coordinate or control the Registry, independent parties can operate nodes, and clients can verify records end-to-end without trusting a single operator. This term does not by itself promise censorship resistance, privacy, availability, or anonymity.
_Avoid_: censorship-proof

## Rules

- **Overwrite rules**: For a fixed DHT key, later updates are accepted only if the SignedUpdate is valid, the signature verifies, Seq strictly increases, and Owner Binding is consistent.
- **Key mismatch rejection**: Updates are rejected when the derived lookup key does not match the record key being overwritten.
