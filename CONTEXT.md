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

## Rules

- **Overwrite rules**: For a fixed DHT key, later updates are accepted only if the SignedUpdate is valid, the signature verifies, Seq strictly increases, and Owner Binding is consistent.
- **Key mismatch rejection**: Updates are rejected when the derived lookup key does not match the record key being overwritten.
