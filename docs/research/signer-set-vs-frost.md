# Research: Explicit signer set versus FROST for multisignature authorization (#86)

## Executive recommendation

Use an **explicit signer set with independent Ed25519 signatures** for the first multisignature protocol version. Defer FROST or another threshold-signature protocol until compact proofs or signer privacy are demonstrated requirements.

This recommendation is based on protocol fit, not a claim that FROST is insecure or unsuitable in general. The explicit model:

- reuses the repository's existing Ed25519 signing and verification path;
- fits a single canonical-CBOR authorization update carried in one extended `SignedEnvelope`;
- makes signer participation and threshold checks directly auditable;
- represents one-key replacement as an authenticated public signer-set transition;
- avoids introducing distributed key generation, share distribution, share refresh, and nonce-coordination protocols into the first implementation; and
- keeps the first implementation within the current Python dependency and testing model.

FROST remains a credible later option when the system has a measured need for a single compact signature or for hiding which participants formed the quorum. Its adoption would require a separate protocol decision for participant enrollment, key generation, share rotation, group-key identity, application-level replay protection, and compatibility with existing records.

## Question and scope

The question is which model best fits the Registry's requirements for a 2-of-3 authorization policy across Identity Records and Provider Records:

1. an explicit `Signer Set` containing independent Ed25519 public keys and multiple signatures; or
2. FROST or another threshold-signature scheme producing one group signature from cooperating participants.

This is decision evidence only. It does not define the final CBOR field numbers, implement either model, widen the existing envelope, or create implementation tickets. The shared-schema ticket, [Design the shared multisignature authorization CBOR schema and `SignedEnvelope` extension](https://github.com/jetpen/decent-registry/issues/87), owns the wire-schema decision.

The analysis follows the map constraints in [Design 2-of-3 multisignature authorization for Identity and Provider Records](https://github.com/jetpen/decent-registry/issues/85): stable record lookup keys, one shared authorization structure, canonical CBOR, monotonic `Seq`, explicit owner binding, public DHT replication, and an absolute private-key boundary.

## Repository constraints

The current protocol is single-key based.

- [`encoding.py`](../../src/decent_registry/encoding.py) encodes `SignedUpdate` as canonical CBOR with the shape `{1: record_fields, 2: payload, 3: seq}`.
- [`signed_envelope.py`](../../src/decent_registry/signed_envelope.py) encodes the stored value as `{1: signed_update_bytes, 2: signature}` and rejects non-canonical CBOR.
- [`verification.py`](../../src/decent_registry/verification.py) hashes the canonical `SignedUpdate` bytes with SHA-256 and verifies one Ed25519 signature. Identity records take the owner key from `record_fields[2]`; Provider Records take it from `record_fields[1]`.
- The existing validator enforces a strictly increasing `seq` and rejects an owner-public-key change on overwrite. The current owner-binding behavior therefore cannot be silently reinterpreted as signer-set rotation.
- [`protocol-concepts.md`](../protocol-concepts.md), [`identity-put-get-examples.md`](../identity-put-get-examples.md), and [`provider-put-get-examples.md`](../provider-put-get-examples.md) describe the same canonical envelope and `put`/`get` behavior for both record families.
- [`pyproject.toml`](../../pyproject.toml) depends on `libp2p`, `cbor2`, and `cryptography`, but declares no FROST or threshold-signature dependency.
- The prior [2-of-3 multisig key replacement and compromise recovery](2-of-3-multisig-key-recovery.md) research establishes the project-specific recovery boundary: two trustworthy current signers can replace one lost or compromised signer; ordinary 2-of-3 authorization cannot recover after two signers are unavailable or compromised.

These constraints favor an extension that preserves the current signed-byte and record-key model while adding threshold policy and proof handling explicitly.

## Primary-source facts

FROST is a threshold protocol, not merely a different serialization of three ordinary private keys. RFC 9591 states:

> “threshold signatures require cooperation among a threshold number of signing participants, each holding a share of a common private key.” [1]

The protocol uses a two-round signing flow:

> “FROST requires two rounds to compute a signature.” [1]

FROST can produce signatures compatible with Ed25519 verification for the specified ciphersuites:

> “Two ciphersuites can be used to produce signatures that are compatible with Edwards-Curve Digital Signature Algorithm (EdDSA) variants Ed25519 and Ed448” [1]

That compatibility is useful, but it does not make FROST signing equivalent to independently signing with three Ed25519 private keys. RFC 9591 also states:

> “However, unlike EdDSA, the signatures produced by FROST are not deterministic, since deriving nonces deterministically allows for a complete key-recovery attack in multi-party, discrete logarithm-based signatures.” [1]

The RFC leaves key generation outside the core signing specification:

> “Key generation for FROST signing is out of scope for this document.” [1]

The RFC describes two possible configuration mechanisms—a trusted dealer or a distributed key-generation protocol—but specifies the trusted-dealer method in Appendix C; the Zcash Foundation implementation includes both trusted-dealer key generation and DKG [1][3]. The official Zcash Foundation implementation is a Rust implementation:

> “Rust implementation of FROST (Flexible Round-Optimised Schnorr Threshold signatures) by the Zcash Foundation” [3]

The repository's audit description states:

> “This includes key generation (both trusted dealer and DKG) and FROST signing.” [3]

These facts establish the relevant trade-off: FROST reduces the stored proof to a group-signature form, but the system must own more participant-state and key-lifecycle machinery before it can safely use that form.

## Comparison

| Criterion | Explicit signer set with independent Ed25519 signatures | FROST / threshold signature |
|---|---|---|
| Authorization representation | Public list of signer identifiers and Ed25519 public keys plus a threshold and epoch | Group public key plus participant shares, threshold, participant identifiers, and a separate key-management lifecycle |
| Stored proof | One proof per participating signer in one envelope; proof count is at least the threshold | One final group signature; participant coordination occurs before publication |
| Verification | Existing Ed25519 verification repeated for distinct current-set members, then threshold counted | FROST/group-signature verification path; Ed25519-compatible ciphersuite support is possible but requires the correct FROST implementation and parameters [1] |
| Rotation | Current quorum signs the complete next public signer set; the record can retain its stable lookup key | Participant replacement requires valid new shares and a defined group-key/configuration transition; changing a public list alone is insufficient |
| Auditability | Envelope can identify exactly which signer proofs were submitted | Final group signature authenticates the group; participant attribution requires additional bundle metadata or operational logs |
| Operational state | Independent private keys remain with their holders; no shared secret or DKG is required | Participants hold shares of one common secret and coordinate nonce commitments and signature shares |
| Replay and sequencing | Directly extends existing canonical bytes, `seq`, owner binding, and durable accepted-state checks | Must still bind the application message to record identity and sequence; FROST nonce-safety and participant-session state are additional concerns |
| Python fit today | Uses dependencies and APIs already present in the repository | The primary implementation evidence located for FROST is Rust; this repository has no FROST dependency [3] |
| Migration risk | Low-to-moderate: add a scheme discriminator and multi-proof handling without changing existing single-key records | High: add a group-key format, share lifecycle, DKG/resharing, coordinator behavior, and a new validation/test-vector surface |

## Explicit signer set

### One shared envelope

The explicit model can keep one canonical signed message and place multiple proofs beside it. Each signer independently signs the exact same canonical authorization-update bytes. The envelope carries the signed bytes once and a proof list containing signer identifiers and signatures.

This is consistent with the multi-signer pattern in COSE. RFC 9052 states:

> “COSE_Sign allows for one or more signatures to be applied to the same content.” [2]

The Registry should not silently adopt COSE's wire format in this ticket. The relevant decision evidence is narrower: a single content object with multiple independently verifiable signatures is a standard and coherent representation for the explicit model. The subsequent schema ticket must decide the Registry-specific CBOR shape, scheme discriminator, proof ordering, and compatibility rules.

### Rotation and replacement

For a current set `[K1, K2, K3]` with threshold `2`, replacing lost or compromised `K1` is a signed state transition:

```text
old set:  [K1, K2, K3]
operation: replace signer K1
new set:  [K2, K3, K4]
old epoch: e
new epoch: e + 1
new seq:   greater than the accepted sequence
```

`K2` and `K3` sign the same complete transition. The verifier checks both proofs against the old set, installs the complete new set atomically, and rejects `K1` for later updates. The public record changes authorization state without changing the stable identity or Provider Record lookup key.

This is a public-record edit, not a secret-share operation. It fits the existing project research, which requires the complete next set and predecessor state to be signed rather than accepting an underspecified “add key” operation. It also preserves the private-key boundary: `K4` is generated and retained by its holder, while the Registry receives only public verification material and signatures.

### Verification and auditability

Verification adds three kinds of logic around the existing Ed25519 operation:

1. validate the signer-set policy and canonical ordering;
2. validate that every proof names a distinct member of the exact current set; and
3. count valid proofs against the threshold before applying the sequence and predecessor-state rules.

The signer identities are visible in the bundle. That is a feature for this Registry's public, auditable record model: a reviewer can determine which two of the three current signers supplied the proofs. The model does not provide signer privacy, and that is an explicit cost rather than an accidental property.

## FROST / threshold signatures

### Proof-size advantage

FROST's principal wire advantage is one final group signature rather than a proof for every participating signer. For a 2-of-3 update, the stored proof can therefore be approximately constant-size with respect to the number of signers, while an explicit bundle grows with the number of proofs and signer identifiers.

The saving is real but bounded in this project. The authorization set is only three signers, the threshold is two, and the Registry already stores small canonical CBOR records. The proof-size reduction must therefore be weighed against the extra participant protocol, implementation dependency, and rotation complexity rather than treated as a sufficient reason by itself.

### Key generation and participant lifecycle

FROST participants do not simply possess three unrelated Ed25519 private keys. They hold shares of a common private key. The initial group requires a trusted-dealer process or distributed key generation, and participant replacement requires a protocol that creates or refreshes valid shares for the new participant while preserving the intended group authorization state.

RFC 9591 explicitly separates signing from key generation and warns about nonce management. It states that the required nonce-safety condition is:

> “This requirement is necessary to avoid replay attacks initiated by other participants that allow for a complete key-recovery attack.” [1]

The Registry would need to specify at least:

- who may initialize a group and how all participants receive shares;
- how participant identities and share identifiers are authenticated;
- how a lost or compromised participant is removed;
- whether rotation preserves the group public key or creates a new one;
- how share refresh or DKG messages are authenticated and completed;
- how a coordinator prevents nonce reuse and cross-session mixing; and
- how the resulting group key is represented in the Identity and Provider Record authorization state.

None of these decisions is implied by adding a FROST signature byte string to the current envelope. They belong in a later FROST-specific design if the project eventually selects that model.

### Auditability and signer privacy

A FROST verifier can validate a signature against the group public key, but the final signature does not by itself identify which threshold participants cooperated. Participant attribution would require additional signed bundle metadata or trusted operational logs. Adding that metadata would reduce the simplicity and possibly the privacy benefit of the one-signature design.

The project must decide whether this loss of public signer attribution is acceptable before adopting FROST. The current recovery design treats explicit signer participation as useful evidence during key replacement and compromise response.

### Verification-path compatibility

FROST's Ed25519-compatible ciphersuites leave open a future reuse of an Ed25519-oriented verifier, but compatibility is conditional on using the specified FROST ciphersuite and its exact key and signature encoding. It does not allow the existing single-key verifier to accept FROST group signatures without a scheme-aware dispatch path.

The current `verification.py` path expects one owner public key and one Ed25519 signature. Explicit multisignature requires repeated calls to that operation plus membership and threshold checks. FROST requires a FROST-aware group public key and verification implementation, plus validation of the application-level authorization state.

## Canonical CBOR, domain separation, and replay

Both models must sign one exact application message. The message must bind at least:

- record family and stable lookup key;
- operation type;
- complete authorization state or complete target state;
- current authorization epoch and target epoch;
- strictly increasing `seq`;
- predecessor state hash; and
- record payload or update contents.

These bindings are Registry decisions, not automatic properties of either cryptographic scheme. They prevent a valid proof from being moved between records, operations, epochs, or predecessor states.

For the explicit model, all signer proofs must cover the same canonical bytes. The verifier must reject a mixed bundle containing proofs over different payloads, duplicate signer identifiers, stale-set proofs, non-canonical CBOR, a non-increasing sequence, or a predecessor hash that does not match the accepted state.

For FROST, the same application message must be passed to the FROST signing operation. FROST's internal domain-separated hashes and nonce rules do not replace Registry-level record binding, sequence checks, or durable conflict handling. Application replay and FROST nonce/session replay are separate failure modes and require separate validation rules.

## Python ecosystem and operational complexity

The repository already has a Python Ed25519 path through `libp2p`, canonical CBOR through `cbor2`, and test fixtures for one-key signing and verification. Its declared dependencies contain no FROST implementation. The primary FROST implementation evidence located for this decision is the Zcash Foundation's Rust repository, which includes DKG and signing [3].

This does not prove that no Python FROST library exists. It establishes the actionable project fact: choosing FROST would add a new cryptographic implementation or binding that is not currently part of the repository. That dependency would require independent review, interoperability vectors, failure-mode testing, and a defined upgrade policy.

The explicit model has more bytes on the wire and more verifier iterations, but it uses a cryptographic primitive and library path already exercised by the project. The main new security logic is policy validation: distinctness, set membership, threshold counting, epoch transitions, and state conflict handling. That is a smaller first implementation surface than introducing DKG, share lifecycle, participant coordination, and FROST verification simultaneously.

## Migration path if FROST becomes necessary later

Choosing explicit signer sets for v1 should not permanently exclude FROST. The shared-schema decision should reserve a versioned authorization scheme discriminator or equivalent extensibility boundary, without defining FROST fields in this research ticket.

A later migration can then:

1. authorize the change from the current explicit signer set using the current quorum;
2. establish and authenticate the FROST participant configuration through a separately specified DKG or trusted-dealer process;
3. publish the new group public key, threshold, participant identifiers, and authorization epoch in a new scheme version;
4. retain the stable record lookup key and the application's sequence/predecessor protections;
5. make verifiers dispatch by authorization scheme and reject unsupported schemes explicitly; and
6. preserve old explicit-signer records as a supported legacy scheme until a separate compatibility decision retires them.

This migration is an implementation and compatibility plan, not a reason to add FROST now. It keeps the v1 decision reversible at the protocol boundary while preventing an unreviewed cryptographic scheme from entering the first implementation.

## Decision

For the first Registry multisignature protocol version:

- **Select:** explicit signer sets with independent Ed25519 signatures.
- **Threshold:** represent the 2-of-3 policy explicitly and require distinct current-set proofs.
- **Envelope direction:** extend the one shared envelope to carry multiple proofs over one canonical signed update; the exact CBOR shape is deferred to the shared-schema ticket.
- **Rotation:** authorize the complete next signer set as an atomic state transition from the current set.
- **Replay protection:** retain strict `seq`, current authorization epoch, predecessor-state binding, canonical CBOR, and stable lookup-key binding.
- **Private-key boundary:** keep private keys with their holders; exchange only public verification material and signatures.
- **FROST status:** defer. Reconsider only when compact proofs, signer privacy, or another demonstrated requirement outweighs DKG/share/nonce and ecosystem complexity.

## Direct answers

- **Which model best fits the current Registry?** Explicit signer sets with independent Ed25519 signatures.
- **Does FROST offer a genuine advantage?** Yes: a compact group signature and less public signer attribution, subject to additional participant coordination and key-management requirements.
- **Can explicit rotation replace one signer without shared-secret resharing?** Yes. The current quorum signs the complete next public signer set.
- **Does FROST rotation equal editing a public key list?** No. The replacement participant must receive a valid share under a separately specified DKG or share-refresh protocol.
- **Can the existing one-signature envelope remain unchanged?** No. Explicit multisignature needs multiple proofs; the shared-schema ticket must define the compatible extension.
- **Does Ed25519 compatibility make FROST a drop-in replacement?** No. The FROST ciphersuite may produce Ed25519-compatible signatures, but verification still needs scheme-aware group-key and participant-state handling [1].
- **Should FROST be implemented now?** No. Defer it until the Registry has a demonstrated compactness or privacy requirement and a reviewed participant/key-lifecycle design.

## Sources

[1] https://www.rfc-editor.org/rfc/rfc9591 — RFC 9591: The Flexible Round-Optimized Schnorr Threshold (FROST) Protocol
[2] https://www.rfc-editor.org/rfc/rfc9052 — RFC 9052: CBOR Object Signing and Encryption (COSE): Structures and Process
[3] https://github.com/ZcashFoundation/frost — Zcash Foundation FROST implementation
