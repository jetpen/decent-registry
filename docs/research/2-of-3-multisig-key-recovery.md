# Research: 2-of-3 multisig identity key replacement and compromise recovery (#78)

## Executive recommendation

Use an **explicit signer set with threshold authorization** for the first multisignature protocol version:

- Keep the identity lookup key stable.
- Store three distinct public keys, a threshold of `2`, and a signer-set epoch in the primary identity record.
- Require two signatures from distinct members of the current set for every authorized update.
- Treat key replacement as a signed state transition that names the retired key and the complete next signer set.
- Bind each transition to the identity, current epoch, predecessor state, and strictly higher sequence number.
- Defer FROST or another threshold-signature scheme until the explicit-signer protocol is proven and compact signatures or signer privacy are demonstrated requirements.

The critical limitation is fundamental: if an attacker controls one key and obtains one honest signature, a 2-of-3 policy cannot distinguish that combination from the owner. If two keys are unavailable or compromised, ordinary 2-of-3 recovery is not possible. A separate recovery or guardian policy is required for those cases.

## Scope and terminology

The owner starts with three keypairs:

```text
active signer set = {K1, K2, K3}
threshold         = 2
signer-set epoch  = 1
```

`K1`, `K2`, and `K3` denote signer identifiers and their corresponding public keys. The private keys remain with their holders. The public record contains only public verification material and state metadata.

A **plain multisignature** envelope carries multiple independent signatures, each identifying a signer. A **threshold signature** produces one signature from cooperation among a threshold number of participants, usually using distributed secret shares. Both can express a 2-of-3 policy, but their key-rotation and operational requirements differ.

## Existing repository constraints

The current implementation is single-key based:

- Identity lookup keys are derived as `sha256(owner_name_bytes)`.
- Identity `record_fields[1]` contains the owner name and `record_fields[2]` contains one owner public key.
- The signed update is canonical CBOR: `{1: record_fields, 2: payload, 3: seq}`.
- Signatures verify an Ed25519 signature over `sha256(canonical_cbor(SignedUpdate))`.
- Validation requires a strictly increasing sequence number.
- Existing state binds a record key to one owner public key; changing it currently raises an owner-collision error.

Sources in this repository:

- [`src/decent_registry/encoding.py`](../../src/decent_registry/encoding.py)
- [`src/decent_registry/verification.py`](../../src/decent_registry/verification.py)
- [`docs/research/identity-recovery-research.md`](identity-recovery-research.md)

Multisig therefore requires a versioned authorization-policy extension and validator changes. It cannot be implemented solely by placing three keys in the existing single-key field.

## Why two remaining keys replace one lost key

Suppose `K1` is lost but `K2` and `K3` remain trustworthy. The owner creates a new keypair `K4`, then constructs a replacement transition:

```text
old set:     [K1, K2, K3]
operation:   replace_signer
retire:      K1
new set:     [K2, K3, K4]
threshold:   2
old epoch:   7
new epoch:   8
old seq:     41
new seq:     42
```

`K2` and `K3` independently sign the same canonical transition. The verifier checks both signatures against the **old** set, confirms that they are distinct active members, and installs the complete new set atomically. Subsequent updates accept only `[K2, K3, K4]`; `K1` is no longer authorized even if its private key later reappears.

The same operation handles a known compromise. The two uncompromised keys authorize replacement of the compromised key and revoke it in the same state transition. A new key must be independently generated; the compromised key's material must not be reused.

This is replacement, not recovery from an arbitrary loss. It works only while at least two trustworthy current signers remain.

## Proposed authorization state

Conceptually, the primary identity record contains:

```text
identity_key:       sha256(owner_name_bytes)
authorization:
  threshold:         2
  epoch:             8
  signers:
    - id: K2
      public_key: <Ed25519 public key>
    - id: K3
      public_key: <Ed25519 public key>
    - id: K4
      public_key: <Ed25519 public key>
state:
  seq:               42
  state_hash:        <hash of the complete canonical accepted state>
```

The exact CBOR integer-key schema is a follow-up design decision. The following invariants are not optional:

1. Signer identifiers are unique within a set.
2. Public keys are unique within a set.
3. `0 < threshold <= len(signers)`.
4. A 2-of-3 policy has exactly three active signers unless a separately specified policy permits another cardinality.
5. The full signer set, threshold, epoch, and sequence are covered by the signed bytes.
6. The set is canonically ordered before encoding.
7. Aliases store a reference to the primary identity and do not duplicate this authorization material.

An alias record should make that relationship explicit, for example:

```text
alias:
  role:              "alias"
  primary_link:      <primary identity lookup key>
  authorization:     absent
```

The primary record carries the authorization policy once:

```text
primary:
  role:              "primary"
  authorization:     <threshold, epoch, signer set, and state>
```

When an alias update requires owner authorization, the validator resolves `primary_link`, reads the primary's accepted authorization state, and binds the alias record key into the signed transition. This is a proposed v2 behavior; the current validator does not yet resolve primary links.

## Signed transition envelope

A plain multisignature transition can be represented conceptually as:

```text
SignedAuthorizationUpdate = {
  identity_key: <stable lookup key>,
  operation: "replace_signer" | "rotate_set" | "ordinary_update",
  old_epoch: 7,
  new_epoch: 8,
  old_seq: 41,
  new_seq: 42,
  prev_state_hash: <hash of accepted state at seq 41>,
  retired_signer_id: K1,             // required for replace_signer
  next_threshold: 2,
  next_signers: [K2, K3, K4],
  update: <application-specific record contents>
}

Envelope = {
  signed_update: canonical_cbor(SignedAuthorizationUpdate),
  proofs: [
    {signer_id: K2, signature: <Ed25519 signature>},
    {signer_id: K3, signature: <Ed25519 signature>}
  ]
}
```

The two proofs must sign exactly the same canonical bytes. The verifier must reject duplicate signer IDs, proofs from non-members of the old set, malformed signatures, non-canonical encodings, and a proof set with fewer than the threshold number of distinct valid signers.

`prev_state_hash` is the hash of the complete canonical accepted state, including the record contents, authorization policy, epoch, and sequence. It prevents a valid transition from being replayed against a different predecessor state or combined with a different payload. `old_epoch` and `old_seq` identify the authorization state on which the signers operated. `new_epoch` changes whenever the signer set or threshold changes. The record key, operation, and complete target state must be included in the signed message to prevent cross-record and cross-operation reuse.

## Key lifecycle protocol

### Enrollment

1. Generate three independent keypairs.
2. Publish the primary identity with the initial signer set, threshold, epoch, and sequence.
3. Ensure all three key holders receive the recovery and rotation procedure.
4. Store no private keys or reusable shared secrets in the DHT.

### Ordinary update

1. Read the latest accepted authorization state.
2. Construct the complete update with the current epoch, predecessor hash, and a higher sequence.
3. Obtain signatures from any two distinct current signers.
4. Verify the signatures locally before publishing.
5. The proposed DHT validator accepts the update only if it extends the accepted state.

### Lost-key replacement

1. Generate `K4` independently.
2. Construct `replace_signer(K1 -> K4)` from the latest accepted state.
3. Have `K2` and `K3` sign the exact same transition.
4. Verify both signatures against the pre-rotation set `[K1, K2, K3]`.
5. Publish the transition.
6. Install `[K2, K3, K4]` atomically at the next epoch.
7. Destroy or quarantine any recovered copy of `K1`; it is cryptographically retired regardless.

### Compromised-key replacement

The protocol is identical, except the owner should treat the transition as urgent:

- Do not wait for the compromised key to cooperate.
- Use the two remaining uncompromised signers.
- Retire the compromised signer explicitly.
- Generate the replacement key on a trusted device or hardware authenticator.
- Review and, if necessary, rotate any other credentials that may have been exposed.
- Publish the revocation/replacement transition as soon as possible.

A compromised key alone cannot authorize an update. It can, however, participate in a takeover if paired with one honest current signer.

### Planned rotation

Routine rotation uses the same state-transition mechanism. For example:

```text
[K1, K2, K3] -> [K1, K2, K4]
```

Two current signers authorize the exact complete next set. The protocol should not accept an unspecified “add key” operation that leaves the final threshold or membership ambiguous.

### Insufficient keys

If two keys are lost or compromised, the remaining key cannot satisfy a 2-of-3 policy. The protocol must reject a one-signature replacement under the normal policy. Enabling an implicit emergency one-signature mode would convert a known loss into an unauthorized-takeover path.

A separate recovery policy may be added, such as an independently held guardian quorum or passkey-based recovery credential. It must be explicitly represented, separately authorized, and bound to the same target and state-transition protections. It is not provided by 2-of-3 multisig itself.

## State-transition table

| Situation | Available trustworthy current signers | Normal result | Required action |
|---|---:|---|---|
| Normal update | 3 | Accept 2 of 3 proofs | Keep signer set unchanged; increment `seq`. |
| One key lost | 2 | Replace lost member | Two remaining signers authorize complete next set; increment epoch and `seq`. |
| One key compromised, detected | 2 | Revoke and replace compromised member | Two uncompromised signers authorize urgent replacement. |
| One key compromised, undetected | 2 honest plus 1 attacker | No cryptographic distinction | Operational monitoring or additional policy is required; attacker plus one honest signer reaches quorum. |
| Two keys lost | 1 | Reject normal recovery | Use separately enrolled recovery authority, if any. |
| Two keys compromised | 1 honest at most | Reject normal recovery | Assume takeover may already be possible; use independent recovery and audit state. |
| Stale DHT replica | Any | Reject stale/conflicting state | Require higher `seq`, expected `old_epoch`, and matching `prev_state_hash`. |
| Replayed old rotation | Any | Reject | Persist accepted sequence/epoch and reject old predecessor state. |
| Equal-sequence conflicting updates | Any | Reject both as an authorization conflict | Do not use arrival time or DHT ordering as authorization; require a later update extending one explicitly accepted state. |

## Threat analysis

### Attacker controls one private key

The attacker can produce one valid proof but cannot authorize an update alone. The owner can replace the key with the other two signers. This is the intended benefit of the 2-of-3 policy.

### Attacker controls one key and obtains one honest signature

The attacker reaches the threshold and can construct a syntactically valid malicious update. The verifier cannot determine whether the honest signer approved the attacker's intended state. This is an unavoidable limitation of a plain 2-of-3 authorization rule.

Mitigations are policy features, not properties of the threshold:

- Require signer review of the complete canonical transition, not only a digest or UI summary.
- Use hardware-backed keys and transaction-display workflows where possible.
- Add an independent recovery or veto mechanism.
- Consider a higher threshold or more participants for the threat model.
- Add an optional delay and cancellation path only if its governance and liveness behavior are specified.

A delay does not prevent an attacker from authorizing a transition; it only creates an intervention window.

### Attacker replays an old valid update

Reject if `new_seq <= accepted_seq`, `old_epoch` is not current, or `prev_state_hash` does not match the accepted state. These checks must be applied before installing the new signer set.

### Attacker combines a stale authorization with a current signer

A proof from an earlier signer set must not count toward a current quorum. The verifier must validate every proof against the exact current epoch and signer set, not merely against a public key that appeared in some historical record. A stale transition also fails because its `old_epoch`, `old_seq`, or `prev_state_hash` does not match the currently accepted complete state. A current signer must sign the current canonical transition; a signature copied from an older transition cannot be combined with a new signature to create a valid mixed-epoch quorum.

### Attacker changes encoding or context

Sign the canonical complete transition. Reject non-canonical CBOR. Include the identity lookup key and operation in the signed domain so a proof for one record or operation cannot be reused for another.

### Stale or conflicting DHT state

A DHT replica can return an older valid record. Validators must maintain monotonic accepted state independently of the retrieved value, or use an equivalent durable conflict-resolution rule. A valid signature on an older record does not make it current again.

### Lost replacement key

Replacing one key does not remove operational risk if the new key is immediately lost. The owner should confirm possession of `K4` before retiring `K1` where the threat model allows a staged operation. If staged replacement is used, both stages must have explicit semantics and the intermediate state must not weaken the threshold.

## Explicit multisignature versus threshold signatures

### Explicit signer set with multiple Ed25519 signatures

Recommended for the first implementation.

Advantages:

- Reuses the repository's existing Ed25519 verification path.
- Makes signer participation auditable.
- Makes membership and duplicate-proof checks explicit.
- Replaces one public key by changing a public signer set; no secret-share refresh is required.
- Avoids distributed key generation and participant nonce coordination.
- Simplifies test vectors and DHT debugging.

Costs:

- Envelope size grows with the number of proofs.
- The record exposes which signers participated.
- The verifier must implement set membership, distinctness, and threshold counting.

### FROST or another threshold-signature protocol

RFC 9591 specifies FROST, including a FROST(Ed25519, SHA-512) ciphersuite. It produces a threshold signature after participant cooperation and can reduce the proof to one group signature.

Costs relevant to this project:

- Participants manage secret shares rather than ordinary independent private keys.
- As a project-design implication, participant replacement would require share refresh or group regeneration; changing a public-key list is insufficient because the participants hold shares of a group secret rather than independent signer keys. The RFC does not define this registry's membership-rotation policy.
- Nonce generation and reuse prevention become critical to private-share security.
- The resulting group signature alone does not reveal which two participants authorized a transition; a coordinator or participants may still retain operational logs.
- Existing Ed25519 verification is not automatically verification of a FROST group signature.

FROST may be appropriate later for compactness or signer privacy. It should not be introduced merely to express 2-of-3 authorization.

## Primary-source findings

### COSE signed-message model

RFC 9052 defines COSE signing structures and leaves application-specific signing and verification rules to the application. This supports defining an application-specific authorization structure in which the complete transition, not only the payload, is the signed object.

Source: [RFC 9052 — CBOR Object Signing and Encryption (COSE): Structures and Process](https://www.rfc-editor.org/rfc/rfc9052)

### FROST threshold signatures

RFC 9591 defines FROST as a two-round threshold Schnorr signature protocol and specifies the Ed25519 ciphersuite. It documents participant shares, threshold cooperation, and nonce requirements. Those participant-state requirements make signer replacement a key-management operation rather than a simple list edit.

Source: [RFC 9591 — The Flexible Round-Optimized Schnorr Threshold (FROST) Signing Protocol](https://www.rfc-editor.org/rfc/rfc9591)

### Verification-method rotation and recovery

W3C DID Core keeps an identifier distinct from its verification methods and describes verification-method rotation, revocation, and recovery as method-specific operations. The relevant design lesson is that a stable identifier can retain its identity while its authorized verification material changes, provided the identifier method defines authenticated state transitions.

Sources:

- [W3C DID Core — Verification Methods](https://www.w3.org/TR/did-core/#verification-methods)
- [W3C DID Core — Verification Relationships](https://www.w3.org/TR/did-core/#verification-relationships)
- [W3C DID Core — Verification Method Rotation](https://www.w3.org/TR/did-core/#verification-method-rotation)
- [W3C DID Core — Verification Method Revocation](https://www.w3.org/TR/did-core/#verification-method-revocation)
- [W3C DID Core — DID Recovery](https://www.w3.org/TR/did-core/#did-recovery)

These sources do not define the decent-registry protocol. They support the separation between a stable identifier and a rotating authorization set; the exact quorum and state machine remain project-specific.

## Follow-up implementation issues

This research should lead to separate implementation issues rather than silently changing the existing single-key protocol:

1. **Authorization-policy schema:** define canonical CBOR fields for threshold, signer IDs, public keys, epoch, and state hash while preserving primary/alias linkage.
2. **Multisignature envelope verification:** verify distinct current-set Ed25519 proofs over one canonical transition.
3. **Signer-set rotation:** implement `replace_signer` and complete-set rotation with atomic epoch/sequence transitions.
4. **Replay and stale-state protection:** enforce predecessor hash, epoch, strict sequence monotonicity, and durable accepted-state handling.
5. **Primary/alias authorization behavior:** keep authorization material on the primary and define how aliases resolve it without duplicating it.
6. **Recovery below threshold:** design and separately review an independent guardian/passkey recovery policy for two-key loss or compromise.
7. **Test vectors:** cover valid 2-of-3 updates, duplicate proofs, one-proof rejection, old-set rejection, lost-key replacement, compromised-key replacement, replay, equal-sequence conflicts, stale predecessor hashes, and insufficient-key recovery.

## Direct answers

- **Can one lost key be replaced?** Yes. The other two current signers authorize a transition that removes the lost key and installs a new public key.
- **Can one compromised key be replaced?** Yes, if the other two remain trustworthy and act before the compromised key is paired with an honest signer.
- **Can one compromised key plus one honest key authorize takeover?** Yes. A 2-of-3 verifier cannot tell that the quorum was assembled maliciously.
- **Can 2-of-3 recover from two lost or compromised keys?** No. That requires an independently specified recovery mechanism.
- **Should the first implementation use FROST?** No. Explicit signer sets with independent Ed25519 signatures have lower protocol and operational complexity and fit the current codebase.
