# Research: Secure owner recovery for lost private keys (#68)

## Problem
Current identity record ownership in this repo is authenticated exclusively via the owner’s private key.

If the owner private key is lost, the owner cannot produce a valid signed `SignedUpdate` that passes identity validation. The repo currently has no alternative recovery/authorization path.

Goal: add a secure “lost key recovery” path using alternative authentication methods.

Constraints from #68:
- Alternative authentication must be feasible and reasonably secure.
- Alternative authentication requires additional information associated with the owner’s identity record.
- Storage must be efficient:
  - alias identity records must not need redundant copies of the same alternative authentication material.
- The owner’s primary identity record must be specially designated as holding the alternative authentication information.
- Alias identity records must link to the primary identity record so the alternative authentication info can be found and used.
- Explicitly reject weak methods (passwords / PIN / question-answer secrets).

## Repo-specific anchors (what exists today)
### Identity record format (v1)
Identity records are stored as CBOR “signed envelopes” containing a canonical `SignedUpdate`.

Current code paths:
- `build_identity_envelope(owner_name_hex, owner_privkey_pem_path, seq)`:
  - `SignedUpdate.record_fields = { 1: owner_name_bytes, 2: owner_pub_bytes }`
  - `SignedUpdate.payload = {}`
- Signature binds to:
  - `sha256(canonical_cbor(SignedUpdate))`
- Envelope format:
  - `Envelope = {1: signed_update_bytes, 2: signature}`

Key derivation:
- Identity object key = `sha256(owner_name_bytes)`
- DHT namespace is `/decent-registry/identity/{object_key_hex}`

### Identity validation invariants
`validate_identity_overwrite` enforces:
- CBOR canonical form
- Signature verification against `record_fields[2]` (owner public key)
- `seq` strictly increasing per `record_key`
- **owner binding:** on overwrite, if an existing identity record exists for `record_key`, the incoming update’s `owner_public_key` must match the previously recorded owner public key.

As implemented in `verification.py`:
- `_enforce_seq_and_owner_binding(...)` raises `ValueError("owner collision")` when the owner public key differs from the stored one.

Implication:
- Any recovery scheme that changes the owner public key on an identity record will require explicit protocol/validator changes.

### Payload handling
For identity record validation, the current implementation primarily extracts/validates `record_fields[1]` and `[2]` and uses seq monotonicity.
- Payload is validated structurally as a CBOR map (because `SignedUpdate.payload` must be a dict), but it is not interpreted for identity auth.

Implication:
- Recovery-related data can be added to payload without breaking current CBOR structure, but **a recovery protocol cannot work without additional validator logic** that interprets that payload and validates the recovery proof.

## Threat model / security requirements
Assumptions for recovery design:
- Identity records and updates are publicly replicated in a DHT.
- Attackers can read existing records and observe recovery attempts.
- Attackers can attempt to craft recovery updates (publicly) using any data they can obtain.
- Attackers can attempt offline guessing/brute force if a recovery method embeds low-entropy secrets or reusable secrets.
- Front-running risk exists if recovery proof requires revealing a secret (or a reusable token) in a public update.

Therefore:
- Any alternative auth that relies on a reusable secret stored in a public DHT record is disallowed unless the secret is not recoverable/offline-attackable from the DHT copy.
- Any alternative auth that requires the owner to reveal a proof secret in a public DHT update must mitigate front-running and replay.

## Candidate alternative authentication methods
Requirement: analyze feasibility and security, including whether the method forces storing a reusable secret in the public DHT.

### Candidate A: Passkeys / FIDO2 / hardware security keys (accept as leading approach)
What it is:
- Public-key based authentication where the authenticator holds a private key and uses it to produce an assertion/signature bound to a relying-party context.

Feasibility in this architecture:
- The “relying party” is not a conventional server with session state, but the verifier can still challenge-bind authentication to:
  - identity record key (`object_key_hex`)
  - the intended recovery update fields (e.g., new owner public key)
  - current `seq` (or recovery nonce derived from seq)

Security properties:
- No reusable shared secret needs to be stored in the DHT.
- Proof can be a signature over a challenge; the DHT stores only public verification parameters (safe under replication).
- Phishing resilience is determined by WebAuthn’s origin/RP binding; the recovery design can enforce strict context binding in the challenge.

Key risks / open points:
- Need library-level support to perform authenticator assertions and verify attestation/signatures (COSE, etc.).
- Passkeys include RP ID and origin constraints; the protocol must define a stable verifier context.
- Recovery must include strong binding to the recovery target so a captured signature cannot be replayed to adopt an attacker-controlled key.

Evaluation outcome:
- **Accept** as the primary recovery credential type: store public credential identifiers/keys in the primary record; require a challenge-bound signature for recovery.

### Candidate B: Authentication app holding a device-generated signing key (conditionally accept)
What it is:
- Treat the app as a private-key holder that can sign a challenge with a device-resident key.

Two variants:
1) **App uses TOTP/HOTP** (shared secret): rejected (see Candidate D).
2) **App uses public-key signing** (e.g., a keypair provisioned into the app, with signatures over challenges): can be treated similarly to passkeys (signature over challenge, verifier stores public key material).

Feasibility:
- Requires a standard for representing the app key material and proving possession.
- If implemented as generic “signed challenge” rather than TOTP, it fits the “no reusable secret in DHT” requirement.

Evaluation outcome:
- **Conditionally accept** for designs where the app-provisioned credential is a private-key signer and only public key material is stored.

### Candidate C: Social recovery / threshold recovery using guardians (accept as robust, but higher UX/protocol complexity)
What it is:
- A set of guardians each hold private signing keys (or can produce signatures) and collectively authorize recovery.

How this avoids storing secrets:
- Primary record stores:
  - guardian public keys
  - threshold `t` and guardian set
- Recovery update includes guardian signatures over a challenge.
- Only public verification material is stored in the DHT.

Security properties:
- Offline theft risk is limited to the guardians’ private keys (not a shared DHT-embedded secret).
- Front-running risk depends on whether the recovery proof is sufficient to effect recovery; however, since guardians sign and threshold protects against a single attacker, front-running typically requires compromising enough guardians.

Key risks / open points:
- UX complexity: need multiple participants to authorize.
- Protocol complexity: recovery update must carry multiple signatures and verifier must check threshold.
- Need clear governance: how to add/remove guardians (and how to recover if guardians change).

Evaluation outcome:
- **Accept** as a viable alternative recovery method, especially when passkeys are unavailable.

### Candidate D: TOTP / “authentication application” shared-secret methods (reject)
What it is:
- TOTP/HOTP use a shared secret between the authenticator app and the verifier.

Why it fails the #68 constraints:
- Secure implementation requires storing a shared secret (or an equivalent reusable secret) somewhere.
- If that secret is stored in the identity record payload (which is publicly replicated), attackers can extract it and compute valid OTP codes offline.

DHT replication effect:
- The record payload is visible to attackers; any stored shared secret becomes compromised.

Evaluation outcome:
- **Reject**.

### Candidate E: Passwords / PINs / question-answer secrets (reject)
Why it fails:
- Such secrets are low entropy relative to offline brute force, and there is no global online rate-limiting in a DHT setting.
- Attackers can read the identity record and attempt offline guessing if the recovery mechanism is based on verifying a submitted password/PIN/Q&A.

Evaluation outcome:
- **Reject**.

### Candidate F: SMS/email one-time codes (reject)
What it is:
- One-time codes delivered to a phone (SMS) or email address.

Why it fails the #68 constraints in this DHT setting:
- Centralized delivery dependency: the verifier relies on an out-of-band channel controlled by third parties (carrier/email providers), which breaks the decentralized/replication threat model.
- Phishing/SIM-swap vulnerability: an attacker who compromises the phone number or email inbox can intercept codes.
- Low-entropy codes: codes are typically short-digit OTPs; offline guessing is feasible once an attacker can observe the recovery attempt state.
- No meaningful online throttling: DHT replication provides no reliable per-identity rate limiting, so brute-force attempts can be attempted at scale.

Evaluation outcome:
- **Reject**.

### Candidate G: Single-use recovery codes (hash-chain / Lamport-style one-time authentication) (conditionally accept)
What it is:
- Owner prepares one-time recovery material offline.
- The identity record stores only non-sensitive commitments / public verification material (no reusable shared secrets).
- During recovery, the owner provides a proof that advances recovery authorization exactly once.

Preferred framing (Lamport-style, stronger than “reveal preimage as code”):
- Store **one-time public keys** (or verifiable commitments that correspond to them) on the primary identity record.
- Recovery update carries a **one-time signature** over the recovery target (e.g., `(alias_record_key, primary_object_key, recovery_seq_or_epoch, new_owner_public_key)`), and the verifier checks that signature against the corresponding one-time public key.
- This prevents an observer from taking the revealed values from one recovery attempt and repurposing them to authorize a different recovery target.

Feasibility in this architecture:
- Fits the “lost key” problem: proof is provided in the recovery update, without requiring the original private key.
- Proof verification is public and depends only on DHT-stored commitments plus the revealed one-time code.

Storage and alias efficiency:
- Primary record stores the commitment(s) once.
- Alias records store only `primary_object_key_hex` and do not duplicate code commitments.

Security properties:
- Offline theft resistance: an attacker who reads the DHT copy learns commitments (hashes) but not preimages; without a preimage they cannot advance recovery.
- Single-use property: each recovery code is usable once; after use, the “next expected” commitment advances, preventing replay.
- If commitment is a hash-chain head, recovering past codes is prevented by hash preimage resistance; only the revealed preimage advances the state.

Open implementation/security points to analyze further:
- Front-running: if recovery requires revealing the next preimage in a public update, an attacker observing the update could replay the same preimage to steal the recovery.
  - Mitigation must be part of the protocol: bind the one-time preimage proof to the specific recovery target (e.g., intended `new_owner_public_key`, `record_key`, and `seq`/recovery nonce) so that replay to a different target is rejected.
- Code exhaustion / backup: owner must safely back up the remaining unrevealed codes or regenerate (regeneration itself requires an auth path).
- Renewal/rotation: after recovery, owner should install new recovery-code commitments.

Evaluation outcome:
- **Conditionally accept** as an additional recovery mechanism candidate, subject to challenge/target binding and anti-front-running construction to mitigate front-running replay.

## Candidate method summary (decision table)
| Method | Store reusable secret in DHT/public record? | Offline brute-force exposure | Phishing resistance | Front-running sensitivity | Verdict |
|---|---:|---:|---:|---:|---|
| Passkeys / FIDO2 (signature over challenge) | No (store public params) | Low | High (if relying party binding enforced) | Medium (if challenge not bound) | **Accept** |
| Hardware security key (same as passkeys) | No | Low | High | Medium | **Accept** |
| App-based public-key signing | No (store public key) | Low | Depends | Medium | **Conditionally accept** |
| Social recovery / threshold guardians | No (store public keys + threshold) | Low (guard keys only) | Depends (guard compromise) | Medium/low | **Accept** |
| Single-use recovery codes (hash-chain / one-time preimages) | No (store commitments only) | Low (commitment-only) | Medium | Medium (requires target-binding + anti-front-running construction) | **Conditionally accept** |
| SMS/email OTP one-time codes | **Yes** (out-of-band delivery) | High (low-entropy codes) | Low | High | **Reject** |
| TOTP/HOTP (shared secret) | **Yes** | **High** | Medium | High | **Reject** |
| Password/PIN/Q&A | **Yes** or equivalent | **High** | Low | High | **Reject** |

## Schema/storage sketch satisfying primary-vs-alias efficiency
This is a v2 extension proposal. It requires validator changes, but it can be designed to keep storage efficient.

### Terminology
- **Primary identity record**: designated record that holds alternative authentication material.
- **Alias identity records**: identity records for aliases that link to the primary identity record.

### Existing limitation
- Validation currently binds `record_key -> owner_public_key` irrevocably under overwrite (seq+owner collision).
- Recovery that changes owner key cannot succeed without adding recovery-aware validator logic.

### Proposed v2 identity payload extension (conceptual)
Keep `record_fields` structure (for now):
- `record_fields[1] = owner_name_bytes`
- `record_fields[2] = owner_public_key_bytes`

Add `SignedUpdate.payload` keys (interpretation added in future code):
- `payload.kind` / `payload.role`:
  - `"primary"` or `"alias"`
- If `role == "primary"`:
  - `payload.recovery`:
    - list of allowed recovery mechanisms (passkey credentials, guardians, etc.)
    - parameters required to verify recovery proofs
- If `role == "alias"`:
  - `payload.primary_link`:
    - reference to the primary identity object key
    - e.g., `primary_object_key_hex`
  - no duplicated recovery material

Important storage efficiency property:
- Aliases store only a pointer/link to the primary record.
- Alternative authentication material is stored once (on the primary record payload).

### Alias record linkage representation
Because identity record keys are derived deterministically:
- Primary object key = `sha256(primary_owner_name_bytes)`

Alias payload should store `primary_object_key_hex` (or a derivation-equivalent reference) so the verifier can locate the primary record when validating an alias recovery/update.

## Recovery protocol sketch (high level)
This sketch assumes we will add new validator logic.

### 1) Enrollment time (while owner private key still available)
Owner uses the current private key to update the primary record payload to add recovery mechanisms.
- For passkeys: register credential identifiers and verification keys.
- For guardians: publish guardian public keys and threshold.
- For any chosen mechanisms: store only public verification material on the primary record.

Owner also publishes alias records that link to the primary:
- Alias record payload includes `primary_object_key_hex`.
- No redundant recovery material stored.

### 2) Recovery time (owner private key lost)
Recovery attempt chooses a new owner public key `new_owner_public_key`.

A recovery update must be constructed so the verifier can accept it without the old owner private key.

Mechanism-specific proof is included in the recovery update:
- Passkey recovery:
  - include a signature/assertion over a challenge bound to:
    - alias/primary record key(s)
    - `seq` / intended update target
    - `new_owner_public_key`
- Guardian recovery:
  - include `t` guardian signatures over the same challenge

### 3) Verification logic required (v2)
Validator must change from today’s overwrite model:
- Today: overwrite requires owner public key equality for an existing record.
- Recovery mode must allow owner key rotation when a valid recovery proof is provided.

At minimum:
- Identify whether update is for a primary or alias identity record.
- If alias:
  - resolve `primary_link` to fetch primary record payload (or require proof against payload embedded in the update).
- Verify recovery proof using primary recovery material.
- Enforce strict binding between:
  - record_key being updated
  - new owner public key being installed
  - current seq state (and increment rule)
  - the recovery nonce (to prevent replay)

### 4) Post-recovery key rotation / revocation
After successful recovery:
- Primary record’s `owner_public_key` is updated to the new key.
- Alias records must also reach a consistent authorization state.
  - Preferred model (storage-efficient): aliases are *validated against the primary record*.
    1) Update alias records during the same recovery session (requires recovery validator support for alias key rotation; more complex and can be storage/UX expensive).
    2) Modify alias validation to defer owner binding to the primary record’s owner key (preferred; satisfies “primary holds alt-auth data” and avoids rotating alias owner state).

Recovery mechanisms should also support rotation:
- Replace passkeys/guardians after recovery.
- Optionally revoke old recovery mechanisms.

## Explicit rejection rationale for weak methods (password/PIN/Q&A)
These methods are rejected due to:
- Public DHT replication:
  - any verification that depends on a reusable low-entropy secret allows offline extraction/brute force.
- No secure online rate limiting:
  - DHT lookups do not provide per-identity throttling.
- Front-running and replay:
  - if proofs require revealing a secret, attackers can replicate or front-run a recovery attempt.

## What needs to be implemented next (follow-up issues)
(Research-only in this ticket; do not implement without a follow-up plan.)

Likely v2 implementation areas:
1) Add identity payload schema interpretation for:
   - `role` (primary vs alias)
   - `primary_link`
   - `recovery` mechanism parameters
2) Add recovery-aware validation paths:
   - allow owner public key rotation when (and only when) recovery proof verifies
   - bind proof to the intended update target + seq + new owner key
3) Define/implement at least one concrete recovery mechanism end-to-end:
   - passkey/WebAuthn-like challenge signature, or
   - guardian threshold signatures.
4) Define alias behavior under recovery:
   - verify via primary recovery material without duplicating storage.

## Recommendation (from this research)
- Primary recovery mechanism: **passkeys / FIDO2 or hardware-backed keys**, because it avoids DHT-embedded reusable secrets and supports signature-only proofs.
- Strong fallback: **social recovery / threshold guardian signatures**, because it also avoids storing secrets in the DHT.
- Single-use recovery codes (Lamport-style / one-time authentication): **conditionally accept**, but require challenge/target binding and anti-front-running construction.
- Password/PIN/Q&A, TOTP/HOTP, and SMS/email OTP-based shared-secret recovery should be **rejected** under #68’s threat model.
- Alias semantics: prefer alias records whose authorization is derived from the primary record (primary_link + validator binding), so alt-auth material stays on the primary and alias owner state need not be redundantly rotated.

Codify the “no reusable DHT-secret” constraint as a first-class security invariant in the v2 validator design.
