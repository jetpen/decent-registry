# Research: seed-phrase key generation and secure backup

## Status and scope

**Claim class:** Documented or researched but unimplemented.

This document evaluates a Bitcoin-like user experience for generating a human-readable recovery phrase, deriving the project's Ed25519 identity key from it, and allowing the user to back up the recovery material without disclosing it to the Registry or other parties.

The recommendation is **not** to make the Registry Bitcoin-compatible. BIP-39 supplies a mnemonic-to-seed encoding that can be reused as an interoperability layer; the key derivation and identity path must be explicitly defined for this project.

## Executive recommendation

Build a versioned local wallet/key-management layer with these boundaries:

1. Generate 256 bits of unpredictable operating-system CSPRNG entropy locally; statistical randomness alone is insufficient for cryptographic secrets.[14]
2. Encode that entropy using the BIP-39 checksum and 2048-word wordlist, producing a 24-word mnemonic.[1]
3. Convert the mnemonic and an optional passphrase to the 64-byte BIP-39 seed using UTF-8 NFKD normalization and PBKDF2-HMAC-SHA512 with 2,048 iterations.[1]
4. Feed the complete 64-byte BIP-39 seed—not the raw entropy or mnemonic text—into SLIP-0010 and derive an Ed25519 extended master key and hardened child key using the `ed25519 seed` domain.[1][5]
5. Pass SLIP-0010's 32-byte child `IL` value directly to the Ed25519 library as its 32-byte private-key input. Do not manually hash, clamp, reinterpret, or expand it; the Ed25519 implementation performs its own SHA-512 expansion and pruning.[9][15]
6. Export the current PKCS#8 PEM representation only when explicitly requested.
7. Keep the mnemonic, optional passphrase, BIP-39 seed, chain code, and private key local. They must never be placed in a SignedUpdate, SignedEnvelope, DHT record, diagnostic log, telemetry event, clipboard by default, or ordinary configuration file.
8. Make backup verification mandatory before considering wallet creation complete. The application must prove that the user can restore the same public key without transmitting the mnemonic.
9. Treat the mnemonic plus the exact passphrase, when enabled, as the recoverable credential. Anyone who obtains the mnemonic alone can derive the no-passphrase identity; anyone who obtains both can derive the configured identity. A passphrase is an additional secret, not a substitute for safely backing up the mnemonic.

The default first implementation should use one mnemonic for one identity root and one fixed, project-defined hardened derivation path. Multisignature and alternative recovery mechanisms remain separate layers; the seed phrase must not silently become a shared recovery secret for a Signer Set. [unverified]

## What Bitcoin actually standardizes

### BIP-39 mnemonic generation

BIP-39 is a human-readable encoding of computer-generated entropy, not a brainwallet scheme. It permits initial entropy (`ENT`) from 128 through 256 bits in 32-bit increments. The checksum is the first `ENT / 32` bits of SHA-256(entropy), and the entropy-plus-checksum bitstream is split into 11-bit word indices.[1]

The resulting lengths are:

| Entropy | Checksum | Words |
|---:|---:|---:|
| 128 bits | 4 bits | 12 |
| 160 bits | 5 bits | 15 |
| 192 bits | 6 bits | 18 |
| 224 bits | 7 bits | 21 |
| 256 bits | 8 bits | 24 |

For this project, 256-bit entropy and a 24-word English mnemonic are the conservative default. The BIP-39 specification strongly discourages non-English wordlists because broad wallet support is concentrated on English.[1] The wallet format should record the exact wordlist identifier and published digest, not merely a language label, because wordlist ordering and normalization affect derivation.[1]

### BIP-39 seed conversion

BIP-39 converts the mnemonic to a 512-bit seed with:

```text
PBKDF2-HMAC-SHA512(
    password = UTF-8-NFKD(mnemonic),
    salt     = UTF-8-NFKD("mnemonic" + passphrase),
    iterations = 2048,
    output_length = 64 bytes,
)
```

The passphrase is technically optional; the empty string is used when absent. Every passphrase produces a valid seed, so a wrong passphrase normally looks like a valid but different wallet. The user experience must therefore avoid presenting the passphrase as an ordinary password-reset mechanism.[1] The fixed BIP-39 PBKDF2 cost is a compatibility parameter, not modern password-hardening guidance; a weak user-selected passphrase remains vulnerable to offline guessing.[1][16]

BIP-39 also has limitations relevant to this project: the seed depends on the exact wordlist, the checksum only detects a limited class of transcription errors, and the scheme has no built-in versioning for downstream key-tree semantics.[1] The Registry must store its own wallet format/version, exact wordlist identifier, passphrase policy, and derivation metadata rather than assuming that a mnemonic alone identifies the derivation algorithm.

### Hierarchical derivation

BIP-32 defines a tree of extended private/public keys. Each extended key consists of key material and a 32-byte chain code. Its purpose is deterministic derivation of many related keys and selective sharing of public subtrees.[2]

BIP-43 recommends reserving the first hardened path component as a purpose field so different tree conventions do not overlap.[3] BIP-44 applies that idea to Bitcoin with the path:

```text
m / purpose' / coin_type' / account' / change / address_index
```

BIP-44's `44'`, Bitcoin coin type `0'`, account, change, and address semantics are Bitcoin wallet conventions, not appropriate identity semantics for this project.[4]

## Correct curve choice for this project

The Registry currently authenticates records with Ed25519 and writes unencrypted PKCS#8 Ed25519 private keys with mode `0o600` through `decent-registry keygen`; see [`src/decent_registry/cli.py`](../../src/decent_registry/cli.py) and [`src/decent_registry/crypto_utils.py`](../../src/decent_registry/crypto_utils.py).

BIP-32's core derivation is specified for secp256k1.[2] It should not be applied to the Registry's Ed25519 keys merely because both systems use a seed phrase.

SLIP-0010 generalizes master-key derivation to Ed25519. For Ed25519 it uses:

```text
I = HMAC-SHA512(key = "ed25519 seed", data = S)
master_private = I[0:32]
master_chain_code = I[32:64]
```

For Ed25519, SLIP-0010 supports private-to-private **hardened** child derivation only; public-child derivation and non-hardened child derivation are not supported.[5] This is a critical design constraint:

- All Registry identity derivation path components must be hardened.
- An xpub-like public derivation workflow must not be promised for Ed25519.
- The application must derive the private child locally, then publish only the resulting Ed25519 public key in the Identity Record.
- A public watch-only identity tree is not available from this derivation scheme.

RFC 8032 defines the Ed25519 private key input as 32 octets of cryptographically secure random data and derives the public key from it using SHA-512 and the Ed25519 pruning procedure.[9] The 32-byte SLIP-0010 child private value is therefore the appropriate input to the existing Ed25519 library boundary, subject to test vectors and library behavior being verified in code.

## Proposed Registry wallet format

The project needs an explicit, versioned wallet format. A conceptual local record is:

```text
WalletFileV1 {
  format: "decent-registry-wallet-v1",
  mnemonic_wordlist: "bip39-english-v1",
  mnemonic_wordlist_sha256: <published wordlist digest>,
  mnemonic_words: 24,
  passphrase_policy: "disabled" | "enabled-but-never-stored",
  derivation_curve: "ed25519",
  derivation_scheme: "slip-0010",
  derivation_path: <project-defined all-hardened path>,
  owner_public_key: <32-byte Ed25519 public key>,
  private_key_export: <optional local PKCS#8 PEM>
}
```

This metadata is not a substitute for the mnemonic. It makes restoration auditable and prevents an implementation from silently changing the curve, path, wordlist, or format in a later release.

The derivation path must be assigned by a project protocol decision. BIP-43 proposes a purpose-field convention; it does not allocate a Registry path. The project must assign and publish a unique, versioned purpose/path and complete end-to-end test vectors.[3] It should have:

- a project-specific hardened purpose component;
- a profile/identity component;
- a key-role component, such as `owner`;
- an optional hardened index for additional identities;
- a format/version binding so future schemes cannot be confused with one another.

Do not use the Bitcoin BIP-44 path or label a Registry key as a Bitcoin extended key. BIP-44's `change` and `address_index` levels are non-hardened, while SLIP-0010 Ed25519 supports hardened private derivation only.[4][5] The exact path is a protocol boundary and needs published test vectors before compatibility is promised.

## Required user experience

### New identity flow

1. The user runs an explicit command such as `decent-registry wallet create`.
2. The CLI obtains entropy from the operating system CSPRNG. It must not accept user-entered words or a user-selected “random” seed as the generation source.
3. The mnemonic is displayed in a dedicated, privacy-preserving terminal flow. The application warns that the words control the identity and must not be shared or entered into a website.
4. The user chooses whether to add a BIP-39 passphrase. The default should be no passphrase for the first version unless the UX can reliably explain that forgetting it causes permanent access loss and that every passphrase restores a different identity.[1]
5. The user confirms the words by re-entering selected positions or the complete phrase. The implementation validates word membership, checksum, normalization, and exact word count before proceeding.
6. The application derives the owner public key locally and displays only public information: public-key fingerprint, derivation scheme, path, and output location.
7. The user performs an offline restore test in a separate process or memory context. The restored public key must equal the original public key.
8. Only after the restore test succeeds may the application write an optional local private-key export or wallet metadata file.

### Backup flow

The primary backup should be a human-readable physical backup created by the user, not an automatically uploaded file. BIP-39 explicitly frames the mnemonic as a human-readable transport of computer-generated randomness that can be written down.[1] Trezor's wallet-backup guidance likewise recommends keeping backups offline, private, and protected from damage or loss.[10][11]

The interface should:

- display the phrase only after an explicit user action;
- state clearly that legitimate support personnel must never request the backup phrase; Trezor explicitly identifies such requests as phishing.[12]
- provide no “send to cloud,” email, or remote backup action;
- disable telemetry and redact command history for the seed flow;
- avoid copying the phrase to the clipboard by default;
- avoid writing the phrase to shell history, temporary files, crash reports, or logs;
- warn against screenshots, photos, chat messages, browser forms, and unencrypted digital notes;
- recommend at least two geographically separate physical backups for high-value identities;
- instruct the user to protect backups from unauthorized access, fire, water, and casual discovery;
- offer a restore/check-backup command that verifies the backup without publishing or transmitting it.

These are product requirements derived from the threat model, not properties automatically provided by BIP-39. Secrets-management guidance emphasizes least privilege, automation, minimizing human interaction with secrets, and reducing secret lifetime in memory.[8] NIST key-management guidance treats key protection, secure generation, storage, distribution, use, and destruction as lifecycle responsibilities.[13]

### Recovery flow

`decent-registry wallet restore` should accept the mnemonic through an interactive no-echo prompt or a protected local input mechanism. It must not accept a seed phrase as a normal command-line argument because process listings, shell history, audit logs, and wrapper scripts can capture arguments.

The restore flow must:

1. validate the phrase and checksum locally;
2. request the optional passphrase without echoing it;
3. derive the same versioned path;
4. show the resulting public-key fingerprint before replacing or creating local key material;
5. require explicit confirmation if the derived identity differs from an existing local identity;
6. write files atomically with restrictive permissions; and
7. erase temporary byte buffers as far as the language and runtime permit.

Python cannot guarantee complete zeroization of all immutable strings and copies. The design should therefore minimize secret lifetime and avoid claiming that ordinary Python memory handling provides hardware-wallet-grade protection.[8]

## Backup options and their trade-offs

### Single 24-word mnemonic

**Recommendation for the initial implementation.** It is simple, portable across BIP-39 implementations, and easy to explain. Its weakness is concentration of trust: one copied or photographed phrase is sufficient to take the identity.

### Mnemonic plus passphrase

**Optional, advanced feature.** The passphrase creates a different BIP-39 seed and can provide plausible deniability, but a forgotten passphrase is equivalent to loss of the intended identity. It also increases support and recovery failure modes.[1]

The application must never store or publish the passphrase. If supported, it needs a separate backup instruction and a restore test that includes the passphrase.

### Shamir-style shares

SLIP-39 defines threshold secret sharing in which a specified minimum number of shares reconstructs the secret and fewer than the threshold do not reveal it. It also defines a two-level group/member scheme and checksummed share mnemonics.[6] Trezor describes multi-share backups as a separate format in which a chosen threshold of shares is required for recovery.[10]

SLIP-39 is a distinct backup format and is not generally interchangeable with BIP-39. Its use would require either:

- adopting SLIP-39 as the project's native backup format; or
- defining a conversion layer that reconstructs the BIP-39 seed locally and never publishes the shares.

**Recommendation:** do not implement SLIP-39 in the first wallet milestone. Design the wallet abstraction so threshold backup can be added later without changing the Registry's wire records. A future implementation must be independently tested for share mixing, threshold boundaries, wrong-group rejection, and recovery of the exact public key.

### Hardware-backed signing

A hardware security key or hardware wallet can keep the private signing key out of the application process, but it changes the product from seed backup to device-backed key management. The Registry should support this as a separate signer/provider interface rather than making a seed phrase the only security model. Public-key authentication and non-exportable keys are distinct security properties; NIST treats non-exportability as a separate authenticator characteristic at the highest assurance level. NIST's AAL3 model requires a phishing-resistant authenticator with a non-exportable private key and an activation factor; a recoverable seed phrase is exportable and must not be presented as satisfying AAL3.[7]

## Threat model and invariants

Assume an attacker can:

- read every public DHT record;
- inspect Registry requests and responses;
- read process arguments, logs, crash dumps, or local files if the host is compromised;
- trick a user into entering a mnemonic into a phishing interface;
- obtain one physical backup if backups are not separated and protected.

The following invariants are mandatory:

1. **No mnemonic on the wire.** The mnemonic and derived secret material never appear in CBOR records, DHT keys, signed envelopes, URLs, provider payloads, or recovery proofs.
2. **No seed-derived private key in an Identity Record.** Existing identity records publish only the owner public key; this boundary must remain.
3. **Deterministic restoration.** A supported backup must reproduce the same public key for the same wallet format, wordlist, passphrase, and derivation path.
4. **Explicit domain separation.** The project must use the Ed25519 SLIP-0010 domain and a versioned project path; it must not reuse a Bitcoin secp256k1 derivation domain.[2][5]
5. **No unauthenticated key replacement.** Possession of a phrase creates a new signing capability but does not by itself define an on-record recovery protocol. Existing Owner Binding and sequence rules still apply; recovery and rotation need explicit signed protocol changes.
6. **No secret logging.** Errors, debug logs, metrics, test artifacts, and CLI output must use fixed redacted messages.
7. **No silent overwrite.** Existing PEM files and wallet metadata must not be replaced without explicit confirmation and atomic-write protection.
8. **Test vectors are compatibility requirements.** The project must publish mnemonic, seed, derived path, private-key, and public-key vectors using non-secret test fixtures before releasing the format.

## What must be built

### 1. Cryptographic and format module

Add a dedicated module, separate from DHT and record validation, that provides:

- BIP-39 English wordlist loading and exact checksum validation;
- entropy-to-mnemonic conversion;
- mnemonic-to-seed PBKDF2-HMAC-SHA512 conversion with NFKD normalization;
- SLIP-0010 Ed25519 master and hardened child derivation;
- strict derivation-path parsing that rejects non-hardened components;
- Ed25519 public-key derivation and signing-key construction;
- versioned wallet metadata encoding;
- deterministic test vectors from BIP-39 and SLIP-0010 plus project-specific vectors.

Use a maintained, audited implementation for BIP-39/SLIP-0010 rather than writing cryptographic primitives from scratch. The project should still own input validation, path policy, format versioning, and integration tests.

### 2. Secure local key boundary

Refactor the current `keygen` behavior into explicit modes:

- `wallet create`: generate mnemonic, derive identity key, verify backup, and optionally write a local key file;
- `wallet restore`: recover locally from mnemonic and optional passphrase;
- `wallet check-backup`: validate a backup and compare its derived public-key fingerprint;
- `wallet export-pem`: explicitly export the current Ed25519 key in the existing format;
- `keygen`: retain legacy random-key generation for compatibility, but clearly distinguish it from recoverable wallet creation.

The current implementation writes an unencrypted PKCS#8 PEM. A seed-derived PEM is still a secret and must have the same restrictive file permissions, redacted errors, atomic creation, and no-overwrite behavior. The wallet feature should not imply that an unencrypted PEM is safe merely because it is derived deterministically.

### 3. Secret-safe CLI and application UX

Build a dedicated terminal UI or carefully designed prompt layer with:

- no-echo input;
- no secret command-line arguments;
- controlled screen clearing where practical;
- explicit warnings and acknowledgement;
- backup verification;
- redacted logging;
- no clipboard integration by default;
- secure temporary-file handling;
- cancellation paths that do not persist partial phrases;
- clear distinction between public output and secret output.

A graphical client would additionally need secure display and input handling, screenshot/clipboard policy, accessibility review, and platform-specific secure storage. These are not solved by the cryptographic derivation module.

### 4. Registry integration

The Registry integration should remain narrow:

- derive the Owner Public Key locally;
- use it in the existing Identity Record fields;
- sign the existing canonical SignedUpdate/SignedEnvelope format;
- publish no seed phrase, passphrase, derivation private key, chain code, or wallet backup metadata.

Identity updates require strictly increasing `Seq` and preserve the current Owner Public Key except for validated Registry operation-5 Owner-Key Rotation; see [`src/decent_registry/verification.py`](../../src/decent_registry/verification.py), [`CONTEXT.md`](../../CONTEXT.md), and [Multisignature Records and Migration](../multisignature-records.md). Seed restoration does not alter those rules. Operation 5 requires the existing legacy-owner proof or version-1 Signer Set threshold; separate lost-key recovery remains unimplemented and requires its own Recovery Policy. The existing research on recovery and multisignature replacement covers those protocol implications:

- [`identity-recovery-research.md`](identity-recovery-research.md)
- [`2-of-3-multisig-key-recovery.md`](2-of-3-multisig-key-recovery.md)

### 5. Testing and release controls

Before release, add tests for:

- all BIP-39 entropy sizes and checksum rejection;
- NFKD mnemonic and passphrase normalization;
- empty and non-empty passphrases;
- BIP-39 official test vectors;
- SLIP-0010 Ed25519 official test vectors;
- every supported project derivation path;
- rejection of non-hardened paths;
- exact public-key reproduction after restore;
- wrong-word, wrong-order, wrong-passphrase, and wrong-path failures;
- no mnemonic/private-key material in logs, exceptions, CBOR, or DHT payloads;
- secure file mode and no-overwrite behavior;
- interrupted creation and partial-file cleanup;
- legacy random PEM compatibility;
- process-level CLI tests proving secrets are not accepted in argv;
- backup-check flow with a separate subprocess or isolated invocation.

Release documentation must include the exact wallet format, derivation path, wordlist, normalization rules, passphrase semantics, backup instructions, and recovery limitations. A future implementation must not claim interoperability with Bitcoin wallets unless it implements and tests the relevant Bitcoin curve, path, serialization, and wallet semantics.

## Phased delivery

### Phase 0: format decision

- Select and document the project-specific derivation path and wallet format version.
- Decide whether the first release supports passphrases.
- Decide whether wallet creation writes PEM, a wallet metadata file, or both.
- Obtain review of the threat model and user-facing backup language.

### Phase 1: deterministic core

- Implement or integrate BIP-39 and SLIP-0010 Ed25519.
- Add official and project-specific test vectors.
- Add strict path and format validation.
- Do not change the DHT protocol.

### Phase 2: local UX

- Add `wallet create`, `wallet restore`, and `wallet check-backup`.
- Add no-echo input, redaction, atomic writes, and restore verification.
- Exercise the flow on clean machines and interrupted processes.

### Phase 3: Registry wiring

- Allow wallet-derived keys to sign existing Identity and Provider updates.
- Preserve legacy random PEM operation.
- Add end-to-end tests proving only public keys and signed records reach the DHT.

### Phase 4: advanced backup and recovery

- Evaluate SLIP-39 or another threshold backup format.
- Add hardware-backed signer support as a separate interface.
- Specify and implement Recovery Policy or Signer Set key replacement independently of mnemonic restoration.

## Decisions that must not be conflated

- **Mnemonic generation** creates backup material.
- **Deterministic derivation** maps backup material to a private/public key.
- **PEM export** is a local serialization of a private key.
- **Identity Record publication** publishes only the public key and signed record data.
- **Key recovery/rotation** changes authorization state and requires a protocol transition.
- **Multisignature** distributes signing authority; it is not equivalent to splitting a mnemonic.
- **Threshold backup** splits backup custody; it is not automatically a DHT recovery protocol.

A safe implementation must preserve these boundaries.

## Sources

[1] https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki — BIP-39: Mnemonic code for generating deterministic keys
[2] https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki — BIP-32: Hierarchical Deterministic Wallets
[3] https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki — BIP-43: Purpose Field for Deterministic Wallets
[4] https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki — BIP-44: Multi-Account Hierarchy for Deterministic Wallets
[5] https://github.com/satoshilabs/slips/blob/master/slip-0010.md — SLIP-0010: Universal private key derivation from master private key
[6] https://github.com/satoshilabs/slips/blob/master/slip-0039.md — SLIP-39: Shamir Backup for BIP-39
[7] https://pages.nist.gov/800-63-4/sp800-63b.html — NIST SP 800-63B Digital Identity Guidelines
[8] https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — OWASP Secrets Management Cheat Sheet
[9] https://datatracker.ietf.org/doc/html/rfc8032 — RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
[10] https://trezor.io/learn/security-privacy/personal-security-standards/understanding-trezor-wallet-backups-12-20-or-24-words — Trezor wallet backups: 12, 20 or 24 words
[11] https://trezor.io/learn/security-privacy/personal-security-standards/wallet-backup-cards-download-and-print-for-your-trezor — Trezor wallet backup cards
[12] https://trezor.io/learn/security-privacy/personal-security-standards/scams-and-phishing — Trezor scams and phishing
[13] https://doi.org/10.6028/NIST.SP.800-57pt1r5 — NIST SP 800-57 Part 1 Revision 5
[14] https://datatracker.ietf.org/doc/html/rfc4086 — RFC 4086: Randomness Requirements for Security
[15] https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/ — Cryptography Ed25519 API
[16] https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — OWASP Password Storage Cheat Sheet
