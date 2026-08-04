# PROTOTYPE — Multisignature Bundle CLI workflow

Issue: [Design the CLI surface and Multisignature Bundle workflow (#91)](https://github.com/jetpen/decent-registry/issues/91)

This is a design artifact on a throwaway prototype branch. It does not change
`src/`, contact the DHT, or define the final integer-key CBOR assignments.
Run the executable simulation with:

```bash
.venv/bin/python scripts/multisig_cli_prototype.py
```

The prototype uses the repository's canonical CBOR and Ed25519 signing helpers
to demonstrate the agreed invariants without becoming production code.

## Proposed command surface

The CLI adds a `multisig` command group. Every command accepts the existing
network/config flags where it contacts the Registry. A command that signs
accepts exactly one local private-key path.

### 1. Draft an unsigned Multisignature Bundle

```bash
decent-registry multisig draft identity \
  --owner-name <OWNER_NAME_HEX> \
  --operation ordinary-update \
  --seq <HIGHER_SEQ> \
  --epoch <CURRENT_EPOCH> \
  --predecessor-envelope <CURRENT_ENVELOPE.cbor> \
  --signer signer-1=<PUBLIC_KEY_HEX> \
  --signer signer-2=<PUBLIC_KEY_HEX> \
  --signer signer-3=<PUBLIC_KEY_HEX> \
  --threshold 2 \
  --output update.bundle.cbor
```

`provider` uses `--object-hash`, `--provider-url`, and repeatable
`--endpoint` in place of `--owner-name`. The draft contains the complete
canonical `SignedUpdate` and an empty proof collection. It includes the
`record_kind`, operation, `Seq`, signer-set epoch, threshold, complete
signer set, and exact predecessor-state binding inside the signed bytes.
The signer set is ordered canonically before encoding.

Draft operations are explicit:

- `ordinary-update`: same signer set and epoch; strictly higher `Seq`.
- `replace-signers`: current quorum authorizes one complete next signer set;
  epoch increases; partial add/remove operations are not valid.
- `upgrade`: explicit legacy single-key owner transition to a complete 2-of-3
  signer set at epoch 1. This is the compatibility exception and is signed by
  the current legacy owner, not by the future set.

The `upgrade` operation must require the current legacy owner key locally and
must not infer or silently perform an upgrade from an ordinary `put`.

### 2. Circulate the exact draft

Copy `update.bundle.cbor` to each signer through the operator's secure channel.
The bundle is the authority for what is signed. Human-readable inspection is
optional and must never replace the canonical bytes.

### 3. Sign locally

```bash
decent-registry multisig sign \
  --bundle update.bundle.cbor \
  --owner-privkey ~/.decent/signer-1.pem \
  --output signer-1.proof.cbor
```

The command loads one private key, verifies that its public key is a member of
the draft's signer set, signs the exact canonical `SignedUpdate` bytes, and
writes a detached proof. It never prints or uploads private material. The
proof includes the signed-update digest, signer identifier, and signature so
merging a proof from another draft fails.

### 4. Merge signature proofs

```bash
decent-registry multisig merge \
  --bundle update.bundle.cbor \
  --proof signer-1.proof.cbor \
  --proof signer-2.proof.cbor \
  --output update.signed.bundle.cbor
```

Merge verifies each proof immediately. It rejects a non-member, duplicate,
malformed, invalid, or wrong-draft proof. Proofs are sorted by signer
identifier in the resulting bundle. A bundle with fewer than two valid
current-set proofs remains circulatable but is not publishable.

### 5. Finalize and reject incomplete bundles

```bash
decent-registry multisig finalize \
  --bundle update.signed.bundle.cbor \
  --output update.envelope.cbor
```

`finalize` performs the complete local validation pass and emits the distinct,
versioned multisignature `SignedEnvelope` only when the threshold is met.
With one valid proof it exits non-zero with a threshold error. It does not
write a pending record to the Registry.

### 6. Submit only the finalized envelope

```bash
decent-registry put identity \
  --envelope update.envelope.cbor \
  --host 127.0.0.1 --port <CLIENT_PORT> \
  --bootstrap <SEED_MULTIADDR>
```

The provider form uses `put provider` and its `--object-hash` lookup key. The
`put` path accepts only a finalized, threshold-valid envelope, then applies
record-family binding, predecessor state, epoch, strict `Seq`, and durable
accepted-state validation before DHT publication. It does not accept a
private-key path for a finalized multisignature submission.

### 7. Resolve records

Existing `get identity` and `get provider` commands should decode both legacy
and versioned envelopes. Their typed results expose common authorization
metadata (`envelope_version`, `record_kind`, `epoch`, `threshold`, signer set,
proof signer identifiers, and `seq`) alongside the existing record-family
fields. A legacy client encountering a versioned envelope rejects it as an
unsupported protocol version; it must not treat one proof as the legacy
signature or issue a legacy overwrite.

## Bundle state machine

```text
DRAFT
  └─ sign locally (one signer, one private key)
      └─ PROOF_COLLECTION
          ├─ fewer than threshold proofs → circulate; finalize/put reject
          └─ threshold valid proofs
              └─ FINALIZED
                  └─ validate predecessor/epoch/seq/record binding
                      └─ put to DHT
```

The current quorum signs a complete replacement transition. The next signer
set cannot authorize its own installation. Equal-`Seq` conflicts, stale
predecessor hashes, stale epochs, duplicate proofs, and proofs from retired
signers are rejected. The accepted state is persisted atomically rather than
selected by DHT arrival order.

## Security boundaries

- Private keys remain with their holders in local, secure, or hardware-backed
  storage.
- Each signing invocation accepts one private-key path only.
- Drafts, proofs, and finalized envelopes contain public keys and signatures,
  never private keys.
- The exact canonical signed bytes are circulated; no signer signs a rendered
  JSON view.
- Legacy records stay on the legacy path until an explicit same-key upgrade.
  After upgrade, legacy-format writes are rejected and there is no downgrade
  or one-signature bypass.
- This prototype does not claim to settle the final integer-key CBOR schema;
  that belongs in the implementation specification after human review.

## Review decision

Recommended baseline: accept the command lifecycle above, use canonical CBOR
for bundle/proof/envelope files, keep `get` backward-compatible by envelope
version, and treat legacy upgrade as an explicit one-key transition. The
prototype's output is the concrete artifact for reviewing whether this flow
is operationally clear before issue #91 is resolved.
