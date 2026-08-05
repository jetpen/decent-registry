# Multisignature Records and Migration

This document describes the implemented version-1 multisignature workflow for Identity Records and Provider Records. It covers the canonical wire format, state transitions, local Multisignature Bundle circulation, finalized SignedEnvelope submission, compatibility with legacy single-key records, and security boundaries.

The implementation is code-backed by `src/decent_registry/encoding.py`, `signed_envelope.py`, `verification.py`, `multisig_bundle.py`, `record_validator.py`, `registry_service.py`, and `dht/libp2p_dht.py`. The CLI commands are exercised by `tests/test_cli_multisig.py`.

## 1. Claim classes and scope

The following behavior is **implemented and code-backed**:

- canonical version-1 multisignature SignedUpdate and SignedEnvelope codecs;
- Identity Record and Provider Record drafts;
- detached local signing and proof merging;
- threshold finalization, including explicit legacy upgrade;
- finalized-envelope `put` for both record families;
- multisignature `get` output with authorization metadata;
- legacy single-key compatibility before upgrade and rejection of legacy writes after upgrade;
- signer replacement, ordinary updates, strict `Seq` ordering, predecessor-state binding, and lookup-key binding.

The following remain **documented or researched but unimplemented**, **proposed design**, or **long-term vision** rather than current Registry behavior:

- recovery policies separate from ordinary threshold authorization;
- FROST, DKG, resharing, or threshold-signature aggregation;
- deployment, availability, privacy, governance, or application-service guarantees;
- HTTP gateways, browser integrations, Identity Graphs, and Companion Service protocols.

This document does not change the legacy wire format. It documents the interfaces already present in the repository.

## 2. Wire format

### 2.1 Legacy SignedEnvelope

The legacy envelope remains the two-key canonical CBOR map:

```text
SignedEnvelope = {
  1: signed_update_bytes,
  2: signature,
}
```

Its embedded legacy SignedUpdate is:

```text
SignedUpdate = {
  1: record_fields,
  2: payload,
  3: seq,
}
```

The legacy envelope codec accepts only this outer shape and rejects a nested multisignature SignedUpdate. The legacy validation path then validates the legacy SignedUpdate, record family, signature, lookup key, Owner Binding, and `Seq`.

### 2.2 Version-1 multisignature SignedEnvelope

The versioned envelope is a different canonical CBOR map:

```text
SignedEnvelopeV1 = {
  1: 1,                         # envelope version
  2: signed_update_bytes,
  3: [ { 1: signer_id, 2: signature }, ... ],
}
```

It carries one canonical multisignature SignedUpdate:

```text
SignedUpdate = {
  1: record_fields,
  2: payload,
  3: seq,
  4: authorization,
}
```

The authorization map is:

```text
authorization = {
  1: 1,                         # explicit independent Ed25519 scheme
  2: record_kind,               # 1 = Identity Record, 2 = Provider Record
  3: operation,                 # 1 genesis, 2 ordinary update,
                                # 3 replace signers, 4 upgrade
  4: epoch,
  5: threshold,
  6: [ { 1: signer_id, 2: public_key }, ... ],
  7: predecessor_state_hash,   # exactly 32 bytes
}
```

Signer identifiers are non-empty UTF-8 text. Public keys are 32-byte Ed25519 public keys. Proof signatures are 64-byte Ed25519 signatures. The signer set and proof collection are ordered by the UTF-8 bytes of `signer_id` before canonical encoding.

The codecs reject non-canonical CBOR, wrong map shapes, unsupported envelope versions, unsupported authorization schemes, duplicate signer identifiers, duplicate public keys, malformed keys, malformed signatures, invalid thresholds, and non-canonical proof ordering. The transition validator additionally checks proof membership, signatures, thresholds, `Seq`, epochs, predecessor state, record-key binding, wrong record kinds, and operation-specific rules.

The canonical bytes of the SignedUpdate are the bytes signed by every signer. The state hash is `sha256(canonical_signed_update_bytes)`. A proof is valid only for that exact byte string; reconstructing an equivalent but differently encoded map is not sufficient.

### 2.3 Record-specific fields

Identity Record multisignature updates retain the existing record shape:

```text
record_fields = {
  1: owner_name_bytes,
  2: owner_public_key,
}
payload = {}
```

The Object Key is `sha256(owner_name_bytes)`. The Owner Public Key remains bound across ordinary updates and is preserved during an explicit upgrade.

Provider Record multisignature updates retain the existing provider payload:

```text
record_fields = {
  1: owner_public_key,
}
payload = {
  1: alg,
  2: version,
  3: object_hash,
  4: provider_url,
  5: endpoints,
}
```

The Object Hash is the provider DHT lookup key and is also signed inside the payload. Endpoints are canonicalized into sorted order by the provider schema before signing.

## 3. State transitions

Every accepted multisignature state is bound to one record lookup key.

| Operation | Authorization requirement | State rule |
| --- | --- | --- |
| `genesis` | Complete 2-of-3 Signer Set; `epoch = 1`; zero predecessor | No prior legacy or multisignature state may exist. |
| `ordinary-update` | Threshold proofs from the current Signer Set | `Seq` strictly increases; epoch, threshold, and Signer Set remain unchanged; predecessor binds the current state hash. |
| `replace-signers` | Threshold proofs from the current Signer Set | `Seq` strictly increases; epoch increases; a new complete 2-of-3 Signer Set is installed; the new set cannot authorize its own installation. |
| `upgrade` | Exactly one valid proof from the legacy Owner Public Key | The legacy state must exist; lookup key, record kind, Owner Binding, and predecessor hash must match; `Seq` strictly increases; `epoch = 1`; the new state contains a complete 2-of-3 Signer Set. |

A finalized ordinary or replacement update requires at least `threshold` distinct valid proofs. An upgrade is intentionally different: it requires exactly one proof from the legacy owner, not the new threshold. After a multisignature state is accepted, a legacy single-key write is rejected for that record key.

The transition rules apply equally to Identity Records and Provider Records. The record kind in authorization key `2` must match the SignedUpdate structure and the DHT namespace.

## 4. Local Multisignature Bundle workflow

A Multisignature Bundle is a local signing artifact. It contains one canonical SignedUpdate and zero or more detached proofs. Partial bundles are never valid Registry state and must never be submitted with `put`.

The workflow is:

1. `bundle draft` creates a canonical unsigned bundle.
2. Each signer runs `bundle sign` locally with one private-key path. The command emits a detached one-proof bundle and does not copy private-key material into the artifact.
3. `bundle merge` verifies the proof is bound to the exact SignedUpdate, belongs to the Signer Set, and has a valid Ed25519 signature. It rejects duplicate signers and mismatched bundles.
4. `bundle finalize` emits a finalized version-1 SignedEnvelope only when the required proof rule is met.
5. Only the finalized file is submitted with `put --finalized-envelope`.

`bundle sign` accepts only an unsigned bundle. To add another proof, sign the original unsigned bundle again and merge the detached proof into the accumulated bundle. Do not sign an already-signed bundle.

### 4.1 Identity Record: genesis

Set the values from the key-management system used by the operators. `OWNER_PUBLIC_KEY_HEX` is the Owner Public Key in the Identity Record. Each `SIGNER_ID=PUBLIC_KEY_HEX` entry is a Signer Set member.

```bash
OWNER_NAME_HEX='<OWNER_NAME_HEX>'
OWNER_PUBLIC_KEY_HEX='<OWNER_PUBLIC_KEY_HEX>'
ALICE_PUBLIC_KEY_HEX='<ALICE_PUBLIC_KEY_HEX>'
BOB_PUBLIC_KEY_HEX='<BOB_PUBLIC_KEY_HEX>'
CAROL_PUBLIC_KEY_HEX='<CAROL_PUBLIC_KEY_HEX>'

# Create the unsigned canonical bundle.
decent-registry bundle draft identity \
  --owner-name "$OWNER_NAME_HEX" \
  --owner-public-key "$OWNER_PUBLIC_KEY_HEX" \
  --seq 1 \
  --threshold 2 \
  --epoch 1 \
  --operation genesis \
  --signer "alice=$ALICE_PUBLIC_KEY_HEX" \
  --signer "bob=$BOB_PUBLIC_KEY_HEX" \
  --signer "carol=$CAROL_PUBLIC_KEY_HEX" \
  --output identity-genesis.draft.cbor

# Each signer uses a separate local private-key file.
decent-registry bundle sign \
  --input identity-genesis.draft.cbor \
  --signer-privkey /secure/local/alice.pem \
  --output identity-alice.proof.cbor

decent-registry bundle sign \
  --input identity-genesis.draft.cbor \
  --signer-privkey /secure/local/bob.pem \
  --output identity-bob.proof.cbor

# Merge detached proofs into a new local bundle.
decent-registry bundle merge \
  --input identity-genesis.draft.cbor \
  --proof identity-alice.proof.cbor \
  --proof identity-bob.proof.cbor \
  --output identity-genesis.partial-or-complete.cbor

# With two valid proofs in this 2-of-3 example, finalize the envelope.
decent-registry bundle finalize \
  --input identity-genesis.partial-or-complete.cbor \
  --output identity-genesis.signed-envelope.cbor
```

The private-key paths above are local inputs only. They are not embedded in the bundle, printed by the CLI, or sent to the Registry.

### 4.2 Provider Record: genesis

```bash
OBJECT_HASH='<OBJECT_HASH_64_HEX>'
PROVIDER_URL='https://example.com/artifact.bin'
OWNER_PUBLIC_KEY_HEX='<OWNER_PUBLIC_KEY_HEX>'
ALICE_PUBLIC_KEY_HEX='<ALICE_PUBLIC_KEY_HEX>'
BOB_PUBLIC_KEY_HEX='<BOB_PUBLIC_KEY_HEX>'
CAROL_PUBLIC_KEY_HEX='<CAROL_PUBLIC_KEY_HEX>'

# Endpoint order in the input does not change the canonical payload; the
# provider schema stores endpoints in lexicographic order.
decent-registry bundle draft provider \
  --object-hash "$OBJECT_HASH" \
  --provider-url "$PROVIDER_URL" \
  --endpoint /ip4/127.0.0.1/tcp/10002 \
  --endpoint /ip4/127.0.0.1/tcp/10001 \
  --owner-public-key "$OWNER_PUBLIC_KEY_HEX" \
  --seq 1 \
  --threshold 2 \
  --epoch 1 \
  --operation genesis \
  --signer "alice=$ALICE_PUBLIC_KEY_HEX" \
  --signer "bob=$BOB_PUBLIC_KEY_HEX" \
  --signer "carol=$CAROL_PUBLIC_KEY_HEX" \
  --output provider-genesis.draft.cbor

decent-registry bundle sign \
  --input provider-genesis.draft.cbor \
  --signer-privkey /secure/local/alice.pem \
  --output provider-alice.proof.cbor

decent-registry bundle sign \
  --input provider-genesis.draft.cbor \
  --signer-privkey /secure/local/bob.pem \
  --output provider-bob.proof.cbor

decent-registry bundle merge \
  --input provider-genesis.draft.cbor \
  --proof provider-alice.proof.cbor \
  --proof provider-bob.proof.cbor \
  --output provider-genesis.complete.cbor

decent-registry bundle finalize \
  --input provider-genesis.complete.cbor \
  --output provider-genesis.signed-envelope.cbor
```

### 4.3 Incomplete bundles and rejection behavior

Finalization of a bundle with fewer than the required distinct proofs fails and does not publish output. The following command is expected to exit non-zero for a 2-of-3 bundle containing only one proof:

```bash
decent-registry bundle finalize \
  --input identity-with-one-proof.cbor \
  --output should-not-be-published.cbor
```

The CLI also rejects:

- duplicate proof signers;
- proofs signed by a non-member of the Signer Set;
- proofs for a different SignedUpdate;
- malformed or invalid signatures;
- signing an already-signed bundle;
- finalized `put` combined with legacy signing arguments;
- finalized envelopes whose record kind or lookup key does not match the command.

### 4.4 Explicit legacy upgrade

Migration is explicit. It does not reinterpret a legacy SignedEnvelope as multisignature state.

1. Resolve or otherwise retain the canonical legacy SignedUpdate bytes for the existing record.
2. Build an `upgrade` bundle with the same record identity and Owner Public Key, `Seq` greater than the legacy `Seq`, `epoch 1`, a complete new Signer Set, and `--predecessor-state-hash` equal to `sha256(legacy_signed_update_bytes)`.
3. The legacy owner signs the upgrade bundle. `bundle finalize` requires exactly that one valid legacy-owner proof.
4. Submit the finalized envelope with `put --finalized-envelope` against the existing record key.

Identity upgrade draft shape:

```bash
decent-registry bundle draft identity \
  --owner-name "$OWNER_NAME_HEX" \
  --owner-public-key "$LEGACY_OWNER_PUBLIC_KEY_HEX" \
  --seq "$UPGRADE_SEQ_GREATER_THAN_LEGACY_SEQ" \
  --threshold 2 \
  --epoch 1 \
  --predecessor-state-hash "$LEGACY_SIGNED_UPDATE_SHA256_HEX" \
  --operation upgrade \
  --signer "legacy-owner=$LEGACY_OWNER_PUBLIC_KEY_HEX" \
  --signer "new-signer=$NEW_SIGNER_PUBLIC_KEY_HEX" \
  --signer "third-signer=$THIRD_SIGNER_PUBLIC_KEY_HEX" \
  --output identity-upgrade.draft.cbor

decent-registry bundle sign \
  --input identity-upgrade.draft.cbor \
  --signer-privkey /secure/local/legacy-owner.pem \
  --output identity-upgrade.owner-proof.cbor

decent-registry bundle merge \
  --input identity-upgrade.draft.cbor \
  --proof identity-upgrade.owner-proof.cbor \
  --output identity-upgrade.complete.cbor

decent-registry bundle finalize \
  --input identity-upgrade.complete.cbor \
  --output identity-upgrade.signed-envelope.cbor
```

The same sequence applies to Provider Records, using `bundle draft provider` and preserving the legacy Provider Record's Owner Public Key and Object Hash. The complete Provider Record command sequence is:

```bash
decent-registry bundle draft provider \
  --object-hash "$OBJECT_HASH" \
  --provider-url "$PROVIDER_URL" \
  --endpoint /ip4/127.0.0.1/tcp/10001 \
  --owner-public-key "$LEGACY_OWNER_PUBLIC_KEY_HEX" \
  --seq "$UPGRADE_SEQ_GREATER_THAN_LEGACY_SEQ" \
  --threshold 2 \
  --epoch 1 \
  --predecessor-state-hash "$LEGACY_SIGNED_UPDATE_SHA256_HEX" \
  --operation upgrade \
  --signer "legacy-owner=$LEGACY_OWNER_PUBLIC_KEY_HEX" \
  --signer "new-signer=$NEW_SIGNER_PUBLIC_KEY_HEX" \
  --signer "third-signer=$THIRD_SIGNER_PUBLIC_KEY_HEX" \
  --output provider-upgrade.draft.cbor

decent-registry bundle sign \
  --input provider-upgrade.draft.cbor \
  --signer-privkey /secure/local/legacy-owner.pem \
  --output provider-upgrade.owner-proof.cbor

decent-registry bundle merge \
  --input provider-upgrade.draft.cbor \
  --proof provider-upgrade.owner-proof.cbor \
  --output provider-upgrade.complete.cbor

decent-registry bundle finalize \
  --input provider-upgrade.complete.cbor \
  --output provider-upgrade.signed-envelope.cbor
```

An upgrade with a wrong predecessor hash, changed Owner Binding, wrong record kind, non-owner proof, more than one proof, or a non-increasing `Seq` is rejected.

## 5. Registry submission and resolution

The finalized envelope is the only bundle artifact accepted by `put`.

### 5.1 Finalized Identity Record submission

```bash
decent-registry put identity \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --owner-name "$OWNER_NAME_HEX" \
  --finalized-envelope identity-genesis.signed-envelope.cbor
```

Do not include `--owner-privkey` or `--seq` in finalized mode. The SignedUpdate inside the finalized envelope supplies the sequence and authorization data.

Resolve it with:

```bash
decent-registry get identity \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --owner-name "$OWNER_NAME_HEX"
```

A multisignature Identity Record includes `object_key`, `owner_name`, `owner_public_key`, `seq`, and an `authorization` object containing `version`, numeric `operation`, `epoch`, `threshold`, sorted `signer_set`, `predecessor_state_hash`, and `state_hash`.

### 5.2 Finalized Provider Record submission

```bash
decent-registry put provider \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --object-hash "$OBJECT_HASH" \
  --finalized-envelope provider-genesis.signed-envelope.cbor
```

Do not include `--provider-url`, `--endpoint`, `--owner-privkey`, or `--seq` in finalized mode.

Resolve it with:

```bash
decent-registry get provider \
  --host 127.0.0.1 \
  --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --object-hash "$OBJECT_HASH"
```

A multisignature Provider Record includes `object_key`, `object_hash`, `alg`, payload `version`, `provider_url`, sorted `endpoints`, `seq`, and the same `authorization` object.

The existing network setup and endpoint rules are documented in [protocol concepts](protocol-concepts.md), [Identity Record put/get examples](identity-put-get-examples.md), and [Provider Record put/get examples](provider-put-get-examples.md).

## 6. Compatibility matrix

| Producer or consumer | Legacy SignedEnvelope | Version-1 multisignature SignedEnvelope | Notes |
| --- | --- | --- | --- |
| Legacy decoder | Reads | Rejects | It accepts only the `{1,2}` envelope and legacy SignedUpdate shape. |
| Versioned decoder | Separate legacy path | Reads | It requires envelope version `1`, keys `{1,2,3}`, canonical CBOR, and authorization key `4`. |
| Legacy `put` before upgrade | Accepted if signature, key, Owner Binding, and `Seq` rules pass | Not applicable | Legacy signing arguments produce a legacy envelope. |
| Finalized-envelope `put` | A finalized legacy envelope remains supported by the legacy path | Accepted after transition validation | Finalized mode cannot be mixed with legacy arguments. |
| Legacy `put` after multisignature upgrade | Rejected | Not applicable | A record key cannot silently downgrade after upgrade. |
| `get identity` / `get provider` | Returns legacy fields | Returns fields plus authorization metadata | Resolution validates the accepted envelope before returning JSON. |
| Partial Multisignature Bundle | Not Registry state | Not Registry state | Keep local; finalize before submission. |

This is compatibility at the record and CLI boundary, not a promise that an old client can understand authorization metadata. An old client must continue using the legacy envelope path and cannot create or update a multisignature state.

## 7. Security boundaries

- Private keys remain local or hardware-backed. The CLI accepts file paths and never places private-key bytes in a bundle or Registry value.
- Signers exchange detached proofs, not private keys.
- Every proof is bound to the exact canonical SignedUpdate bytes.
- `merge` verifies signer membership and the Ed25519 signature before adding a proof.
- `finalize` verifies the threshold rule or the explicit single-owner upgrade rule.
- The Registry accepts only finalized envelopes, never partial bundles.
- `Seq`, predecessor state, record kind, lookup key, epoch, Owner Binding, and Signer Set rules are validated at the Registry boundary.
- Valid signatures do not guarantee DHT availability, endpoint reachability, privacy, permanence, or resistance to deployment failure.
- Recovery, key compromise response, and governance are not supplied by the ordinary Signer Set rules.

## 8. Verification and source links

Run the full suite from the repository root:

```bash
.venv/bin/pytest -q
```

The CLI-specific evidence is in [`tests/test_cli_multisig.py`](../tests/test_cli_multisig.py). The protocol source of truth is [protocol concepts](protocol-concepts.md). The implementation entry points are:

- [`encoding.py`](../src/decent_registry/encoding.py) — canonical SignedUpdate and authorization encoding;
- [`signed_envelope.py`](../src/decent_registry/signed_envelope.py) — legacy and versioned SignedEnvelope codecs;
- [`verification.py`](../src/decent_registry/verification.py) — proof and transition validation;
- [`multisig_bundle.py`](../src/decent_registry/multisig_bundle.py) — local Bundle operations;
- [`record_validator.py`](../src/decent_registry/record_validator.py) — record-family and overwrite integration;
- [`registry_service.py`](../src/decent_registry/registry_service.py) and [`libp2p_dht.py`](../src/decent_registry/dht/libp2p_dht.py) — finalized put/get integration.

The root [README](../README.md) and [developer guide](developer-guide.md) provide entry points for installation, node setup, and the non-multisignature CLI basics.

## 9. Current versus future

Current multisignature behavior is a versioned explicit-Ed25519 Signer Set with threshold proofs and a local circulation workflow. It is not FROST, not a recovery service, not a deployment topology, and not a privacy layer. Future work may define those surfaces, but they must not be inferred from the implemented version-1 format.
