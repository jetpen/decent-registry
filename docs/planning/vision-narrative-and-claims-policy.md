# Vision narrative and claims policy

**Status:** planning decision
**Issue:** #73
**Map:** [Documentation ecosystem vision and application guide for decentralized services](https://github.com/jetpen/decent-registry/issues/71)

## Framing

Sovereignty, privacy, anti-centralization, and anti-censorship are ecosystem goals. They guide the project’s direction and documentation, but they are not guaranteed properties of the current prototype.

The vision narrative must avoid presenting the current software as unstoppable, ungovernable, censorship-proof, or inherently immune to administration, compromise, outage, or misuse.

## Claim classes

Every substantive claim in the vision documentation must belong to one of four explicitly labeled classes:

1. **Implemented and code-backed** — behavior verified against repository code and tests.
2. **Documented or researched but unimplemented** — supported by repository documentation or research, but not exposed as a shipped interface.
3. **Proposed design** — a possible future design or integration boundary, not an implementation guarantee.
4. **Long-term vision** — ecosystem goals and aspirations, explicitly not current capabilities.

A document may use section headings to classify groups of claims, or attach a class label to individual claims. It must not mix current behavior and aspirations in an unlabeled paragraph.

## Implemented today

The “implemented today” section should enumerate only code-backed surfaces, using repository-path citations and avoiding production-maturity claims:

- CLI commands for `keygen`, `node`, `put`, and `get`, implemented in [`src/decent_registry/cli.py`](../../src/decent_registry/cli.py).
- Signed record structures using `SignedUpdate` and `SignedEnvelope`, with canonical CBOR encoding, implemented across [`signed_envelope.py`](../../src/decent_registry/signed_envelope.py), [`encoding.py`](../../src/decent_registry/encoding.py), and [`envelope_builder.py`](../../src/decent_registry/envelope_builder.py).
- Ed25519 signature verification in [`verification.py`](../../src/decent_registry/verification.py) and key utilities in [`crypto_utils.py`](../../src/decent_registry/crypto_utils.py).
- Strict monotonic `Seq` and `Owner Binding` enforcement in [`record_validator.py`](../../src/decent_registry/record_validator.py) and [`verification.py`](../../src/decent_registry/verification.py).
- Provider and Identity Record schemas in [`provider_schema.py`](../../src/decent_registry/provider_schema.py) and the registry service orchestration in [`registry_service.py`](../../src/decent_registry/registry_service.py).
- LMDB durable storage through [`durable_store.py`](../../src/decent_registry/durable_store.py) and the storage abstraction in [`storage_backend.py`](../../src/decent_registry/storage_backend.py).
- libp2p Kad-DHT node, provider and identity namespaces, and DHT `put`/`get` operations in [`dht/libp2p_dht.py`](../../src/decent_registry/dht/libp2p_dht.py).
- YAML and CLI configuration loading through [`config.py`](../../src/decent_registry/config.py) and the CLI.

These statements describe repository behavior. They do not claim production readiness, global availability, permanence, or resistance to every attack or failure mode.

## Researched but unimplemented

The following are research inputs or design analyses, not shipped interfaces:

- `kad:` URL grammar and route concepts in [`docs/research/registry-url-format.md`](../research/registry-url-format.md).
- Chromium extension DHT URL resolution and rendering in [`docs/research/browser-extension-dht-url-rendering.md`](../research/browser-extension-dht-url-rendering.md).
- Lost-key recovery mechanisms, including passkeys, guardian recovery, one-time recovery material, and related validator changes in [`docs/research/identity-recovery-research.md`](../research/identity-recovery-research.md).
- Explicit 2-of-3 signer-set authorization and key replacement in [`docs/research/2-of-3-multisig-key-recovery.md`](../research/2-of-3-multisig-key-recovery.md).
- Any HTTP gateway, native-messaging bridge, identity alias lookup, or reverse lookup by Owner Public Key identified by research or inventory documents.

These must not be described as existing URL handlers, browser APIs, HTTP endpoints, SDKs, recovery protocols, or multisignature support.

## Proposed designs

Companion registry, identity, storage, and social services are proposed ecosystem concepts. Their documentation may define user-facing roles, boundaries, relationships, and value, but this map does not define production wire protocols or imply implementation.

Future integration designs must identify their dependencies on the implemented registry surface and preserve the distinction between a design proposal and a working interface.

## Long-term vision

The long-term narrative may describe goals such as:

- giving people more control over the services and records they rely on;
- enabling independently operated infrastructure rather than requiring one coordinating organization;
- allowing clients to verify signed information without trusting a single operator;
- reducing unnecessary centralization and improving resilience to censorship or service withdrawal;
- supporting future companion services that extend the ecosystem without requiring a blockchain-centered architecture.

These are objectives. The documentation must not convert them into guarantees about all deployments or future services.

## Rejection of blockchain-centered Web 3.0 framing

The project rejects blockchain-centered Web 3.0 framing as a deliberate design position. This is a project choice, not a universal condemnation of all blockchain architectures.

The narrative should state that decent-registry uses peer-to-peer libp2p Kad-DHT and signed, verifiable records without a blockchain, native token, or consensus layer. The stated reasons are project priorities: self-hosting, end-to-end verifiability, and lower participation barriers for node operators.

The documentation should avoid universal claims or slogans about the inherent merits or defects of blockchain or Web 3.0. It should instead explain the concrete architectural choice and its consequences.

## Operational definition of “decentralized”

Within this project’s documentation, “decentralized” means:

- no single organization is required to coordinate or control the registry;
- independent parties can operate nodes;
- clients can verify records end-to-end without trusting a single operator.

This definition does not imply that every deployment is censorship-resistant, private, highly available, anonymous, or free of governance. Those properties depend on the deployment, threat model, operational practices, and future implementation work.

## Documentation rules

- Cite code-backed claims with repository paths.
- Link research-only claims to their research files and label them unimplemented.
- Label companion-service material as proposed unless implementation evidence exists.
- Keep long-term goals in a clearly marked vision section.
- State relevant limitations alongside claims rather than hiding them in a distant disclaimer.
- Reuse the canonical protocol, setup, configuration, and put/get guides instead of duplicating their operational content.
- Use the vocabulary defined in [`CONTEXT.md`](../../CONTEXT.md), including `SignedUpdate`, `SignedEnvelope`, `Identity Record`, `Provider Record`, `Owner Name`, `Owner Public Key`, `Object Key`, `Object Hash`, `Seq`, `Owner Binding`, `Canonical CBOR`, and `Ed25519`.

## Resolution audit trail

The interactive grilling confirmed:

1. Core sovereignty, privacy, anti-centralization, and anti-censorship language describes ecosystem goals rather than prototype guarantees.
2. The rejection of blockchain-centered Web 3.0 is a deliberate project framing and architectural choice, not a universal claim about all blockchain systems.
3. The four claim classes above are mandatory: implemented and code-backed; documented or researched but unimplemented; proposed design; long-term vision.

This artifact resolves #73. It does not resolve companion-service boundaries (#74), end-user scenario selection (#75), or developer-guide structure (#77).

## Verification

The repository test baseline is `.venv/bin/pytest -q`: 56 passed, 1 skipped. This planning artifact makes no code or test changes.

## Source inputs

- [`docs/planning/developer-surface-inventory.md`](developer-surface-inventory.md)
- [`CONTEXT.md`](../../CONTEXT.md)
- [`README.md`](../../README.md)
- [`docs/research/identity-recovery-research.md`](../research/identity-recovery-research.md)
- [`docs/research/2-of-3-multisig-key-recovery.md`](../research/2-of-3-multisig-key-recovery.md)
- [`docs/research/registry-url-format.md`](../research/registry-url-format.md)
- [`docs/research/browser-extension-dht-url-rendering.md`](../research/browser-extension-dht-url-rendering.md)
- [`src/decent_registry/`](../../src/decent_registry/)
