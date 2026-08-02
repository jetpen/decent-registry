# Developer application guide specification

**Status:** planning decision
**Issue:** #77
**Map:** [Documentation ecosystem vision and application guide for decentralized services](https://github.com/jetpen/decent-registry/issues/71)

## Decision summary

The future canonical application guide is `docs/developer-guide.md`. Its primary audience is application developers integrating with decent-registry through the CLI or Python APIs. The guide follows the thirteen-chapter structure below, links to existing operator and integrator guides instead of duplicating them, and applies the four claim classes established by #73 throughout.

The guide documents implemented registry behavior first. Research-only, proposed, and long-term material is clearly labeled and never presented as a current interface.

## Scope and audience

The guide serves developers who build applications on top of the implemented registry package and CLI. It assumes familiarity with basic Python development and command-line use.

Operators and integrators remain served by the canonical setup and configuration guides:

- [`README.md`](../../README.md)
- [`protocol-concepts.md`](../protocol-concepts.md)
- [`single-node-server-setup.md`](../single-node-server-setup.md)
- [`multi-node-cluster-setup.md`](../multi-node-cluster-setup.md)
- [`client-keygen-cli-config.md`](../client-keygen-cli-config.md)
- [`provider-put-get-examples.md`](../provider-put-get-examples.md)
- [`identity-put-get-examples.md`](../identity-put-get-examples.md)

The application guide links to those documents for operational detail and should not create competing command variants.

## Chapter structure and source mapping

### 1. Introduction and audience

Orient application developers to the registry, the implemented CLI/Python surfaces, and the distinction between current capabilities and future ecosystem concepts.

**Sources:** [`README.md`](../../README.md), [`developer-surface-inventory.md`](developer-surface-inventory.md).

### 2. Prerequisites and environment setup

Describe Python 3.11+, virtual-environment creation, development dependency installation, installation of the `decent-registry` console script, key generation, and access to a running node.

**Sources:** the `README.md` Development section, [`client-keygen-cli-config.md`](../client-keygen-cli-config.md), [`single-node-server-setup.md`](../single-node-server-setup.md), and [`multi-node-cluster-setup.md`](../multi-node-cluster-setup.md).

### 3. Core concepts and vocabulary

Explain `SignedUpdate`, `SignedEnvelope`, Identity Record, Provider Record, Owner Name, Owner Public Key, Object Key, Object Hash, Seq, Owner Binding, Canonical CBOR, and Ed25519. Use the terms in `CONTEXT.md` without introducing conflicting synonyms.

**Sources:** [`CONTEXT.md`](../../CONTEXT.md), [`protocol-concepts.md`](../protocol-concepts.md).

### 4. Key management and private-key secrecy

Explain `keygen`, PKCS#8 PEM paths, file permissions, public-key derivation, and the rule that private keys must never be displayed, logged, transmitted as registry content, or included in application bundles. Private keys remain in local or hardware-backed storage and are used only for signing.

**Sources:** [`client-keygen-cli-config.md`](../client-keygen-cli-config.md), [`crypto_utils.py`](../../src/decent_registry/crypto_utils.py), [`cli.py`](../../src/decent_registry/cli.py), and the repository’s private-key secrecy policy.

### 5. CLI integration with runnable put/get examples

Provide runnable workflows for `keygen`, `node`, `put identity`, `put provider`, `get identity`, and `get provider`. Explain how to obtain bootstrap multiaddrs and key paths from the canonical setup/configuration guides. Examples must be tested against the current CLI syntax.

**Sources:** [`README.md`](../../README.md), [`provider-put-get-examples.md`](../provider-put-get-examples.md), [`identity-put-get-examples.md`](../identity-put-get-examples.md), [`cli.py`](../../src/decent_registry/cli.py), and the setup guides.

### 6. Python API integration

Show how applications use `RegistryService`, envelope builders, `SignedEnvelope`, canonical encoding, verification, record validation, provider schemas, the DHT adapter, and the storage-backend abstraction. The guide must direct callers to these surfaces rather than duplicating cryptographic or validation logic.

**Sources:** [`registry_service.py`](../../src/decent_registry/registry_service.py), [`envelope_builder.py`](../../src/decent_registry/envelope_builder.py), [`signed_envelope.py`](../../src/decent_registry/signed_envelope.py), [`verification.py`](../../src/decent_registry/verification.py), [`record_validator.py`](../../src/decent_registry/record_validator.py), and the integration checklist in [`developer-surface-inventory.md`](developer-surface-inventory.md).

### 7. Records, schemas, and canonical CBOR

Explain Identity Record and Provider Record fields, endpoint normalization, object-key rules, canonical CBOR, signature input, and update sequencing. Link to protocol concepts rather than restating the complete protocol specification.

**Sources:** [`protocol-concepts.md`](../protocol-concepts.md), [`encoding.py`](../../src/decent_registry/encoding.py), [`provider_schema.py`](../../src/decent_registry/provider_schema.py), [`signed_envelope.py`](../../src/decent_registry/signed_envelope.py), and [`envelope_builder.py`](../../src/decent_registry/envelope_builder.py).

### 8. Storage and DHT behavior

Explain the libp2p Kad-DHT adapter, implemented `put`/`get` behavior, LMDB durable storage, the storage abstraction, provider and identity namespaces, and Object Key derivation. Treat namespace strings and derivation rules as protocol surface.

**Sources:** [`libp2p_dht.py`](../../src/decent_registry/dht/libp2p_dht.py), [`durable_store.py`](../../src/decent_registry/durable_store.py), [`storage_backend.py`](../../src/decent_registry/storage_backend.py), and [`protocol-concepts.md`](../protocol-concepts.md).

### 9. Configuration

Explain server and client configuration, host/port, bootstrap values, datastore paths, mapsize, verbosity, and precedence between configuration files and CLI overrides.

**Sources:** [`config.py`](../../src/decent_registry/config.py), [`client-keygen-cli-config.md`](../client-keygen-cli-config.md), [`single-node-server-setup.md`](../single-node-server-setup.md), and [`multi-node-cluster-setup.md`](../multi-node-cluster-setup.md).

### 10. Testing and verification

Describe the test command, expected baseline, local verification of signatures and record validation, and how to check CLI examples. The recorded baseline is `.venv/bin/pytest -q`: 56 passed, 1 skipped.

**Sources:** the `README.md` Development section, `pyproject.toml`, `tests/`, and [`developer-surface-inventory.md`](developer-surface-inventory.md).

### 11. Research and proposed surfaces

Clearly label each item as researched but unimplemented, proposed design, or long-term vision. Link to the developer-surface inventory research section, [`2-of-3-multisig-key-recovery.md`](../research/2-of-3-multisig-key-recovery.md), [`identity-recovery-research.md`](../research/identity-recovery-research.md), [`registry-url-format.md`](../research/registry-url-format.md), [`browser-extension-dht-url-rendering.md`](../research/browser-extension-dht-url-rendering.md), and [`companion-service-concepts.md`](companion-service-concepts.md).

The guide must explicitly state that these are not implemented interfaces, APIs, or protocols. It must not imply current CLI or Python support for HTTP gateways, browser extensions, native-messaging bridges, identity graphs, recovery, multisignature bundles, general-purpose storage services, or social services.

### 12. Limitations and boundaries

Collect operational and architectural limitations: bootstrap peer identity lifecycle, DHT/storage availability, public-record visibility, current single-key identity authorization, absence of companion-service protocols, and the distinction between research and implementation.

**Sources:** the Boundaries and limitations section of [`developer-surface-inventory.md`](developer-surface-inventory.md), the canonical setup guides, and the research files.

### 13. Glossary and index

Provide a compact glossary using `CONTEXT.md` vocabulary and an index linking to source modules, canonical guides, planning artifacts, and research documents.

**Sources:** [`CONTEXT.md`](../../CONTEXT.md), [`protocol-concepts.md`](../protocol-concepts.md), and the canonical documentation index in [`developer-surface-inventory.md`](developer-surface-inventory.md).

## Prerequisites

The guide should require or link to procedures for:

- Python 3.11 or newer.
- A repository virtual environment with development dependencies installed.
- An installed `decent-registry` console script.
- An Ed25519 PKCS#8 PEM key generated with strict file permissions.
- A running single-node or multi-node registry setup.
- Connectivity to a registry node and a valid identify-style bootstrap multiaddr when required.

All operational parameter derivations, especially bootstrap multiaddrs and key paths, must point to the canonical setup/configuration guides rather than inventing values.

## Runnable examples

The final guide must include tested examples for:

- `decent-registry keygen`.
- Starting a node and obtaining its listen address and peer identity.
- Publishing and resolving Provider Records.
- Publishing and resolving Identity Records.
- A Python integration using the implemented service and verification surfaces.
- Running `.venv/bin/pytest -q` and interpreting the result.

Examples must not include private-key material, must not log it, and must use file paths for PEM keys. The guide must distinguish examples that run today from pseudocode for proposed services.

## Integration boundaries and API surface

- CLI integration uses `keygen`, `node`, `put identity`, `put provider`, `get identity`, and `get provider`.
- Python integration uses `RegistryService`, `Libp2pKadDHT`, envelope construction, canonical encoding, verification, record validation, provider schemas, and the storage-backend abstraction.
- Applications use the storage abstraction rather than coupling directly to LMDB.
- DHT namespace strings and Object Key derivation are treated as protocol surface.
- The guide links to canonical setup, configuration, protocol, and put/get guides instead of duplicating them.
- HTTP gateways, browser extensions, native-messaging bridges, identity graphs, recovery, multisignature bundles, general-purpose storage services, and social services remain research or proposed surfaces.

## Companion-service coverage rule

The guide may explain registry, identity, storage, and social services as proposed application concepts, using [`companion-service-concepts.md`](companion-service-concepts.md) and the scenario catalog as sources. It must not define production wire protocols or imply current support. This rule clears the remaining planning ambiguity about the level of companion-service detail.

## Resolution audit trail

The interactive grilling confirmed:

1. The guide targets application developers and documents implemented surfaces first while separating research, proposed, and vision material.
2. The thirteen-chapter structure above is mandatory.
3. Prerequisites and runnable examples use the canonical guides as the source for operational parameters; examples cover CLI and Python integration and the current test baseline.
4. Integration boundaries include the confirmed CLI and Python surfaces, storage abstraction, DHT protocol surface, canonical-guide linking, and explicit exclusion of research/proposed interfaces from current support.

This artifact resolves #77. It does not implement the final `docs/developer-guide.md` or any companion service.

## Verification

This planning artifact makes no code or test changes. The repository baseline remains `.venv/bin/pytest -q`: 56 passed, 1 skipped.

## Source inputs

- [`developer-surface-inventory.md`](developer-surface-inventory.md)
- [`documentation-information-architecture.md`](documentation-information-architecture.md)
- [`vision-narrative-and-claims-policy.md`](vision-narrative-and-claims-policy.md)
- [`companion-service-concepts.md`](companion-service-concepts.md)
- [`end-user-scenario-catalog.md`](end-user-scenario-catalog.md)
- [`README.md`](../../README.md)
- [`CONTEXT.md`](../../CONTEXT.md)
- [`src/decent_registry/`](../../src/decent_registry/)
