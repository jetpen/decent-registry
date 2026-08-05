# Developer guide

## 1. Introduction and audience

This guide is for application developers integrating with `decent-registry` through its CLI or Python package. It documents the implemented Registry first, then separates researched, proposed, and long-term ecosystem material.

`decent-registry` publishes and resolves signed Identity Records and Provider Records over libp2p Kad-DHT. It is a peer-to-peer registry foundation, not an implemented identity graph, general-purpose storage service, social service, HTTP gateway, or browser SDK.

Use [Vision and ecosystem](vision-and-ecosystem.md) for project framing and [Companion services](companion-services.md) for proposed service boundaries. The four Claim Classes used throughout this guide are:

1. **Implemented and code-backed** — verified against repository code and tests.
2. **Documented or researched but unimplemented** — supported by documentation or research but not a shipped interface.
3. **Proposed design** — a possible future convention or integration boundary.
4. **Long-term vision** — an Ecosystem Goal, not a current capability.

Operators should use the canonical [single-node setup](single-node-server-setup.md), [multi-node setup](multi-node-cluster-setup.md), and [configuration guide](client-keygen-cli-config.md). This guide links to those documents instead of creating competing operational procedures.

## 2. Prerequisites and environment setup

The implemented package requires Python 3.11 or newer. For repository development:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

The installation provides the `decent-registry` console script. Application integration also requires:

- an Ed25519 PKCS#8 PEM key generated locally with strict file permissions;
- a running single-node or multi-node Registry; and
- connectivity to a Registry node, including an identify-style bootstrap multiaddr when the command requires one.

Use [client key generation and configuration](client-keygen-cli-config.md) for key paths and YAML configuration, [single-node setup](single-node-server-setup.md) for one node, and [multi-node setup](multi-node-cluster-setup.md) for bootstrap topology. Do not invent bootstrap addresses: copy the complete `[BOOTSTRAP] <listen_multiaddr>/p2p/<peer_id>` value emitted by the node.

## 3. Core concepts and vocabulary

Use the vocabulary in [`CONTEXT.md`](../CONTEXT.md) and [protocol concepts](protocol-concepts.md):

- **SignedUpdate** is the canonical record data containing `record_fields`, a `payload`, and monotonic `seq`; its bytes are bound to the Ed25519 signature.
- **SignedEnvelope** is the canonical CBOR wrapper containing SignedUpdate bytes and the signature. It is the DHT value that is stored and transported.
- **Identity Record** binds an Owner Name to an Owner Public Key. Its DHT key is derived from the owner-name bytes.
- **Provider Record** binds an Object Hash to a provider URL and sorted multiaddr endpoints.
- **Owner Name** is the byte-string identity input used to derive an Identity Record key.
- **Owner Public Key** is the Ed25519 public key used for signature verification and owner binding.
- **Object Key** is the lookup key for an Identity Record. **Object Hash** is the SHA-256 hex key input for a Provider Record.
- **Seq** is the non-negative update order. Accepted overwrites require a strictly greater value.
- **Owner Binding** commits a record key to its first accepted owner public key; later overwrites must use the same key.
- **Canonical CBOR** provides deterministic bytes for signing and verification.
- **Ed25519** is the signature scheme used by the Registry.

## 4. Key management and private-key secrecy

Generate a local PKCS#8 PEM key with:

```bash
decent-registry keygen --output ~/.decent/owner_privkey.pem
```

The CLI writes the file with mode `0o600` and never prints the private-key material. Commands receive the PEM path through `--owner-privkey` or `crypto.owner_privkey_pem_path` in the client YAML file. The key is loaded only for local signing; the Registry receives public verification material and signatures, not the private key.

Private keys must never be displayed, logged, transmitted as Registry content, committed, included in example bundles, or sent to an application service. Keep them in local secure storage or hardware-backed storage. See [client key generation and configuration](client-keygen-cli-config.md) and [`crypto_utils.py`](../src/decent_registry/crypto_utils.py).

## 5. CLI integration with put/get examples

The implemented CLI surface is `keygen`, `node`, `bundle draft`, `bundle sign`, `bundle merge`, `bundle finalize`, `put identity`, `put provider`, `get identity`, and `get provider`. The full, tested legacy workflows are in [Provider Record put/get examples](provider-put-get-examples.md) and [Identity Record put/get examples](identity-put-get-examples.md). The implemented multisignature workflow is in [Multisignature Records and Migration](multisignature-records.md). The following commands show the interface shape without inventing deployment values.

Start a node and copy its emitted bootstrap address:

```bash
decent-registry -v node --host 127.0.0.1 --port <NODE_PORT>
# copy: [BOOTSTRAP] <listen_multiaddr>/p2p/<peer_id>
```

Publish and resolve an Identity Record:

```bash
decent-registry put identity \
  --host 127.0.0.1 --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --owner-name <OWNER_NAME_HEX> \
  --owner-privkey ~/.decent/owner_privkey.pem \
  --seq 1

decent-registry get identity \
  --host 127.0.0.1 --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --owner-name <OWNER_NAME_HEX>
```

Publish and resolve a Provider Record:

```bash
decent-registry put provider \
  --host 127.0.0.1 --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --object-hash <OBJECT_HASH_64_HEX> \
  --provider-url <HTTPS_OR_HTTP_URL> \
  --owner-privkey ~/.decent/owner_privkey.pem \
  --seq 1 \
  --endpoint /ip4/127.0.0.1/tcp/<SERVICE_PORT>

decent-registry get provider \
  --host 127.0.0.1 --port <CLIENT_PORT> \
  --bootstrap <SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID> \
  --object-hash <OBJECT_HASH_64_HEX>
```

`--bootstrap` may be repeated or comma-separated. It must contain `/p2p/<peer_id>`. Provider endpoints are repeatable, must begin with `/`, and are normalized into sorted order before signing. `put` updates require strictly increasing `--seq` and preserve Owner Binding. These snippets use placeholders intentionally; the canonical examples contain the complete local end-to-end scripts.

## 6. Python API integration

The Python API is organized around `RegistryService`, which delegates to a `RegistryDHT` implementation. `Libp2pKadDHT` implements that protocol. Applications should use these surfaces rather than duplicating signing, canonical encoding, verification, or sequence rules.

The integration shape is:

```python
import trio

from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.registry_service import RegistryService


async def main() -> None:
    async with Libp2pKadDHT(listen="/ip4/127.0.0.1/tcp/<CLIENT_PORT>") as dht:
        # Bootstrap the DHT using a deployment-provided identify-style multiaddr.
        await dht.bootstrap("<SEED_LISTEN_MULTIADDR>/p2p/<SEED_PEER_ID>")
        service = RegistryService(dht=dht)

        await service.put_provider(
            object_hash="<OBJECT_HASH_64_HEX>",
            provider_url="<HTTPS_OR_HTTP_URL>",
            owner_privkey_pem_path="/secure/path/owner_privkey.pem",
            seq=1,
            endpoints=["/ip4/127.0.0.1/tcp/<SERVICE_PORT>"],
        )
        provider = await service.get_provider(
            object_hash="<OBJECT_HASH_64_HEX>"
        )
        print(provider)

        await service.put_identity(
            owner_name_hex="<OWNER_NAME_HEX>",
            owner_privkey_pem_path="/secure/path/owner_privkey.pem",
            seq=1,
        )
        identity = await service.get_identity(owner_name_hex="<OWNER_NAME_HEX>")
        print(identity)


trio.run(main)
```

The snippet is an integration shape: deployment-specific port, bootstrap, object, and key-path values are required. The complete tested workflows remain in the canonical example guides. The service implementation is [`registry_service.py`](../src/decent_registry/registry_service.py); envelope construction, verification, schemas, DHT behavior, and storage are indexed in the [developer surface inventory](planning/developer-surface-inventory.md).

## 7. Records, schemas, and canonical CBOR

Provider and Identity Records are signed through the same envelope path:

1. Build the record payload using the schema and normalized fields.
2. Construct a `SignedUpdate` with its record fields, payload, and `Seq`.
3. Encode the update as deterministic Canonical CBOR.
4. Sign the canonical update bytes with the local Ed25519 key.
5. Wrap the bytes and signature in a `SignedEnvelope`.
6. Store the envelope through the appropriate DHT namespace.

Relevant modules are [`provider_schema.py`](../src/decent_registry/provider_schema.py), [`envelope_builder.py`](../src/decent_registry/envelope_builder.py), [`encoding.py`](../src/decent_registry/encoding.py), [`signed_envelope.py`](../src/decent_registry/signed_envelope.py), [`verification.py`](../src/decent_registry/verification.py), and [`record_validator.py`](../src/decent_registry/record_validator.py).

Provider payloads validate the provider URL and endpoint list. Endpoints are multiaddrs, are sorted before signing, and the Provider Record uses its 64-hex Object Hash as the DHT key. Identity lookup derives `sha256(owner_name_bytes).hexdigest()` from the hex-decoded Owner Name. A later overwrite must have a strictly larger `Seq`, a valid signature, a matching derived key, and a consistent Owner Binding.

Use [protocol concepts](protocol-concepts.md) as the protocol source of truth. Do not reimplement canonical encoding or validation in an application.

## 8. Storage and DHT behavior

The implemented DHT namespaces are:

- Provider: `/decent-registry/provider/{object_hash}`
- Identity: `/decent-registry/identity/{object_key_hex}`, where `object_key_hex = sha256(owner_name_bytes).hexdigest()`

[`Libp2pKadDHT`](../src/decent_registry/dht/libp2p_dht.py) provides the libp2p Kad-DHT node and signed record `put`/`get` operations. [`storage_backend.py`](../src/decent_registry/storage_backend.py) defines the storage abstraction and [`durable_store.py`](../src/decent_registry/durable_store.py) provides the LMDB durable implementation.

Applications should depend on the storage-backend abstraction when they need to integrate storage behavior. Do not couple application logic directly to LMDB unless the application explicitly owns that deployment concern. Namespace strings and Object Key derivation are protocol surface and must not be changed casually.

The Registry’s LMDB and DHT replication are not a general-purpose Storage Service. A proposed Storage Service is documented separately in [Companion services](companion-services.md).

## 9. Configuration

The server YAML file defaults to `~/.decent/registry.yaml`; client commands default to `~/.decent/registry_cli.yaml`. The following is a **client configuration** example for `~/.decent/registry_cli.yaml`. Configuration is grouped into `network`, `datastore`, `logging`, and `crypto`:

```yaml
network:
  host: 127.0.0.1
  port: 9001
  bootstrap:
    - /ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>
datastore:
  path: .scratch/decent-registry.lmdb
  mapsize_bytes: 1099511627776
logging:
  verbosity: 0
crypto:
  owner_privkey_pem_path: ~/.decent/owner_privkey.pem
```

The server configuration uses the same `network`, `datastore`, and `logging` groups with its own defaults; see [single-node setup](single-node-server-setup.md) and [multi-node setup](multi-node-cluster-setup.md). The implementation accepts command-line overrides for host, port, bootstrap, datastore path, mapsize, verbosity, and owner-key path. CLI values override YAML values; built-in defaults apply where neither is supplied.

A client `network.port` is required after configuration and CLI merging, and the node command also requires a server port before starting. Bootstrap entries must be multiaddr strings beginning with `/`. The client key path is validated for existence without logging or reading key material into configuration errors. See [`config.py`](../src/decent_registry/config.py) and [client key generation and configuration](client-keygen-cli-config.md) for the canonical details.

## 10. Testing and verification

Run the full repository suite from the project root:

```bash
.venv/bin/pytest -q
```

Pytest discovers tests from `tests/` as configured in `pyproject.toml`. The verified baseline for this guide is **115 passed, 1 skipped**.

For an integration change, verify the affected single test or test module first, then run the full suite. Check signatures, Canonical CBOR, strict `Seq` behavior, Owner Binding, provider endpoint normalization, namespace derivation, and CLI exit behavior. The canonical Provider and Identity Record guides include runnable end-to-end scripts; use them for network workflows rather than inventing a parallel test procedure.

## 11. Research and proposed surfaces

The following are not implemented interfaces, APIs, or protocols:

- **Documented or researched but unimplemented:** `kad:` URL grammar and route concepts in [registry URL research](research/registry-url-format.md).
- **Documented or researched but unimplemented:** Chromium extension rendering and DHT integration in [browser extension research](research/browser-extension-dht-url-rendering.md).
- **Proposed design:** HTTP gateways and native-messaging bridges described by the [developer surface inventory](planning/developer-surface-inventory.md).
- **Proposed design:** Identity Graphs, aliases, and reverse Owner Public Key lookup.
- **Documented or researched but unimplemented:** Separate Recovery Policy conventions, including passkey, guardian, one-time recovery, and key-replacement research in [identity recovery research](research/identity-recovery-research.md) and [2-of-3 multisig recovery research](research/2-of-3-multisig-key-recovery.md). The version-1 explicit-Ed25519 Bundle and finalized-record workflow is implemented; see [Multisignature Records and Migration](multisignature-records.md).
- **Proposed design:** General-purpose Storage Services, Social Graphs, messaging, and collaborative services in [Companion services](companion-services.md).

The CLI and Registry provide the implemented version-1 explicit-Ed25519 multisignature workflow documented in [Multisignature Records and Migration](multisignature-records.md). Do not present research workflows—such as FROST, recovery policy, HTTP gateways, browser integrations, or Companion Service protocols—as current commands or APIs.

## 12. Limitations and boundaries

- A bootstrap multiaddr contains a peer identity, and node identity persists with the node’s durable-store location; deployment operators must manage its lifecycle.
- DHT routing, record availability, endpoint reachability, and replication depend on the deployment. Valid signatures do not guarantee availability, permanence, privacy, or anonymity.
- Legacy Identity Records use single-key authorization. Version-1 multisignature Identity and Provider Records use explicit Ed25519 Signer Sets and threshold proofs; recovery policy, Identity Graphs, and FROST remain unimplemented.
- Registry LMDB storage and DHT replication do not provide a general-purpose content Storage Service.
- Public Identity and Provider Records are not private by default.
- No HTTP gateway, browser extension, native-messaging bridge, Social Graph protocol, or production Companion Service protocol is implemented.
- Research and long-term Ecosystem Goals must remain visibly distinct from code-backed behavior.

Private keys remain local or hardware-backed and must never be displayed, logged, transmitted as Registry content, committed, or included in bundles. Only public verification material and signatures may be exchanged.

## 13. Glossary and index

Use [`CONTEXT.md`](../CONTEXT.md) as the project glossary. It defines the canonical forms of SignedUpdate, SignedEnvelope, Identity Record, Provider Record, Owner Name, Owner Public Key, Object Key, Object Hash, Seq, Owner Binding, Canonical CBOR, Ed25519, Registry, Companion Service, Identity Graph, Social Graph, Storage Service, Signer Set, Multisignature Bundle, Recovery Policy, Claim Class, Ecosystem Goal, and Decentralized.

### Source index

- [README](../README.md)
- [Vision and ecosystem](vision-and-ecosystem.md)
- [Companion services](companion-services.md)
- [Protocol concepts](protocol-concepts.md)
- [Single-node setup](single-node-server-setup.md)
- [Multi-node setup](multi-node-cluster-setup.md)
- [Client key and configuration](client-keygen-cli-config.md)
- [Provider put/get examples](provider-put-get-examples.md)
- [Identity put/get examples](identity-put-get-examples.md)
- [Developer surface inventory](planning/developer-surface-inventory.md)
- [Developer guide specification](planning/developer-application-guide-spec.md)
- [Documentation information architecture](planning/documentation-information-architecture.md)
- [Vision claims policy](planning/vision-narrative-and-claims-policy.md)
- [End-user scenario catalog](planning/end-user-scenario-catalog.md)
- [Research: registry URL format](research/registry-url-format.md)
- [Research: browser extension DHT rendering](research/browser-extension-dht-url-rendering.md)
- [Research: identity recovery](research/identity-recovery-research.md)
- [Research: 2-of-3 multisignature recovery](research/2-of-3-multisig-key-recovery.md)
- [`src/decent_registry/`](../src/decent_registry/)
- [`tests/`](../tests/)

