# Documentation information architecture

**Status:** planning decision
**Issue:** #72
**Map:** [Documentation ecosystem vision and application guide for decentralized services](https://github.com/jetpen/decent-registry/issues/71)

## Decision summary

The documentation plan uses four audience tiers and four content areas. The audience tiers describe who the documentation serves; the content areas describe the planned audience-facing documents. Existing operator and integrator guides remain canonical and are linked rather than duplicated.

## Audience tiers

1. **End users** — people using applications and services built on the ecosystem.
2. **Application developers** — developers integrating applications with decent-registry through its CLI or Python APIs.
3. **Operators and integrators** — people running nodes, configuring storage and DHT connectivity, and managing keys.
4. **Ecosystem and vision readers** — people evaluating the decentralization goals, companion-service concepts, claims, and limitations.

Operators and integrators are a cross-cutting audience rather than a fifth content area. They are served by the existing canonical guides:

- [Protocol concepts](../protocol-concepts.md)
- [Single-node server setup](../single-node-server-setup.md)
- [Multi-node cluster setup](../multi-node-cluster-setup.md)
- [Client key generation and configuration](../client-keygen-cli-config.md)
- [Provider put/get examples](../provider-put-get-examples.md)
- [Identity put/get examples](../identity-put-get-examples.md)

## Content areas

The working hypothesis of four content areas is confirmed:

1. **Vision and ecosystem narrative** — the purpose, framing, goals, claims policy, and limitations of the peer-to-peer ecosystem. Detailed decisions are handled by [Vision narrative and claims policy](https://github.com/jetpen/decent-registry/issues/73).
2. **End-user scenarios** — concrete scenarios showing actors, motivations, flows, services involved, current-versus-future status, sovereignty properties, and limitations. Detailed decisions are handled by [End-user scenario catalog and format](https://github.com/jetpen/decent-registry/issues/75).
3. **Developer/application guide** — the structure, prerequisites, runnable examples, integration boundaries, canonical-guide links, and implemented-versus-aspirational separation needed by application developers. Detailed decisions are handled by [Developer application guide structure and content specification](https://github.com/jetpen/decent-registry/issues/77), using the [developer-surface inventory](developer-surface-inventory.md) from #76 as an implementation-fact input.
4. **Companion-service concepts** — the user-facing roles, boundaries, relationships, and value of registry, identity, storage, and social services without defining production wire protocols. Detailed decisions are handled by [Companion service concepts: registry, identity, storage, social](https://github.com/jetpen/decent-registry/issues/74).

## Claim classes

Every planned document must distinguish these claim classes:

- **Implemented and code-backed** — behavior verified against repository code and tests.
- **Documented or researched but unimplemented** — material supported by repository documentation or research, but not exposed as a shipped interface.
- **Proposed design** — a possible future design or integration boundary, not an implementation guarantee.
- **Long-term vision** — ecosystem goals and aspirations, explicitly not current capabilities.

Research such as the `kad:` URL grammar and browser-extension rendering remains in the second class unless and until the corresponding software is implemented. The planning documents must not present it as an existing URL handler, browser API, HTTP gateway, or SDK.

## File and directory structure

### Planned canonical audience-facing documents

These files are to be created by later implementation tickets:

- `docs/vision-and-ecosystem.md`
- `docs/end-user-scenarios.md`
- `docs/developer-guide.md`
- `docs/companion-services.md`

### Planning and specification artifacts

The wayfinder artifacts belong under `docs/planning/`:

- `docs/planning/documentation-information-architecture.md` — this decision
- `docs/planning/vision-narrative-and-claims-policy.md`
- `docs/planning/end-user-scenario-catalog.md`
- `docs/planning/developer-application-guide-spec.md`
- `docs/planning/companion-service-concepts.md`
- `docs/planning/developer-surface-inventory.md` — completed research input from #76

The planning artifacts specify content and boundaries. They do not themselves implement companion services or write the final audience-facing documents unless a later ticket explicitly says so.

## README entry points

The implementation phase should extend the existing root `README.md` `## Documentation` section with two subsections:

### Ecosystem and user documentation

- `docs/vision-and-ecosystem.md`
- `docs/end-user-scenarios.md`
- `docs/developer-guide.md`
- `docs/companion-services.md`

### Operator and integrator documentation

- Existing protocol, setup, configuration, and provider/identity example guides

The root README remains the project index. A separate `docs/README.md` is not planned. This decision does not modify `README.md` during the planning phase.

## Future implementation-ticket grouping and order

The final implementation backlog should contain one writing ticket per canonical document:

1. **Vision and ecosystem narrative** → writes `docs/vision-and-ecosystem.md`.
2. **Companion-service concepts** → writes `docs/companion-services.md`.
3. **End-user scenarios** → writes `docs/end-user-scenarios.md`.
4. **Developer application guide** → writes `docs/developer-guide.md`.

The intended dependency order is:

- Vision and ecosystem narrative blocks companion-service concepts.
- Companion-service concepts blocks end-user scenarios.
- End-user scenarios blocks the developer application guide.
- The developer application guide also depends on the completed #76 developer-surface inventory and the #77 guide specification.

These are future implementation tickets, not work performed while resolving this planning decision. The remaining child issues must settle their content specifications before those writing tickets are created and wired.

## Constraints

- Use the vocabulary in `CONTEXT.md`: SignedUpdate, SignedEnvelope, Identity Record, Provider Record, Owner Name, Owner Public Key, Object Key, Object Hash, Seq, Owner Binding, Canonical CBOR, and Ed25519.
- Link to existing protocol, setup, CLI, and record put/get guides instead of duplicating them.
- Do not define production wire protocols for companion services in this documentation plan.
- Do not describe the current prototype as unstoppable, ungovernable, or censorship-proof.
- Keep research-only URL, browser, gateway, alias, and reverse-lookup proposals visibly separate from implemented interfaces.

## Resolution audit trail

The following decisions were confirmed in the interactive grilling for #72:

1. Four audience tiers: end users; application developers; operators and integrators; ecosystem and vision readers.
2. Four content areas: vision/ecosystem narrative; end-user scenarios; developer/application guide; companion-service concepts.
3. Canonical audience documents live under `docs/`; planning artifacts live under `docs/planning/`.
4. The root README is the entry point, with ecosystem/user and operator/integrator subsections; no separate `docs/README.md`.
5. Future implementation tickets are grouped one per canonical document and follow the confirmed dependency order above.

This artifact resolves the information-architecture decision. It does not resolve the separate questions in #73, #74, #75, or #77.

## Verification

The repository baseline before this planning-only change was `.venv/bin/pytest -q`: 56 passed, 1 skipped. No code or tests were changed by this artifact.
