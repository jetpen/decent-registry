# DPI Evasion Research: Xray-core VLESS + REALITY and libp2p Kad-DHT

**Claim class:** Documented or researched but unimplemented, except where explicitly marked as code-backed.

**Question:** Which DPI-evasion properties are used by Xray-core's VLESS + REALITY deployment, and can comparable properties be adapted to `decent-registry`'s libp2p Kad-DHT transport?

## Executive assessment

Xray-core's VLESS + REALITY is primarily a **transport and endpoint-authentication design**, not a modification to the application protocol being carried. Its relevant mechanisms are:

1. TLS ClientHello mimicry or randomization through uTLS.
2. A TLS 1.3-compatible handshake whose visible server-side behavior is intended to resemble a permitted TLS service.
3. An authenticated, temporary certificate mechanism derived from a client/server shared secret rather than a conventional public certificate chain.
4. A decoy/redirect path for clients that fail the REALITY authentication condition, including optional crawler behavior after the client receives the target site's real certificate.
5. A single transport port and ordinary-looking application transport options, with current Xray configuration accepting REALITY over raw TCP and selected HTTP-derived transports.[1][4][5][6]

Adapting the **Kademlia algorithm or wire messages** will not provide DPI evasion. The feasible boundary is a replacement or extension of the libp2p transport/security layer, potentially combined with relay/front-door nodes. The recommended design is to preserve the existing Kad-DHT protocol and signed-record semantics while adding a separately specified, standards-based cover transport. Directly embedding REALITY into every DHT peer is technically possible but has low-to-medium feasibility and high maintenance, interoperability, and detection risk.

## Scope and safety boundary

This document describes protocol properties, architectural implications, and evaluation criteria. It does not provide operational circumvention configurations, target-domain selection guidance, or deployment instructions for bypassing a specific network filter.

## 1. Threat model

A hostile network operator may:

- block IP addresses, ports, DNS names, or known hosting ranges;
- inspect TCP/UDP metadata, packet sizes, timing, directionality, and connection lifetime;
- parse visible TLS fields such as SNI, ALPN, supported versions, cipher suites, extensions, and ClientHello ordering;
- actively connect to suspected endpoints and compare their responses with the claimed cover service;
- collect fingerprints over time and block a protocol after its implementation becomes distinctive;
- block an entire transport class, such as UDP, regardless of encryption.

TLS protects application confidentiality and integrity, but it does not automatically make a flow indistinguishable from a browser or a permitted service. TLS 1.3 still exposes a ClientHello and other metadata needed for negotiation; RFC 8446 defines the secure-channel goal and the handshake/record structure, not censorship indistinguishability.[11]

## 2. Relevant Xray-core / REALITY techniques

### 2.1 ClientHello fingerprint mimicry

uTLS exposes low-level ClientHello control and provides browser-oriented, randomized, and custom fingerprints. Its documentation explicitly describes the purpose as resistance to ClientHello fingerprinting and notes that mimicry is limited: parroting affects the ClientHello, not the complete subsequent behavior.[6]

This matters because a Go program's default TLS ClientHello can be uncommon enough to classify even when the payload is encrypted. Xray's use of uTLS allows a client to select a profile resembling a common implementation or a controlled randomized profile. RFC 8701's GREASE mechanism supplies a standards-defined example of deliberately varying extensibility values, but GREASE is for ecosystem extensibility and does not itself create censorship resistance.[12]

**Transferable lesson:** treat the handshake fingerprint as a versioned compatibility surface. Prefer a small set of measured, current profiles over an obviously unique custom fingerprint. Randomization must remain protocol-valid and should not create a new, rare fingerprint distribution.

**Limitation:** ClientHello mimicry does not conceal IP addresses, port numbers, timing, packet lengths, server behavior, or application-layer flow shape. A censor can also update its browser fingerprints or classify the post-handshake traffic.

### 2.2 REALITY's decoy-service model

The REALITY project describes a server-side implementation derived from Go TLS and provides a configuration model with an apparent target, accepted server names, a server private key, client short identifiers, and a client public key.[1] Xray's current configuration code restricts REALITY to raw TCP, XHTTP, or gRPC transport variants.[5]

The important property is not simply “TLS encryption.” The server is designed to present one behavior to an authorized client and another behavior to an unauthenticated or incorrectly formed connection. The project documentation states that a client may receive either a temporary trusted certificate or the real target certificate, and that the client distinguishes those outcomes.[1] The Xray client source shows the corresponding structure: it derives an authentication key from the configured public key and the ClientHello key share, uses an AEAD-protected ClientHello field, verifies a temporary Ed25519 certificate when the derived value matches, and otherwise treats the peer as a real-certificate path.[4] [unverified]

**Transferable lesson:** active-probe resistance requires a plausible response for unauthorized probes, not merely rejection. The response must not reveal a distinctive “this is the hidden service” error path.

**Limitations:**

- A decoy response is only as plausible as the endpoint and implementation behind it.
- An active censor can compare response behavior, certificates, timing, and content over repeated probes.
- The endpoint's IP, routing neighborhood, SNI behavior, and traffic volume remain observable.
- Any bespoke handshake becomes a moving reverse-engineering target.
- A failed connection that retries through a visibly different protocol can itself become a classifier feature.

The REALITY README contains strong project claims such as “undistinguishable” and “eliminate the detectable TLS fingerprint.” Those are design goals and project claims, not independently established guarantees; the implementation should be evaluated against the specific censor model rather than treated as universally indistinguishable.[1]

### 2.3 Shared-secret authentication without a conventional certificate chain

The Xray client source derives an authentication key from the server-provided public key and the ephemeral TLS key share, then uses it to authenticate the temporary certificate path.[4] The REALITY source implements TLS certificate-signature verification and the associated TLS 1.3 certificate-verification context.[2][3]

This allows an authorized client to recognize the hidden service without requiring the endpoint to present a certificate whose public identity is the hidden service's public name. It also provides a way for an unauthorized probe to be served a normal target certificate or otherwise receive a plausible cover response.

**Transferable lesson:** separate (a) public cover-service authentication, (b) private authorization to enter the overlay, and (c) libp2p peer identity authentication. They should not be collapsed into one reusable secret or one visible application identifier.

### 2.4 Fallback and crawler behavior

The REALITY design documents a fallback distinction: a rejected or redirected connection receives the target site's real certificate, while an authorized connection receives a temporary trusted certificate. The Xray client can enter crawler mode after receiving the real certificate; the source performs HTTP/2 requests using the established connection and follows page paths.[1][4]

This behavior addresses active probes by making an unauthorized connection look more like an ordinary visit to the cover service. It is not equivalent to making every hidden application flow look like the cover site's complete traffic.

**Transferable lesson:** an unauthenticated probe should receive a safe, ordinary response, while the hidden protocol should only activate after authentication. For `decent-registry`, this is more naturally implemented at a public edge or relay than inside every DHT node.

### 2.5 Transport selection and fallback discipline

libp2p's QUIC specification recommends offering QUIC but also recommends a TCP-based option because UDP is blocked in some networks.[9] QUIC provides confidentiality, integrity, multiplexed streams, and path migration, but it remains visibly UDP/QUIC to a censor that blocks or classifies that transport.[13]

**Transferable lesson:** support independent transport paths—at minimum a TCP-based path and a QUIC path where available—but do not assume that adding encryption or path migration defeats a network that blocks the transport class. Fallback policy must avoid a deterministic retry sequence that exposes the hidden protocol.

## 3. What libp2p already provides

libp2p's Noise specification provides an authenticated key exchange, forward-secret symmetric encryption, and authentication of a Noise static key using the libp2p identity key.[8] The specification also warns that early handshake data may be replayed and must be idempotent; it requires that handshake payloads be validated before being exposed to other components.[8]

libp2p QUIC uses TLS for peer authentication and identifies the application protocol using ALPN `libp2p`.[9] That is useful for interoperability but may be a direct classification feature for a censor able to inspect the TLS handshake. [unverified]

The Kad-DHT specification is transport-independent at the algorithmic level. It defines peer routing, `PUT_VALUE`, `GET_VALUE`, and related operations; value storage finds the closest peers and sends `PUT_VALUE` to them, while lookups use iterative `GET_VALUE`/`FIND_NODE` exchanges.[7] The specification separately distinguishes client and server mode based on reachability and resource constraints.[7]

The current `decent-registry` adapter is code-backed as a TCP-only host construction at the repository level: `Libp2pKadDHT.__init__` calls `new_host(..., enable_tcp=True)`, and `__aenter__` runs the host with the configured TCP listen multiaddress. The adapter then constructs the standard `KadDHT` service. It does not currently expose a custom REALITY security transport, cover endpoint, relay front door, or QUIC listener. See [`src/decent_registry/dht/libp2p_dht.py`](../../src/decent_registry/dht/libp2p_dht.py). [unverified]

## 4. Feasibility of adapting Kad-DHT for DPI evasion

| Candidate | Feasibility | DPI value | Main issue |
|---|---:|---:|---|
| Modify Kad-DHT messages or XOR routing | Low value | Low | DPI acts primarily on the connection and metadata; encrypted RPC contents are already below the security layer. |
| Keep Kad-DHT and add ordinary libp2p TLS/Noise | High | Low–medium | Protects content and peer authentication but may expose libp2p negotiation, ALPN, handshake, addresses, and flow shape. |
| Add REALITY-like security to every peer | Medium-low | Medium, conditional | Requires a custom security upgrader, compatible TLS/uTLS/REALITY implementation, identity binding, safe fallback, and cross-language maintenance. |
| Put a cover-protocol edge in front of DHT relays | Medium | Medium–high, conditional | Hides core peers and can centralize exposure at replaceable edges, but introduces relays, latency, abuse controls, and availability dependencies. |
| Add TCP-cover, QUIC, and relay alternatives | Medium-high | Medium | Improves reachability across heterogeneous blocking; does not defeat an adversary that blocks all candidate paths or recognizes the profiles. |
| Obfuscate only DHT record values | Low value | Low | Values are already signed and transported inside the secure channel; this does not hide endpoint or flow metadata. |

### 4.1 Why changing Kademlia is the wrong layer

The DHT's distinctive observable properties—peer-to-peer connection graph, repeated request/response exchanges, long-lived server behavior, bootstrap contacts, and advertised addresses—are not eliminated by changing the lookup key or protobuf fields. A censor that cannot decrypt RPC contents can still classify connections using handshake and traffic metadata. A censor that can actively probe an endpoint can also observe whether it accepts libp2p negotiation or Kad-DHT streams.

Changing the DHT wire messages would additionally reduce interoperability with existing libp2p implementations while leaving the principal DPI surface unchanged. The correct separation is:

- **DHT layer:** routing, record storage, signed-record validation, replication, quorum/conflict rules.
- **Secure channel:** peer authentication, confidentiality, forward secrecy, replay handling.
- **Cover transport/front door:** visible handshake, decoy behavior, authorized-entry decision, and possibly relay forwarding.
- **Discovery/addressing:** bootstrap and relay addresses that do not unnecessarily expose private node topology.

### 4.2 Direct REALITY-compatible peer transport

A direct adaptation would need to implement or integrate all of the following:

1. A TLS-compatible ClientHello path with maintained fingerprints.
2. REALITY-compatible server/client authentication and certificate handling.
3. A safe unauthenticated response path.
4. Binding from the authorized channel to the libp2p peer identity key and then to Noise/TLS or another authenticated libp2p secure channel.
5. Multistream/protocol negotiation after the cover handshake without exposing a distinctive application token.
6. Correct stream multiplexing, deadlines, cancellation, connection reuse, and error handling.
7. Interoperability tests across the Python implementation and any future Go/Rust implementations.

This is not a small adapter around `KadDHT`; it is a transport/security subsystem. The current Python dependency set does not include a native REALITY implementation, and the Xray/REALITY code is Go. Reimplementing cryptographic protocol behavior in Python would violate the repository's guidance to use established libraries for cryptography and wire protocols and would create a long-term compatibility burden.

### 4.3 Relay/front-door architecture

A more feasible architecture is:

1. Public edge nodes expose one or more ordinary-looking, authenticated cover transports.
2. Edge nodes forward an already authenticated, encrypted stream to DHT-capable relay or server nodes.
3. Core DHT nodes advertise relay reachability rather than direct private addresses where direct inbound connectivity is unsafe.
4. The edge does not terminate or reinterpret signed registry records; it forwards opaque secure-channel traffic.
5. The core still authenticates the libp2p peer identity and applies ordinary Kad-DHT validation.

This architecture does not make the network invisible. It changes the exposure from “every DHT node is a public classified service” to “replaceable edge nodes carry traffic to the overlay.” It also creates explicit relay trust, capacity, abuse, and availability requirements. Multiple independent operators and transport paths are necessary to avoid replacing state censorship with a single service dependency.

## 5. Recommended design direction

### Recommendation

**Do not modify Kademlia to implement DPI evasion.** Preserve the Kad-DHT protocol and signed-record layer. Add a transport-provider abstraction and evaluate a cover-capable edge/relay transport separately.

### Proposed stages

1. **Transport abstraction:** isolate host construction, security upgrade, stream multiplexing, and multiaddr handling from `Libp2pKadDHT`. Keep record validation and DHT calls unchanged.
2. **Baseline encrypted transports:** support existing libp2p Noise/TLS and QUIC/TCP alternatives first. Measure visible fingerprints and failure modes before adding bespoke behavior.
3. **Peer-identity binding:** ensure the post-cover channel authenticates the libp2p identity key and does not rely on a reusable public-DHT secret. Bind authorization to the peer identity and the intended protocol context.
4. **Relay-aware addressing:** add relay multiaddresses and limit identify/address advertisement to addresses the node is willing and able to serve. Treat bootstrap material as sensitive topology metadata.
5. **Cover edge experiment:** prototype a replaceable edge that forwards opaque authenticated streams. Keep this behind an explicit feature boundary; do not make it part of core Kad-DHT semantics.
6. **Only then evaluate REALITY-like mechanisms:** use a maintained implementation or a narrowly scoped interoperable specification. Do not fork Xray's TLS stack into the Python registry without a clear maintenance owner.

## 6. Evaluation criteria

A transport should not be accepted based on successful encrypted connectivity alone. Evaluation should include:

- passive classifier performance on packet captures from ordinary cover traffic and registry traffic;
- active-probe response equivalence and error-path analysis;
- ClientHello, SNI, ALPN, certificate, record-size, and timing comparisons;
- behavior under TCP blocking, UDP blocking, DNS poisoning, IP blocking, and selective resets;
- connection churn, NAT rebinding, relay failure, and bootstrap loss;
- resource costs from cover responses and probe floods;
- peer-identity privacy and leakage through identify, multiaddrs, logs, and error messages;
- interoperability across supported libp2p implementations;
- cryptographic review, especially channel binding, replay resistance, key rotation, downgrade prevention, and fallback behavior.

Success criteria must be stated against a named adversary model. “Indistinguishable” is not a general property that can be inferred from TLS encryption or a browser-like ClientHello.

## 7. Conclusion

Xray-core VLESS + REALITY demonstrates a useful pattern: combine a common transport handshake, implementation-level fingerprint control, private authorization, and plausible behavior for unauthorized probes. Its strongest transferable idea is architectural separation between the visible cover service and the authorized encrypted channel.

That pattern is not a reason to alter Kademlia. `decent-registry` can retain its DHT algorithm, signed `SignedEnvelope` records, and record validation while replacing or extending the transport beneath them. A direct REALITY-compatible libp2p transport is feasible in principle but is a substantial security-sensitive subsystem. A relay/front-door design is more feasible for a hostile-state threat model because it avoids requiring every DHT node to be a publicly exposed decoy endpoint, at the cost of relay dependence and additional operational complexity.

The current implementation has no DPI-evasion transport. Any documentation or roadmap that presents censorship resistance as implemented would contradict the repository's claim-class policy.

The research also reviewed the current upstream libp2p Identify specification.[10] This source is included for context on address and protocol advertisement.

## Sources

[1] https://raw.githubusercontent.com/XTLS/REALITY/main/README.en.md
[2] https://raw.githubusercontent.com/XTLS/REALITY/main/auth.go
[3] https://raw.githubusercontent.com/XTLS/REALITY/main/conn.go
[4] https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/reality/reality.go
[5] https://raw.githubusercontent.com/XTLS/Xray-core/main/infra/conf/transport_internet.go
[6] https://raw.githubusercontent.com/refraction-networking/utls/master/README.md
[7] https://raw.githubusercontent.com/libp2p/specs/master/kad-dht/README.md
[8] https://raw.githubusercontent.com/libp2p/specs/master/noise/README.md
[9] https://raw.githubusercontent.com/libp2p/specs/master/quic/README.md
[10] https://raw.githubusercontent.com/libp2p/specs/master/identify/README.md
[11] https://www.rfc-editor.org/rfc/rfc8446
[12] https://www.rfc-editor.org/rfc/rfc8701
[13] https://www.rfc-editor.org/rfc/rfc9000

The research also reviewed the current upstream libp2p Identify specification.[10] This source is included for context on address and protocol advertisement.

## Repository references

- [`CONTEXT.md`](../../CONTEXT.md): claim classes and domain vocabulary.
- [`src/decent_registry/dht/libp2p_dht.py`](../../src/decent_registry/dht/libp2p_dht.py): current TCP host and Kad-DHT adapter.
- [`docs/protocol-concepts.md`](../protocol-concepts.md): current transport and lookup description.
- [`docs/research/kad-dht-resiliency-research.md`](kad-dht-resiliency-research.md): existing partition and multi-seed observations.

## Evidence notes

The primary implementation evidence used for the Xray/REALITY description is the current upstream source, not third-party configuration guides. Claims about REALITY's censorship performance are treated as project design claims unless independently measured against a specified censor model. libp2p and IETF citations describe protocol behavior and security properties; they do not establish DPI resistance.
