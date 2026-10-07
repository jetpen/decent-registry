# Research: Chromium extension for resolving `kad:<MA>//<context>` and rendering objects (#70)

It documents a proposed browser integration, not current Registry functionality.

Repo URL grammar (v0 proposal):
- `kad:<multiaddr>//<context-path>[?<query>]`
- Multiaddr ends at the first literal `//`.
- Custom parsing is required (cannot rely on standard URI “authority” parsing).

The registry service returns, depending on route:
- Identity/Provider records using current schemas; the Provider Record contains `provider_urls` and separate multiaddr `endpoints`.
- A proposed redirect, if implemented, must select an HTTP(S) locator from `provider_urls`.

Since the registry URLs are not standard `http(s)` resources, Chrome extensions cannot simply “GET the custom scheme”.

## Hard constraints from Chromium extension APIs
### 1) `chrome.webRequest` cannot see custom schemes
The above allows `http://`, `https://`, `ftp://`, `ws://`, `wss://`, `urn:`, and `chrome-extension://`. It does not make a generic `file://` URI a portable Provider Record locator.
Source: https://developer.chrome.com/docs/extensions/reference/api/webRequest

### 2) `chrome.declarativeNetRequest` cannot rewrite to custom schemes
`chrome.declarativeNetRequest` `URLTransform.scheme` only allows `http`, `https`, `ftp`, and `chrome-extension`.
Source: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest (URLTransform.scheme)

### 3) Chrome extensions cannot “register” custom URL schemes globally
Chromium WebExtensions do not provide a `protocol_handlers` manifest key (that key is PWA/Firefox WebExtension oriented). Chrome only supports URL scheme handling through:
- PWA URL protocol handler registration (manifest `protocol_handlers`) and
- the web/PWA API `Navigator.registerProtocolHandler()`.

This statement is a Chrome-extension capability boundary, not an implementation detail: MV3 extension manifests do not define a generic `protocol_handlers` field.

Consequence: the browser cannot be taught (by an extension alone) to treat raw `kad:` links typed into the address bar or opened by the OS as HTTP content.

Sources:
- Chrome PWA URL protocol handlers: https://developer.chrome.com/docs/web-platform/best-practices/url-protocol-handler
- MDN `registerProtocolHandler()`: https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler

### 4) `registerProtocolHandler()` is not an extension mechanism
Navigator.registerProtocolHandler() is a web/PWA API:
- limited availability,
- requires HTTPS / secure context,
- and the custom scheme naming rules prefer a `web+`-prefixed scheme.

Source: https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler

Therefore: an extension must not rely on intercepting navigation to `kad:` via network APIs.

## Key enabling fact from this repo
Provider Records return validated `provider_urls` plus separate multiaddr `endpoints`. URI schemes are protocol-agnostic; clients must choose a scheme they can access and verify returned bytes against the Object Hash. The proposed browser flow opens only HTTP(S) locators. Other schemes require separate handlers that are not implemented here.

## Recommended extension architecture (MV3)
### Overview
Use a **content script** to capture `kad:` links on regular web pages, and a **service worker** to resolve them via a **local bridge**.

Recommended bridge choices (either):
- **A. Local HTTP gateway** (best UX + simplest rendering):
  - Extension calls `http://127.0.0.1:<port>/resolve?...`.
  - Gateway talks to the DHT and returns the verified Provider Record, including `provider_urls`, or a future redirect response.
  - For navigation, the extension selects only an HTTP(S) locator from the returned list.
  - A future redirect implementation must likewise select an HTTP(S) locator; the Registry itself must not treat every URI scheme as a browser-safe redirect.

- **B. Native messaging host** (if you prefer not to run an HTTP gateway):
  - Extension talks to a native app via `chrome.runtime.connectNative` / `sendNativeMessage`.
  - Native app performs DHT lookups and returns resolved data.

Both are compatible; the extension's direct navigation mode is limited to HTTP(S) locators. Other schemes need a separate handler; any bridge that retrieves bytes must do so under explicit security controls.

### Why content script + service worker
- Content scripts can detect anchor clicks and link attributes (DOM access).
- Native messaging APIs are not available in content scripts; messages must route through extension pages/service worker.
Source: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging (nativeMessaging is for extension pages/service worker)

### Flow
1) Content script:
   - Intercept link activations that can trigger navigation, not only plain clicks:
     - left click
     - middle click / auxclick
     - ctrl/meta modified clicks
     - (optional) context-menu navigation via `chrome.contextMenus`
   - `preventDefault()`.
   - Send the raw URL string to service worker via `chrome.runtime.sendMessage`.

2) Service worker:
   - Parse using the custom grammar parser rules from `docs/research/registry-url-format.md`.
   - Call local bridge (gateway or native host) with the raw URL or parsed parts.

3) Bridge:
   - Resolve context route:
     - `by-hash/<H>`: query provider namespace and identity namespace; return whichever exists (and both if collision).
     - `identity/by-name/<owner-name>`: compute identity key (sha256(owner_name_bytes)).
     - `identity/by-alias/<alias>`: resolve v2 primary/alias semantics (requires v2 validator implementation).
     - `identity/by-owner-pubkey/<pubkey>`: requires future reverse index; until implemented, return 501.
     - `provider/by-hash/<H>`: return the Provider Record, including `provider_urls` and multiaddr `endpoints`.
     - A proposed `/redirect` route may select an HTTP(S) locator only; generic URI schemes are not automatically safe browser redirect targets.

4) Service worker rendering:
   - If selecting a provider location, open only a caller-selected HTTP(S) locator. Non-HTTP schemes require another handler, which is outside the proposed extension.
   - If a future bridge returns bytes, create a `Blob` + object URL and open/render.

Given browser support constraints, the proposed extension should open only HTTP(S) locators. Other URI schemes require an external handler that is out of scope.

## Rendering strategy (two modes)
   ### Mode A: Navigation (recommended)
   - Resolve `kad:` → the Provider Record, then select an HTTP(S) locator from `provider_urls`.
   - Let Chromium perform the GET for that HTTP(S) locator using normal browser navigation.
   - Pros: no extension-side MIME handling, CSP/CORS handled by the browser as usual.

   ### Mode B: Fetch-and-render inside extension UI (optional)
   - Only if the bridge returns bytes (e.g. future v3): gateway fetches content and returns `{ mime_type, bytes_base64 }`.
   - Extension constructs `Blob` from bytes, creates an object URL, and renders inside the extension or a new tab.
   - Risks/constraints: MIME-sniffing, large binary memory pressure, and extension UI CSP/sandboxing.

## Address-bar / OS-level limitations and omnibox workaround
   Content scripts only run on matching web pages and can intercept link activations in those pages.
   They cannot reliably intercept:
   - URLs typed directly in the browser address bar, or
   - OS-level handling of `kad:` links.

   Therefore support typed URLs via the extension omnibox keyword (see “Omnibox support”).

## End-to-end example (navigation mode)
   Assume:
   - registry URL to resolve: `kad:/ip4/127.0.0.1/tcp/9000/p2p/<PEERID>//provider/by-hash/<H>/redirect`
   - DHT route `/decent-registry/provider/<H>` holds a Provider Record whose `provider_urls` includes `https://example.com/object.bin`.

   Flow:
   1) User clicks a link with that `href` on a normal HTTPS page.
   2) Content script prevents default navigation and sends the raw `kad:` URL to the service worker.
   3) Service worker parses it using the grammar in `docs/research/registry-url-format.md`.
   4) Service worker calls the local bridge: `GET /resolve?url=<encoded kad: URL>`.
   5) Bridge performs the DHT GET, selects an HTTP(S) locator from `provider_urls`, and returns `{ "redirect": "https://example.com/object.bin" }`.
   6) Service worker opens a tab to `https://example.com/object.bin` (Chromium does the actual GET + rendering).

## URL parser requirements (must match repo grammar)
   Implement the parser exactly as specified in `docs/research/registry-url-format.md`:

Pseudocode:
```
parse_kad_url(raw):
  # 1. split at first ':'
  scheme, rest = split_once(raw, ':')
  assert scheme == "kad"

  # 2. split rest at first literal '//' into multiaddr + context_query
  multiaddr, after = split_once(rest, '//')
  assert multiaddr starts_with '/'

  # 3. context_path is before optional '?' in `after`
  context_path, query = split_once(after, '?')

  return (scheme, multiaddr, context_path, query)
```

Percent-decoding rules:
- For `identity/by-name/<owner-name>` and `identity/by-alias/<alias>`: apply percent-decoding to UTF-8 bytes, then compute SHA-256 over the raw decoded bytes (no Unicode normalization beyond percent-decoding).

Delimiter edge case:
- Multiaddrs containing empty path components (e.g. `/unix//path`) conflict with the `//` delimiter; either exclude these transports from v1 or change delimiter before implementation.

## Rendering semantics per route (extension perspective)
Routes from `docs/research/registry-url-format.md`:

1) `by-hash/<sha256hex>`
- Extension receives either:
  - `{ matches: [{type:'identity',...},{type:'provider',...}] }`, or
  - `{ type:'provider', provider_urls: [...], endpoints: [...] }`, or
  - `{ type:'identity', ... }`.
- If provider exists: select a supported HTTP(S) locator from `provider_urls` and navigate only to that locator.
- If only identity exists: extension cannot render an object because identity does not contain an object URL.

2) `identity/by-name/...` and `identity/by-alias/...`
- Identity payload does not contain Provider Record `provider_urls` or endpoints.
- Extension should present identity info in a UI panel, and/or attempt a second step:
  - if a “primary identity” includes enough information to find a provider (requires v2 behavior not specified here), then resolve provider.

3) `provider/by-hash/<sha256hex>`
- Extension receives a Provider Record with one or more `provider_urls` plus separate multiaddr `endpoints`.
- The browser client selects a supported HTTP(S) locator; it must not navigate directly to an unsupported scheme.

4) `provider/by-hash/<sha256hex>/redirect`
- The proposed bridge selects a supported HTTP(S) locator from `provider_urls` and returns it as the redirect target.
- Extension navigates only to that validated HTTP(S) target.

## Bridge implementation options
### Option A: Local HTTP gateway
Goal: keep extension logic simple; treat the DHT resolution as a local RPC.

Connectivity requirement:
- Repo `decent-registry node` is libp2p-only (no HTTP server surface in this codebase).
- The extension bridge must therefore run a local HTTP(S) endpoint (e.g. `http://127.0.0.1:<port>/resolve?...`) that:
  1) parses the `kad:` URL (multiaddr + context path),
  2) dials the peer identified by the multiaddr,
  3) performs the Kad-DHT GET under the correct namespace key(s), and
  4) returns JSON containing the Provider Record with `provider_urls`, or a proposed redirect explicitly selected from supported HTTP(S) locators.

Gateway endpoints (proposed):
- `GET /resolve?url=<encoded_decent_registry_url>`
  - returns JSON like:
    - `{ "provider_urls": ["https://...", "ipfs://..."] }`
    - or `{ "redirect": "https://..." }` (HTTP(S) selected by the bridge)
    - or `{ "matches": [...] }`

This also allows the gateway to host/contain the Python libp2p DHT logic.

### Option B: Native messaging host
Native messaging basics:
- Extension uses `chrome.runtime.connectNative(appName)` / `sendNativeMessage()`.
- `nativeMessaging` must be declared in extension manifest.
Source:
- https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging

Important constraints:
- Native messaging is not available in content scripts; route through service worker.

Recommended use case:
- Use native messaging for the DHT resolution step.
- Still fetch the actual object bytes using a supported HTTP(S) locator selected from `provider_urls`; other schemes require a separate handler, outside this extension proposal.

## Security considerations
- Validate all inputs in bridge:
  - Multiaddr must be syntactically valid.
  - Context path must match known route grammar.
  - Enforce max lengths for any percent-decoded name/alias.
- Prevent open redirect:
  - Only follow caller-selected HTTP(S) locators from `provider_urls`; generic URI scheme validation alone cannot make a locator safe for browser navigation.
- Constrain network access:
  - If using local HTTP gateway, scope it to localhost origin and require the extension to call it.
- Avoid SSRF where applicable:
  - Before a future bridge fetches a provider locator, apply SSRF controls beyond URI validation; never assume a syntactically valid locator is safe to fetch.
- UX/safety:
  - If identity-only resolution occurs, show info instead of attempting navigation.

## Manifest skeleton (MV3)
Minimal MV3 concepts (pseudo):

- service worker (background): parses and resolves
- content script: intercepts `a[href^="kad:"]` clicks
- permissions:
  - `nativeMessaging` (only if using option B)
  - `tabs` (if you need to create tabs / inspect tab state)
  - `scripting`/`activeTab` (optional for UI injection)

If using option A (local HTTP gateway), also set:
- `host_permissions`: `http://127.0.0.1:<gateway_port>/*` (and/or `http://localhost:*/*`), so the extension can fetch from the gateway.

References:
- Native messaging concepts: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging

## Implementation plan (testable deliverables)
1) Create a local bridge (gateway or native host) that resolves each route in `docs/research/registry-url-format.md` and returns Provider Records with `provider_urls`; any redirect target must be explicitly selected from supported HTTP(S) locators.
2) Build an extension prototype:
   - content script intercepts anchor clicks;
   - service worker calls bridge;
   - on a Provider Record, selects a supported HTTP(S) locator from `provider_urls` before opening a tab.
3) Create a test HTML page served from `https://` origin containing links:
   - one `provider/by-hash/<H>`
   - one `provider/by-hash/<H>/redirect`
   - one `by-hash/<H>` collision scenario.
4) Use a local DHT node running `decent-registry node` (from repo docs) and seed/put records required for each test.
5) Verify:
   - provider records resolve;
   - redirect resolves;
   - unknown routes show errors;
   - identity-only does not navigate.

## Omnibox support (optional but recommended UX)
To allow users to paste/type the raw scheme URL into Chrome’s address bar and have the extension resolve it, add:
- `"omnibox": { "keyword": "kad" }` in the extension manifest
- `chrome.omnibox.onInputEntered` handler that opens a new tab only after selecting an HTTP(S) locator from the resolved `provider_urls`.

Source: https://developer.chrome.com/docs/extensions/reference/api/omnibox

## Alternatives and non-extension mechanisms
- PWA `protocol_handlers` / `registerProtocolHandler()`:
  - could support a `web+...` variant of the scheme, but it is not an extension capability and has limited availability.
  - treat as a fallback/second phase.
Sources:
- https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler
- https://developer.chrome.com/docs/web-platform/best-practices/url-protocol-handler

## Open decisions
- Bridge choice: local HTTP gateway vs native messaging host.
- Whether to support identity-only “rendering” as an information UI panel.
- Whether to implement v2 alias semantics and owner-pubkey reverse lookup before shipping the extension.
