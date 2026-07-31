# Research: Chromium extension for resolving `decent-registry:<MA>//<context>` and rendering objects (#70)

## Problem statement
Given a URL in the repo-defined grammar (from `docs/research/registry-url-format.md`), a Chromium browser should be able to fetch/resolve it and render the target object in the browser.

Repo URL grammar (v0 proposal):
- `decent-registry:<multiaddr>//<context-path>[?<query>]`
- Multiaddr ends at the first literal `//`.
- Custom parsing is required (cannot rely on standard URI “authority” parsing).

The registry service returns, depending on route:
- Identity/Provider *records*; and/or
- A *redirect* to an HTTP(S) `provider_url` (provider record payload includes `provider_url`).

Since the registry URLs are not standard `http(s)` resources, Chrome extensions cannot simply “GET the custom scheme”.

## Hard constraints from Chromium extension APIs
### 1) `chrome.webRequest` cannot see custom schemes
`chrome.webRequest` only exposes a limited set of schemes; it explicitly lists accessible schemes as `http://`, `https://`, `ftp://`, `file://`, `ws://`, `wss://`, `urn:`, `chrome-extension://`.
Source: https://developer.chrome.com/docs/extensions/reference/api/webRequest

### 2) `chrome.declarativeNetRequest` cannot rewrite to custom schemes
`chrome.declarativeNetRequest` `URLTransform.scheme` only allows `http`, `https`, `ftp`, and `chrome-extension`.
Source: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest (URLTransform.scheme)

### 3) Chrome extensions cannot “register” custom URL schemes globally
Chromium WebExtensions do not provide a `protocol_handlers` manifest key (that key is PWA/Firefox WebExtension oriented). Chrome only supports URL scheme handling through:
- PWA URL protocol handler registration (manifest `protocol_handlers`) and
- the web/PWA API `Navigator.registerProtocolHandler()`.

This statement is a Chrome-extension capability boundary, not an implementation detail: MV3 extension manifests do not define a generic `protocol_handlers` field.

Consequence: the browser cannot be taught (by an extension alone) to treat raw `decent-registry:` links typed into the address bar or opened by the OS as HTTP content.

Sources:
- Chrome PWA URL protocol handlers: https://developer.chrome.com/docs/web-platform/best-practices/url-protocol-handler
- MDN `registerProtocolHandler()`: https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler

### 4) `registerProtocolHandler()` is not an extension mechanism
Navigator.registerProtocolHandler() is a web/PWA API:
- limited availability,
- requires HTTPS / secure context,
- and the custom scheme naming rules prefer a `web+`-prefixed scheme.

Source: https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler

Therefore: an extension must not rely on intercepting navigation to `decent-registry:` via network APIs.

## Key enabling fact from this repo
Provider payload includes `provider_url` and endpoints.
- The provider URL is validated to start with `http://` or `https://`.
Source: `src/decent_registry/provider_schema.py` (`_validate_object_url`)

Therefore a practical rendering path is:
1) Resolve the `decent-registry:` URL to either a provider record or directly a redirect.
2) Navigate or fetch the returned `provider_url` using normal browser HTTP(S).

## Recommended extension architecture (MV3)
### Overview
Use a **content script** to capture `decent-registry:` links on regular web pages, and a **service worker** to resolve them via a **local bridge**.

Recommended bridge choices (either):
- **A. Local HTTP gateway** (best UX + simplest rendering):
  - Extension calls `http://127.0.0.1:<port>/resolve?...`.
  - Gateway talks to the DHT and returns JSON with either `{ provider_url }` or `{ "redirect" }`.
  - Extension then navigates to `provider_url` or returns fetched bytes into a renderer.

- **B. Native messaging host** (if you prefer not to run an HTTP gateway):
  - Extension talks to a native app via `chrome.runtime.connectNative` / `sendNativeMessage`.
  - Native app performs DHT lookups and returns resolved data.

Both are compatible; option A is usually preferred because object rendering still requires HTTP(S) fetches.

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
     - `provider/by-hash/<H>`: return provider record (including `provider_url`).
     - `provider/by-hash/<H>/redirect`: return redirect `Location` == validated `provider_url`.

4) Service worker rendering:
   - If redirect/provider_url is present: `chrome.tabs.create({ url: provider_url })` OR `window.location = provider_url` from an injected view.
   - If bridge returns bytes (future v3): create `Blob` + object URL and open/render.

Given repo constraints, object bytes should generally come from `provider_url` over HTTP(S).

## Rendering strategy (two modes)
   ### Mode A: Navigation (recommended)
   - Resolve `decent-registry:` → `provider_url` (or redirect `Location`).
   - Let Chromium perform the GET for the returned `provider_url` using normal browser navigation.
   - Pros: no extension-side MIME handling, CSP/CORS handled by the browser as usual.

   ### Mode B: Fetch-and-render inside extension UI (optional)
   - Only if the bridge returns bytes (e.g. future v3): gateway fetches content and returns `{ mime_type, bytes_base64 }`.
   - Extension constructs `Blob` from bytes, creates an object URL, and renders inside the extension or a new tab.
   - Risks/constraints: MIME-sniffing, large binary memory pressure, and extension UI CSP/sandboxing.

## Address-bar / OS-level limitations and omnibox workaround
   Content scripts only run on matching web pages and can intercept link activations in those pages.
   They cannot reliably intercept:
   - URLs typed directly in the browser address bar, or
   - OS-level handling of `decent-registry:` links.

   Therefore support typed URLs via the extension omnibox keyword (see “Omnibox support”).

## End-to-end example (navigation mode)
   Assume:
   - registry URL to resolve: `decent-registry:/ip4/127.0.0.1/tcp/9000/p2p/<PEERID>//provider/by-hash/<H>/redirect`
   - DHT route `/decent-registry/provider/<H>` holds a provider record whose `provider_url` is `https://example.com/object.bin`.

   Flow:
   1) User clicks a link with that `href` on a normal HTTPS page.
   2) Content script prevents default navigation and sends the raw `decent-registry:` URL to the service worker.
   3) Service worker parses it using the grammar in `docs/research/registry-url-format.md`.
   4) Service worker calls the local bridge: `GET /resolve?url=<encoded decent-registry url>`.
   5) Bridge performs the DHT GET and returns `{ "redirect": "https://example.com/object.bin" }`.
   6) Service worker opens a tab to `https://example.com/object.bin` (Chromium does the actual GET + rendering).

## URL parser requirements (must match repo grammar)
   Implement the parser exactly as specified in `docs/research/registry-url-format.md`:

Pseudocode:
```
parse_decent_registry_url(raw):
  # 1. split at first ':'
  scheme, rest = split_once(raw, ':')
  assert scheme == "decent-registry"

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
  - `{ type:'provider', provider_url: ... }`, or
  - `{ type:'identity', ... }`.
- If provider exists: navigate to `provider_url`.
- If only identity exists: extension cannot render an object because identity does not contain an object URL.

2) `identity/by-name/...` and `identity/by-alias/...`
- Identity payload does not contain `provider_url` by itself.
- Extension should present identity info in a UI panel, and/or attempt a second step:
  - if a “primary identity” includes enough information to find a provider (requires v2 behavior not specified here), then resolve provider.

3) `provider/by-hash/<sha256hex>`
- Extension receives provider record with `provider_url`.
- Extension navigates to `provider_url`.

4) `provider/by-hash/<sha256hex>/redirect`
- Extension receives validated redirect target.
- Extension navigates to that target.

## Bridge implementation options
### Option A: Local HTTP gateway
Goal: keep extension logic simple; treat the DHT resolution as a local RPC.

Connectivity requirement:
- Repo `decent-registry node` is libp2p-only (no HTTP server surface in this codebase).
- The extension bridge must therefore run a local HTTP(S) endpoint (e.g. `http://127.0.0.1:<port>/resolve?...`) that:
  1) parses the `decent-registry:` URL (multiaddr + context path),
  2) dials the peer identified by the multiaddr,
  3) performs the Kad-DHT GET under the correct namespace key(s), and
  4) returns a JSON response containing either `provider_url` or a redirect target.

Gateway endpoints (proposed):
- `GET /resolve?url=<encoded_decent_registry_url>`
  - returns JSON like:
    - `{ "provider_url": "https://..." }`
    - or `{ "redirect": "https://..." }`
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
- Still fetch the actual object bytes via HTTP(S) from `provider_url`.

## Security considerations
- Validate all inputs in bridge:
  - Multiaddr must be syntactically valid.
  - Context path must match known route grammar.
  - Enforce max lengths for any percent-decoded name/alias.
- Prevent open redirect:
  - Only follow `provider_url` values validated by `provider_schema` (must start `http://` or `https://`).
- Constrain network access:
  - If using local HTTP gateway, scope it to localhost origin and require the extension to call it.
- Avoid SSRF where applicable:
  - Treat provider_url strictly as validated HTTP(S) target.
- UX/safety:
  - If identity-only resolution occurs, show info instead of attempting navigation.

## Manifest skeleton (MV3)
Minimal MV3 concepts (pseudo):

- service worker (background): parses and resolves
- content script: intercepts `a[href^="decent-registry:"]` clicks
- permissions:
  - `nativeMessaging` (only if using option B)
  - `tabs` (if you need to create tabs / inspect tab state)
  - `scripting`/`activeTab` (optional for UI injection)

If using option A (local HTTP gateway), also set:
- `host_permissions`: `http://127.0.0.1:<gateway_port>/*` (and/or `http://localhost:*/*`), so the extension can fetch from the gateway.

References:
- Native messaging concepts: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging

## Implementation plan (testable deliverables)
1) Create a local bridge (gateway or native host) that resolves each route in `docs/research/registry-url-format.md` and returns provider_url / redirect.
2) Build an extension prototype:
   - content script intercepts anchor clicks;
   - service worker calls bridge;
   - on provider_url returns, it opens a tab.
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
- `"omnibox": { "keyword": "decent" }` in the extension manifest
- `chrome.omnibox.onInputEntered` handler that opens a new tab to `provider_url` after resolution.

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
