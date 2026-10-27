# py-libp2p 0.8.1 upgrade qualification

**Selected version:** `libp2p==0.8.1` is the latest stable release considered for this change (2026-10-27). The project requirement is raised to `libp2p>=0.8.1`; `uv.lock` selects 0.8.1. Its dependency resolution adds `prometheus-client==0.26.0`; other direct dependency versions remain unchanged.

**Claim class:** The dependency constraint and lock are implemented and code-backed; the latest-stable assessment is documented or researched but unimplemented.

## Release-note review

**Claim class:** documented or researched but unimplemented. This section summarizes upstream release notes; it does not claim the Registry implements every upstream API/transport change.

Source: [py-libp2p release notes](https://py-libp2p.readthedocs.io/en/stable/release_notes.html).

The 0.8.0 notes describe changes that matter when checking callers and error handling:

- `new_host()` moved `connection_config` to the end of its signature; positional callers must be updated. Registry construction uses keyword arguments.
- `IListener.listen()` and concrete listeners removed the `nursery` argument. Registry does not call the listener API directly.
- TCP dial failures now raise `OpenConnectionError` rather than returning `False`; TCP reset handling now raises `ConnectionClosedError` rather than silently returning an empty read. Registry lookup paths must continue to fail closed on these failures.

The 0.8.1 notes change default TLS certificate/hostname verification for `wss` and WebSocket dialing behavior. The Registry currently configures TCP, so those WebSocket changes do not directly affect its transport path.

Source inspection of the selected DHT release found an additional caller-compatibility seam: inbound handling calls `add_peer(..., skip_server_mode_check=True)`. The Registry routing-eligibility wrapper must accept and forward that keyword only after its own serving-proof eligibility check; it must not let the libp2p override bypass Registry policy.

## Qualification findings

**Claim class:** implemented and code-backed. The candidate Registry change and recorded test results in this section describe changes exercised in the updated checkout.

The existing fresh-network-reader integration test passed with the locked 0.7.0 environment and failed against an isolated 0.8.1 resolution: trying an unavailable address followed by a working address for the same PeerID returned no record. The isolated per-configured-peer reader fixes this candidate behavior without using the writer cache or DHT repair path. The test passes against 0.8.1 after the change.

**Claim class:** documented or researched but unimplemented. The statement below about the upgrade alone is based on the recorded 0.8.1 characterization in #124's current issue body, not inferred from the native test in this change.

The 0.8.1 release alone **partially changes but does not fix** the stale-referral behavior from #124: its connection-type report changes, but the request-only CLIENT peer can still remain in `closerPeers`.

**Claim class:** implemented and code-backed. The Registry-owned serving-eligibility correction was implemented independently and merged in [PR #126](https://github.com/jetpen/decent-registry/pull/126).

**Tracker status:** GitHub records [#124](https://github.com/jetpen/decent-registry/issues/124) as closed/completed.

**Claim class:** implemented and code-backed for the combined-system result. The opt-in native Registry qualification was rerun with 0.8.1 and the #126 gate in place and passed, including the publish-A / separate reads / publish-B / fresh-read sequence. This confirms the combined system, not that the dependency upgrade alone fixes #124.

**Claim class:** implemented and code-backed. Validation on the candidate snapshot: focused DHT/Registry suites passed (71 passed, 1 skipped); full suite passed (265 passed, 2 skipped); the explicit native #124 qualification passed (1 passed). See the associated PR for exact commands and run output.
