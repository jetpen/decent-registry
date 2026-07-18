# 06 — Node CLI (start listener + join via bootstrap)

**What to build:** A CLI entry point that starts a DHT node (TCP listener) and supports joining the DHT using an explicit list of bootstrap seed endpoints.

**Blocked by:** 05 — Package and productionize Python DHT prototype

**Status:** resolved

## Answer

- Implemented installable console-script CLI `decent-registry node`.
- Supports TCP listener start and optional join via `--bootstrap` seed endpoints.
- Bootstrap failures (unreachable seeds) propagate a non-zero exit code (`1`) in bounded `--run-seconds` mode.
- Verified minimal RPC contract: started an in-process node and confirmed `PING`/`PONG` round-trip via `send_direct`.
- Test verification: `pytest -q` (now `5 passed`).

