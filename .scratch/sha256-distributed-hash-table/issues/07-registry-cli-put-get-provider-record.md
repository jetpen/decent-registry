# 07 — Registry CLI (put + get provider record by object hash)

**What to build:** A CLI entry point that publishes provider registry records to the DHT (PUT_VALUE/store) and resolves object hashes to provider endpoints (iterative GET_VALUE/find-value).

**Blocked by:** 06 — Node CLI (start listener + join via bootstrap)

**Status:** resolved

## Answer

- Implemented registry CLI subcommands:
  - `decent-registry put` publishes a provider registry record for an `object_hash` with TTL (`version=1`, `expires_at = now + ttl_seconds`) via DHT `PUT_VALUE`.
  - `decent-registry get` resolves an `object_hash` via iterative value lookup (`iterative_find_value` / `GET_VALUE` walker) and prints `not found` on expiry.
- CLI verification:
  - `tests/test_cli_registry.py` covers put→get round-trip and TTL expiry returning not-found.
- Test verification: `pytest -q` => `7 passed`.
