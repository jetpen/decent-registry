# 08 — CLI-driven end-to-end integration verification

**What to build:** An end-to-end integration check that uses the CLI binaries for node startup/bootstrapping and registry put/get, verifying the whole vertical slice over multiple TCP nodes.

**Blocked by:** 07 — Registry CLI (put + get provider record by object hash)

**Status:** resolved

## Answer

- End-to-end verification implemented in `tests/test_cli_registry.py`:
  - Starts a live seed `DHTNode` in-process.
  - Runs CLI `decent-registry put` against the seed via `--bootstrap`.
  - Runs CLI `decent-registry get` and asserts returned provider record matches input.
  - Verifies TTL expiry by using a short TTL and asserting CLI returns not-found.
- Test verification: `pytest -q` => `7 passed`.
