# 02 — Provider Record Schema

Type: research
Status: resolved

Define the schema and validation rules for the DHT value record used by the registry.

## Answer
Minimal, prototype-first, JSON-serializable schema.

### 1. Key
- DHT routing key = `object_hash` = SHA-256 of the object, encoded as lowercase hex (64 chars).

### 2. Value record (stored by `PUT_VALUE` on the k-closest nodes)
- JSON object:

```json
{
  "version": 1,
  "object_hash": "<sha256hex>",
  "ttl_seconds": 172800,
  "expires_at": 1730000000,
  "providers": [
    {
      "provider_id": "<ed25519-public-key-hex>",
      "endpoints": ["tcp://<host>:<port>", "http://<host>:<port>"],
      "last_seen": 1730000000
    }
  ]
}
```

Notes:
- `expires_at` = `now + ttl_seconds` (sender-computed; receivers can also enforce `now <= expires_at`).
- `ttl_seconds` default target value: 48h (172800s), aligned with common kad-style operational defaults.

### 3. Provider entry
Required fields:
- `provider_id`: node identifier for the provider (Ed25519 public key, represented as a 64-character lowercase hex string). In a Python prototype, it can be generated or mocked as a 256-bit identifier.
- `endpoints`: list of application-level addresses the client can use to reach the provider.
- `last_seen`: sender’s UNIX timestamp.

### 4. Dedup rules
Prototype dedup: unique by `provider_id` + sorted `endpoints`.
- If an incoming record contains duplicate providers after dedup, keep the one with the newest `last_seen`.

### 5. Validation rules (prototype)
On receipt of a record:
- `version == 1`
- `object_hash` matches the lookup key
- `expires_at` is a valid integer and not already expired (or treat as invalid/expired)
- Each provider entry has non-empty `provider_id` and non-empty `endpoints` list

### 6. Update semantics
- Republishing/updating provider info for the same `object_hash` overwrites the stored value record for that key.
- Clients should treat expired records as absent and trigger a re-lookup.

## Comments
This schema is intended for the Python prototype; no signatures/auth in v1. Security/auth can be a later ticket.
