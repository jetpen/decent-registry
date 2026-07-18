import time

class Storage:
    def __init__(self):
        # Maps object_hash (hex) -> value_record dict
        self._store = {}

    def put(self, key: str, record: dict) -> bool:
        """Stores a valid registry record, overwriting any stale or existing record."""
        self._store[key] = record
        return True

    def get(self, key: str) -> dict | None:
        """Retrieves record if present and not expired."""
        if key not in self._store:
            return None
        record = self._store[key]
        expires_at = record.get("expires_at", 0)
        if time.time() > expires_at:
            # Self-prune expired record
            del self._store[key]
            return None
        return record

    def keys(self):
        # Clean expired first
        now = time.time()
        expired = [k for k, r in self._store.items() if now > r.get("expires_at", 0)]
        for k in expired:
            del self._store[k]
        return self._store.keys()
