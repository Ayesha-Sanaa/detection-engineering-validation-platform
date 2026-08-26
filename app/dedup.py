import hashlib
import time
from threading import Lock


DEDUP_WINDOW_SECONDS = 300


class DedupCache:
    def __init__(self, window_seconds: int = DEDUP_WINDOW_SECONDS):
        self._store: dict[str, float] = {}
        self._lock = Lock()
        self._window = window_seconds

    @staticmethod
    def _make_key(alert: dict) -> str:
        raw = "|".join(
            str(alert.get(field, ""))
            for field in (
                "host",
                "user",
                "technique_id",
                "rule_name",
            )
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_duplicate(self, alert: dict) -> bool:
        key = self._make_key(alert)
        now = time.time()

        with self._lock:
            self._prune(now)
            last_seen = self._store.get(key)

            if last_seen is not None and (now - last_seen) < self._window:
                return True

            self._store[key] = now
            return False

    def _prune(self, now: float) -> None:
        expired = [
            key
            for key, timestamp in self._store.items()
            if (now - timestamp) >= self._window
        ]

        for key in expired:
            del self._store[key]


dedup_cache = DedupCache()
