"""Tiny JSON-file cache with TTL for online lookups (VirusTotal's free tier is heavily rate limited)."""
from __future__ import annotations

import json
import time
from pathlib import Path

from ai_soc import config as C


class Cache:
    def __init__(self, path: Path | None = None, ttl: int = 7 * 86400):
        self.path = Path(path or C.INTEL_DIR / "lookup_cache.json")
        self.ttl = ttl
        self.data = json.load(open(self.path)) if self.path.exists() else {}
        self.hits = self.misses = 0

    def get(self, key):
        v = self.data.get(key)
        if v and time.time() - v["t"] < self.ttl:
            self.hits += 1
            return v["v"]
        self.misses += 1
        return None

    def put(self, key, value):
        self.data[key] = {"t": time.time(), "v": value}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        json.dump(self.data, open(self.path, "w"))
