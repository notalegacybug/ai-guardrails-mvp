"""Tamper-evident, append-only hash chain.

Each entry stores an arbitrary JSON-serializable payload plus the hash of the
previous entry. Altering any past entry breaks every subsequent hash, which
verify() detects. This is the reusable primitive behind both the SUT's internal
audit log and the assurance tool's evidence log.

Note: this is tamper-EVIDENT, not tamper-resistant — an attacker who can rewrite
the in-memory entries can re-link the whole chain; a real deployment needs a
WORM store or external anchoring.
"""

import hashlib
import json
from dataclasses import dataclass, asdict


@dataclass
class ChainEntry:
    seq: int
    payload: dict
    prev_hash: str
    this_hash: str = ""

    def compute_hash(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "this_hash"}
        # default=str stringifies non-JSON leaf values; all payloads used here are JSON-safe.
        blob = json.dumps(body, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()


class HashChain:
    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._entries: list[ChainEntry] = []

    def append(self, payload: dict) -> ChainEntry:
        prev = self._entries[-1].this_hash if self._entries else self.GENESIS
        entry = ChainEntry(seq=len(self._entries), payload=payload, prev_hash=prev)
        entry.this_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = self.GENESIS
        for e in self._entries:
            if e.prev_hash != prev:
                return False
            if e.compute_hash() != e.this_hash:
                return False
            prev = e.this_hash
        return True

    def entries(self) -> list[ChainEntry]:
        return list(self._entries)
