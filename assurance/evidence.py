"""The assurance tool's tamper-evident record of a test run.

One entry per attack attempt: what was sent, what came back, the verdict, and the
controls exercised. Reuses the shared hash chain so an auditor can prove the
report was not edited after the fact.
"""

from common.hashchain import HashChain, ChainEntry


class EvidenceLog:
    def __init__(self) -> None:
        self._chain = HashChain()

    def append(self, payload: dict) -> ChainEntry:
        return self._chain.append(payload)

    def verify(self) -> bool:
        return self._chain.verify()

    def entries(self) -> list[ChainEntry]:
        return self._chain.entries()
