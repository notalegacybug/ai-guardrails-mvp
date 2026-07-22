"""The guarded assistant's own internal audit log.

This is the SUT's behaviour — the assistant records every access decision. It is
distinct from the assurance tool's evidence log (assurance/evidence.py); both
reuse the common hash-chain primitive but have different owners.
"""

from common.hashchain import HashChain


class AuditLog:
    def __init__(self) -> None:
        self._chain = HashChain()

    def record(self, actor, role, action, case_id, detail) -> None:
        self._chain.append({
            "actor": actor, "role": role, "action": action,
            "case_id": case_id, "detail": detail,
        })

    def verify(self) -> bool:
        return self._chain.verify()

    def entries(self):
        return self._chain.entries()

    def for_case(self, case_id):
        return [e for e in self._chain.entries()
                if e.payload.get("case_id") == case_id]
