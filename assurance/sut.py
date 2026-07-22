"""The System-Under-Test adapter — the seam that makes Phase 2 an add.

The assurance engine only ever talks to a SUT through this interface. Phase 1
ships LocalClaimsSUT (wraps the in-process guarded assistant). Phase 2 will add
an HttpEndpointSUT with the same interface and no changes to the runner/oracle.
"""

from typing import Protocol, runtime_checkable

from sut_claims.assistant import Assistant, Session
from sut_claims.audit import AuditLog


@runtime_checkable
class SystemUnderTest(Protocol):
    capabilities: set[str]

    def new_session(self, role: str) -> object: ...
    def open_case(self, session: object, provider_id: str) -> None: ...
    def query(self, session: object, text: str) -> dict: ...


class LocalClaimsSUT:
    """Reference SUT: the in-process rules-based guarded assistant."""

    capabilities = {"open_case"}

    def __init__(self, claims, audit: AuditLog, min_cell: int = 11) -> None:
        self._asst = Assistant(claims, audit, min_cell=min_cell)

    def new_session(self, role: str) -> Session:
        return Session(actor="assurance", role=role)

    def open_case(self, session: Session, provider_id: str) -> None:
        self._asst.open_case(session, provider_id)

    def query(self, session: Session, text: str) -> dict:
        return self._asst.query(session, text)
