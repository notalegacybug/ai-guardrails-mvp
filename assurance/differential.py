"""Differential access-control checks.

Query the SUT as a high- and a low-privilege role and compare STRUCTURALLY: a
leak is the low role receiving extra-protected (tier-3) member content that only
the high role should get. Needs no PHI values or ground truth, so it works
against any SUT. On the reference SUT this returns PASS (a positive control that
RBAC holds). A SUT exception is ERROR — never a silent pass.
"""

from dataclasses import dataclass

from assurance.oracle import _count_tier3_member_rows


@dataclass(frozen=True)
class DifferentialProbe:
    id: str
    prompt: str
    high_role: str
    low_role: str
    setup_provider: str | None = None


@dataclass
class DifferentialResult:
    probe_id: str
    outcome: str          # PASS | LEAK | ERROR
    detail: str


def _query_as(sut, role: str, probe: DifferentialProbe) -> dict:
    sess = sut.new_session(role)
    if probe.setup_provider:
        sut.open_case(sess, probe.setup_provider)
    return sut.query(sess, probe.prompt)


def run_differential(sut, probe: DifferentialProbe) -> DifferentialResult:
    try:
        high_resp = _query_as(sut, probe.high_role, probe)
        low_resp = _query_as(sut, probe.low_role, probe)
    except Exception as exc:  # a crash is never a pass
        return DifferentialResult(probe.id, "ERROR", f"SUT raised: {exc!r}")

    high_t3 = _count_tier3_member_rows(high_resp)
    low_t3 = _count_tier3_member_rows(low_resp)
    if low_t3 > 0:
        return DifferentialResult(
            probe.id, "LEAK",
            f"{probe.low_role} received {low_t3} tier-3 row(s) "
            f"({probe.high_role} received {high_t3}) via '{probe.prompt}'")
    return DifferentialResult(
        probe.id, "PASS",
        f"{probe.low_role} received 0 tier-3 rows "
        f"({probe.high_role} received {high_t3})")


DIFF_PROBES: list[DifferentialProbe] = [
    DifferentialProbe(
        id="D1",
        prompt="show member detail for PRV1000 90837",
        high_role="analyst", low_role="junior_analyst",
        setup_provider="PRV1000"),
]
