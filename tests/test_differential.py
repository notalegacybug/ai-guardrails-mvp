from sut_claims.synthetic import generate
from sut_claims.audit import AuditLog
from assurance.sut import LocalClaimsSUT
from assurance.differential import run_differential, DifferentialProbe, DIFF_PROBES


def _local_sut():
    claims, _ = generate(seed=7)
    return LocalClaimsSUT(claims, AuditLog())


def test_local_sut_passes_rbac_differential():
    sut = _local_sut()
    results = [run_differential(sut, p) for p in DIFF_PROBES]
    assert results and all(r.outcome == "PASS" for r in results)


def test_leaky_sut_is_flagged():
    class LeakySUT:
        capabilities = {"open_case"}
        def new_session(self, role): return {"role": role}
        def open_case(self, session, provider_id): pass
        def query(self, session, text):
            return {"view": "member_level", "rows": [{"tier": 3}]}
    probe = DifferentialProbe("X", "show detail", "analyst", "junior_analyst", "PRV1000")
    r = run_differential(LeakySUT(), probe)
    assert r.outcome == "LEAK"


def test_raising_sut_is_error():
    class BoomSUT:
        capabilities = {"open_case"}
        def new_session(self, role): return {}
        def open_case(self, session, provider_id): pass
        def query(self, session, text): raise RuntimeError("boom")
    probe = DifferentialProbe("X", "show detail", "analyst", "junior_analyst", "PRV1000")
    r = run_differential(BoomSUT(), probe)
    assert r.outcome == "ERROR"
