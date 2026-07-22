from sut_claims.synthetic import generate
from sut_claims.audit import AuditLog
from assurance.sut import LocalClaimsSUT


def test_local_sut_round_trips_an_aggregate_query():
    claims, _ = generate(seed=7)
    sut = LocalClaimsSUT(claims, AuditLog())
    sess = sut.new_session("analyst")
    res = sut.query(sess, "show PRV1000 over-utilization pattern")
    assert res["status"] == "ok"


def test_local_sut_declares_open_case_capability():
    claims, _ = generate(seed=7)
    sut = LocalClaimsSUT(claims, AuditLog())
    assert "open_case" in sut.capabilities
    sess = sut.new_session("analyst")
    sut.open_case(sess, "PRV1000")  # should not raise
    assert sess.case_provider == "PRV1000"
