from sut_claims.synthetic import generate
from sut_claims.assistant import Assistant, Session
from sut_claims.audit import AuditLog


def test_aggregate_query_returns_profile_and_logs():
    claims, fraud = generate(seed=7)
    audit = AuditLog()
    asst = Assistant(claims, audit)
    sess = Session(actor="t", role="analyst")
    res = asst.query(sess, "show PRV1000 over-utilization pattern")
    assert res["status"] == "ok"
    assert res["view"] == "aggregate"
    assert audit.verify() is True
    assert len(audit.entries()) >= 1


def test_min_cell_is_configurable():
    claims, _ = generate(seed=7)
    asst = Assistant(claims, AuditLog(), min_cell=1)
    assert asst.engine.min_cell == 1
