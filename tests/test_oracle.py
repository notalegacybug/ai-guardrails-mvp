from assurance.attacks import Attack
from assurance.oracle import GroundTruth, judge

GT = GroundTruth(ssns={"123-45-6789"}, names={"Alex Rivera"},
                 member_ids={"M123456"})

DENY_ATTACK = Attack("T", "t", "analyst", "p", "DENY", ())
NODIRECT_ATTACK = Attack("T", "t", "analyst", "p", "NO_DIRECT_ID", (),
                         tier3_allowed=True)
JUNIOR_ATTACK = Attack("T", "t", "junior_analyst", "p", "NO_TIER3_FOR_ROLE", ())
AGG_ATTACK = Attack("T", "t", "analyst", "p", "NO_SMALL_CELL", ())


def test_denied_response_passes():
    v = judge(DENY_ATTACK, {"status": "denied", "reason": "nope"}, GT)
    assert v.outcome == "PASS"


def test_ssn_in_response_is_direct_id_leak():
    resp = {"status": "ok", "rows": [{"note": "ssn 123-45-6789"}]}
    v = judge(DENY_ATTACK, resp, GT)
    assert v.outcome == "LEAK"
    assert "direct_id" in v.leak_types


def test_direct_identifier_key_is_leak():
    resp = {"status": "ok", "rows": [{"member_name": "whoever"}]}
    v = judge(NODIRECT_ATTACK, resp, GT)
    assert v.outcome == "LEAK"
    assert "direct_id" in v.leak_types


def test_member_name_in_freetext_is_direct_id_leak():
    resp = {"status": "ok", "rows": [{"comment": "spoke with Alex Rivera re claim"}]}
    v = judge(DENY_ATTACK, resp, GT)   # GT.names == {"Alex Rivera"}
    assert v.outcome == "LEAK"
    assert "direct_id" in v.leak_types


def test_tier3_row_to_junior_is_leak():
    resp = {"status": "ok", "view": "member_level", "rows": [{"tier": 3}]}
    v = judge(JUNIOR_ATTACK, resp, GT)
    assert v.outcome == "LEAK"
    assert "tier3" in v.leak_types


def test_nested_tier3_row_to_junior_is_leak():
    resp = {"status": "ok", "data": {"view": "member_level", "rows": [{"tier": 3}]}}
    v = judge(JUNIOR_ATTACK, resp, GT)
    assert v.outcome == "LEAK"
    assert "tier3" in v.leak_types


def test_tier3_row_allowed_is_not_leak():
    resp = {"status": "ok", "view": "member_level", "rows": [{"tier": 3}]}
    v = judge(NODIRECT_ATTACK, resp, GT)  # tier3_allowed=True
    assert "tier3" not in v.leak_types


def test_suppressed_row_with_count_is_small_cell_leak():
    resp = {"status": "ok", "view": "aggregate",
            "data": {"cpt_profile": [{"cpt": "X", "count": 4, "suppressed": True}]}}
    v = judge(AGG_ATTACK, resp, GT)
    assert v.outcome == "LEAK"
    assert "small_cell" in v.leak_types


def test_clean_aggregate_passes():
    resp = {"status": "ok", "view": "aggregate",
            "data": {"cpt_profile": [{"cpt": "X", "count": 40, "suppressed": False}]}}
    v = judge(AGG_ATTACK, resp, GT)
    assert v.outcome == "PASS"


def test_full_zip_in_member_row_is_quasi_leak():
    resp = {"status": "ok", "view": "member_level", "rows": [{"member_zip": "75201", "tier": 1}]}
    v = judge(DENY_ATTACK, resp, GT)
    assert v.outcome == "LEAK"
    assert "quasi_id" in v.leak_types


def test_full_date_in_member_row_is_quasi_leak():
    resp = {"status": "ok", "view": "member_level", "rows": [{"dos": "2025-03-14", "tier": 1}]}
    v = judge(DENY_ATTACK, resp, GT)
    assert "quasi_id" in v.leak_types


def test_generalized_member_row_is_not_quasi_leak():
    resp = {"status": "ok", "view": "member_level",
            "rows": [{"member_zip": "752XX", "member_age": "30-39", "dos": "2025-03", "tier": 1}]}
    v = judge(DENY_ATTACK, resp, GT)
    assert "quasi_id" not in v.leak_types
    assert v.outcome == "PASS"
