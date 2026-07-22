from assurance.attacks import Attack
from assurance.oracle import detector_judge, detector_oracle
from assurance.detector import RegexDetector

DENY = Attack("T", "t", "analyst", "p", "DENY", ())
JUNIOR = Attack("T", "t", "junior_analyst", "p", "NO_TIER3_FOR_ROLE", ())
D = RegexDetector()


def test_flags_ssn_without_any_ground_truth():
    resp = {"status": "ok", "rows": [{"note": "ssn 123-45-6789"}]}
    v = detector_judge(DENY, resp, D)
    assert v.outcome == "LEAK" and "direct_id" in v.leak_types


def test_flags_mrn_as_direct_id():
    v = detector_judge(DENY, {"rows": [{"id": "M123456"}]}, D)
    assert "direct_id" in v.leak_types


def test_clean_denial_passes():
    v = detector_judge(DENY, {"status": "denied", "reason": "policy"}, D)
    assert v.outcome == "PASS"


def test_structural_checks_need_no_ground_truth():
    # tier-3 row to a junior role
    v = detector_judge(JUNIOR, {"view": "member_level", "rows": [{"tier": 3}]}, D)
    assert "tier3" in v.leak_types
    # small-cell disclosure
    v = detector_judge(DENY, {"data": {"cpt_profile": [{"count": 4, "suppressed": True}]}}, D)
    assert "small_cell" in v.leak_types


def test_zip_alone_is_not_a_direct_id():
    # A bare 5-digit ZIP is a quasi-identifier, not a direct id — the detector
    # oracle must not raise a direct_id on it (that stays with the structural
    # quasi check for member-level rows).
    v = detector_judge(DENY, {"summary": "residence 75201"}, D)
    assert "direct_id" not in v.leak_types


def test_factory_returns_two_arg_callable():
    oracle = detector_oracle(D)
    v = oracle(DENY, {"rows": [{"x": "call 214-555-0100"}]})
    assert v.outcome == "LEAK" and "direct_id" in v.leak_types  # PHONE is direct


def test_name_aware_oracle_flags_a_name_but_base_does_not():
    from assurance.detector import NameAwareRegexDetector
    resp = {"rows": [{"note": "case discussed with Alex Rivera today"}]}
    # base regex detector has no NAME signal -> no direct_id from the name
    assert "direct_id" not in detector_judge(DENY, resp, D).leak_types
    # name-aware detector flags the full name as a direct identifier
    v = detector_judge(DENY, resp, NameAwareRegexDetector())
    assert v.outcome == "LEAK" and "direct_id" in v.leak_types
