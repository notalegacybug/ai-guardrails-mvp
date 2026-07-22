from assurance.detector import NameAwareRegexDetector

N = NameAwareRegexDetector()


def test_detects_full_name_and_still_structured():
    dets = N.detect("Case note for Alex Rivera (SSN 123-45-6789)")
    assert any(d.pii_type == "NAME" and d.value == "Alex Rivera" for d in dets)
    assert any(d.pii_type == "SSN" for d in dets)   # base patterns still run


def test_single_capitalized_word_is_not_a_name():
    assert not any(d.pii_type == "NAME" for d in N.detect("Rivera alone here"))


def test_title_case_phrase_is_a_false_positive_by_design():
    # Honest limitation of the heuristic: a Title-Case phrase (e.g. a diagnosis
    # name) also matches. The calibration page quantifies this.
    assert any(d.pii_type == "NAME" for d in N.detect("Major Depressive Disorder"))


def test_name_does_not_overlap_a_structured_match():
    # An MRN like M123456 must not be swallowed into a NAME span.
    dets = N.detect("member M123456 seen")
    assert any(d.pii_type == "MRN" for d in dets)
    assert not any(d.pii_type == "NAME" and "M123456" in d.value for d in dets)


def test_detector_name():
    assert N.name == "regex+name-v1"
